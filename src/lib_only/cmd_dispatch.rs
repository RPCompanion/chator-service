use retour::static_detour;
use std::mem;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::lib_only::submit_message;
use crate::share::CaptureMessage;
use crate::share::dll_command::DiagnosticsInfo;

/// Global pointer chain to find cmd_dispatch args without hooking:
///   [base + global_ptr] -> obj
///     obj + 0x30 = cmdContext  (vtable at base + context_vtable)
///       cmdContext + 0x48 = cmdManager (vtable at base + manager_vtable)
///
/// All three are RVAs supplied by the offset table for the running build.
#[derive(Clone, Copy, Debug)]
pub struct GlobalChain {
    pub global_ptr: usize,
    pub context_vtable: usize,
    pub manager_vtable: usize,
}

// cmd_dispatch is void(manager, cmd_name_sso, msg_sso) — 3 args, no return value.
static_detour! {
    static CmdDispatchHook: extern "C" fn(*mut u8, *mut u8, *mut u8);
}

static CAPTURED_MANAGER: Mutex<Option<usize>> = Mutex::new(None);
static BASE_ADDRESS: Mutex<Option<isize>> = Mutex::new(None);
static GLOBAL_CHAIN: Mutex<Option<GlobalChain>> = Mutex::new(None);
static DETOUR_ENABLED: AtomicBool = AtomicBool::new(false);
static LAST_GAME_CMD: Mutex<Option<String>> = Mutex::new(None);
static GAME_CALL_COUNT: Mutex<u64> = Mutex::new(0);

/// EA/BioWare 16-byte SSO string.
///
/// Inline (len < 16): data in bytes[0..14], byte[15] = 15 - len.
/// Heap (len >= 16): bytes[0..7] = pointer, bytes[8..11] = u32 length,
///                   bytes[12..15] = capacity with high bit of byte[15] set (0x80).
#[repr(C)]
struct EaSsoString {
    data: [u8; 16],
}

impl EaSsoString {
    fn from_str(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut sso = EaSsoString { data: [0u8; 16] };

        if len < 16 {
            // Inline: copy bytes into data[0..len], set data[15] = 15 - len
            sso.data[..len].copy_from_slice(bytes);
            sso.data[15] = (15 - len) as u8;
        } else {
            // Heap: allocate, store pointer + length + capacity|0x80000000
            let layout = std::alloc::Layout::from_size_align(len + 1, 1).unwrap();
            unsafe {
                let ptr = std::alloc::alloc(layout);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
                *ptr.add(len) = 0; // null terminator
                // bytes[0..8] = pointer
                sso.data[..8].copy_from_slice(&(ptr as u64).to_le_bytes());
                // bytes[8..12] = u32 length
                sso.data[8..12].copy_from_slice(&(len as u32).to_le_bytes());
                // bytes[12..16] = u32 capacity with high bit set
                let cap_flags = (len as u32) | 0x80000000;
                sso.data[12..16].copy_from_slice(&cap_flags.to_le_bytes());
            }
        }

        sso
    }

    /// Read the string content back for logging.
    fn as_str(&self) -> Option<String> {
        let byte15 = self.data[15];
        if byte15 & 0x80 != 0 {
            // Heap mode
            let ptr = u64::from_le_bytes(self.data[..8].try_into().unwrap()) as *const u8;
            let len = u32::from_le_bytes(self.data[8..12].try_into().unwrap()) as usize;
            if ptr.is_null() || len == 0 {
                return None;
            }
            unsafe {
                let slice = std::slice::from_raw_parts(ptr, len);
                Some(String::from_utf8_lossy(slice).to_string())
            }
        } else {
            // Inline mode: length = 15 - byte15
            let len = (15 - byte15) as usize;
            Some(String::from_utf8_lossy(&self.data[..len]).to_string())
        }
    }
}

impl Drop for EaSsoString {
    fn drop(&mut self) {
        let byte15 = self.data[15];
        if byte15 & 0x80 != 0 {
            // Heap mode — free the allocation
            let ptr = u64::from_le_bytes(self.data[..8].try_into().unwrap()) as *mut u8;
            let len = u32::from_le_bytes(self.data[8..12].try_into().unwrap()) as usize;
            if !ptr.is_null() {
                let layout = std::alloc::Layout::from_size_align(len + 1, 1).unwrap();
                unsafe {
                    std::alloc::dealloc(ptr, layout);
                }
            }
        }
    }
}

/// Read an SSO string from a raw pointer (for logging game calls).
unsafe fn read_sso_string(ptr: *const u8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe {
        let byte15 = *ptr.add(15);
        if byte15 & 0x80 != 0 {
            // Heap
            let data_ptr = *(ptr as *const u64) as *const u8;
            let len = *(ptr.add(8) as *const u32) as usize;
            if data_ptr.is_null() || len == 0 {
                return None;
            }
            let slice = std::slice::from_raw_parts(data_ptr, len);
            Some(String::from_utf8_lossy(slice).to_string())
        } else {
            // Inline
            let len = (15 - byte15) as usize;
            let slice = std::slice::from_raw_parts(ptr, len);
            Some(String::from_utf8_lossy(slice).to_string())
        }
    }
}

/// Reads the manager pointer from the global pointer chain. Returns None when
/// no chain is known for this build or any step of the chain fails validation.
unsafe fn read_pointers_from_global(base_address: isize) -> Option<usize> {
    let chain = (*GLOBAL_CHAIN.lock().unwrap())?;
    unsafe {
        let base = base_address as *const u8;

        let global_ptr = base.add(chain.global_ptr) as *const *const u8;
        let obj = *global_ptr;
        if obj.is_null() {
            return None;
        }

        let context = *(obj.offset(0x30) as *const *const u8);
        if context.is_null() {
            return None;
        }

        // Verify cmdContext vtable
        let ctx_vtable = *(context as *const usize);
        let expected_ctx_vtable = base_address as usize + chain.context_vtable;
        if ctx_vtable != expected_ctx_vtable {
            return None;
        }

        let manager = *(context.offset(0x48) as *const *const u8);
        if manager.is_null() {
            return None;
        }

        // Verify cmdManager vtable
        let mgr_vtable = *(manager as *const usize);
        let expected_mgr_vtable = base_address as usize + chain.manager_vtable;
        if mgr_vtable != expected_mgr_vtable {
            return None;
        }

        Some(manager as usize)
    }
}

/// Installs the cmd_dispatch detour. `cmd_dispatch_rva` comes from the offset
/// table; `chain` is optional and only needed for sending without a prior
/// game call having populated the manager pointer.
pub fn begin_detour(
    base_address: isize,
    cmd_dispatch_rva: u64,
    chain: Option<GlobalChain>,
) -> Result<(), String> {
    *BASE_ADDRESS.lock().unwrap() = Some(base_address);
    *GLOBAL_CHAIN.lock().unwrap() = chain;

    // Try to read manager from the global chain immediately
    if chain.is_some() {
        unsafe {
            if let Some(manager) = read_pointers_from_global(base_address) {
                *CAPTURED_MANAGER.lock().unwrap() = Some(manager);
                submit_message(CaptureMessage::Info(format!(
                    "cmd_dispatch manager from global: 0x{:x}",
                    manager
                )));
            } else {
                submit_message(CaptureMessage::Info(
                    "cmd_dispatch global chain not yet populated, will capture from hook"
                        .to_string(),
                ));
            }
        }
    } else {
        submit_message(CaptureMessage::Info(
            "cmd_dispatch global chain unknown for this build, will capture manager from hook"
                .to_string(),
        ));
    }

    let target_address = base_address as usize + cmd_dispatch_rva as usize;
    unsafe {
        let target: extern "C" fn(*mut u8, *mut u8, *mut u8) = mem::transmute(target_address);
        CmdDispatchHook
            .initialize(target, cmd_dispatch_detour)
            .map_err(|e| format!("initialize failed: {:?}", e))?;
        CmdDispatchHook
            .enable()
            .map_err(|e| format!("enable failed: {:?}", e))?;
    }
    DETOUR_ENABLED.store(true, Ordering::Relaxed);
    submit_message(CaptureMessage::Info(format!(
        "cmd_dispatch detour initialized at 0x{:x}",
        target_address
    )));
    Ok(())
}

fn cmd_dispatch_detour(
    manager: *mut u8,
    cmd_name_sso: *mut u8,
    msg_sso: *mut u8,
) {
    let mgr_addr = manager as usize;
    if mgr_addr != 0 {
        *CAPTURED_MANAGER.lock().unwrap() = Some(mgr_addr);
    }

    // Read command name from the SSO string for logging
    let cmd_str = unsafe { read_sso_string(cmd_name_sso) }
        .unwrap_or_else(|| "<unreadable>".to_string());

    *LAST_GAME_CMD.lock().unwrap() = Some(cmd_str.clone());
    let mut count = GAME_CALL_COUNT.lock().unwrap();
    *count += 1;
    let call_num = *count;
    drop(count);

    submit_message(CaptureMessage::Info(format!(
        "cmd_dispatch GAME CALL #{}: cmd=\"{}\", mgr=0x{:x}",
        call_num, cmd_str, mgr_addr
    )));

    CmdDispatchHook.call(manager, cmd_name_sso, msg_sso);
}

fn resolve_command_name(cmd: &str) -> String {
    let lower = cmd.to_ascii_lowercase();
    let resolved = if lower == "e" || lower == "emote" || lower == "em" {
        "emote"
    } else if lower == "s" || lower == "say" {
        "say"
    } else if lower == "y" || lower == "yell" {
        "yell"
    } else if lower == "w" || lower == "whisper" || lower == "tell" {
        "whisper"
    } else if lower == "g" || lower == "guild" {
        "guild"
    } else if lower == "p" || lower == "party" || lower == "group" {
        "group"
    } else if lower == "o" || lower == "ops" {
        "ops"
    } else if lower == "general" {
        "general"
    } else if lower == "pvp" {
        "pvp"
    } else if lower == "trade" {
        "trade"
    } else if lower == "officer" || lower == "go" {
        "officer"
    } else {
        return lower;
    };
    resolved.to_string()
}

/// SWTOR chat messages are limited to 255 characters.
const MAX_MESSAGE_LEN: usize = 255;

pub fn send_command(command: &str, message: &str) -> Result<(), String> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Message too long ({} chars, max {})",
            message.len(),
            MAX_MESSAGE_LEN
        ));
    }

    // Re-read manager from global chain for freshness
    if let Some(base) = *BASE_ADDRESS.lock().unwrap() {
        unsafe {
            if let Some(manager) = read_pointers_from_global(base) {
                *CAPTURED_MANAGER.lock().unwrap() = Some(manager);
            }
        }
    }

    let manager = CAPTURED_MANAGER
        .lock()
        .unwrap()
        .ok_or_else(|| "cmd_dispatch manager not available".to_string())?;

    let resolved = resolve_command_name(command);

    // Build 16-byte EA SSO strings for both cmd_name and message
    let cmd_sso = EaSsoString::from_str(&resolved);
    let mut msg_sso = EaSsoString::from_str(message);

    submit_message(CaptureMessage::Info(format!(
        "send_command: cmd=\"{}\" msg=\"{}\", mgr=0x{:x}",
        resolved,
        msg_sso.as_str().unwrap_or_default(),
        manager,
    )));

    // Call through the detour (which calls the original function)
    CmdDispatchHook.call(
        manager as *mut u8,
        &cmd_sso as *const EaSsoString as *mut u8,
        &mut msg_sso as *mut EaSsoString as *mut u8,
    );

    submit_message(CaptureMessage::Info(
        "send_command completed".to_string(),
    ));

    Ok(())
}

pub fn get_diagnostics() -> DiagnosticsInfo {
    let manager = *CAPTURED_MANAGER.lock().unwrap();
    let base = *BASE_ADDRESS.lock().unwrap();

    let global_manager = if let Some(base_addr) = base {
        unsafe {
            read_pointers_from_global(base_addr).map(|m| format!("0x{:x}", m))
        }
    } else {
        None
    };

    let pointers_match = match (&manager, &global_manager) {
        (Some(m), Some(gm)) => format!("0x{:x}", m) == *gm,
        _ => false,
    };

    DiagnosticsInfo {
        manager_ptr: manager.map(|m| format!("0x{:x}", m)),
        context_ptr: None,
        global_chain_manager: global_manager,
        global_chain_context: None,
        pointers_match,
        detour_enabled: DETOUR_ENABLED.load(Ordering::Relaxed),
        last_game_call_cmd: LAST_GAME_CMD.lock().unwrap().clone(),
        last_send_result: None,
    }
}

pub fn end_detour() {
    unsafe {
        let _ = CmdDispatchHook.disable();
    }
    DETOUR_ENABLED.store(false, Ordering::Relaxed);
}
