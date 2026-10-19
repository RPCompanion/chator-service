use retour::static_detour;
use std::mem;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::lib_only::chat_gateway;
use crate::lib_only::memory::{self, Regions};
use crate::lib_only::sigscan::{self, ChainVtables};
use crate::lib_only::submit_message;
use crate::share::CaptureMessage;
use crate::share::dll_command::DiagnosticsInfo;

/// Global pointer chain to find cmd_dispatch args without hooking:
///   [base + global_ptr] -> obj (OmegaClientApp)
///     obj + 0x30 = cmdContext  (OmegaAreaObject, vtable at base + context_vtable)
///       cmdContext + 0x48 = cmdManager (AreaServerRequestIFaceProxy, vtable at base + manager_vtable)
///
/// All three are RVAs, from the offset table or found at runtime (`ChainSource::Rtti`).
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
/// The captured manager's vtable pointer, checked before every send: without a global chain the
/// manager is only known from an earlier game call and may have been freed since (character
/// switch, logout), and calling cmd_dispatch on it would crash the game.
static CAPTURED_VTABLE: Mutex<Option<usize>> = Mutex::new(None);
static BASE_ADDRESS: Mutex<Option<isize>> = Mutex::new(None);
static GLOBAL_CHAIN: Mutex<Option<GlobalChain>> = Mutex::new(None);
/// Vtables found by RTTI while the global is not found yet: the game creates its
/// OmegaClientApp during startup, possibly after we were injected.
static CHAIN_VTABLES: Mutex<Option<ChainVtables>> = Mutex::new(None);

/// Where the global pointer chain comes from.
pub enum ChainSource {
    Table(GlobalChain),
    /// Vtables found by RTTI; the global is searched for in `.data`.
    Rtti(ChainVtables),
    None,
}
static DETOUR_ENABLED: AtomicBool = AtomicBool::new(false);
static LAST_GAME_CMD: Mutex<Option<String>> = Mutex::new(None);
static GAME_CALL_COUNT: Mutex<u64> = Mutex::new(0);

/// EA/BioWare 16-byte SSO string.
///
/// Inline (len < 16): data in bytes[0..14], byte[15] = 15 - len.
/// Heap (len >= 16): bytes[0..7] = pointer, bytes[8..11] = u32 length,
///                   bytes[12..15] = capacity with high bit of byte[15] set (0x80).
#[repr(C)]
pub(crate) struct EaSsoString {
    data: [u8; 16],
}

impl EaSsoString {
    pub(crate) fn from_str(s: &str) -> Self {
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
pub(crate) unsafe fn read_sso_string(ptr: *const u8) -> Option<String> {
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

/// Remembers a manager the game just used (or the global chain just validated), with its vtable.
fn capture_manager(manager: usize) {
    let vtable = unsafe { *(manager as *const usize) };
    *CAPTURED_MANAGER.lock().unwrap() = Some(manager);
    *CAPTURED_VTABLE.lock().unwrap() = Some(vtable);
}

/// Finds the `.data` global holding the OmegaClientApp object, the start of the chain: the first
/// 8-byte slot pointing at an object with that vtable. Returns its RVA and how many slots
/// matched; None until the game has created the object.
fn find_global(base: usize, app_vtable_rva: u32) -> Option<(usize, usize)> {
    let pe = unsafe { sigscan::PeImage::parse(base) }.ok()?;
    let data = pe.section(".data")?;
    let bytes = unsafe { pe.section_bytes(data) };
    let image = base..base + pe.image_size() as usize;
    let app_vtable = base + app_vtable_rva as usize;

    let mut regions = Regions::default();
    let mut first = None;
    let mut count = 0;
    for (i, slot) in bytes.chunks_exact(8).enumerate() {
        let value = usize::from_le_bytes(slot.try_into().unwrap());
        if value < 0x10000 || value % 8 != 0 || value > 0x7fff_ffff_ffff || image.contains(&value) {
            continue;
        }
        if regions.readable(value) && unsafe { *(value as *const usize) } == app_vtable {
            count += 1;
            first.get_or_insert(data.rva as usize + i * 8);
        }
    }
    first.map(|global| (global, count))
}

/// With vtables from RTTI but no global yet, looks for the global (again).
fn resolve_global_chain(base_address: isize) {
    if GLOBAL_CHAIN.lock().unwrap().is_some() {
        return;
    }
    let Some(vtables) = *CHAIN_VTABLES.lock().unwrap() else {
        return;
    };
    if let Some((global_ptr, count)) = find_global(base_address as usize, vtables.app) {
        *GLOBAL_CHAIN.lock().unwrap() = Some(GlobalChain {
            global_ptr,
            context_vtable: vtables.context as usize,
            manager_vtable: vtables.manager as usize,
        });
        submit_message(CaptureMessage::Info(format!(
            "cmd_dispatch global chain found: global 0x{:x} ({} slot(s) point at the OmegaClientApp)",
            global_ptr, count
        )));
    }
}

/// One line about the global chain for the hook report.
pub fn chain_status() -> String {
    match (*GLOBAL_CHAIN.lock().unwrap(), *CHAIN_VTABLES.lock().unwrap()) {
        (Some(chain), Some(v)) => format!(
            "global chain found at runtime: global 0x{:x}, vtables 0x{:x} / 0x{:x} / 0x{:x}",
            chain.global_ptr, v.app, v.context, v.manager
        ),
        (Some(chain), None) => format!("global chain from table: global 0x{:x}", chain.global_ptr),
        (None, Some(_)) => "global chain vtables found, global not set yet (game starting); retried when sending".to_string(),
        (None, None) => "global chain unavailable; sends need a chat message from the game first".to_string(),
    }
}

/// The captured manager, if it still looks like the object the game used.
fn live_manager() -> Result<usize, String> {
    let (Some(manager), Some(vtable)) = (*CAPTURED_MANAGER.lock().unwrap(), *CAPTURED_VTABLE.lock().unwrap()) else {
        if GLOBAL_CHAIN.lock().unwrap().is_some() {
            return Err("The game is not ready to chat yet. Log in to a character, then try again.".to_string());
        }
        return Err("ChaTOR has not seen the game send a chat message yet. Post any /e from the game's chat box once, then try again.".to_string());
    };
    if memory::read_usize(manager) == Some(vtable) {
        Ok(manager)
    } else {
        *CAPTURED_MANAGER.lock().unwrap() = None;
        Err("The game's chat state changed since ChaTOR last saw it (character switch?). Post any /e from the game's chat box once, then try again.".to_string())
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
    chain: ChainSource,
) -> Result<(), String> {
    *BASE_ADDRESS.lock().unwrap() = Some(base_address);
    let (table, vtables) = match chain {
        ChainSource::Table(chain) => (Some(chain), None),
        ChainSource::Rtti(vtables) => (None, Some(vtables)),
        ChainSource::None => (None, None),
    };
    *GLOBAL_CHAIN.lock().unwrap() = table;
    *CHAIN_VTABLES.lock().unwrap() = vtables;
    resolve_global_chain(base_address);

    // Try to read manager from the global chain immediately
    if GLOBAL_CHAIN.lock().unwrap().is_some() {
        unsafe {
            if let Some(manager) = read_pointers_from_global(base_address) {
                capture_manager(manager);
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
            "cmd_dispatch global chain not available yet, will capture manager from hook or retry when sending"
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
        capture_manager(mgr_addr);
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

    // Log the text only when it carries markup (an item link the player shift-clicked in, or
    // escaped '<'), to learn the exact link format the game hands to cmd_dispatch.
    if let Some(msg) = unsafe { read_sso_string(msg_sso) } {
        if msg.contains('<') || msg.contains("&lt;") {
            submit_message(CaptureMessage::Info(format!("cmd_dispatch GAME CALL #{} message with markup: {}", call_num, msg)));
        }
    }

    CmdDispatchHook.call(manager, cmd_name_sso, msg_sso);
}

/// Where a chat command goes (frida-scripts/chat_send_routes_oct2026.md).
enum Route {
    /// cmd_dispatch on the area server, with the game's command name.
    Dispatch(&'static str),
    /// The chat gateway's channel message; the channel number as in chat_recv (SwtorChannel).
    Channel(i32),
    /// The chat gateway's whisper; the message is "name: text".
    Whisper,
}

/// Commands as ChaTOR writes them (SwtorChannel.get_command) plus the game's long forms.
fn route(command: &str) -> Option<Route> {
    Some(match command.to_ascii_lowercase().as_str() {
        "e" | "em" | "emote" => Route::Dispatch("emote"),
        "s" | "say" => Route::Dispatch("say"),
        "y" | "yell" => Route::Dispatch("yell"),
        "w" | "whisper" | "tell" => Route::Whisper,
        "1" | "general" => Route::Channel(51),
        "2" | "pvp" => Route::Channel(52),
        "3" | "trade" => Route::Channel(53),
        "p" | "party" | "group" => Route::Channel(54),
        "ops" => Route::Channel(55),
        "oa" => Route::Channel(56),
        "g" | "guild" => Route::Channel(57),
        "o" | "officer" => Route::Channel(58),
        "oo" => Route::Channel(61),
        _ => return None,
    })
}

/// SWTOR chat messages are limited to 255 characters.
const MAX_MESSAGE_LEN: usize = 255;

/// Sends `/command message` the way the game would: emote / say / yell through cmd_dispatch,
/// channels and whispers through the chat gateway. Errors (without sending anything) for
/// commands it cannot send directly or channels whose id is not known yet.
pub fn send_command(command: &str, message: &str) -> Result<(), String> {
    if message.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Message too long ({} chars, max {})",
            message.len(),
            MAX_MESSAGE_LEN
        ));
    }
    match route(command) {
        Some(Route::Dispatch(name)) => dispatch(name, message),
        Some(Route::Channel(channel)) => chat_gateway::send_channel(channel, message),
        Some(Route::Whisper) => {
            let (name, text) = message
                .split_once(':')
                .ok_or_else(|| "A whisper needs \"name: message\"".to_string())?;
            chat_gateway::send_whisper(name.trim(), text.trim_start())
        }
        None => Err(format!("/{} cannot be sent directly", command)),
    }
}

/// The OmegaClientApp object at the start of the global chain (the chat gateway hangs off it too).
pub fn app_object() -> Option<usize> {
    let base = (*BASE_ADDRESS.lock().unwrap())?;
    resolve_global_chain(base);
    let chain = (*GLOBAL_CHAIN.lock().unwrap())?;
    memory::read_usize(base as usize + chain.global_ptr).filter(|&app| app != 0)
}

fn dispatch(name: &str, message: &str) -> Result<(), String> {
    // Re-read manager from global chain for freshness
    if let Some(base) = *BASE_ADDRESS.lock().unwrap() {
        resolve_global_chain(base);
        unsafe {
            if let Some(manager) = read_pointers_from_global(base) {
                capture_manager(manager);
            }
        }
    }

    let manager = live_manager()?;

    // Build 16-byte EA SSO strings for both cmd_name and message
    let cmd_sso = EaSsoString::from_str(name);
    let mut msg_sso = EaSsoString::from_str(message);

    submit_message(CaptureMessage::Info(format!(
        "send_command: cmd=\"{}\" msg=\"{}\", mgr=0x{:x}",
        name,
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
