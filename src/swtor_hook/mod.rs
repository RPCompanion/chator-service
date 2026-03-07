use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use tracing::{error, info, debug};

use windows::Win32::Foundation::{BOOL, HWND, LPARAM, MAX_PATH};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, QueryFullProcessImageNameW,
};

use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

use windows::core::PWSTR;

use crate::comms::{self, FromService};

pub mod message_hash_container;
pub mod post;

static SWTOR_HWND: Mutex<Option<HWND>> = Mutex::new(None);
static SWTOR_PID: Mutex<Option<u32>> = Mutex::new(None);

static PROCESS_CHECKSUM: OnceLock<Vec<u8>> = OnceLock::new();
static PROCESS_IS_ACCESSIBLE: AtomicBool = AtomicBool::new(true);

const ACCESS_IS_DENIED: i32 = 0x80070005u32 as i32;
const PROCESS_NAME: &str = "Star Wars™: The Old Republic™";

fn should_attempt_to_get_checksum() -> bool {
    if !PROCESS_IS_ACCESSIBLE.load(Ordering::Relaxed) {
        debug!("Checksum skip: process not accessible");
        return false;
    }

    if PROCESS_CHECKSUM.get().is_some() {
        return false;
    }

    true
}

/// Attempts to compute the SWTOR process checksum. Call this when SWTOR is found
/// and when capture is enabled — both conditions must hold for injection to work.
pub fn set_process_checksum() {
    if !should_attempt_to_get_checksum() {
        return;
    }

    let pid = match *SWTOR_PID.lock().unwrap() {
        Some(pid) => pid,
        None => {
            debug!("Checksum skip: no SWTOR PID");
            return;
        }
    };

    info!("Attempting to compute SWTOR process checksum (pid: {})", pid);

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if handle.is_err() {
            let err = handle.unwrap_err();
            if err.code().0 == ACCESS_IS_DENIED {
                PROCESS_IS_ACCESSIBLE.store(false, Ordering::Relaxed);
                error!("Access denied opening SWTOR process — are we running as admin?");
            }

            error!("Error opening process: {}", err);
            return;
        }

        let mut buffer: [u16; MAX_PATH as usize + 1] = [0; MAX_PATH as usize + 1];
        let mut size = buffer.len() as u32;

        match QueryFullProcessImageNameW(
            handle.unwrap(),
            PROCESS_NAME_FORMAT(0),
            PWSTR(&mut buffer as *mut _),
            &mut size,
        ) {
            Ok(_) => {
                let path_str = String::from_utf16(&buffer).unwrap().replace("\0", "");
                info!("SWTOR executable path: {}", path_str);
                let path = Path::new(&path_str);

                match fs::read(path) {
                    Ok(program_bytes) => {
                        let mut hasher = Sha256::new();
                        hasher.update(&program_bytes);
                        let checksum = hasher.finalize().to_vec();
                        info!("SWTOR checksum computed: {:X?}", &checksum[..8]);
                        let _ = PROCESS_CHECKSUM.set(checksum);
                    }
                    Err(e) => {
                        error!("Failed to read SWTOR executable at {}: {}", path_str, e);
                    }
                }
            }
            Err(e) => {
                error!("QueryFullProcessImageNameW failed: {}", e);
            }
        }
    }
}

extern "system" fn enum_windows_existing_proc(hwnd: HWND, _param1: LPARAM) -> BOOL {
    let mut text: [u16; 256] = [0; 256];
    unsafe {
        GetWindowTextW(hwnd, &mut text);

        let window_text: String;
        match String::from_utf16(&text) {
            Ok(text) => {
                window_text = text.replace("\0", "");
            }
            Err(_) => {
                return BOOL(1);
            }
        }

        if window_text == PROCESS_NAME {
            let mut process_id: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut process_id as *mut u32));

            SWTOR_PID.lock().unwrap().replace(process_id);
            SWTOR_HWND.lock().unwrap().replace(hwnd);
            set_process_checksum();

            return BOOL(0);
        }

        return BOOL(1);
    }
}

pub fn hook_into_existing() {
    unsafe {
        //Enumerated every window and wasn't able to find SWTOR Window
        if let Ok(_) = EnumWindows(Some(enum_windows_existing_proc), LPARAM(0)) {
            SWTOR_HWND.lock().unwrap().take();
            SWTOR_PID.lock().unwrap().take();
        }
    }
}

pub fn window_in_focus() -> bool {
    if let Some(hwnd) = SWTOR_HWND.lock().unwrap().as_ref() {
        unsafe {
            return GetForegroundWindow() == *hwnd;
        }
    }

    false
}

pub fn get_pid() -> Option<u32> {
    SWTOR_PID.lock().unwrap().clone()
}

pub fn get_hwnd() -> Option<HWND> {
    SWTOR_HWND.lock().unwrap().clone()
}

pub fn checksum_match(checksum: &[u8; 32]) -> Result<bool, &'static str> {
    if let Some(process_checksum) = PROCESS_CHECKSUM.get() {
        return Ok(checksum.iter().eq(process_checksum.iter()));
    }

    return Err("PROCESS_CHECKSUM not yet initialized");
}

pub fn is_hooked_in() -> bool {
    SWTOR_HWND.lock().unwrap().is_some()
}

pub fn start_swtor_hook() {
    thread::spawn(move || {
        let mut last_hooked_in = false;
        loop {
            hook_into_existing();
            let hooked_in = is_hooked_in();
            if hooked_in != last_hooked_in {
                info!("SWTOR hooked_in changed: {} -> {}", last_hooked_in, hooked_in);
                if hooked_in {
                    info!("SWTOR found (pid: {:?})", get_pid());
                }
                last_hooked_in = hooked_in;
            }
            debug!("Sending IsHookedIn({})", hooked_in);
            comms::send(FromService::IsHookedIn(hooked_in));
            thread::sleep(Duration::from_millis(1000));
        }
    });
}
