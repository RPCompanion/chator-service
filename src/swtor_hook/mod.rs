use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use tracing::error;

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
        return false;
    }

    if !comms::state::capture_chat_log() {
        return false;
    }

    if PROCESS_CHECKSUM.get().is_some() {
        return false;
    }

    true
}

fn set_process_checksum() {
    if !should_attempt_to_get_checksum() {
        return;
    }

    let pid = SWTOR_PID.lock().unwrap().unwrap();

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if handle.is_err() {
            let err = handle.unwrap_err();
            if err.code().0 == ACCESS_IS_DENIED {
                PROCESS_IS_ACCESSIBLE.store(false, Ordering::Relaxed);
            }

            error!("Error opening process: {}", err);
            return;
        }

        let mut buffer: [u16; MAX_PATH as usize + 1] = [0; MAX_PATH as usize + 1];
        let mut size = buffer.len() as u32;

        if let Ok(_) = QueryFullProcessImageNameW(
            handle.unwrap(),
            PROCESS_NAME_FORMAT(0),
            PWSTR(&mut buffer as *mut _),
            &mut size,
        ) {
            let path_str = String::from_utf16(&buffer).unwrap().replace("\0", "");
            let path = Path::new(&path_str);

            let program_bytes = fs::read(path).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(program_bytes);
            PROCESS_CHECKSUM.set(hasher.finalize().to_vec()).unwrap();
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
        loop {
            hook_into_existing();
            comms::send(FromService::IsHookedIn(is_hooked_in()));
            thread::sleep(Duration::from_millis(1000));
        }
    });
}
