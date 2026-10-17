use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{error, info, debug};

use windows::Win32::Foundation::{HWND, LPARAM, MAX_PATH};
use windows::core::BOOL;
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

// Stored as isize: `HWND` wraps a raw pointer since windows 0.53 and is not `Send`.
static SWTOR_HWND: Mutex<Option<isize>> = Mutex::new(None);
static SWTOR_PID: Mutex<Option<u32>> = Mutex::new(None);

static PROCESS_CHECKSUM: OnceLock<Vec<u8>> = OnceLock::new();
static PROCESS_IS_ACCESSIBLE: AtomicBool = AtomicBool::new(true);
static LAST_CHECKSUM_ERROR_LOG: Mutex<Option<Instant>> = Mutex::new(None);
const CHECKSUM_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Environment variable the launcher may set with an alternative path to
/// swtor.exe (e.g. `Z:\mnt\...\swtor.exe` under Proton, where the game's
/// own `S:` drive letter can be missing from the prefix).
pub const SWTOR_EXE_FALLBACK_ENV: &str = "CHATOR_SWTOR_EXE";

/// Logs checksum failures at ERROR the first time and then every 30s; DEBUG in between.
fn log_checksum_failure(message: String) {
    let mut last = LAST_CHECKSUM_ERROR_LOG.lock().unwrap();
    let due = last.map(|t| t.elapsed() >= CHECKSUM_ERROR_LOG_INTERVAL).unwrap_or(true);
    if due {
        error!("{}", message);
        *last = Some(Instant::now());
    } else {
        debug!("{}", message);
    }
}

fn hash_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let program_bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&program_bytes);
    Ok(hasher.finalize().to_vec())
}

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

    debug!("Attempting to compute SWTOR process checksum (pid: {})", pid);

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
                debug!("SWTOR executable path (from process): {}", path_str);

                // Candidate paths: the one the process reports, then the
                // launcher-provided fallback.
                let mut candidates: Vec<(String, &str)> = vec![(path_str.clone(), "process image path")];
                if let Ok(fallback) = std::env::var(SWTOR_EXE_FALLBACK_ENV) {
                    if !fallback.trim().is_empty() {
                        candidates.push((fallback, SWTOR_EXE_FALLBACK_ENV));
                    }
                }

                let mut failures = Vec::new();
                for (candidate, origin) in &candidates {
                    match hash_file(Path::new(candidate)) {
                        Ok(checksum) => {
                            info!(
                                "SWTOR checksum computed from {} ({}): {}",
                                candidate,
                                origin,
                                checksum.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                            );
                            let _ = PROCESS_CHECKSUM.set(checksum);
                            return;
                        }
                        Err(e) => failures.push(format!("{} ({}): {}", candidate, origin, e)),
                    }
                }

                let message = format!(
                    "Failed to read swtor.exe for checksum. Tried: {}. Under Proton this usually means the game's drive letter (e.g. S:) is missing from the prefix; the launcher should pass STEAM_COMPAT_LIBRARY_PATHS/STEAM_COMPAT_INSTALL_PATH and {}.",
                    failures.join("; "),
                    SWTOR_EXE_FALLBACK_ENV
                );
                log_checksum_failure(message.clone());
                comms::notify_once("error", message);
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
            SWTOR_HWND.lock().unwrap().replace(hwnd.0 as isize);
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
    if let Some(hwnd) = get_hwnd() {
        unsafe {
            return GetForegroundWindow() == hwnd;
        }
    }

    false
}

pub fn get_pid() -> Option<u32> {
    SWTOR_PID.lock().unwrap().clone()
}

pub fn get_hwnd() -> Option<HWND> {
    SWTOR_HWND
        .lock()
        .unwrap()
        .map(|raw| HWND(raw as *mut core::ffi::c_void))
}

pub fn checksum_match(checksum: &[u8; 32]) -> Result<bool, &'static str> {
    if let Some(process_checksum) = PROCESS_CHECKSUM.get() {
        return Ok(checksum.iter().eq(process_checksum.iter()));
    }

    return Err("PROCESS_CHECKSUM not yet initialized");
}

/// Lowercase hex SHA256 of the running swtor.exe, if computed.
pub fn checksum_hex() -> Option<String> {
    PROCESS_CHECKSUM
        .get()
        .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect())
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
            crate::capture_injector::retry_if_needed();
            thread::sleep(Duration::from_millis(1000));
        }
    });
}
