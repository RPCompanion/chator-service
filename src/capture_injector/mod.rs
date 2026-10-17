use std::sync::LazyLock;
use std::thread;
use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use syringe_container::SyringeContainer;
use tracing::{debug, error, info};

use dll_syringe::{Syringe, process::OwnedProcess};
use serde::{Deserialize, Serialize};
use serde_json::{Deserializer, Value};

use crate::comms::{self, FromService};
use crate::share::dll_command::{DllCommand, DllResponse};
use crate::share::offsets::HookReport;
use crate::{share::CaptureMessage, swtor_hook};

pub mod message_container;
mod syringe_container;

use self::message_container::{CapturedMessage, SwtorMessageContainer};

static MESSAGE_CONTAINER: LazyLock<Mutex<SwtorMessageContainer>> =
    LazyLock::new(|| Mutex::new(SwtorMessageContainer::new()));

static INJECTED: AtomicBool = AtomicBool::new(false);
/// Set when injection failed for a reason that will not fix itself (e.g. the
/// build is not in the offset table). Cleared by `allow_retries()`.
static RETRY_BLOCKED: AtomicBool = AtomicBool::new(false);
static LAST_RETRY: Mutex<Option<std::time::Instant>> = Mutex::new(None);
/// How often the hook loop re-attempts injection while chat logging is on.
pub const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub fn is_injected() -> bool {
    INJECTED.load(Ordering::SeqCst)
}

pub fn allow_retries() {
    RETRY_BLOCKED.store(false, Ordering::SeqCst);
}

/// Called once a second by the SWTOR watcher. Re-attempts injection when chat
/// logging is on, nothing is injected yet, and the last failure was transient.
pub fn retry_if_needed() {
    if !comms::state::capture_chat_log() || is_injected() || RETRY_BLOCKED.load(Ordering::SeqCst) {
        return;
    }
    if swtor_hook::get_pid().is_none() {
        return;
    }
    {
        let mut last = LAST_RETRY.lock().unwrap();
        if let Some(t) = *last {
            if t.elapsed() < RETRY_INTERVAL {
                return;
            }
        }
        *last = Some(std::time::Instant::now());
    }
    info!("Chat logging is on but nothing is injected; retrying injection");
    match start_injecting_capture() {
        Ok(()) => info!("Capture injection started on retry"),
        Err(e) => error!("Capture injection retry failed: {:?}", e),
    }
}
static CONTINUE_LOGGING: AtomicBool = AtomicBool::new(false);

struct DllConnection {
    reader: std::io::BufReader<TcpStream>,
    writer: TcpStream,
}

static DLL_CONNECTION: LazyLock<Mutex<Option<DllConnection>>> =
    LazyLock::new(|| Mutex::new(None));

fn connect_to_dll(port: u16) {
    match TcpStream::connect(format!("127.0.0.1:{}", port)) {
        Ok(stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .ok();
            let reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let writer = stream;
            *DLL_CONNECTION.lock().unwrap() = Some(DllConnection { reader, writer });
            info!("Connected to DLL command port {}", port);
        }
        Err(e) => {
            error!("Failed to connect to DLL command port: {}", e);
        }
    }
}

fn disconnect_dll() {
    let mut guard = DLL_CONNECTION.lock().unwrap();
    if let Some(mut conn) = guard.take() {
        if let Ok(json) = serde_json::to_string(&DllCommand::Stop) {
            let _ = conn.writer.write_all(json.as_bytes());
            let _ = conn.writer.write_all(b"\n");
            let _ = conn.writer.flush();
        }
    }
}

pub fn send_diagnostics() -> Result<crate::share::dll_command::DiagnosticsInfo, String> {
    let mut guard = DLL_CONNECTION
        .lock()
        .map_err(|_| "Lock poisoned".to_string())?;
    let conn = guard
        .as_mut()
        .ok_or_else(|| "DLL not connected".to_string())?;

    let cmd = DllCommand::Diagnostics;
    let mut json = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
    json.push('\n');
    conn.writer
        .write_all(json.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    conn.writer
        .flush()
        .map_err(|e| format!("Flush failed: {}", e))?;

    let mut line = String::new();
    use std::io::BufRead;
    conn.reader
        .read_line(&mut line)
        .map_err(|e| format!("Read failed: {}", e))?;

    let resp: DllResponse =
        serde_json::from_str(line.trim()).map_err(|e| format!("Parse response failed: {}", e))?;

    match resp {
        DllResponse::DiagnosticsResult(info) => Ok(info),
        _ => Err("Unexpected response type".to_string()),
    }
}

/// Asks the DLL to install its hooks and returns what it managed to do.
fn install_hooks_in_dll(
    sha256: Option<String>,
    offsets: std::collections::BTreeMap<String, u64>,
    dynamic_lookup: bool,
) -> Result<HookReport, String> {
    let mut guard = DLL_CONNECTION
        .lock()
        .map_err(|_| "Lock poisoned".to_string())?;
    let conn = guard
        .as_mut()
        .ok_or_else(|| "DLL not connected".to_string())?;

    let cmd = DllCommand::InstallHooks {
        sha256,
        offsets,
        dynamic_lookup,
    };
    let mut json = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
    json.push('\n');
    conn.writer
        .write_all(json.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    conn.writer
        .flush()
        .map_err(|e| format!("Flush failed: {}", e))?;

    let mut line = String::new();
    use std::io::BufRead;
    conn.reader
        .read_line(&mut line)
        .map_err(|e| format!("Read failed: {}", e))?;

    let resp: DllResponse =
        serde_json::from_str(line.trim()).map_err(|e| format!("Parse response failed: {}", e))?;

    match resp {
        DllResponse::InstallHooksResult(report) => Ok(report),
        _ => Err("Unexpected response type".to_string()),
    }
}

pub fn send_chat_command(command: &str, message: &str) -> Result<(), String> {
    let mut guard = DLL_CONNECTION
        .lock()
        .map_err(|_| "Lock poisoned".to_string())?;
    let conn = guard
        .as_mut()
        .ok_or_else(|| "DLL not connected".to_string())?;

    let cmd = DllCommand::SendChatCommand {
        command: command.to_string(),
        message: message.to_string(),
    };
    let mut json = serde_json::to_string(&cmd).map_err(|e| e.to_string())?;
    json.push('\n');
    conn.writer
        .write_all(json.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    conn.writer
        .flush()
        .map_err(|e| format!("Flush failed: {}", e))?;

    let mut line = String::new();
    use std::io::BufRead;
    conn.reader
        .read_line(&mut line)
        .map_err(|e| format!("Read failed: {}", e))?;

    let resp: DllResponse =
        serde_json::from_str(line.trim()).map_err(|e| format!("Parse response failed: {}", e))?;

    match resp {
        DllResponse::SendChatResult(r) => r,
        _ => Err("Unexpected response type".to_string()),
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CaptureError {
    AlreadyInjected,
    SwtorNotRunning,
    WrongGuiSettings,
    UnsupportedVersion,
    NotYetFullyReady,
}

pub fn start_injecting_capture() -> Result<(), CaptureError> {
    info!("start_injecting_capture called");

    if INJECTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        info!("Already injected, skipping");
        return Err(CaptureError::AlreadyInjected);
    }

    let swtor_pid = swtor_hook::get_pid();
    if swtor_pid.is_none() {
        error!("SWTOR process not found");
        return Err(CaptureError::SwtorNotRunning);
    }
    let swtor_pid = swtor_pid.unwrap();
    info!("Found SWTOR process (pid: {})", swtor_pid);

    let sha256 = match swtor_hook::checksum_hex() {
        Some(sha) => sha,
        None => {
            error!("Could not verify SWTOR checksum: not yet computed (see swtor_hook errors above)");
            comms::notify_once(
                "warn",
                "Chat logging is waiting: the swtor.exe checksum could not be computed yet. See chator-service.log for the path that failed.",
            );
            INJECTED.store(false, Ordering::Relaxed);
            return Err(CaptureError::NotYetFullyReady);
        }
    };

    let dynamic_lookup = comms::state::dynamic_offset_lookup();
    let table = comms::state::offset_table();
    let offsets = match table.find(&sha256) {
        Some(v) => {
            info!(
                "SWTOR build {} found in offset table ({}), {} offset(s)",
                sha256,
                v.label.as_deref().unwrap_or("unlabelled"),
                v.offsets.len()
            );
            v.offsets.clone()
        }
        None if dynamic_lookup => {
            info!(
                "SWTOR build {} not in offset table; continuing with dynamic lookup only",
                sha256
            );
            Default::default()
        }
        None => {
            error!(
                "SWTOR build {} not in offset table and dynamic lookup is disabled",
                sha256
            );
            comms::notify_once(
                "error",
                format!(
                    "Chat logging disabled: swtor.exe build {}… is not in the offsets table and dynamic offset lookup is off.",
                    &sha256[..12]
                ),
            );
            RETRY_BLOCKED.store(true, Ordering::SeqCst);
            INJECTED.store(false, Ordering::Relaxed);
            return Err(CaptureError::UnsupportedVersion);
        }
    };

    info!("Starting injection thread for pid {}", swtor_pid);
    start_injecting_thread(swtor_pid, sha256, offsets, dynamic_lookup);
    Ok(())
}

fn start_injecting_thread(
    swtor_pid: u32,
    sha256: String,
    offsets: std::collections::BTreeMap<String, u64>,
    dynamic_lookup: bool,
) {
    thread::spawn(move || {
        info!("Injection thread started for pid {}", swtor_pid);
        CONTINUE_LOGGING.store(true, Ordering::Relaxed);

        let target_process = OwnedProcess::from_pid(swtor_pid).unwrap();
        let syringe = Syringe::for_process(target_process);

        info!("Injecting DLL into SWTOR...");
        let syringe_container = SyringeContainer::inject(&syringe);

        if let Err(ref e) = syringe_container {
            error!("DLL injection failed: {:?}", e);
            INJECTED.store(false, Ordering::Relaxed);
            CONTINUE_LOGGING.store(false, Ordering::Relaxed);
            return;
        }

        info!("DLL injection succeeded");
        let syringe_container = syringe_container.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let chator_port = listener.local_addr().unwrap().port();

        info!("ChaTOR listening on port {}", chator_port);

        // ChaTOR must have restarted for this to be the case.
        let module_port: u16 = if syringe_container.capture_module_initalized() {
            info!("Capture module already initialized");
            syringe_container.set_chator_port(chator_port);
            syringe_container.get_module_ports().local_port
        } else {
            info!("Initializing capture module");
            syringe_container.init_capture_module(chator_port)
        };

        info!("Module listening on {}", module_port);

        connect_to_dll(module_port);

        match install_hooks_in_dll(Some(sha256), offsets, dynamic_lookup) {
            Ok(report) => {
                if report.installed_count() == report.hooks.len() {
                    info!("All hooks installed: {}", report.summary());
                } else {
                    error!(
                        "{} of {} hooks installed: {}",
                        report.installed_count(),
                        report.hooks.len(),
                        report.summary()
                    );
                }
                for h in &report.hooks {
                    info!(
                        "  hook {}: rva={:?} source={:?} installed={} {}",
                        h.name,
                        h.rva.map(|r| format!("0x{:x}", r)),
                        h.source,
                        h.installed,
                        h.detail.as_deref().unwrap_or("")
                    );
                }
                comms::send(FromService::HookReport(report));
            }
            Err(e) => error!("InstallHooks failed: {}", e),
        }

        let tcp_thread = thread::spawn(move || {
            start_tcp_listener_loop(listener);
        });

        start_logging_propagation();
        tcp_thread.join().unwrap();

        disconnect_dll();
        thread::sleep(Duration::from_secs(1));

        if let Err(err) = syringe_container.eject() {
            error!("Error ejecting payload: {:?}", err);
        } else {
            info!("Payload ejected");
        }

        CONTINUE_LOGGING.store(false, Ordering::Relaxed);
        INJECTED.store(false, Ordering::Relaxed);
    });
}

fn start_tcp_listener_loop(listener: TcpListener) {
    let mut stream = listener.accept().unwrap().0;

    stream
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    info!("Listening for messages");
    let mut buffer: [u8; 2048] = [0; 2048];
    while CONTINUE_LOGGING.load(Ordering::Relaxed) {
        match stream.read(&mut buffer) {
            Ok(_) => {}
            Err(ref e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(err) => {
                error!("Error reading from stream: {:?}", err);
                break;
            }
        }

        Deserializer::from_slice(&buffer)
            .into_iter::<Value>()
            .for_each(|value| {
                if let Ok(value) = value {
                    if let Ok(message) = serde_json::from_value(value) {
                        debug!("Received message: {:?}", message);
                        handle_message(message);
                    }
                }
            });
        buffer = [0; 2048];
    }
    info!("Stopped listening for messages");
}

fn handle_message(message: CaptureMessage) {
    match message {
        CaptureMessage::Panic(panic_message) => {
            panic!("{}", panic_message);
        }
        ref m => {
            debug!("handle_message received: {:?}", m);
            MESSAGE_CONTAINER.lock().unwrap().push(message);
        }
    }
}

fn start_logging_propagation() {
    info!("Starting message propagation loop");
    thread::spawn(move || {
        while CONTINUE_LOGGING.load(Ordering::Relaxed)
            || !MESSAGE_CONTAINER
                .lock()
                .unwrap()
                .unstored_messages
                .is_empty()
        {
            let unstored_messages = MESSAGE_CONTAINER.lock().unwrap().drain_unstored();

            if !unstored_messages.is_empty() {
                info!(
                    "Propagating {} captured message(s) to ChaTOR",
                    unstored_messages.len()
                );
            }

            for msg in unstored_messages {
                match msg {
                    CapturedMessage::Chat(swtor_msg) => {
                        debug!("Sending captured chat message: {:?}", swtor_msg);
                        comms::send(FromService::SwtorMessage(swtor_msg));
                    }
                    CapturedMessage::Roll(dice_roll) => {
                        info!(
                            "[ROLL] Sending dice roll to ChaTOR: player={}, result={}",
                            dice_roll.player_name, dice_roll.result_text
                        );
                        comms::send(FromService::DiceRoll(dice_roll));
                    }
                }
            }

            thread::sleep(Duration::from_secs(1));
        }
        info!("Message propagation loop ended");
    });
}

pub fn stop_injecting_capture() {
    stop_injecting_capture_with_timeout(Duration::from_secs(30));
}

/// Asks the injection thread to stop (DllCommand::Stop + eject) and waits up to
/// `timeout` for it to finish.
pub fn stop_injecting_capture_with_timeout(timeout: Duration) {
    if !INJECTED.load(Ordering::Relaxed) {
        return;
    }

    CONTINUE_LOGGING.store(false, Ordering::Relaxed);

    let started = std::time::Instant::now();
    while INJECTED.load(Ordering::Relaxed) {
        if started.elapsed() > timeout {
            error!("Timed out waiting for capture to stop after {:?}", timeout);
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
}
