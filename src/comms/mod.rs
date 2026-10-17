use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::model::{
    dice_roll::DiceRoll,
    swtor_message::SwtorMessage,
    user_character_message::UserCharacterMessages,
};
use crate::share::offsets::{HookReport, OffsetTable};

pub mod state;

#[derive(Serialize, Deserialize)]
pub enum FromClient {
    CaptureChatLog(bool),
    RetryMessageSubmission(bool),
    SubmitPost {
        retry: bool,
        character_message: UserCharacterMessages,
        callback_id: i64,
    },
    /// Offset table (bundled + downloaded) and whether runtime signature
    /// scanning is allowed. Sent before CaptureChatLog(true).
    ConfigureOffsets {
        dynamic_lookup: bool,
        table: OffsetTable,
    },
}

#[derive(Serialize, Deserialize)]
pub enum FromService {
    IsHookedIn(bool),
    SwtorMessage(SwtorMessage),
    DiceRoll(DiceRoll),
    SubmitPostResult {
        callback_id: i64,
        result: Result<(), String>,
    },
    KeepWindowInFocus(bool),
    /// Which hooks the injected DLL installed and where.
    HookReport(HookReport),
    /// Human-readable status for the client log / UI. `level` is
    /// "error", "warn" or "info".
    ServiceNotice { level: String, message: String },
}

static NOTICES_SENT: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);
const NOTICE_REPEAT_AFTER: Duration = Duration::from_secs(60);

/// Logs `message` at `level` and forwards it to the client. Identical
/// messages are forwarded at most once a minute so retry loops stay quiet.
pub fn notify_once(level: &str, message: impl Into<String>) {
    let message = message.into();
    let now = Instant::now();
    {
        let mut guard = NOTICES_SENT.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        if let Some(last) = map.get(&message) {
            if now.duration_since(*last) < NOTICE_REPEAT_AFTER {
                return;
            }
        }
        map.insert(message.clone(), now);
    }
    match level {
        "error" => error!("[to client] {}", message),
        "warn" => warn!("[to client] {}", message),
        _ => info!("[to client] {}", message),
    }
    send(FromService::ServiceNotice {
        level: level.to_string(),
        message,
    });
}

static WRITE_STREAM: Mutex<Option<TcpStream>> = Mutex::new(None);

/// Initializes the write side of the connection.
pub fn init(stream: TcpStream) {
    let mut guard = WRITE_STREAM.lock().unwrap();
    *guard = Some(stream);
}

/// Sends a message to the client.
static SEND_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Consecutive send failures before we conclude the client is gone.
const MAX_SEND_FAILURES: u32 = 3;

pub fn send(msg: FromService) {
    use std::sync::atomic::Ordering;
    let failures = {
        let mut guard = WRITE_STREAM.lock().unwrap();
        match *guard {
            Some(ref mut stream) => {
                let mut json = serde_json::to_string(&msg).unwrap();
                json.push('\n');
                match stream.write_all(json.as_bytes()) {
                    Ok(()) => {
                        SEND_FAILURES.store(0, Ordering::Relaxed);
                        return;
                    }
                    Err(e) => {
                        error!("Failed to send message to client: {}", e);
                        SEND_FAILURES.fetch_add(1, Ordering::Relaxed) + 1
                    }
                }
            }
            None => return,
        }
    };
    if failures >= MAX_SEND_FAILURES {
        shutdown("client connection lost");
    }
}

/// Stops capture (tells the DLL to remove its hooks and ejects it) and exits
/// the process. Used when ChaTOR disconnects or stops answering; without it a
/// stale service kept running under Wine, holding the DLL's command channel.
pub fn shutdown(reason: &str) {
    use std::sync::atomic::Ordering;
    if SHUTTING_DOWN.swap(true, Ordering::SeqCst) {
        return;
    }
    let reason = reason.to_string();
    std::thread::spawn(move || {
        info!("Shutting down: {}", reason);
        crate::capture_injector::stop_injecting_capture_with_timeout(Duration::from_secs(10));
        info!("Shutdown complete");
        std::process::exit(0);
    });
}

/// Blocking read loop — reads FromClient messages and dispatches them.
pub fn recv_loop(stream: TcpStream) {
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<FromClient>(&line) {
                    Ok(msg) => handle_message(msg),
                    Err(e) => error!("Failed to parse FromClient message: {}", e),
                }
            }
            Err(e) => {
                error!("Connection read error: {}", e);
                break;
            }
        }
    }
    info!("Client disconnected");
}

fn handle_message(msg: FromClient) {
    match msg {
        FromClient::CaptureChatLog(value) => {
            info!("CaptureChatLog set to {}", value);
            state::set_capture_chat_log(value);
            if value {
                crate::capture_injector::allow_retries();
                // Ensure checksum is computed before attempting injection
                crate::swtor_hook::set_process_checksum();
                info!("Starting capture injection...");
                match crate::capture_injector::start_injecting_capture() {
                    Ok(()) => info!("Capture injection started successfully"),
                    Err(e) => error!(
                        "Capture injection failed: {:?} (will retry every {}s while chat logging is on)",
                        e,
                        crate::capture_injector::RETRY_INTERVAL.as_secs()
                    ),
                }
            } else {
                info!("Stopping capture injection...");
                crate::capture_injector::stop_injecting_capture();
                info!("Capture injection stopped");
            }
        }
        FromClient::ConfigureOffsets {
            dynamic_lookup,
            table,
        } => {
            info!(
                "ConfigureOffsets received: dynamic_lookup={}, {} table version(s): {:?}",
                dynamic_lookup,
                table.versions.len(),
                table
                    .versions
                    .iter()
                    .map(|v| format!(
                        "{}..({}) {:?}",
                        &v.sha256[..v.sha256.len().min(8)],
                        v.label.as_deref().unwrap_or(""),
                        v.offsets.keys().collect::<Vec<_>>()
                    ))
                    .collect::<Vec<_>>()
            );
            state::set_offset_config(dynamic_lookup, table);
            crate::capture_injector::allow_retries();
        }
        FromClient::RetryMessageSubmission(value) => {
            info!("RetryMessageSubmission set to {}", value);
            state::set_retry_message_submission(value);
        }
        FromClient::SubmitPost {
            retry,
            character_message,
            callback_id,
        } => {
            info!(
                "SubmitPost received (callback_id: {}, retry: {})",
                callback_id, retry
            );
            std::thread::spawn(move || {
                let result = route_submit_post(retry, character_message);
                info!(
                    "SubmitPost result (callback_id: {}): {:?}",
                    callback_id, result
                );
                send(FromService::SubmitPostResult {
                    callback_id,
                    result,
                });
            });
        }
    }
}

fn is_roll_command(msg: &str) -> bool {
    let trimmed = msg.trim().to_ascii_lowercase();
    trimmed == "/roll" || trimmed.starts_with("/roll ")
}

fn is_whisper_command(msg: &str) -> bool {
    let trimmed = msg.trim().to_ascii_lowercase();
    trimmed.starts_with("/w ")
        || trimmed.starts_with("/whisper ")
        || trimmed.starts_with("/tell ")
}

fn parse_slash_command(msg: &str) -> Option<(String, String)> {
    let trimmed = msg.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let without_slash = &trimmed[1..];
    if let Some(space_idx) = without_slash.find(' ') {
        let cmd = without_slash[..space_idx].to_string();
        let message = without_slash[space_idx + 1..].to_string();
        Some((cmd, message))
    } else {
        Some((without_slash.to_string(), String::new()))
    }
}

fn route_submit_post(
    retry: bool,
    mut character_message: UserCharacterMessages,
) -> Result<(), String> {
    character_message.prepare_messages();

    // All messages go through keystroke injection for now.
    // cmd_dispatch only works reliably for emote/say/yell — guild, whisper,
    // group, ops, and roll all bypass cmd_dispatch's entry point and use
    // a different code path (roll_wrapper → cmd_dispatch+0x210).
    crate::swtor_hook::post::submit_post(retry, character_message)
        .map_err(|e| e.to_string())

    // TODO: Re-enable cmd_dispatch routing once we understand which commands
    // go through cmd_dispatch vs roll_wrapper+0x210.
    //
    // let message_type = character_message.message_type;
    // let character_id = character_message.character_id;
    // let mut keystroke_messages = Vec::new();
    //
    // for message in &character_message.messages {
    //     if is_roll_command(message) || is_whisper_command(message) || !message.starts_with('/') {
    //         keystroke_messages.push(message.clone());
    //     } else if let Some((cmd, text)) = parse_slash_command(message) {
    //         match crate::capture_injector::send_chat_command(&cmd, &text) {
    //             Ok(()) => {
    //                 info!("Direct dispatch succeeded: /{} {}", cmd, text);
    //             }
    //             Err(e) => {
    //                 info!(
    //                     "Direct dispatch failed ({}), falling back to keystroke injection",
    //                     e
    //                 );
    //                 keystroke_messages.push(message.clone());
    //             }
    //         }
    //     } else {
    //         keystroke_messages.push(message.clone());
    //     }
    // }
    //
    // if !keystroke_messages.is_empty() {
    //     let ks_cm = UserCharacterMessages {
    //         message_type,
    //         character_id,
    //         messages: keystroke_messages,
    //     };
    //     crate::swtor_hook::post::submit_post(retry, ks_cm).map_err(|e| e.to_string())?;
    // }
    //
    // Ok(())
}
