use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::model::{dice_roll::DiceRoll, swtor_message::SwtorMessage, user_character_message::UserCharacterMessages};

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
}

static WRITE_STREAM: Mutex<Option<TcpStream>> = Mutex::new(None);

/// Initializes the write side of the connection.
pub fn init(stream: TcpStream) {
    let mut guard = WRITE_STREAM.lock().unwrap();
    *guard = Some(stream);
}

/// Sends a message to the client.
pub fn send(msg: FromService) {
    let mut guard = WRITE_STREAM.lock().unwrap();
    if let Some(ref mut stream) = *guard {
        let mut json = serde_json::to_string(&msg).unwrap();
        json.push('\n');
        if let Err(e) = stream.write_all(json.as_bytes()) {
            error!("Failed to send message to client: {}", e);
        }
    }
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
                // Ensure checksum is computed before attempting injection
                crate::swtor_hook::set_process_checksum();
                info!("Starting capture injection...");
                match crate::capture_injector::start_injecting_capture() {
                    Ok(()) => info!("Capture injection started successfully"),
                    Err(e) => error!("Capture injection failed: {:?}", e),
                }
            } else {
                info!("Stopping capture injection...");
                crate::capture_injector::stop_injecting_capture();
                info!("Capture injection stopped");
            }
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
            info!("SubmitPost received (callback_id: {}, retry: {})", callback_id, retry);
            std::thread::spawn(move || {
                let result = crate::swtor_hook::post::submit_post(retry, character_message);
                info!("SubmitPost result (callback_id: {}): {:?}", callback_id, result);
                send(FromService::SubmitPostResult {
                    callback_id,
                    result: result.map_err(|e| e.to_string()),
                });
            });
        }
    }
}
