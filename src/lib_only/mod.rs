use std::sync::LazyLock;
use std::sync::Mutex;

use crate::share::{AsJson, CaptureMessage};

pub mod chat_gateway;
pub mod chat_message;
pub mod cmd_dispatch;
pub mod dice_roll;
pub mod friends_list;
pub mod memory;
pub mod sigscan;

static MESSAGES: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));
/// Messages buffered while no service is connected; oldest are dropped past this.
const MAX_QUEUED_MESSAGES: usize = 5000;

pub fn submit_message(capture_message: CaptureMessage) {
    let mut messages = MESSAGES.lock().unwrap();
    if messages.len() >= MAX_QUEUED_MESSAGES {
        let excess = messages.len() + 1 - MAX_QUEUED_MESSAGES;
        messages.drain(..excess);
    }
    messages.push(capture_message.as_json());
}

pub fn drain_messages() -> Vec<String> {
    let mut messages = MESSAGES.lock().unwrap();
    messages.drain(..).collect()
}
