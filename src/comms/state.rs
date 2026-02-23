use std::sync::Mutex;

static CAPTURE_CHAT_LOG: Mutex<bool> = Mutex::new(false);

/// Sets whether the service should capture the chat log or not.
pub fn set_capture_chat_log(value: bool) {
    let mut capture_chat_log = CAPTURE_CHAT_LOG.lock().unwrap();
    *capture_chat_log = value;
}

/// Gets whether the service should capture the chat log or not.
pub fn get_capture_chat_log() -> bool {
    let capture_chat_log = CAPTURE_CHAT_LOG.lock().unwrap();
    *capture_chat_log
}
