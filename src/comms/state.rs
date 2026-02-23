use std::sync::Mutex;

static CAPTURE_CHAT_LOG: Mutex<bool> = Mutex::new(false);
static RETRY_MESSAGE_SUBMISSION: Mutex<bool> = Mutex::new(false);

/// Sets whether the service should capture the chat log or not.
pub fn set_capture_chat_log(value: bool) {
    let mut capture_chat_log = CAPTURE_CHAT_LOG.lock().unwrap();
    *capture_chat_log = value;
}

/// Gets whether the service should capture the chat log or not.
pub fn capture_chat_log() -> bool {
    let capture_chat_log = CAPTURE_CHAT_LOG.lock().unwrap();
    *capture_chat_log
}

/// Sets whether the service should retry message submission or not.
pub fn set_retry_message_submission(value: bool) {
    let mut retry_message_submission = RETRY_MESSAGE_SUBMISSION.lock().unwrap();
    *retry_message_submission = value;
}

/// Gets whether the service should retry message submission or not.
pub fn retry_message_submission() -> bool {
    let retry_message_submission = RETRY_MESSAGE_SUBMISSION.lock().unwrap();
    *retry_message_submission
}
