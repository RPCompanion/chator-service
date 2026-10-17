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

use std::sync::LazyLock;

use crate::share::offsets::OffsetTable;

/// Offset configuration pushed by the client: whether the DLL may locate hook
/// targets by scanning, and the offset table (bundled + downloaded) to use.
struct OffsetConfig {
    dynamic_lookup: bool,
    client_table: Option<OffsetTable>,
}

static OFFSET_CONFIG: LazyLock<Mutex<OffsetConfig>> = LazyLock::new(|| {
    Mutex::new(OffsetConfig {
        dynamic_lookup: true,
        client_table: None,
    })
});

/// Stores the offset configuration received from the client.
pub fn set_offset_config(dynamic_lookup: bool, table: OffsetTable) {
    let mut cfg = OFFSET_CONFIG.lock().unwrap();
    cfg.dynamic_lookup = dynamic_lookup;
    cfg.client_table = Some(table);
}

/// Whether the DLL may use runtime signature scanning.
pub fn dynamic_offset_lookup() -> bool {
    OFFSET_CONFIG.lock().unwrap().dynamic_lookup
}

/// The effective offset table: client-provided entries first, then the table
/// compiled into this binary.
pub fn offset_table() -> OffsetTable {
    let cfg = OFFSET_CONFIG.lock().unwrap();
    let bundled = OffsetTable::bundled();
    match &cfg.client_table {
        Some(client) => OffsetTable::merged(client, &bundled),
        None => bundled,
    }
}
