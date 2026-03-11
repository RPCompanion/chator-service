
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use thiserror::Error;
use super::AsJson;

#[derive(Deserialize, Serialize, Debug)]
pub struct RawSwtorMessage {
    pub channel: i32,
    pub timestamp: DateTime<Utc>,
    pub from: String,
    pub to: String,
    pub message: String,
}

enum StrConversion {
    FromMessage,
    ToMessage,
    ChatMessage
}

#[derive(Error, Debug)]
pub enum RawStrConversionError {

    #[error("FromMessage conversion error -> {0}")]
    FromMessage(String),

    #[error("ToMessage conversion error -> {0}")]
    ToMessage(String),

    #[error("ChatMessage conversion error -> {0}")]
    ChatMessage(String)

}

impl RawStrConversionError {

    pub fn new(conv: StrConversion, message: String) -> RawStrConversionError {

        match conv {
            StrConversion::FromMessage => RawStrConversionError::FromMessage(message),
            StrConversion::ToMessage => RawStrConversionError::ToMessage(message),
            StrConversion::ChatMessage => RawStrConversionError::ChatMessage(message)
        }

    }

}

/// Read a 16-byte EA/BioWare SSO string from a raw pointer.
///
/// Inline (len < 16): data in bytes[0..14], byte[15] = 15 - length.
/// Heap (len >= 16): bytes[0..7] = pointer, bytes[8..11] = u32 length,
///                   byte[15] has 0x80 set.
unsafe fn read_ea_sso(ptr: *const u8) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe {
        let byte15 = *ptr.add(15);
        if byte15 & 0x80 != 0 {
            // Heap mode: first 8 bytes are a pointer to the string data
            let data_ptr = *(ptr as *const *const u8);
            let len = *(ptr.add(8) as *const u32) as usize;
            if data_ptr.is_null() || len == 0 {
                return Some(String::new());
            }
            let slice = std::slice::from_raw_parts(data_ptr, len);
            Some(String::from_utf8_lossy(slice).to_string())
        } else {
            // Inline mode: length = 15 - byte15
            let len = (15 - byte15) as usize;
            if len == 0 {
                return Some(String::new());
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            Some(String::from_utf8_lossy(slice).to_string())
        }
    }
}

impl RawSwtorMessage {

    pub fn new(channel: i32, from: String, to: String, message: String) -> RawSwtorMessage {

        RawSwtorMessage {
            channel,
            timestamp: Utc::now(),
            from,
            to,
            message
        }

    }

    pub fn from_raw_ptrs(channel_id: i32, from: *const u8, to: *const u8, chat_message: *const u8) -> Result<RawSwtorMessage, RawStrConversionError> {

        let converter = |ptr: *const u8, conv: StrConversion| -> Result<String, RawStrConversionError> {
            unsafe {
                match read_ea_sso(ptr) {
                    Some(s) => Ok(s),
                    None => Err(RawStrConversionError::new(conv, "Null SSO pointer".to_string())),
                }
            }
        };

        let t_from         = converter(from, StrConversion::FromMessage)?;
        let t_to           = converter(to, StrConversion::ToMessage)?;
        let t_chat_message = converter(chat_message, StrConversion::ChatMessage)?;

        Ok(RawSwtorMessage::new(channel_id, t_from, t_to, t_chat_message))

    }

}

impl AsJson for RawSwtorMessage {}
