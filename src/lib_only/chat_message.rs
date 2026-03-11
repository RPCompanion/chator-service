use retour::static_detour;
use std::mem;

use crate::lib_only::submit_message;
use crate::share::CaptureMessage;
use crate::share::raw_swtor_message::RawSwtorMessage;

const CHAT_RELATIVE_ADDRESS: isize = 0x0521cc0;

// chat_recv(param_1, from_sso, to_sso, channel_id, msg_sso)
// All string params are 16-byte EA SSO string pointers. Returns void.
static_detour! {
    static ChatHook: extern "C" fn(*mut u8, *const u8, *const u8, i32, *const u8);
}

pub fn begin_detour(base_address: isize) {
    unsafe {
        let target: extern "C" fn(*mut u8, *const u8, *const u8, i32, *const u8) =
            mem::transmute(base_address + CHAT_RELATIVE_ADDRESS);
        match ChatHook.initialize(target, receive_chat_message_detour) {
            Ok(_) => {
                submit_message(CaptureMessage::Info(
                    "Chat Message detour initialized".to_string(),
                ));
                ChatHook.enable().unwrap();
            }
            Err(_) => {
                submit_message(CaptureMessage::CaptureError(
                    "Failed to initialize chat message detour".to_string(),
                ));
            }
        }
    }
}

fn receive_chat_message_detour(
    param_1: *mut u8,
    from: *const u8,
    to: *const u8,
    channel_id: i32,
    chat_message: *const u8,
) {
    match RawSwtorMessage::from_raw_ptrs(channel_id, from, to, chat_message) {
        Ok(message) => {
            submit_message(CaptureMessage::Chat(message));
        }
        Err(e) => {
            submit_message(CaptureMessage::Error(e.to_string()));
        }
    }

    ChatHook.call(param_1, from, to, channel_id, chat_message);
}

pub fn end_detour() {
    unsafe {
        ChatHook.disable().unwrap();
    }
}
