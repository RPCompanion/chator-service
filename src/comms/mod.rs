use serde::{Deserialize, Serialize};

use crate::model::{swtor_message::SwtorMessage, user_character_message::UserCharacterMessages};

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
    SubmitPostResult {
        callback_id: i64,
        result: Result<(), String>,
    },
    KeepWindowInFocus(bool),
}

/// Sends a message to the client.
pub fn send(from: FromService) {
    todo!()
}
