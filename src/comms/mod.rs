use serde::{Deserialize, Serialize};

pub mod state;

#[derive(Serialize, Deserialize)]
pub enum FromClient {
    CaptureChatLog(bool),
}

#[derive(Serialize, Deserialize)]
pub enum FromService {
    IsHookedIn(bool),
}

/// Sends a message to the client.
pub fn send(from: FromService) {
    todo!()
}
