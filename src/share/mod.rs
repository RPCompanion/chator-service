use raw_swtor_message::RawSwtorMessage;
use raw_dice_roll::RawDiceRoll;
use serde::{Deserialize, Serialize};

pub mod dll_command;

/// Id of this build, shared by the service and the DLL built with it (see build.rs).
pub const BUILD_ID: u64 = parse_build_id(env!("CHATOR_BUILD_ID"));

const fn parse_build_id(digits: &str) -> u64 {
    let bytes = digits.as_bytes();
    let mut value: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        value = value * 10 + (bytes[i] - b'0') as u64;
        i += 1;
    }
    value
}
pub mod module_ports;
pub mod offsets;
pub mod raw_swtor_message;
pub mod raw_dice_roll;

#[derive(Deserialize, Serialize, Debug)]
pub enum CaptureMessage {
    Info(String),
    CaptureError(String),
    Panic(String),
    Chat(RawSwtorMessage),
    Roll(RawDiceRoll),
    Error(String),
}

impl AsJson for CaptureMessage {}

pub trait AsJson {
    fn as_json(&self) -> String
    where
        Self: serde::ser::Serialize,
    {
        serde_json::to_string(self).unwrap()
    }
}
