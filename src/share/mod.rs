use raw_swtor_message::RawSwtorMessage;
use raw_dice_roll::RawDiceRoll;
use serde::{Deserialize, Serialize};

pub mod module_ports;
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
