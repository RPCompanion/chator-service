use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::share::raw_swtor_message::RawSwtorMessage;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SwtorMessage {
    pub channel: i32,
    #[serde(default = "default_timestamp")]
    pub timestamp: DateTime<Utc>,
    pub from: String,
    pub to: String,
    pub message: String,
}

fn default_timestamp() -> DateTime<Utc> {
    Utc::now()
}

impl From<RawSwtorMessage> for SwtorMessage {
    fn from(raw_swtor_message: RawSwtorMessage) -> Self {
        SwtorMessage {
            channel: raw_swtor_message.channel,
            timestamp: raw_swtor_message.timestamp,
            from: raw_swtor_message.from,
            to: raw_swtor_message.to,
            message: raw_swtor_message.message,
        }
    }
}
