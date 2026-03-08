use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::AsJson;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RawDiceRoll {
    pub timestamp: DateTime<Utc>,
    pub player_name: String,
    pub result_text: String,
}

impl RawDiceRoll {
    pub fn new(player_name: String, result_text: String) -> RawDiceRoll {
        RawDiceRoll {
            timestamp: Utc::now(),
            player_name,
            result_text,
        }
    }
}

impl AsJson for RawDiceRoll {}
