use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::share::raw_dice_roll::RawDiceRoll;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DiceRoll {
    pub timestamp: DateTime<Utc>,
    pub player_name: String,
    pub result_text: String,
}

impl From<RawDiceRoll> for DiceRoll {
    fn from(raw: RawDiceRoll) -> Self {
        DiceRoll {
            timestamp: raw.timestamp,
            player_name: raw.player_name,
            result_text: raw.result_text,
        }
    }
}
