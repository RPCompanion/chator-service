use tracing::{debug, info, warn};

use crate::comms::state::retry_message_submission;
use crate::model::dice_roll::DiceRoll;
use crate::model::swtor_message::SwtorMessage;
use crate::share::*;
use crate::swtor::SwtorChannel;
use crate::swtor_hook::post;
use crate::utils::StringUtils;

pub enum CapturedMessage {
    Chat(SwtorMessage),
    Roll(DiceRoll),
}

pub struct SwtorMessageContainer {
    pub unstored_messages: Vec<CapturedMessage>,
}

impl SwtorMessageContainer {
    pub fn new() -> SwtorMessageContainer {
        SwtorMessageContainer {
            unstored_messages: Vec::new(),
        }
    }

    pub fn push(&mut self, capture_message: CaptureMessage) {
        match capture_message {
            CaptureMessage::Chat(raw_swtor_message) => {
                let swtor_message = SwtorMessage::from(raw_swtor_message);
                if retry_message_submission() {
                    let channel = match SwtorChannel::try_from(swtor_message.channel) {
                        Ok(channel) => channel,
                        Err(_) => SwtorChannel::EMOTE,
                    };

                    post::push_incoming_message_hash(
                        channel,
                        swtor_message.get_parsed_message().as_u64_hash(),
                    );
                }

                self.unstored_messages.push(CapturedMessage::Chat(swtor_message));
            }
            CaptureMessage::Roll(raw_dice_roll) => {
                info!("[ROLL] Received raw dice roll from DLL: player={}, result={}", raw_dice_roll.player_name, raw_dice_roll.result_text);
                let dice_roll = DiceRoll::from(raw_dice_roll);
                self.unstored_messages.push(CapturedMessage::Roll(dice_roll));
            }
            CaptureMessage::Info(msg) => {
                info!("[DLL] {}", msg);
            }
            CaptureMessage::CaptureError(msg) => {
                warn!("[DLL ERROR] {}", msg);
            }
            CaptureMessage::Error(msg) => {
                warn!("[DLL ERROR] {}", msg);
            }
            _ => {}
        }
    }

    pub fn drain_unstored(&mut self) -> Vec<CapturedMessage> {
        self.unstored_messages.drain(..).collect()
    }
}
