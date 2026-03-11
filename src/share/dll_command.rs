use serde::{Deserialize, Serialize};

/// Commands sent from the service to the injected DLL via TCP.
#[derive(Serialize, Deserialize)]
pub enum DllCommand {
    Stop,
    SendChatCommand { command: String, message: String },
    Diagnostics,
}

/// Responses sent from the DLL back to the service via TCP.
#[derive(Serialize, Deserialize)]
pub enum DllResponse {
    SendChatResult(Result<(), String>),
    DiagnosticsResult(DiagnosticsInfo),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DiagnosticsInfo {
    pub manager_ptr: Option<String>,
    pub context_ptr: Option<String>,
    pub global_chain_manager: Option<String>,
    pub global_chain_context: Option<String>,
    pub pointers_match: bool,
    pub detour_enabled: bool,
    pub last_game_call_cmd: Option<String>,
    pub last_send_result: Option<i64>,
}
