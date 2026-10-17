use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::share::offsets::HookReport;

/// Commands sent from the service to the injected DLL via TCP.
#[derive(Serialize, Deserialize)]
pub enum DllCommand {
    Stop,
    SendChatCommand { command: String, message: String },
    Diagnostics,
    /// Install the game hooks. `offsets` holds RVAs from the offset table for
    /// the running build (may be empty). When `dynamic_lookup` is set, hooks
    /// that support it locate their target by scanning the loaded image first.
    InstallHooks {
        sha256: Option<String>,
        offsets: BTreeMap<String, u64>,
        dynamic_lookup: bool,
    },
}

/// Responses sent from the DLL back to the service via TCP.
#[derive(Serialize, Deserialize)]
pub enum DllResponse {
    SendChatResult(Result<(), String>),
    DiagnosticsResult(DiagnosticsInfo),
    InstallHooksResult(HookReport),
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
