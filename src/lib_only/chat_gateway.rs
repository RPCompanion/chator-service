//! Chat gateway sends (channels, whispers) and the channel ids they need.
//!
//! Channel and whisper messages go to the chat gateway server, not the area server:
//!   OmegaClientApp +0x60 -> ChatGatewayObject +0x40 -> ChatGatewayRequestIFaceProxy
//! Its channel RPC takes the channel's id ("gld.<guild id>", "gen.dro_chat", ...), which the
//! client only gets from the server. So we hook ChatGatewayObject's channel-message handler
//! (ChatGatewayResponseIFace) and remember the id of every channel number a message arrives on;
//! the server echoes the player's own channel messages too. Until a channel has been seen,
//! sending to it fails and the service falls back to typing.
//! See frida-scripts/chat_send_routes_oct2026.md.

use retour::static_detour;
use std::collections::BTreeMap;
use std::mem;
use std::sync::Mutex;

use crate::lib_only::cmd_dispatch::{self, EaSsoString, read_sso_string};
use crate::lib_only::memory;
use crate::lib_only::submit_message;
use crate::share::CaptureMessage;

// channel_message_received(this, ?, from_sso, channel_id_sso, i32 channel, text_sso)
static_detour! {
    static ChannelMessageHook: extern "C" fn(*mut u8, *mut u8, *const u8, *const u8, i32, *const u8);
}

/// Absolute addresses of the chat gateway's RPC methods.
#[derive(Clone, Copy, Debug)]
pub struct Methods {
    /// (proxy, channel_id_sso, text_sso)
    pub channel_message: usize,
    /// (proxy, name_sso, text_sso, u32 4)
    pub whisper: usize,
}

static BASE_ADDRESS: Mutex<Option<usize>> = Mutex::new(None);
static METHODS: Mutex<Option<Methods>> = Mutex::new(None);
/// Channel id per channel number (SwtorChannel), learned from incoming channel messages.
static CHANNEL_IDS: Mutex<BTreeMap<i32, String>> = Mutex::new(BTreeMap::new());

/// Remembers where the RPC methods are; sending works once this is set.
pub fn set_methods(base: usize, methods: Methods) {
    *BASE_ADDRESS.lock().unwrap() = Some(base);
    *METHODS.lock().unwrap() = Some(methods);
}

/// Hooks the channel-message handler at the absolute `address`.
pub fn begin_detour(address: usize) -> Result<(), String> {
    unsafe {
        let target: extern "C" fn(*mut u8, *mut u8, *const u8, *const u8, i32, *const u8) =
            mem::transmute(address);
        ChannelMessageHook
            .initialize(target, channel_message_detour)
            .map_err(|e| format!("initialize failed: {:?}", e))?;
        ChannelMessageHook
            .enable()
            .map_err(|e| format!("enable failed: {:?}", e))?;
    }
    submit_message(CaptureMessage::Info(format!(
        "chat gateway channel message detour initialized at 0x{:x}",
        address
    )));
    Ok(())
}

pub fn end_detour() {
    unsafe {
        let _ = ChannelMessageHook.disable();
    }
}

fn channel_message_detour(
    this: *mut u8,
    unknown: *mut u8,
    from: *const u8,
    channel_id: *const u8,
    channel: i32,
    text: *const u8,
) {
    if let Some(id) = unsafe { read_sso_string(channel_id) } {
        learn(channel, id);
    }
    ChannelMessageHook.call(this, unknown, from, channel_id, channel, text);
}

/// Records `id` for `channel` if it looks like a channel id ("gld.4611689236999446983").
fn learn(channel: i32, id: String) {
    let plausible = (1..1000).contains(&channel)
        && id.len() < 128
        && id.split_once('.').is_some_and(|(kind, rest)| {
            !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_lowercase()) && !rest.is_empty()
        })
        && id.bytes().all(|b| b.is_ascii_graphic());
    if !plausible {
        return;
    }
    let mut ids = CHANNEL_IDS.lock().unwrap();
    if ids.get(&channel) != Some(&id) {
        submit_message(CaptureMessage::Info(format!("chat channel {} is {}", channel, id)));
        ids.insert(channel, id);
    }
}

/// The ChatGatewayRequestIFaceProxy, found from the app object and checked by RTTI class name.
fn proxy() -> Result<usize, String> {
    let base = (*BASE_ADDRESS.lock().unwrap()).ok_or("chat gateway not set up")?;
    let app = cmd_dispatch::app_object().ok_or("The game is not ready to chat yet")?;
    let gateway = memory::read_usize(app + 0x60)
        .filter(|&g| memory::is_class(base, g, "ChatGatewayObject"))
        .ok_or("chat gateway object not found")?;
    memory::read_usize(gateway + 0x40)
        .filter(|&p| memory::is_class(base, p, "ChatGatewayRequestIFaceProxy"))
        .ok_or_else(|| "chat gateway proxy not found".to_string())
}

fn methods() -> Result<Methods, String> {
    (*METHODS.lock().unwrap()).ok_or_else(|| "chat gateway methods not found for this build".to_string())
}

/// Sends `text` to the channel with this number. Fails, without sending, while the channel's id
/// is unknown.
pub fn send_channel(channel: i32, text: &str) -> Result<(), String> {
    let id = CHANNEL_IDS
        .lock()
        .unwrap()
        .get(&channel)
        .cloned()
        .ok_or_else(|| {
            format!("ChaTOR has not seen a message in channel {} yet (it learns each channel from the first message there, yours or anyone's)", channel)
        })?;
    let methods = methods()?;
    let proxy = proxy()?;
    let id_sso = EaSsoString::from_str(&id);
    let text_sso = EaSsoString::from_str(text);
    submit_message(CaptureMessage::Info(format!("chat gateway: channel {} ({}), {} chars", channel, id, text.len())));
    let send: extern "C" fn(*mut u8, *const EaSsoString, *const EaSsoString) =
        unsafe { mem::transmute(methods.channel_message) };
    send(proxy as *mut u8, &id_sso, &text_sso);
    Ok(())
}

/// Whispers `text` to the character called `name`.
pub fn send_whisper(name: &str, text: &str) -> Result<(), String> {
    if name.is_empty() || text.is_empty() {
        return Err("A whisper needs a name and a message".to_string());
    }
    let methods = methods()?;
    let proxy = proxy()?;
    let name_sso = EaSsoString::from_str(name);
    let text_sso = EaSsoString::from_str(text);
    submit_message(CaptureMessage::Info(format!("chat gateway: whisper, {} chars", text.len())));
    // The game passed 4 here for every whisper seen (also the whisper channel number).
    let send: extern "C" fn(*mut u8, *const EaSsoString, *const EaSsoString, u32) =
        unsafe { mem::transmute(methods.whisper) };
    send(proxy as *mut u8, &name_sso, &text_sso, 4);
    Ok(())
}
