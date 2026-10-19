mod logging;
mod share;
mod swtor;
mod utils;

mod lib_only;

use std::collections::BTreeMap;
use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use std::str;
use std::thread;
use std::time::Duration;

use lib_only::chat_message;
use lib_only::cmd_dispatch;
use lib_only::dice_roll;
use lib_only::sigscan;

use share::CaptureMessage;
use share::offsets::{HookReport, HookStatus, OffsetSource, names};

use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::core::PCSTR;

use lib_only::{drain_messages, submit_message};

use crate::share::module_ports::ModulePorts;

static QUIT: AtomicBool = AtomicBool::new(false);

// TcpListener port for the chator client
static CHATOR_PORT: AtomicU16 = AtomicU16::new(0);
// TcpListener port for this injected module
static LOCAL_PORT: AtomicU16 = AtomicU16::new(0);
// Result of the last (and only) hook installation; hooks are installed once per injection.
static HOOK_REPORT: Mutex<Option<HookReport>> = Mutex::new(None);

#[unsafe(no_mangle)]
extern "system" fn capture_module_initalized() -> bool {
    CHATOR_PORT.load(Ordering::Relaxed) != 0
}

#[unsafe(no_mangle)]
extern "system" fn get_module_ports() -> ModulePorts {
    ModulePorts::new(
        CHATOR_PORT.load(Ordering::Relaxed),
        LOCAL_PORT.load(Ordering::Relaxed),
    )
}

#[unsafe(no_mangle)]
extern "system" fn set_chator_port(port: u16) {
    CHATOR_PORT.store(port, Ordering::Relaxed);
}

/*
    This function is called by the chator client to initialize the module.
    Returns the port that the module is listening on.
*/
#[unsafe(no_mangle)]
extern "system" fn init_capture_module(chator_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // May be a re-initialisation after DllCommand::Stop (hooks removed, state
    // reset) when the eject did not unload the module.
    QUIT.store(false, Ordering::Relaxed);
    CHATOR_PORT.store(chator_port, Ordering::Relaxed);
    LOCAL_PORT.store(port, Ordering::Relaxed);

    set_panic_hook();
    start_command_listener(listener);

    if let Err(_) = start_tcp_messenger() {
        return 0;
    }

    // Hooks are installed when the service sends DllCommand::InstallHooks with
    // the offsets for this build; see install_hooks().

    port
}

fn should_quit() -> bool {
    QUIT.load(Ordering::Relaxed)
}

fn start_tcp_messenger() -> Result<(), &'static str> {
    let stream_connector = move || -> Result<TcpStream, &'static str> {
        loop {
            if should_quit() {
                return Err("Quitting");
            }

            /*
                I'm making the assumption that the chator client might change the port later on (definitely possible in dev environments).
                This is a simple way to handle that.
            */
            let ip_addr_str = format!("127.0.0.1:{}", CHATOR_PORT.load(Ordering::Relaxed));

            match TcpStream::connect(&ip_addr_str) {
                Ok(stream) => {
                    return Ok(stream);
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(1000));
                }
            }
        }
    };

    let mut stream = stream_connector()?;

    thread::spawn(move || {
        loop {
            if should_quit() {
                break;
            }

            for message in drain_messages() {
                if let Err(_) = stream.write(message.as_bytes()) {
                    if should_quit() {
                        break;
                    }

                    if let Ok(s) = stream_connector() {
                        stream = s;
                    } else {
                        return;
                    }

                    stream.write(message.as_bytes()).unwrap();
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    Ok(())
}

fn set_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        submit_message(CaptureMessage::Panic(format!("Panic: {panic_info:?}")));
    }));
}

/// Serves DllCommands from the service, one connection at a time. A dropped
/// connection (the service died or ChaTOR restarted) keeps the hooks installed
/// and goes back to accepting, so the next service can reconnect and pick up
/// where the last one left off. Only an explicit `Stop` removes the hooks.
fn start_command_listener(listener: TcpListener) {
    thread::spawn(move || {
        'accept: loop {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };
            submit_message(CaptureMessage::Info("Service connected to DLL command port".to_string()));
            let write_stream = match stream.try_clone() {
                Ok(w) => w,
                Err(_) => continue,
            };
            let reader = std::io::BufReader::new(stream);
            let mut writer = std::io::BufWriter::new(write_stream);

            use std::io::BufRead;
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };

                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<share::dll_command::DllCommand>(&line) {
                Ok(share::dll_command::DllCommand::Stop) => break 'accept,
                Ok(share::dll_command::DllCommand::SendChatCommand { command, message }) => {
                    let result = cmd_dispatch::send_command(&command, &message);
                    let response = share::dll_command::DllResponse::SendChatResult(result);
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = writer.write_all(json.as_bytes());
                        let _ = writer.write_all(b"\n");
                        let _ = writer.flush();
                    }
                }
                Ok(share::dll_command::DllCommand::InstallHooks {
                    sha256,
                    offsets,
                    dynamic_lookup,
                }) => {
                    let report = install_hooks(sha256, &offsets, dynamic_lookup);
                    let response = share::dll_command::DllResponse::InstallHooksResult(report);
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = writer.write_all(json.as_bytes());
                        let _ = writer.write_all(b"\n");
                        let _ = writer.flush();
                    }
                }
                Ok(share::dll_command::DllCommand::Diagnostics) => {
                    let info = cmd_dispatch::get_diagnostics();
                    let response = share::dll_command::DllResponse::DiagnosticsResult(info);
                    if let Ok(json) = serde_json::to_string(&response) {
                        let _ = writer.write_all(json.as_bytes());
                        let _ = writer.write_all(b"\n");
                        let _ = writer.flush();
                    }
                }
                Err(_) => {
                    if line.trim() == "stop" {
                        break 'accept;
                    }
                    submit_message(CaptureMessage::Error(format!(
                        "Invalid DLL command: {}",
                        line
                    )));
                }
                }
            }
            // Connection dropped without Stop: keep hooks, wait for the next service.
            submit_message(CaptureMessage::Info(
                "Service disconnected from DLL command port; keeping hooks and waiting for reconnect".to_string(),
            ));
        }

        // Explicit Stop: tear everything down and let a later init start fresh.
        end_detours();
        QUIT.store(true, Ordering::Relaxed);
        CHATOR_PORT.store(0, Ordering::Relaxed);
        LOCAL_PORT.store(0, Ordering::Relaxed);
    });
}

/// Picks a hook's RVA: the runtime scan when dynamic lookup is on and it succeeds, else the offset
/// table. Returns the RVA, where it came from, and notes for the report.
fn resolve_rva(
    offsets: &BTreeMap<String, u64>,
    name: &str,
    dynamic_lookup: bool,
    scan: impl FnOnce() -> Result<sigscan::ScanHit, String>,
) -> (Option<u64>, OffsetSource, Vec<String>) {
    let table_rva = offsets.get(name).copied();
    let mut detail: Vec<String> = Vec::new();

    if dynamic_lookup {
        match scan() {
            Ok(hit) => {
                detail.push(format!("scan: {}", hit.detail));
                if let Some(t) = table_rva {
                    if t != hit.rva as u64 {
                        detail.push(format!(
                            "table offset 0x{:x} differs from scan result 0x{:x}; using scan",
                            t, hit.rva
                        ));
                    }
                }
                return (Some(hit.rva as u64), OffsetSource::Dynamic, detail);
            }
            Err(e) => detail.push(format!("scan failed: {}", e)),
        }
    }
    match table_rva {
        Some(t) => (Some(t), OffsetSource::Table, detail),
        None => {
            detail.push("no table offset for this build".to_string());
            (None, OffsetSource::None, detail)
        }
    }
}

/// Installs all hooks once. Later calls (e.g. after the service restarts while
/// the DLL stays injected) return the report from the first installation.
fn install_hooks(
    sha256: Option<String>,
    offsets: &BTreeMap<String, u64>,
    dynamic_lookup: bool,
) -> HookReport {
    if let Some(existing) = HOOK_REPORT.lock().unwrap().as_ref() {
        submit_message(CaptureMessage::Info(
            "InstallHooks: hooks already installed, returning previous report".to_string(),
        ));
        return existing.clone();
    }

    let mut report = HookReport {
        sha256,
        dynamic_lookup,
        hooks: Vec::new(),
    };

    let base_address = unsafe {
        match GetModuleHandleA(PCSTR(b"swtor.exe\0".as_ptr())) {
            Ok(hmodule) => hmodule.0 as isize,
            Err(e) => {
                submit_message(CaptureMessage::CaptureError(format!(
                    "Failed to find swtor.exe module: {:?}",
                    e
                )));
                for name in [names::CHAT_RECV, names::ROLL_HANDLER, names::CMD_DISPATCH] {
                    report.hooks.push(HookStatus {
                        name: name.to_string(),
                        rva: None,
                        source: OffsetSource::None,
                        installed: false,
                        detail: Some("swtor.exe module handle not found".to_string()),
                    });
                }
                *HOOK_REPORT.lock().unwrap() = Some(report.clone());
                return report;
            }
        }
    };
    submit_message(CaptureMessage::Info(format!(
        "Installing hooks, module base 0x{:x}, dynamic_lookup={}, table offsets: {:?}",
        base_address, dynamic_lookup, offsets
    )));

    // ---- chat_recv: dynamic lookup first, table as fallback ----
    {
        let (rva, source, mut detail) = resolve_rva(offsets, names::CHAT_RECV, dynamic_lookup, || unsafe {
            sigscan::find_chat_recv(base_address as usize)
        });

        let installed = match rva {
            Some(r) => match chat_message::begin_detour(base_address as usize + r as usize) {
                Ok(()) => true,
                Err(e) => {
                    detail.push(e);
                    false
                }
            },
            None => false,
        };
        report.hooks.push(HookStatus {
            name: names::CHAT_RECV.to_string(),
            rva,
            source,
            installed,
            detail: Some(detail.join("; ")),
        });
    }

    // ---- roll_handler: table only ----
    {
        let rva = offsets.get(names::ROLL_HANDLER).copied();
        let mut detail = None;
        let installed = match rva {
            Some(r) => match dice_roll::begin_detour(base_address as usize + r as usize) {
                Ok(()) => true,
                Err(e) => {
                    detail = Some(e);
                    false
                }
            },
            None => {
                detail = Some("no table offset for this build".to_string());
                false
            }
        };
        report.hooks.push(HookStatus {
            name: names::ROLL_HANDLER.to_string(),
            rva,
            source: if rva.is_some() { OffsetSource::Table } else { OffsetSource::None },
            installed,
            detail,
        });
    }

    // ---- cmd_dispatch + its global pointer chain: dynamic lookup first, table as fallback ----
    {
        let (rva, source, mut detail) = resolve_rva(offsets, names::CMD_DISPATCH, dynamic_lookup, || unsafe {
            sigscan::find_cmd_dispatch(base_address as usize)
        });
        let mut chain = cmd_dispatch::ChainSource::None;
        if dynamic_lookup {
            match unsafe { sigscan::find_chain_vtables(base_address as usize) } {
                Ok(vtables) => chain = cmd_dispatch::ChainSource::Rtti(vtables),
                Err(e) => detail.push(format!("chain vtable scan failed: {}", e)),
            }
        }
        if let (cmd_dispatch::ChainSource::None, Some(g), Some(c), Some(m)) = (
            &chain,
            offsets.get(names::GLOBAL_PTR),
            offsets.get(names::CONTEXT_VTABLE),
            offsets.get(names::MANAGER_VTABLE),
        ) {
            chain = cmd_dispatch::ChainSource::Table(cmd_dispatch::GlobalChain {
                global_ptr: *g as usize,
                context_vtable: *c as usize,
                manager_vtable: *m as usize,
            });
        }
        let installed = match rva {
            Some(r) => match cmd_dispatch::begin_detour(base_address, r, chain) {
                Ok(()) => true,
                Err(e) => {
                    detail.push(e);
                    false
                }
            },
            None => false,
        };
        detail.push(cmd_dispatch::chain_status());
        report.hooks.push(HookStatus {
            name: names::CMD_DISPATCH.to_string(),
            rva,
            source,
            installed,
            detail: Some(detail.join("; ")),
        });
    }

    submit_message(CaptureMessage::Info(format!(
        "Hook installation finished: {}",
        report.summary()
    )));
    *HOOK_REPORT.lock().unwrap() = Some(report.clone());
    report
}

fn end_detours() {
    chat_message::end_detour();
    dice_roll::end_detour();
    cmd_dispatch::end_detour();
    // Hooks are gone, so a later InstallHooks must really reinstall.
    *HOOK_REPORT.lock().unwrap() = None;
}
