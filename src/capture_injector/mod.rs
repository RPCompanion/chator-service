use std::sync::LazyLock;
use std::thread;
use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use syringe_container::SyringeContainer;
use tracing::{debug, error, info};

use chator_macros::sha256_to_array;
use dll_syringe::{Syringe, process::OwnedProcess};
use serde::{Deserialize, Serialize};
use serde_json::{Deserializer, Value};

use crate::comms::{self, FromService};
use crate::{share::CaptureMessage, swtor_hook};

pub mod message_container;
mod syringe_container;

use self::message_container::SwtorMessageContainer;

const SUPPORTED_SWTOR_CHECKSUM: [u8; 32] =
    sha256_to_array!("58A46A11EDB0B7DC98DBAB590C01BC91BAD79A558CE6BEADAFF656FEBD8E3DD4");

static MESSAGE_CONTAINER: LazyLock<Mutex<SwtorMessageContainer>> =
    LazyLock::new(|| Mutex::new(SwtorMessageContainer::new()));

static INJECTED: AtomicBool = AtomicBool::new(false);
static CONTINUE_LOGGING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize, Serialize)]
pub enum CaptureError {
    AlreadyInjected,
    SwtorNotRunning,
    WrongGuiSettings,
    UnsupportedVersion,
    NotYetFullyReady,
}

pub fn start_injecting_capture() -> Result<(), CaptureError> {
    info!("start_injecting_capture called");

    if INJECTED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        info!("Already injected, skipping");
        return Err(CaptureError::AlreadyInjected);
    }

    let swtor_pid = swtor_hook::get_pid();
    if swtor_pid.is_none() {
        error!("SWTOR process not found");
        return Err(CaptureError::SwtorNotRunning);
    }
    let swtor_pid = swtor_pid.unwrap();
    info!("Found SWTOR process (pid: {})", swtor_pid);

    match swtor_hook::checksum_match(&SUPPORTED_SWTOR_CHECKSUM) {
        Ok(true) => info!("SWTOR checksum matches supported version"),
        Ok(false) => {
            error!("SWTOR checksum does not match supported version");
            return Err(CaptureError::UnsupportedVersion);
        }
        Err(e) => {
            error!("Could not verify SWTOR checksum: {:?}", e);
            return Err(CaptureError::NotYetFullyReady);
        }
    }

    info!("Starting injection thread for pid {}", swtor_pid);
    start_injecting_thread(swtor_pid);
    Ok(())
}

fn start_injecting_thread(swtor_pid: u32) {
    thread::spawn(move || {
        info!("Injection thread started for pid {}", swtor_pid);
        CONTINUE_LOGGING.store(true, Ordering::Relaxed);

        let target_process = OwnedProcess::from_pid(swtor_pid).unwrap();
        let syringe = Syringe::for_process(target_process);

        info!("Injecting DLL into SWTOR...");
        let syringe_container = SyringeContainer::inject(&syringe);

        if let Err(ref e) = syringe_container {
            error!("DLL injection failed: {:?}", e);
            INJECTED.store(false, Ordering::Relaxed);
            CONTINUE_LOGGING.store(false, Ordering::Relaxed);
            return;
        }

        info!("DLL injection succeeded");
        let syringe_container = syringe_container.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let chator_port = listener.local_addr().unwrap().port();

        info!("ChaTOR listening on port {}", chator_port);

        // ChaTOR must have restarted for this to be the case.
        let module_port: u16 = if syringe_container.capture_module_initalized() {
            info!("Capture module already initialized");
            syringe_container.set_chator_port(chator_port);
            syringe_container.get_module_ports().local_port
        } else {
            info!("Initializing capture module");
            syringe_container.init_capture_module(chator_port)
        };

        info!("Module listening on {}", module_port);

        let tcp_thread = thread::spawn(move || {
            start_tcp_listener_loop(listener, module_port);
        });

        start_logging_propagation();
        tcp_thread.join().unwrap();

        if let Err(err) = syringe_container.eject() {
            error!("Error ejecting payload: {:?}", err);
        } else {
            info!("Payload ejected");
        }

        CONTINUE_LOGGING.store(false, Ordering::Relaxed);
        INJECTED.store(false, Ordering::Relaxed);
    });
}

fn start_tcp_listener_loop(listener: TcpListener, module_port: u16) {
    let mut stream = listener.accept().unwrap().0;

    stream
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    info!("Listening for messages");
    let mut buffer: [u8; 2048] = [0; 2048];
    while CONTINUE_LOGGING.load(Ordering::Relaxed) {
        match stream.read(&mut buffer) {
            Ok(_) => {}
            Err(ref e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(err) => {
                error!("Error reading from stream: {:?}", err);
                break;
            }
        }

        Deserializer::from_slice(&buffer)
            .into_iter::<Value>()
            .for_each(|value| {
                if let Ok(value) = value {
                    if let Ok(message) = serde_json::from_value(value) {
                        debug!("Received message: {:?}", message);
                        handle_message(message);
                    }
                }
            });
        buffer = [0; 2048];
    }
    info!("Stopped listening for messages");

    if let Ok(mut stream) = TcpStream::connect(&format!("127.0.0.1:{}", module_port)) {
        stream.write(b"stop").unwrap();
    }

    thread::sleep(Duration::from_secs(1));
}

fn handle_message(message: CaptureMessage) {
    match message {
        CaptureMessage::Panic(panic_message) => {
            panic!("{}", panic_message);
        }
        _ => {
            MESSAGE_CONTAINER.lock().unwrap().push(message);
        }
    }
}

fn start_logging_propagation() {
    info!("Starting message propagation loop");
    thread::spawn(move || {
        while CONTINUE_LOGGING.load(Ordering::Relaxed)
            || !MESSAGE_CONTAINER
                .lock()
                .unwrap()
                .unstored_messages
                .is_empty()
        {
            let unstored_messages = MESSAGE_CONTAINER.lock().unwrap().drain_unstored();

            if !unstored_messages.is_empty() {
                info!("Propagating {} captured message(s) to ChaTOR", unstored_messages.len());
            }

            for msg in unstored_messages {
                debug!("Sending captured message: {:?}", msg);
                comms::send(FromService::SwtorMessage(msg));
            }

            thread::sleep(Duration::from_secs(1));
        }
        info!("Message propagation loop ended");
    });
}

pub fn stop_injecting_capture() {
    if !INJECTED.load(Ordering::Relaxed) {
        return;
    }

    CONTINUE_LOGGING.store(false, Ordering::Relaxed);

    while INJECTED.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
    }
}
