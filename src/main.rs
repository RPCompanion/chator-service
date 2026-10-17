use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use tracing::{error, info};

pub mod capture_injector;
pub mod comms;
pub mod logging;
pub mod model;
pub mod share;
pub mod swtor;
pub mod swtor_hook;
pub mod utils;

fn main() {
    let _guard = logging::init();

    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:30100".to_string());

    info!("Service log directory: {}", logging::log_dir().display());
    info!("Connecting to ChaTOR at {}", address);

    let stream = match TcpStream::connect(&address) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to ChaTOR at {}: {}", address, e);
            return;
        }
    };

    let read_stream = stream.try_clone().expect("Failed to clone TCP stream");

    comms::init(stream);
    info!("Connected to ChaTOR");

    swtor_hook::start_swtor_hook();
    info!("SWTOR hook started");

    // Blocking — runs until the connection drops
    comms::recv_loop(read_stream);

    // Remove hooks / eject the DLL before exiting so the next service starts clean.
    comms::shutdown("client disconnected");
    thread::sleep(Duration::from_secs(15));
    error!("Shutdown did not complete in time; exiting anyway");
    std::process::exit(1);
}
