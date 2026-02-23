use std::net::TcpStream;
use std::thread;

pub mod capture_injector;
pub mod comms;
pub mod logging;
pub mod swtor;
pub mod swtor_hook;

fn main() {
    let _guard = logging::init();
    let mut stream = TcpStream::connect("127.0.0.1:30100").unwrap();
    let mut reader = stream.try_clone().expect("Clone failed");

    setup_write_stream(stream);
    loop_read_stream(reader);
}

fn loop_read_stream(mut reader: TcpStream) {}

fn setup_write_stream(mut stream: TcpStream) {
    thread::spawn(move || {});
}
