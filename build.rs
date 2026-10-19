//! Stamps each build with an id that the service and the DLL from that build share
//! (CHATOR_BUILD_ID), so the service can tell when a DLL from another build is still loaded in
//! the game and must be replaced rather than reused.
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    println!("cargo:rustc-env=CHATOR_BUILD_ID={id}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
