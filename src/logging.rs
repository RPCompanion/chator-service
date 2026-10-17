use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use chrono::prelude::*;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{self, fmt, prelude::*, EnvFilter};
use tracing_appender::{self, non_blocking::WorkerGuard};

/// Env var the ChaTOR client sets so service logs land next to its own logs.
pub const LOG_DIR_ENV: &str = "CHATOR_LOG_DIR";

/// Candidate log directories, most preferred first:
///   1. CHATOR_LOG_DIR (set by the client's launcher)
///   2. `logs/` next to the executable (dev builds, Windows portable folder)
///   3. %LOCALAPPDATA%\ChaTOR\logs (installed Linux packages run us from a
///      read-only /usr/lib or AppImage mount, seen through Wine's Z: drive)
///   4. the temp directory
fn log_dir_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(dir) = std::env::var(LOG_DIR_ENV) {
        if !dir.trim().is_empty() {
            out.push(PathBuf::from(dir));
        }
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join("logs"))) {
        out.push(dir);
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        out.push(PathBuf::from(local).join("ChaTOR").join("logs"));
    }
    out.push(std::env::temp_dir().join("ChaTOR").join("logs"));
    out
}

fn is_writable_dir(dir: &PathBuf) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".write-test");
    match fs::write(&probe, b"") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

static LOG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// The directory the service logs to (resolved once).
pub fn log_dir() -> &'static PathBuf {
    LOG_DIR.get_or_init(|| {
        log_dir_candidates()
            .into_iter()
            .find(is_writable_dir)
            .unwrap_or_else(|| PathBuf::from("."))
    })
}

pub fn init() -> WorkerGuard {

    let log_path = log_dir().clone();
    delete_stale_files(&log_path);

    let file_appender = tracing_appender::rolling::daily(&log_path, "chator-service.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = if cfg!(debug_assertions) {

        EnvFilter::from("trace")
            .add_directive("selectors::matching=off".parse().unwrap())

    } else {

        EnvFilter::from("error")
            .add_directive(LevelFilter::INFO.into())
            .add_directive("selectors::matching=off".parse().unwrap())

    };

    tracing_subscriber::registry()
        .with(fmt::layer()
            .with_writer(non_blocking)
            .with_level(true)
            .with_ansi(false)
        )
        .with(env_filter)
        .init();

    guard

}

fn delete_stale_files(log_path: &PathBuf) {

    let files = match fs::read_dir(log_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    for file in files {

        let file = match file {
            Ok(f) => f.path(),
            Err(_) => continue,
        };

        if !file.is_file() {
            continue;
        }

        // The directory may be shared with the client's chator.log files.
        let is_ours = file
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("chator-service.log"))
            .unwrap_or(false);
        if !is_ours {
            continue;
        }

        let metadata = match fs::metadata(&file) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let date_time: DateTime<Utc> = modified.into();
        let current_time = Utc::now();
        if (current_time - date_time).num_days() >= 7 {
            let _ = fs::remove_file(&file);
        }

    }

}