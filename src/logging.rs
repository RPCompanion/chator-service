use std::fs;
use std::path::PathBuf;

use chrono::prelude::*;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{self, fmt, prelude::*, EnvFilter};
use tracing_appender::{self, non_blocking::WorkerGuard};

fn log_dir() -> PathBuf {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("logs")))
        .unwrap_or_else(|| PathBuf::from("./logs"));
    dir
}

pub fn init() -> WorkerGuard {

    let log_path = log_dir();
    if !log_path.exists() {
        fs::create_dir_all(&log_path)
            .expect("error while creating logs directory");
    } else {
        delete_stale_files(&log_path);
    }

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