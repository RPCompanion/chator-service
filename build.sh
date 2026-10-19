#!/usr/bin/env bash
# Builds chator-service (chator-service.exe + swtor_chat_capture.dll) for Windows
# from Linux, then copies both into the ChaTOR app so it bundles them.
#
# Cross-compiling uses cargo-xwin (cargo install --locked cargo-xwin, or
# `uv tool install cargo-xwin`), which fetches the MSVC CRT/SDK on first use and
# drives clang-cl / lld-link. Needs clang, lld and llvm on PATH.
# rust-toolchain.toml pins nightly (retour uses unstable features).
#
# Usage:
#   ./build.sh            debug build  -> target/x86_64-pc-windows-msvc/debug/
#   ./build.sh --release  release build -> target/x86_64-pc-windows-msvc/release/
# Any extra arguments are passed straight to cargo.
#
# CHATOR_APP_DIR overrides where the ChaTOR repo is (default: ../ChaTOR).
set -euo pipefail

cd "$(dirname "$0")"

TARGET=x86_64-pc-windows-msvc
PROFILE_DIR=debug
for arg in "$@"; do
  [[ "$arg" == "--release" ]] && PROFILE_DIR=release
done

if ! command -v cargo-xwin >/dev/null 2>&1; then
  echo "cargo-xwin not found. Install it with: cargo install --locked cargo-xwin" >&2
  exit 1
fi

cargo xwin build --target "$TARGET" "$@"

OUT="target/$TARGET/$PROFILE_DIR"
echo
echo "Built:"
ls -l "$OUT/chator-service.exe" "$OUT/swtor_chat_capture.dll"

# Make the build available to the ChaTOR app (config.toml points at
# service/chator-service.exe; tauri.conf.json bundles the service/ folder).
APP_DIR="${CHATOR_APP_DIR:-$(cd .. && pwd)/ChaTOR}"
APP_SERVICE_DIR="$APP_DIR/src-tauri/service"
mkdir -p "$APP_SERVICE_DIR"
# Copy to a temporary name and rename over the old file: a running SWTOR may still have the old
# DLL mapped, and overwriting that file in place would change the game's mapped pages.
for f in chator-service.exe swtor_chat_capture.dll; do
  cp -f "$OUT/$f" "$APP_SERVICE_DIR/.$f.new"
  mv -f "$APP_SERVICE_DIR/.$f.new" "$APP_SERVICE_DIR/$f"
done
echo "Copied into $APP_SERVICE_DIR"
