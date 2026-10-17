#!/usr/bin/env bash
# Builds chator-service (chator-service.exe + swtor_chat_capture.dll) for Windows.
#
# This is just `cargo build --target x86_64-pc-windows-msvc`. Everything that
# makes cross-compiling work is configured next to this script:
#   .cargo/config.toml   lld as linker, clang-cl for C deps, xwin CRT/SDK paths
#   rust-toolchain.toml  nightly toolchain with the x86_64-pc-windows-msvc target
#
# Usage:
#   ./build.sh            debug build  -> target/x86_64-pc-windows-msvc/debug/
#   ./build.sh --release  release build -> target/x86_64-pc-windows-msvc/release/
# Any extra arguments are passed straight to cargo.
set -euo pipefail

cd "$(dirname "$0")"

TARGET=x86_64-pc-windows-msvc
PROFILE_DIR=debug
for arg in "$@"; do
  [[ "$arg" == "--release" ]] && PROFILE_DIR=release
done

cargo build --target "$TARGET" "$@"

OUT="target/$TARGET/$PROFILE_DIR"
echo
echo "Built:"
ls -l "$OUT/chator-service.exe" "$OUT/swtor_chat_capture.dll"
