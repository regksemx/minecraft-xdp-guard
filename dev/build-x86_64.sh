#!/bin/bash
# Builds a static x86_64 loader (musl, no dependencies on the target) inside
# the dev container and copies it to dist/xdp-loader-x86_64. Works on any
# host, including Apple Silicon: the embedded BPF object is architecture
# independent and the loader is cross compiled.
set -euo pipefail
cd "$(dirname "$0")/.."

dev/run.sh bash -c '
    CC_x86_64_unknown_linux_musl=$(command -v x86_64-linux-musl-gcc || command -v x86_64-linux-gnu-gcc) \
    RUSTFLAGS="-C linker=rust-lld" cargo build --release --target x86_64-unknown-linux-musl &&
    mkdir -p dist &&
    cp target/x86_64-unknown-linux-musl/release/xdp-loader dist/xdp-loader-x86_64'
ls -l dist/xdp-loader-x86_64
