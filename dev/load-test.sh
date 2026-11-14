#!/bin/bash
# Load test with the real loader, see dev/e2e/load.py: spoofed floods from
# several threads while real clients keep playing. Expects the release build
# (cargo build --release) and root.
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
clang -Wall -Wextra -O2 dev/e2e/flood.c -o "$out/flood" -lpthread
python3 dev/e2e/load.py "${1:-target/release/xdp-loader}" "$out/flood"
