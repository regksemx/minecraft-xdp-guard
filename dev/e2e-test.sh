#!/bin/bash
# End-to-end test with the real loader, see dev/e2e/run.py. Expects the
# release build (cargo build --release) and root.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 dev/e2e/run.py "${1:-target/release/xdp-loader}"
