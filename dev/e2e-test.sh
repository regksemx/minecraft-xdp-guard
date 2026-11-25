#!/bin/bash
# End-to-end tests with the real loader, see dev/e2e/run.py and
# dev/e2e/telemetry.py. Expects the release build (cargo build --release)
# and root.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 dev/e2e/run.py "${1:-target/release/xdp-loader}"
python3 dev/e2e/telemetry.py "${1:-target/release/xdp-loader}"
