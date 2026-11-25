#!/bin/bash
# Records the attack timeline of dev/bench/attack.py (with and without the
# filter) and the cost per packet of `dev/kernel-test.sh bench` into
# dev/bench/out/, the input of dev/bench/charts.py. Expects the release build
# (cargo build --release) and root.
set -euo pipefail
cd "$(dirname "$0")/../.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
clang -Wall -Wextra -O2 dev/e2e/flood.c -o "$out/flood" -lpthread
mkdir -p dev/bench/out
python3 dev/bench/attack.py "${1:-target/release/xdp-loader}" "$out/flood" dev/bench/out "${@:2}"
dev/kernel-test.sh bench | tee dev/bench/out/bench.txt
