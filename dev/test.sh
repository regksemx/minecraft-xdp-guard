#!/bin/bash
# The whole test suite: Rust and native C unit tests, the in-kernel tests of
# the BPF program and the end-to-end test with the real loader. Needs root
# on Linux; dev/run.sh runs it in a container.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== unit tests (cargo test)"
cargo test --release

echo "== in-kernel tests (BPF_PROG_TEST_RUN)"
dev/kernel-test.sh

echo "== end-to-end test (loader + XDP on a veth pair)"
cargo build --release
dev/e2e-test.sh
