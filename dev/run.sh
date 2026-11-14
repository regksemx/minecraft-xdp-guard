#!/bin/bash
# Runs a command inside the Linux build/test container (needed on macOS, and
# handy on Linux to keep the toolchain off the host). Without arguments it
# runs the whole test suite.
#
#   dev/run.sh                      # all tests
#   dev/run.sh cargo build --release
#   dev/run.sh dev/kernel-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if ! docker image inspect xdp-dev >/dev/null 2>&1; then
    docker build -t xdp-dev dev
fi
if [ $# -eq 0 ]; then
    set -- dev/test.sh
fi
# privileged: loading BPF programs and creating network namespaces
exec docker run --rm --privileged \
    -v "$PWD":/src -v xdp-cargo:/root/.cargo/registry -v xdp-target:/src/target \
    xdp-dev "$@"
