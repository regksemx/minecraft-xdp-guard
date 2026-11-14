#!/bin/bash
# Builds the BPF object and runs xdp/tests/kernel_test.c against the running
# kernel (BPF_PROG_TEST_RUN, nothing is attached). Needs root, clang, libbpf
# and bpftool; see dev/run.sh for a container that has them.
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

clang -Wall -Wextra -Wno-language-extension-token -O2 -g -target bpf -mcpu=v3 \
    -c xdp/minecraft_filter.c -o "$out/minecraft_filter.o"
bpftool gen skeleton "$out/minecraft_filter.o" name minecraft_filter > "$out/minecraft_filter.skel.h"
clang -Wall -Wextra -O2 -g -I"$out" xdp/tests/kernel_test.c -o "$out/kernel_test" -lbpf -lelf -lz
# `dev/kernel-test.sh bench` measures the cost per packet instead
"$out/kernel_test" "$@"
