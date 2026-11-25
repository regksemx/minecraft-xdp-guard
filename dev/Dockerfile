# Build and test environment: clang/libbpf for the BPF object, rust for the
# loader, bpftool for the skeleton of the in-kernel tests, python and iproute2
# for the end-to-end test. Build it with dev/run.sh.
FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      clang llvm lld libbpf-dev libelf-dev zlib1g-dev bpftool linux-libc-dev make gcc libc6-dev \
      ca-certificates curl pkg-config iproute2 python3 procps && \
    rm -rf /var/lib/apt/lists/*
# `clang -target bpf` does not search the multiarch include directory, where
# Debian keeps asm/types.h (gcc-multilib does the same on x86)
RUN ln -s /usr/include/$(gcc -print-multiarch)/asm /usr/include/asm
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH
# ASan/UBSan runtime for the native C unit tests
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libclang-rt-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
# static x86_64 build from any host, see dev/build-x86_64.sh; the C compiler
# is for the bits of ring (rustls, the telemetry reports) written in C
RUN rustup target add x86_64-unknown-linux-musl && rustup component add rustfmt clippy
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross && \
    rm -rf /var/lib/apt/lists/*
