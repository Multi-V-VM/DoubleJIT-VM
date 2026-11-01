#!/usr/bin/env bash
# Execute the Rust JIT runtime and the original source fixtures under both ISAs.
# Requires rustup targets, qemu-user and cross GCC toolchains; see docs.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -L /usr/aarch64-linux-gnu"
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="$PWD/scripts/riscv64-rust-linker.sh"
export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv64 -L /usr/riscv64-linux-gnu"
for native_target in aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu; do
    if [[ $native_target == aarch64-* ]]; then native_name=arm64; else native_name=riscv64; fi
    cargo test --no-default-features --features ebpf --target "$native_target" --test risc_native_roundtrip
    cargo run --no-default-features --features ebpf --target "$native_target" --example risc-ebpf-native -- "$native_name" "target/native-roundtrips/$native_name/answer42"
    # QEMU validates semantics/code size only. No simulated speedup is reported.
    cargo run --no-default-features --features ebpf --target "$native_target" --example risc-native-bench -- "$native_name" "target/native-roundtrips/$native_name/bench"
done
