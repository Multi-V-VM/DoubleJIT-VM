#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact="$root/target/x86_64-test-binaries/test_binaries/arithmetic_test/compiled_test_arithm"

"$root/scripts/build_x86_64_test_binaries.sh"
cd "$root"
cargo run --features x86_elf --example x86-elf-wasm-bench -- "$artifact" 50 1000 | \
    tee "$root/target/x86_64-test-binaries/arithmetic-benchmark.txt"
