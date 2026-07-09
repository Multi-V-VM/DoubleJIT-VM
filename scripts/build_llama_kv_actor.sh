#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out_dir=${1:-"$root/target/llama-kv-actor"}
x86_compiler=${X86_64_CC:-x86_64-linux-gnu-gcc}
arm_compiler=${AARCH64_CC:-cc}
actor="$root/actors/llama_kv_copy_actor.c"
entry="$root/actors/actor_start_x86_64.S"

command -v "$x86_compiler" >/dev/null || {
    echo "missing x86 compiler: $x86_compiler" >&2
    exit 1
}
command -v "$arm_compiler" >/dev/null || {
    echo "missing AArch64 compiler: $arm_compiler" >&2
    exit 1
}

mkdir -p "$out_dir"

"$x86_compiler" -O0 -fno-pie -no-pie -ffreestanding -fno-builtin -nostdlib \
    -Wl,-e,_start -Wl,--build-id=none "$entry" "$actor" \
    -o "$out_dir/llama-kv-copy-actor.x86_64"

"$arm_compiler" -O2 -fno-pie -no-pie "$actor" \
    -o "$out_dir/llama-kv-copy-actor.aarch64"

file "$out_dir/llama-kv-copy-actor.x86_64" "$out_dir/llama-kv-copy-actor.aarch64"
