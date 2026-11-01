#!/usr/bin/env bash
# Old GNU ld cannot merge the ISA attributes emitted by current Rust. Use the
# LLD shipped with Rust while retaining the cross GCC driver/sysroot libraries.
set -euo pipefail
risc_sysroot=$(rustc --print sysroot)
risc_host=$(rustc -vV | sed -n 's/^host: //p')
risc_linkers="$risc_sysroot/lib/rustlib/$risc_host/bin/gcc-ld"
exec riscv64-linux-gnu-gcc -B"$risc_linkers" -fuse-ld=lld "$@"
