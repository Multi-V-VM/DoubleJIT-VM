#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out_dir=${1:-"$root/target/x86_64-test-binaries"}
compiler=${X86_64_CC:-x86_64-linux-gnu-gcc}
stubs="$root/scripts/x86_64_host_stubs.S"
manifest="$out_dir/manifest.tsv"

command -v "$compiler" >/dev/null || {
    echo "missing $compiler; install gcc-x86-64-linux-gnu" >&2
    exit 1
}

mkdir -p "$out_dir"
printf 'source\tartifact\tstatus\tdetail\n' > "$manifest"

# These are all C test programs with a main() entry point. The RISC-V-only
# assembly fixtures and rv64minilibc.c are intentionally reported separately:
# compiling their RISC-V inline assembly as x86_64 would not test this path.
sources=(
    test_binaries/add_test/main.c
    test_binaries/archive/hello_world.c
    test_binaries/archive/io_test.c
    test_binaries/arithmetic_test/compiled_test_arithm.c
    test_binaries/benchmarks/GCBench.c
    test_binaries/benchmarks/mandelbrot.c
    test_binaries/conformance/tst-ieee754.c
    test_binaries/float_test/f_arithm_test.c
    test_binaries/float_test/f_arithm_test_stdlib.c
    test_binaries/float_test/float_test.c
    test_binaries/fstat_test/test_fstat.c
    test_binaries/sort_example/merge_sort.c
    tests/x86_elf_sse_avx_memory.c
)

for source in "${sources[@]}"; do
    artifact="$out_dir/${source%.c}"
    mkdir -p "$(dirname "$artifact")"
    log="$artifact.build.log"
    flags=()
    if [[ "$source" == "tests/x86_elf_sse_avx_memory.c" ]]; then
        flags+=(-mavx)
    fi
    if "$compiler" -O0 -fno-pie -no-pie -ffreestanding -fno-builtin -nostdlib "${flags[@]}" \
        -Wl,-e,main "$root/$source" "$stubs" -o "$artifact" >"$log" 2>&1; then
        printf '%s\t%s\tbuilt\tfreestanding x86_64 ELF with translator hostcall stubs\n' \
            "$source" "${artifact#$root/}" >> "$manifest"
    else
        printf '%s\t%s\tbuild-failed\t%s\n' \
            "$source" "${artifact#$root/}" "$(tail -n 1 "$log" | tr '\t' ' ')" >> "$manifest"
    fi
done

while IFS= read -r source; do
    printf '%s\t-\tnot-built\tRISC-V assembly source; no direct x86_64 translation unit\n' "$source" >> "$manifest"
done < <(cd "$root" && find test_binaries -type f -name '*.S' | sort)
printf '%s\t-\tnot-built\tRISC-V syscall support source without main(); replaced by hostcall ABI for x86_64 fixtures\n' \
    'test_binaries/riscvminilib/rv64minilibc.c' >> "$manifest"

cat "$manifest"
