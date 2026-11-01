# Kops-inspired x86 -> eBPF -> x86 acceleration

**Historical rotate-only snapshot.** The backend has since added the remaining
six families and ALU folding. See [current implementation](kops-native-ops-expanded.md).
The scope statements and measurements below describe the earlier version;
in particular, the former add-only control is now optimized.

This experiment implements immediate-rotate recovery from
[Kops: Safely Extending the eBPF Compilation Pipeline with Native Operations,
arXiv:2606.24213v1](https://arxiv.org/html/2606.24213v1), especially §4.1,
§5/Table 3 and §6.2. The supplied paper is `2606.24213v1.pdf` at the repository
root. It motivates retaining a vanilla-eBPF sequence while choosing a smaller
native implementation, and checking that discarded temporary registers are
dead. This repository implements that idea in its userspace JIT.

## Implemented path

```text
x86 SHL/SHR/OR sequence
    -> ordinary Linux-layout eBPF MOV/LSH/RSH/OR
    -> validate the entire program
    -> optionally recognize the rotate and check liveness
    -> native x86-64 ROL
    -> prepare executable memory once, execute repeatedly with runtime inputs
```

The plain emitter remains available and is the default. Enable recovery with
`EbpfX86Compiler::new().with_native_ops(true)`. Each artifact exposes
`fusions()`, including the original four eBPF instructions, source instruction
index, width, count, destination, and temporary. No caller-supplied native
machine code or rewrite metadata is accepted by the safe library API.

For width `w` of 32 or 64, the recognized sequence is:

```text
t = d
d <<= k
t >>= w-k
d |= t
```

For `0 < k < w`, its destination equals `rotate_left(d, k)` at width `w`.
All four instructions must use the same width and the specified register
relationships; `t != d`. Backward liveness analysis must show that `t` is
dead after the region. The runtime exposes only the returned r0, so the final
live set is `{r0}`. If the temporary is read later, this implementation retains
the original four instructions. This rule would need revisiting for an API
that exposes the complete final register file.

Validation precedes recognition, including reserved fields, register bounds,
legal immediate shift counts, and exactly one terminal EXIT. No jumps, memory
accesses, helper calls, or alternate entries can cross a candidate region.
ALU32 writes zero-extend; ALU64 arithmetic wraps. The x86 frontend masks shift
counts as x86 does before lowering them to eBPF. Flags are outside the frontend's
existing register-only contract.

The experiment covers immediate left rotations only. It does not implement
the paper's variable rotations, kernel kfunc/sidecar ABI, module registration,
kernel verifier, all seven EInsn families, or Lean proofs. The stored
`proof_sequence` is inspectable bytecode; it is not a formal proof certificate.

## Use the optimized runtime

```rust
use doublejit_vm::backend::{EbpfX86Compiler, X86EbpfCompiler};
use doublejit_vm::X86Mode;

// mov rcx,rax; shl rax,13; shr rcx,51; or rax,rcx; ret
let source = [0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe0, 13,
              0x48, 0xc1, 0xe9, 51, 0x48, 0x09, 0xc8, 0xc3];
let bpf = X86EbpfCompiler::new(X86Mode::X86_64).compile(&source)?;
let native = EbpfX86Compiler::new()
    .with_native_ops(true)
    .compile(bpf.instructions())?;
assert_eq!(native.fusions().len(), 1);
let runtime = native.prepare()?;
let input = 0x0123_4567_89ab_cdef_u64;
assert_eq!(runtime.execute_with_input(input)?, input.rotate_left(13));
```

`execute_with_input` initializes guest r0/RAX from one scalar argument, with
r1..r9 zero. `execute()` remains equivalent to input zero. This is a defined
leaf-function convention, not a general x86 calling convention. The generated
code obeys the host System V ABI and uses an owned read/execute mapping.

## Reproduce

```bash
cargo test --features ebpf
cargo build --release --features ebpf --example x86-ebpf-x86-bench
taskset -pc $$  # choose an allowed CPU
taskset -c 2 target/release/examples/x86-ebpf-x86-bench 1000000 9 target/kops-poc
objdump -D -b binary -m i386:x86-64 target/kops-poc/rotate64.optimized.bin
```

Arguments are calls per sample, an odd sample count from 3 to 101, and an
output directory. The executable exports input x86, ordinary eBPF, plain and
optimized native bytes, fusion records, `summary.csv`, and `samples.csv`.
The disassembly contains 128 ROL instructions in each optimized rotate fixture.

Each invocation performs 128 rounds of rotate-then-add, with rotate counts
5/13/17/23 repeated, and addition constant `0x13579bdf`. Inputs are runtime
values, dependent on the previous invocation's result and the iteration
number. This measures a dependent compute workload, not packet throughput.
There are four paths with the same observable result:

1. Original expanded x86 executed directly, with a minimal input ABI wrapper.
2. The existing per-instruction eBPF-to-x86 emitter.
3. The same emitter with rotate recovery enabled.
4. A release-compiled Rust reference using `rotate_left`.

Every path runs 2,000 warmup calls. Sample order rotates among the four paths
to reduce order bias. All paths receive the same input chain, and their final
checksums must match. The report uses median hot-call latency; x86 decoding,
JIT compilation, mapping, and permission changes stay outside timed execution.
Those setup costs are separately reported as one observation per path, not a
statistically robust compilation benchmark. Rust compilation happens during
the release build; its CSV code size and setup time are zero sentinels, not
claims of a zero-size function or free compilation.

## Measured result

Measured 2026-11-01 on an Intel Xeon Gold 5418Y, x86-64 Linux `7.3.0+`,
Rust `1.96.0`, CPU affinity 2, release build, 9 samples of 1,000,000 calls.
The recorded run started after compilation and regression tests finished.
Frequency was not locked. In particular, the rotate64 samples include slower
outliers; retain the raw ranges when interpreting the medians.

| Workload | Original x86 ns/call | Plain JIT ns/call | Native ops ns/call | Rust reference ns/call | Speedup vs plain | Speedup vs original |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rotate64 | 122.49 | 121.55 | 67.68 | 67.67 | 1.796x | 1.810x |
| rotate32 | 122.52 | 121.54 | 67.68 | 67.67 | 1.796x | 1.810x |
| add64 control | 33.97 | 33.97 | 33.97 | 1.58 | 1.000x | 1.000x |

Each rotate fixture fuses 128 regions. Native code shrinks from 2,720 to 1,440
bytes for rotate64 (47.1%), and from 2,080 to 1,184 bytes for rotate32 (43.1%).
The add-only control has zero matches and identical plain/optimized machine
code, 928 bytes. Its Rust reference can collapse the constant-add chain; the
large gap there demonstrates an optimization this JIT does not implement.

Inspectable measurements:
[summary](../bench-results/kops-native-ops-summary.csv) and
[all 108 samples](../bench-results/kops-native-ops-samples.csv).
The raw data includes min/max, per-path checksums, code sizes, fusion counts,
and separately observed setup costs.

The measured gain applies to intentionally expanded rotate-heavy code. It
recovers approximately the native compiler's performance for this workload;
it does not establish a gain over already optimized x86 containing ROL, general
x86 applications, or production packet processing. The paper's kernel results
are not reproduced here. Repeated execution is necessary to amortize setup;
calling `prepare()` inside the measured hot loop would discard that benefit.

## Correctness checks

`cargo test --features ebpf` passes 85 tests, including six new native-operation
tests. For both widths, every legal nonzero count is checked across all ten
mapped destination registers (including high registers and scratch r0) with
boundary and deterministic pseudorandom inputs: 63,920 input cases, each checked
against Rust for both plain and optimized JITs. Additional tests cover live
temporaries, aliases, mixed widths, wrong shift pairs, invalid encodings,
missing/trailing EXIT, x86 shift masking, and agreement with the WASM backend.
The benchmark also checks all four paths against edge inputs and verifies
every measured checksum. These are differential tests, not exhaustive proofs.
