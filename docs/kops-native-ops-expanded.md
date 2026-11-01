# Native-operation coverage and profitability

This implements bounded userspace patterns for all seven EInsn families in
[Kops §5/Table 3](https://arxiv.org/html/2606.24213v1), plus immediate-ALU folding.
The paper's §6.2 motivates temporary liveness checks; §7.3 motivates family
selection instead of indiscriminately enabling every match. These are native
JIT transformations over ordinary Linux-layout eBPF, not the kernel Kops ABI,
its verifier integration, or formal proofs.

## Implemented forms

| Family | Recognized form | Native emission / requirements |
| --- | --- | --- |
| Rotate | MOV scratch,dst; two complementary immediate shifts; OR, equal widths, dead scratch | ROL or ROR, 32/64 bits, counts 1..width-1 |
| Select | One supported conditional jump skipping exactly one MOV | CMP/TEST + inverse CMOV; signed/unsigned/equality/bit-test conditions; branch and move widths independent |
| Bit extract | Immediate SHR followed by low-contiguous-mask AND | BMI1 BEXTR; retain ordinary sequence without BMI1; reuse private control register until clobbered |
| Endian load | Fixed-offset LDX32/64 followed by matching BE conversion | MOVBE with feature detection; retain load + BSWAP without MOVBE |
| Prefetch | Canonical JA +0 with explicit validated buffer-offset hint | PREFETCHT0; requires explicit policy enablement |
| Bulk copy | Contiguous alternating LDX64/STX64 pairs, same dead scratch, even pair count | Unaligned SSE2 MOVDQU loads/stores in 16-byte chunks; disjoint complete intervals required |
| Address calculation | Immediate LSH 0..3; ADD another register; optional ADD immediate | LEA, modulo 32/64 bits; destination/base alias falls back |
| ALU folding (additional) | Consecutive same-width, same-destination immediate ADD/AND/OR/XOR | One equivalent ALU instruction; ADD64 folds only while the combined immediate fits signed 32 bits |

The original left-rotate `fusions()` API is retained. `optimizations()` covers
all families, recording each original instruction region and its operation
kind. The stored `proof_sequence` is inspectable ordinary bytecode, not a
machine-checked proof. Register shifts are also implemented in the ordinary
emitter, including RCX source/destination aliases, but variable rotate patterns
are not fused in this version. Prefetch placement is explicit, not guessed.

The frontend now accepts register ADD/SUB/AND, immediate AND/SUB, CL shifts,
BSWAP, bounded loads/stores, PREFETCHT0, and CMP + short Jcc over one MOV.
Every family has an x86-source-to-eBPF-to-native regression fixture. Direct
LDX/STX supports widths 1/2/4/8; the frontend supports MOV32/64 buffer transfers
and MOVZX byte/word loads. The WASM backend supports the extended ALU operations,
but not the new native backend's buffer or conditional-assignment ABI.

## Execution contract and validation

`execute_with_input(value)` supplies r0/RAX and clears r1..r9.
`execute_with_memory(value, &mut buffer)` additionally supplies an immutable
buffer base through reserved eBPF r10. The x86 frontend denotes that base using
RBP exclusively in `[rbp + nonnegative displacement]` memory operands. This
is a leaf-test ABI, not an emulated native stack or a kernel BPF stack.

Only fixed displacements are allowed; arithmetic on r10, copying r10 into
another register, indexed addressing, negative offsets, arbitrary pointers,
helper calls, and arbitrary control flow are rejected. Validation computes
`artifact.required_memory()`. Every invocation checks the exclusive mutable
slice length before entering generated code. Native reads/writes, including
SIMD-widened copies and prefetch addresses, stay inside that proven range.
The host buffer base and scratch registers are private R12/R13; both and RBX
are saved/restored according to the System V ABI. Code uses RX mappings after
preparation and can be called repeatedly.

Conditional control flow is limited to a forward jump over one MOV. The
compiler treats the branch and its MOV as one region, so rewrites cannot start
inside a skipped instruction or straddle a branch. Liveness unions both arms.
A conditional 32-bit MOV must preserve the original destination's high bits
when skipped: the emitter zero-extends its candidate into private scratch and
uses a 64-bit CMOV. Comparisons can independently be 32 or 64 bits.

All bytecode is validated before any optimization. Bulk copying requires the
entire recognized source/destination intervals to be disjoint, and the removed
scalar scratch must be dead. An overlapping run is retained in full, including
any locally disjoint tail. No-op prefetch hints must reference canonical JA +0
instructions; duplicate or out-of-range sites fail validation.

## Policies and API

```rust
use doublejit_vm::backend::{EbpfX86Compiler, NativeOpPolicy};

// Native operations enabled, but predictable-branch and hot-data regressions
// are avoided by leaving conditional selection and prefetch opt-in.
let conservative = EbpfX86Compiler::new().with_native_ops(true);

// Opt into conditional selection for a branch-unpredictable workload.
let conditional = EbpfX86Compiler::new().with_policy(NativeOpPolicy {
    select: true,
    ..NativeOpPolicy::default()
});

// Diagnostic policy, not a promise that all replacements improve performance.
let all = EbpfX86Compiler::new().with_policy(NativeOpPolicy::all());

// Exercise fallbacks even on BMI1/MOVBE machines.
let portable = all.without_optional_isa();
```

`EbpfX86Compiler::new()` remains the plain emitter. Each policy boolean can be
changed independently. `compile_program(&x86_bpf_program)` preserves explicit
prefetch hints from the frontend. `compile(instructions)` has no prefetch hints
and leaves the corresponding NOPs alone. Direct BPF callers can use
`compile_with_prefetch_hints(instructions, &[(site_index, buffer_offset)])`.

Feature detection prevents emitting unsupported BMI1/MOVBE instructions.
Generated bytes are inspectable, but artifacts are not a cross-host code cache:
recompile for a different host's ISA. SIMD copying requires only x86-64's SSE2.
A `prepare()` runtime owns its mapping; reuse it instead of preparing per call.

## Reproduce

```bash
cargo test --features ebpf
cargo test --release --features ebpf --test x86_all_native_ops
cargo build --release --features ebpf --example x86-native-ops-bench
# Substitute a CPU allowed by your affinity mask.
taskset -c 2 target/release/examples/x86-native-ops-bench 200000 9 target/all-native-ops
objdump -D -b binary -m i386:x86-64 target/all-native-ops/extract.optimized.bin
```

The benchmark runs 128 rounds per call, except that a bulk-copy round contains
eight qword copies (64 bytes). It measures 9 interleaved samples of 200,000 calls
per path after 2,000 warmup calls. A deterministic xorshift input generator and
`black_box` prevent constant-input benchmarking. The same generator, calling
wrapper, memory size, and checksum work are used for all paths. Initialization,
translation, compilation, and memory preparation are outside the hot timer;
setup costs are separately recorded as individual observations, not medians.

All fixtures are actual x86 byte sequences lowered through the frontend.
Before timing, each path is compared against an independent Rust eBPF
interpreter on boundary inputs and complete buffer contents. Measured batches
must agree on their output checksum and final buffer. Raw samples and source,
eBPF, plain/all/default native bytes, and optimization records are exported.

## Measured results

Recorded 2026-11-01, Intel Xeon Gold 5418Y, Linux 7.3.0+, Rust 1.96.0, release
build, CPU affinity 2, BMI1/MOVBE available. Compilation/tests finished before
the measured run. CPU frequency is not locked; these are synthetic workload
medians, not production throughput claims. The 1 KiB buffer remains hot, so
the prefetch workload intentionally does not establish a cold-memory benefit.

Speedup is plain-JIT median divided by the selected-policy median.

| Workload | Plain ns/call | All families ns/call | All-family speedup | Default-policy speedup |
| --- | ---: | ---: | ---: | ---: |
| Right rotation | 251.41 | 117.94 | 2.132x | 2.135x |
| Bit extract | 156.60 | 152.11 | 1.030x | 1.029x |
| LEA | 93.56 | 31.49 | 2.971x | 2.972x |
| Select, predictable | 19.72 | 90.18 | 0.219x | 1.010x |
| Select, unpredictable | 492.38 | 132.51 | 3.716x | 1.004x |
| Endian load | 33.71 | 33.71 | 1.000x | 1.000x |
| Bulk copy | 136.49 | 102.41 | 1.333x | 1.333x |
| Prefetch, hot buffer | 23.67 | 26.47 | 0.894x | 0.999x |
| Immediate ALU chain | 8.25 | 3.16 | 2.613x | 2.613x |

The default policy produces byte-identical plain code for select and prefetch
fixtures; the small default-policy differences there are measurement variation.
Conditional selection is worth opting into for the unpredictable fixture, but
not for the predictable fixture. The bit-extract improvement is small enough
to treat cautiously. Endian fusion reduced the instruction sequence without
measurably improving this load-heavy test. The old add-only negative control
is now an ALU-folding workload and benefits accordingly.

See [summary CSV](../bench-results/kops-all-native-ops-summary.csv) and
[all 243 samples](../bench-results/kops-all-native-ops-samples.csv). Raw path
indices are 0=plain, 1=all families, 2=default policy. Re-run on the intended
workload before selecting aggressive policies. This suite compares backends
for the same bytecode; it does not show speedup over an optimizing native
compiler or reproduce the paper's kernel/application measurements.

## Verification and remaining boundaries

The complete `--features ebpf` suite passes 97 tests. The new test module has
12 tests covering every family, widths/counts, all mapped registers, aliases,
all supported condition codes, buffer bounds, exact memory effects, overlaps,
live temporaries, CPU fallbacks, extraction-control reuse and invalidation,
malformed regions, policy disabling, and end-to-end x86 fixtures. Its reference
interpreter uses ordinary Rust arithmetic/slices independently of the native
emitter. Release tests also exercise the generated ABI under optimized callers.
These tests provide evidence, not an exhaustive or formal equivalence proof.

The implementation deliberately covers bounded forms. It does not add arbitrary
x86 ELF execution to this path, general loops/jumps, unbounded memory,
variable-rotation fusion, automatic prefetch selection, kernel Kops loading,
whole-program native replacement, or Lean proofs. Existing ELF/WASM execution
remains a separate backend.
