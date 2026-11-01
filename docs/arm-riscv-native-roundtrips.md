# ARM64 and RV64 native round trips

The two new paths are:

```text
AArch64 leaf bytes -> Linux-layout eBPF -> AArch64 machine code
RV64 leaf bytes    -> Linux-layout eBPF -> RV64I machine code
```

Both execute directly on a matching little-endian Linux host. No WASM or
kernel BPF loader is used. Code generation is available on other hosts, but
`prepare()` rejects a target/host mismatch before making code callable.

## APIs and build configuration

```rust
use doublejit_vm::backend::{
    Arm64EbpfCompiler, RiscV64EbpfCompiler, EbpfNativeCompiler, NativeTarget,
};

// mov x0,40; add x0,x0,2; ret
let words = [0xd2800500_u32, 0x91000800, 0xd65f03c0];
let source: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
let bpf = Arm64EbpfCompiler::new().compile(&source)?;
let artifact = EbpfNativeCompiler::new(NativeTarget::Arm64)
    .with_native_ops(true)
    .compile(bpf.instructions())?;
let runtime = artifact.prepare()?; // requires AArch64 Linux
assert_eq!(runtime.execute_with_input(0)?, 42);
```

For RV64 use `RiscV64EbpfCompiler` and `NativeTarget::RiscV64`; the example's
source words are `0x02800513, 0x00250513, 0x00008067`. `RiscEbpfProgram` exposes
raw eBPF, byte encoding, and one source offset per emitted eBPF instruction.
Artifacts expose native bytes, target, required buffer length, and optimization
records. `EbpfNativeError` aliases the existing shared native-backend error.

The new `wasm` feature is enabled by default, preserving the preexisting build.
Use `--no-default-features --features ebpf` to exclude Wasmer/WASIX/Tokio and
build a native-only library or executable. This is essential on RV64. The
`x86_elf` feature enables WASM explicitly; the existing ELF backend is unchanged.
The older RISC-V `EbpfCompiler`/`AyaEbpfBuilder` still enforces its separate
one-source-instruction/one-BPF-instruction contract. These leaf frontends do
not claim that contract and do not silently relax its checks.

## Supported source subset

| Source | Implemented forms | Guest register contract |
| --- | --- | --- |
| AArch64 | MOVZ/MOVN/MOVK, MOV alias, ADD/SUB immediate and shifted register, non-inverting register AND/ORR/EOR, LSL/LSR/ASR/UBFX bitfield aliases, fixed-offset unsigned LDR/STR byte/half/word/dword, RET | x0..x8 / w0..w8; ZR for supported source operands; x20 reserved as immutable buffer base |
| RV64 | LUI, ADDI/XORI/ORI/ANDI, immediate shifts, ADD/SUB/AND/OR/XOR and register shifts, ADDIW and RV64 word add/sub/shifts, LB/LH/LW/LD/LBU/LHU/LWU, SB/SH/SW/SD, canonical RET | a0..a7 and t0; x0 is constant zero; s0 reserved as immutable buffer base |

Inputs are little-endian sequences of 4-byte instructions with one final RET.
ARM SP operations, flag-setting arithmetic, arbitrary source branches/calls,
unsupported registers, general ELF binaries, RV compressed instructions,
RV multiply/divide/vector/bit-manipulation extensions, ARM32 and RV32 source
modes are rejected. The source subset is deliberately narrower than the
native backend's accepted BPF subset; e.g. BPF conditional assignments are
supported by both emitters without claiming general source branch decoding.

The frontend maps the source return register (ARM x0, RV a0) to BPF r0, eight
other supported registers to r1..r8, and reserves r9 for lowering scratch.
Unlike a two-address-only frontend, it handles `dst == rhs` for noncommutative
three-address instructions by preserving the RHS before overwriting dst.
ARM W-register writes zero the upper 32 bits; RV64 *W instructions sign-extend
the 32-bit result. Signed RV loads also emit explicit sign extension. Source
x0/ZR is not confused with BPF r0. Source mappings include all expansions.

`execute_with_input(value)` initializes r0 and clears r1..r9.
`execute_with_memory(value, &mut buffer)` additionally binds r10 to the slice.
All loads/stores have nonnegative fixed offsets, checked before entering native
code. The source x20/s0 register is an ABI convention for that buffer, not a
native stack frame. Pointer arithmetic, pointer extraction and arbitrary host
addresses remain unavailable. Buffer size errors are returned before execution.

## Native emitters and optimization coverage

Both emitters accept the shared validated native-BPF subset: MOV, ADD, SUB,
AND, OR, XOR, logical/arithmetic shifts at both widths, fixed-offset loads and
stores, BE16/32/64 conversion, EXIT, NOP, and a supported conditional jump over
exactly one MOV. The existing x86 validator and liveness rules are shared.
Arithmetic right shift was added to all direct emitters and the WASM backend
so sign-extension expansions have consistent semantics.

| Operation | AArch64 emission | RV64I emission |
| --- | --- | --- |
| Expanded immediate rotate | ROR/EXTR alias, one instruction | Three shifts/OR operations with private scratch; no Zbb requirement |
| Shift-and-mask extraction | UBFM/UBFX | Shift pair where it reduces native code size |
| Shift-plus-add | ADD with shifted operand | Combined sequence only when it removes redundant width fixups |
| Immediate ALU chain | Fold equal-width ADD/AND/OR/XOR | Same folding; materialize larger immediates as necessary |
| Explicit 32-to-64 sign extension | SXTW | ADDIW |
| ALU32 then sign extension | Preserve W operation plus SXTW | Fuse into ADDW/SUBW/SLLW/SRLW/SRAW or immediate *W; logical ops followed by SEXT.W |
| Conditional assignment | CMP/TST + branch, optional CSEL | Correct forward branch fallback; RV64I has no general CMOV |
| Endian conversion | REV / masked REV16 | Integer shifts/masks; no Zbb REV8 assumption |
| Disjoint contiguous copy | LDP/STP pairs with dead-scratch and overlap checks | Scalar fallback |
| Explicit prefetch hint | PRFM when enabled | Validated no-op fallback; no Zicbop assumption |

Optimization enablement follows `NativeOpPolicy`; conditional selection and
prefetch remain opt-in. A target that lacks a profitable/supported replacement
retains ordinary code. RV rotate/extract/shift-add rewrites are accepted only
if the emitted sequence is smaller. Records contain the original bytecode;
they are not formal equivalence proofs. RV memory accesses use byte loads and
stores so arbitrary Rust slice alignment is supported even on cores that trap
misaligned wide accesses. This favors defined behavior over memory throughput.

The emitters use only ABI-volatile registers and preserve the return address.
ARM reserves x10 for the buffer and x11..x13 for scratch; RV retains a1 as the
buffer and uses t3..t6 privately. RV r0..r9 map to a0, a2..a7, t0..t2. The
caller-facing signature is `extern "C" fn(u64, *mut u8) -> u64`, hidden behind
the validated safe runtime. See the official
[AAPCS64 register contract](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).

Code is copied into writable memory, changed to RX, then instruction caches
are synchronized. ARM uses the toolchain's `__clear_cache`; RV uses the Linux
`riscv_flush_icache` syscall with flags zero, covering thread migration rather
than relying only on local `fence.i`. This follows the
[Linux RISC-V instruction-cache guidance](https://docs.kernel.org/arch/riscv/cmodx.html).

## Run on hardware

```bash
# On ARM64 Linux:
cargo run --release --no-default-features --features ebpf \
  --example risc-ebpf-native -- arm64
# On RV64 Linux:
cargo run --release --no-default-features --features ebpf \
  --example risc-ebpf-native -- riscv64
```

Either command prints `result: 42` after checking plain and optimized code with
three runtime inputs. On a nonmatching host it exports code without pretending
to execute it; supply an optional output directory to retain both stages.

`risc-native-bench` emits 128-round rotation, add-chain and word-operation
fixtures, checks independent Rust expected results, and records source/BPF/native
sizes. Timing is disabled by default. On physical target hardware, opt in with
a final iteration count:

```bash
cargo run --release --no-default-features --features ebpf \
  --example risc-native-bench -- arm64 target/arm-native 1000000
# Substitute riscv64 on an RV64 machine.
```

Timed mode prepares each mapping once, warms up, alternates nine samples,
checks checksums, and reports median hot execution time separately from code
size. It does not compare against an optimizing native compiler. Running that
mode under QEMU measures emulation, not hardware acceleration.

## Reproduce cross-ISA execution tests from x86

```bash
sudo apt-get install qemu-user gcc-aarch64-linux-gnu gcc-riscv64-linux-gnu
rustup target add aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu
./scripts/test_native_roundtrips.sh
```

The script configures Cargo runners, executes the target Rust tests, runs both
answer-42 examples, and exports verified benchmark artifacts without timing.
Old GNU RISC-V linkers cannot read modern Rust ISA attributes; the included
`riscv64-rust-linker.sh` uses Rust's bundled LLD while retaining cross-GCC's
sysroot/library selection. Adjust the runner sysroot paths if your distribution
installs cross libraries elsewhere. Generated instructions use RV64I, while
the surrounding Rust test executable targets `riscv64gc`.

The tests compare emitted plain and optimized code with an independent Rust
BPF interpreter, including all mapped registers, ALU32/64, register/immediate
operands, arithmetic shifts, all supported comparisons, aliasing, buffer
boundaries, unaligned slices, endian operations, overlap fallbacks, and word
sign-extension fusions. Frontend fixtures are additionally executed as their
original machine code with a controlled source-ABI wrapper, so encoder/decoder
agreement alone cannot make a wrong translation appear correct.

## Recorded validation, 2026-11-01

Both target suites and examples executed successfully under QEMU user 4.2.1
on the x86-64 workspace host. Each target has nine passing dedicated tests
(eight full-suite tests plus the added word-fusion test). Both examples return
42. Host regressions pass with `--features ebpf` (106 tests),
`--no-default-features --features ebpf` (83 tests), and `--all-features`
(109 tests, including the existing ELF path).
No physical ARM or RISC-V performance measurement was available.

| Target / 128-round fixture | Plain native bytes | Optimized native bytes |
| --- | ---: | ---: |
| ARM64 rotate64 | 2608 | 1072 |
| ARM64 add64 | 560 | 52 |
| ARM64 word32 | 560 | 52 |
| RV64 rotate64 | 2600 | 2088 |
| RV64 add64 | 552 | 52 |
| RV64 word32 | 2600 | 552 |

[Recorded CSV](../bench-results/arm-riscv-roundtrips.csv) labels execution as
QEMU and intentionally leaves timing columns empty. These demonstrate code
reduction and execution equivalence, not a claimed native speedup.
