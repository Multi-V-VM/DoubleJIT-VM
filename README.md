# Multi V Virtual Machine
MVVM is a double JIT VM from RiscV assembly or elf to wasm, with all linux implemented. Here 'V' can be translated into multiple meanings: RiscV, Variable Level, etc. 
## Design Doc
```bash
riscv binary [compile phase 1] wasm bytecode loaded [compile phase 2] native code -> executing
```
### Frontend 
Parse the elf, map the page to a linear memory defined in WebAssembly, interpret code with code cache. Refer a lot from [ria-jit](https://github.com/ria-jit/ria-jit), [riscv-jit-emulator](https://github.com/programmerjake/riscv-jit-emulator), [ckb-vm](https://github.com/nervosnetwork/ckb-vm/) and [valheim](https://github.com/imkiva/valheim/)
### Middleend
From riscv to WebAssembly. use the wasmtime currently, implement a LLVMOpaqueExecutionEngine/FastJIT like JIT interface and apply the runtime using (WASIX)[https://github.com/wasix-org/wasix-libc]. map the register to stack based WebAssembly Model.
### eBPF compiler branch
The `ebpf-compiler` branch adds a feature-gated RISC-V to eBPF path next to the WebAssembly path:

```bash
cargo run --features ebpf --example riscv-ebpf-compiler -- <path-to-riscv-elf> [output-ebpf.bin]
```

This path uses Aya-rs' `aya-obj` `bpf_insn` bindings and follows the verification discipline used in `../Movable/`: lowering emits explicit obligations, then a verifier checks that each accepted RISC-V instruction maps to exactly one eBPF instruction. Because eBPF is a two-address ISA with a small register file, the compiler rejects instructions that need extra moves, unsupported registers, sign-extension fixups, indirect control flow, or syscall ABI bridging.

The eBPF ReJIT path commits replacements through `EbpfRejitCache`: it compiles a candidate block, verifies the one-to-one compilation proof, runs a conservative kernel-verifier preflight (exit, jump bounds, no unproved backward jumps, and no memory access without pointer provenance), then atomically replaces the cached block only if all checks pass.

### x86/x64 -> eBPF -> WebAssembly

The `ebpf-compiler` branch also includes an executable cross-architecture path:

```text
x86 or x86_64 machine code -> Linux eBPF bpf_insn -> WebAssembly -> Wasmer native code
```

It is useful for exercising the eBPF representation on an AArch64 host without requiring an x86 host. The frontend decodes a deliberately small, straight-line subset of x86 and x86_64: register-only `mov`, immediate `add`, register `xor`/`or`, immediate `shl`/`shr`, and `ret`. The WASM backend remains arithmetic-only; bounded buffer operations and conditional assignments are supported by the direct x86 backend below. Calls, syscalls, and arbitrary control flow remain unsupported. x86_64 immediates must fit in the eBPF ALU immediate range.

Run the end-to-end examples with:

```bash
cargo run --features ebpf --example x86-ebpf-wasm -- x86_64
cargo run --features ebpf --example x86-ebpf-wasm -- x86
```

Both examples compile a small leaf function that returns `42`. The eBPF-to-WASM lowering preserves the zero-extension semantics of 32-bit x86 operations, then uses the existing Wasmer backend to compile and execute the generated WASM on the current host architecture.

Verify the feature-gated paths with:

```bash
cargo test --features ebpf
```

### x86/x64 -> eBPF -> x86-64 PoC (direct JIT)

The `ebpf` feature also provides a direct userspace native backend:

```text
x86 / x86_64 leaf machine code -> Linux-layout eBPF bpf_insn -> x86-64 machine code -> execution
```

`X86EbpfCompiler` decodes the input and `EbpfX86Compiler` consumes only the
resulting eBPF instructions. This path does not go through WASM or load a BPF
program into the kernel. Native execution currently requires x86-64 Linux;
other hosts can generate and inspect the x86-64 bytes.

```bash
cargo run --features ebpf --example x86-ebpf-x86 -- x86_64
cargo run --features ebpf --example x86-ebpf-x86 -- x86
# Save input machine code, eBPF bytecode, and generated x86-64 machine code.
cargo run --features ebpf --example x86-ebpf-x86 -- x86_64 target/x86-ebpf-x86
objdump -D -b binary -m i386:x86-64 target/x86-ebpf-x86/output-x86_64.bin
cargo test --features ebpf --test x86_ebpf_x86
```

Both examples return `42` and print the bytecode at each stage. The native
backend accepts canonical eBPF ALU32/ALU64 `MOV`, `ADD`, `SUB`, `AND`, `XOR`,
`OR`, and immediate/register `LSH`/`RSH`, followed by `EXIT`. It additionally
supports fixed-offset buffer loads/stores, endian conversion, and a conditional
jump over exactly one register/immediate MOV. ALU32 results are zero-extended and ALU64 immediates
are sign-extended; arithmetic wraps at its operand width. Registers r0..r9
start at zero with `execute()`. `execute_with_input(value)` initializes r0 to a
runtime input and resets r1..r9; the result is r0 as a `u64` bit pattern.
The generated prologue/epilogue preserves the System V host ABI. `prepare()`
copies code into writable memory and then changes it to read/execute;
the returned runtime owns that mapping and supports repeated calls.

`execute_with_memory(input, &mut buffer)` supplies a bounded buffer. Guest r10
is an immutable buffer base, and every access uses a validated nonnegative
fixed offset. The x86 frontend maps `[rbp + displacement]` to that buffer ABI;
this is not a native stack frame or the Linux kernel BPF stack convention.
Too-small buffers fail before execution. Arbitrary pointers, arbitrary jumps,
loops, helpers, calls, and full ELF execution remain unsupported. CMP/Jcc is
accepted only as a conditional assignment over one MOV; flags are not exposed.

#### Kops-inspired native-operation acceleration

All seven hardware-idiom families from
[Kops, arXiv:2606.24213v1](https://arxiv.org/abs/2606.24213v1) now have bounded
userspace implementations: immediate rotate (left/right), conditional select,
bit extract, endian-load fusion, explicit prefetch, non-overlapping bulk copy,
and LEA. The backend also folds consecutive immediate ADD/AND/OR/XOR operations
and reuses BEXTR control constants. Complete validation happens before matching;
`artifact.optimizations()` records each replacement and its original bytecode.
`fusions()` retains the earlier left-rotate inspection API.

```rust
// Conservative policy: conditional select and prefetch remain opt-in.
let compiler = EbpfX86Compiler::new().with_native_ops(true);
// Explicit all-family experiment (can regress on some workloads).
let compiler = EbpfX86Compiler::new().with_policy(NativeOpPolicy::all());
```

Use `compile_program(&bpf)` to retain the x86 frontend's explicit prefetch hints.
`compile(bpf.instructions())` still works, treating prefetch proof NOPs as NOPs.
BMI1 and MOVBE require host feature detection; `.without_optional_isa()` forces
portable fallback. Every policy family is independently configurable.

```bash
cargo test --features ebpf
cargo build --release --features ebpf --example x86-native-ops-bench
# Pick a CPU permitted by taskset -pc $$.
taskset -c 2 target/release/examples/x86-native-ops-bench 200000 9 target/all-native-ops
```

The benchmark compares plain JIT, all-family policy, and conservative policy
using runtime inputs, warmup, interleaved samples, medians, and independently
checked return values and complete memory contents. It exports source x86,
eBPF, native code, replacement records, setup costs, and raw CSV samples.
See [current coverage and measured results](docs/kops-native-ops-expanded.md).
The [earlier rotation experiment](docs/kops-native-ops-poc.md) is retained as a
historical snapshot; its add-only control now benefits from ALU folding.

This is a userspace PoC, not the paper's kernel extension or Lean proofs.
It implements the documented patterns, not every variant of every operation.
Arbitrary precompiled x86 programs and already optimized native code are not
claimed to accelerate universally.

### ARM64 -> eBPF -> ARM64 and RV64 -> eBPF -> RV64

`Arm64EbpfCompiler` and `RiscV64EbpfCompiler` decode restricted little-endian
leaf machine code to ordinary eBPF. `EbpfNativeCompiler` emits AArch64 or RV64I
machine code directly, with no WASM execution stage. Both pipelines support
runtime input, bounded buffers, inspected optimization records, and reusable
RX mappings with architecture-specific instruction-cache synchronization.

```bash
# On matching Linux hardware:
cargo run --no-default-features --features ebpf --example risc-ebpf-native -- arm64
cargo run --no-default-features --features ebpf --example risc-ebpf-native -- riscv64
# From this x86 host: cross-build and execute both targets under QEMU.
./scripts/test_native_roundtrips.sh
```

The leaf frontends intentionally differ from the older one-to-one RISC-V
compiler: they support the normal scalar return register, RET, three-address
arithmetic with alias handling, and expansion where ISA semantics require it.
ARM W results are zero-extended; RV64 word results are sign-extended. The
existing `AyaEbpfBuilder` and its verification contract remain separate.

The default `wasm` feature preserves existing WASM behavior. Disabling default
features permits lightweight native builds, including RISC-V hosts unsupported
by Wasmer. The emitted RV64 code uses baseline integer instructions, requiring
no Zbb/Zba/V extension. ARM32, RV32, compressed source instructions, and general
ELF/OS execution are outside these leaf frontends.

See [supported instructions, ABI, validation and reproduction](docs/arm-riscv-native-roundtrips.md).
QEMU results establish execution correctness and code size, not hardware speedup.

### x86_64 ELF stack, branches, and libc calls

For non-leaf x86_64 test programs, enable the `x86_elf` feature. This path parses an ELF image, preserves loadable data segments, models the x86 register file and stack in WASM linear memory, and dispatches direct calls, returns, and conditional branches through a translated program counter. Wasmer Singlepass then produces native code for the current host, including AArch64.

The extended WASM state machine supplies guest `argc`/`argv`, a reusable host heap, and host-backed libc adapters. The exercised ABI includes `printf`, `fprintf`, `puts`, `putchar`, `exit`, `malloc`, `calloc`, `free`, `gettimeofday`, `clock_gettime`, `fopen`, `fclose`, `fflush`, `fwrite`, `open`, `fstat`, `scanf`/`__isoc99_scanf`, `atoi`, `strerror`, `__errno_location`, and `pow`. `printf` and `fprintf` forward the six integer and eight XMM variadic argument registers; `%d`, `%i`, `%u`, `%x`, `%p`, `%c`, `%s`, `%f`, `%e`, and `%g` are implemented. Set `DOUBLEJIT_STDIN` to provide deterministic stdin for the scanning adapter.

This is a host ABI bridge for translated, freestanding test ELFs, not a claim of complete POSIX/libc emulation. It deliberately rejects x87 and does not implement threads, signals, processes, dynamic linking, arbitrary variadic stack arguments, or full packed AVX state. Scalar SSE and VEX/AVX low-lane memory instructions are supported: `MOVSS/MOVSD`, `MOVAPS/MOVAPD`, `VMOVSS/VMOVSD`, `VMOVAPS/VMOVAPD`, `PXOR/XORPS/XORPD`, `VXORPS`, `MOVQ/VMOVQ`, scalar add/sub/mul/div, conversion, and `UCOMI`/`COMI` forms. 256-bit packed YMM upper lanes remain an explicit unsupported instruction class.

```bash
# ARM build host only: install the x86_64 cross compiler once.
sudo apt-get install gcc-x86-64-linux-gnu

# Build every C test program with a main() as a freestanding x86_64 ELF.
./scripts/build_x86_64_test_binaries.sh

# Translate and execute a real x86_64 ELF on the current host.
cargo run --features x86_elf --example x86-elf-wasm -- \
  target/x86_64-test-binaries/test_binaries/add_test/main

# The runner passes subsequent arguments as guest argv[1..].
cargo run --features x86_elf --example x86-elf-wasm -- \
  target/x86_64-test-binaries/test_binaries/fstat_test/test_fstat Cargo.toml

# Host stdin and guest file output are both deterministic.
DOUBLEJIT_STDIN=73 cargo run --features x86_elf --example x86-elf-wasm -- \
  target/x86_64-test-binaries/test_binaries/archive/io_test

# Separate ELF translation, Wasmer preparation, and hot execution timing.
cargo run --features x86_elf --example x86-elf-wasm-bench -- \
  target/x86_64-test-binaries/test_binaries/arithmetic_test/compiled_test_arithm 50 1000

cargo test --features x86_elf
```

The leaf `x86 -> bpf_insn -> WASM` path above remains Linux eBPF-layout bytecode. The non-leaf ELF path is an extended WASM execution model: arbitrary x86 stack frames and libc calls cannot be made kernel-verifier-loadable eBPF without a separate helper ABI and pointer-provenance proof.

#### ARM benchmark snapshot

Measured on the Parallels Ubuntu AArch64 guest after rebuilding the x86_64 fixtures with `-O0 -ffreestanding -nostdlib` and translator hostcall stubs. `compiled_test_arithm` reaches 366 decoded x86 instructions and finishes with exit result `0`.

| Workload | ELF translation | Wasmer prepare | Hot execution |
| --- | ---: | ---: | ---: |
| `arithmetic_test/compiled_test_arithm` | 1.870 ms | 32.382 ms | 1.726 ms/run |

All 12 original C test programs with `main()`, plus the SSE/AVX memory regression fixture, build as x86_64 ELFs. The current execution matrix is intentionally split by ISA/runtime coverage:

| Programs | Result on the AArch64 path |
| --- | --- |
| `add_test`, `archive/hello_world` | Executed; `add_test` prints `13`, `16`, `19` and both return `0`. |
| `arithmetic_test/compiled_test_arithm` | Executed through stack frames, calls, branches, integer memory operations, and integer divide-by-zero compatibility handling; returns `0`. |
| `archive/io_test`, `fstat_test` | `DOUBLEJIT_STDIN=73` writes `73` to host `program.txt`; `fstat_test Cargo.toml` prints the host file metadata. Both return `0`. |
| `GCBench`, `mandelbrot`, `float_test/f_arithm_test`, `float_test/float_test`, `sort_example` | Execute on the AArch64 path and return `0`. `GCBench` completed in 40.725 seconds in the latest full-matrix run. |
| `float_test/f_arithm_test_stdlib` | Executes its 27 scalar floating-point checks and returns `2`: its two failures are the source program's intentional exact-equality checks for `202.105263` and `428.571429`, not a translation failure. |
| `tests/x86_elf_sse_avx_memory` | Executes a real VEX sequence containing `vmovsd`, `vmovss`, `vmovapd`, `vmovaps`, `vaddsd`, `vmulss`, and `vucomi*`; returns `0`. |
| `conformance/tst-ieee754` | Explicitly rejected at x87 `FLD1`, by design. |

The four `.S` fixtures and `riscvminilibc.c` remain RISC-V-specific inputs, so they are recorded by the build manifest rather than falsely assembled as x86_64.

### llama.cpp KV Actor Experiment

The ReFlux-style KV-cache movement actor, its real x86 native baseline, and
the corresponding x86-to-AArch64 DoubleJIT measurements are documented in
[`docs/llama-kv-actor-experiment.md`](docs/llama-kv-actor-experiment.md).
The same artifact includes a verified drain-and-switch live-migration run that
snapshots and restores its 8,208-byte actor control state between AArch64
DoubleJIT runtimes, plus crash injection before `ready`, between `ready` and
`active`, and after `active` with exactly-once replay checks.
## Backend
From WebAssembly or eBPF to the native host backend. The compiler emits architecture-neutral eBPF bytecode; the final native backend may be x86, RISC-V, or another architecture supported by the selected runtime/JIT.
## Comparison of WebAssembly and RISC-V
1. Code/Data Separation

Most modern architectures, including RISC-V, use the same address space for code and data, but WebAssembly does not. In fact, the running code does not even have a way to read/write itself.

Simplify the implementation of the JIT compiler. If the code is self-modifying, then the JIT compiler needs to have the ability to detect changes and regenerate the target code, which requires a fairly complex implementation mechanism.

WebAssembly assumes a fully functional runtime environment. The runtime environment handles the linking, relocation, and other preparations, and the program does not need to care about getting it up and running on its own.

Security. Code that can be dynamically generated and modified is a dangerous point of attack.

2. Static types and control flow constraints

WebAssembly is very "structural". The standard requires that all function calls, loops, jumps and value types follow specific structural constraints, e.g. passing two arguments to a function that takes three, jumping to a position in another function, performing a floating point add operation on two integers, etc. will result in compilation/validation failures; RISC-V has no such constraints, and the validity of instructions depends only on their own coding.

3. Machine Model

WebAssembly is a stack machine instruction set, while RISC-V is a register machine instruction set.

In WebAssembly, each instruction semantically pops its operands off the value stack and then pushes the result onto the value stack. However, unlike other stack-machine based bytecode formats such as Java, the structure of the value stack at any instruction in the program can be statically determined. This design facilitates better compilation optimization.

In RISC-V, each instruction is encoded with 0 - 3 register numbers. Where with is the input register and is the output register. Except for special types of instructions such as memory access and privileged instructions, each instruction only reads data from the input register and stores the result in the output register.

4. Memory Management

Although WebAssembly and RISC-V both define an untyped, byte-addressable memory, there are some detailed differences between them; WebAssembly's memory is equivalent to a large array: the effective address starts at 0 and expands continuously up to some program-defined initial value and can grow. RISC-V, on the other hand, uses virtual memory, using page tables to map addresses to physical memory.


Memory layout

WebAssembly's memory design, while clean and easy to implement, has a number of problems.

Address 0 is valid, which can cause some programs to behave differently than expected when dereferencing null pointers.

It is not possible to create an "invalid" address range that does not map to any physical address, so it is not possible to implement a stack guard page in a multi-threaded environment. 5.

5. Synchronization mechanism

A Turing-complete calculator requires at least one conditional branch instruction. Similarly, an instruction set architecture that supports multi-threaded synchronization requires at least one "atomic conditional branch" instruction. Such instructions are available under WebAssembly and under RISC-V, corresponding to the CAS model and the LL/SC model, respectively.

LL/SC has stronger semantics than CAS, which suffers from intractable ABA issues, but LL/SC does not. This also means that it is much more difficult to simulate LL/SC on a CAS architecture than vice versa.

## Features
- [ ] qemu-user like API
- [x] wasix compatibility
- [x] JIT RV64IMACGVF ISA to wasm
- [x] doubly JIT codebase infrastructure
- [x] x86/x64 register-only subset to eBPF to WASM
- [x] x86/x64 register-only subset to eBPF to native x86-64 (Linux userspace JIT)
- [ ] rvv to wasm simd
- [x] Lazy loaded memory?
- [x] Lazy loaded csr and fp.
