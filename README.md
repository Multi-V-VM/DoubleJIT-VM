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

It is useful for exercising the eBPF representation on an AArch64 host without requiring an x86 host. The frontend decodes a deliberately small, straight-line subset of x86 and x86_64: register-only `mov`, immediate `add`, register `xor`, and `ret`. Memory operands, branches, calls, syscalls, and unsupported registers are rejected explicitly. x86_64 immediates must fit in the eBPF ALU immediate range.

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

### x86_64 ELF stack, branches, and libc calls

For non-leaf x86_64 test programs, enable the `x86_elf` feature. This path parses an ELF image, preserves loadable data segments, models the x86 register file and stack in WASM linear memory, and dispatches direct calls, returns, and conditional branches through a translated program counter. Wasmer Singlepass then produces native code for the current host, including AArch64.

The current libc hostcall ABI implements `printf`, `puts`, `exit`, `malloc`, `calloc`, and `free`. The fixture linker supplies symbol-resolvable stubs for additional C-library names so the translator can report ISA coverage independently from a host libc. Those stubs are not behavioral implementations of file I/O, scanning, time, or floating-point library routines.

```bash
# ARM build host only: install the x86_64 cross compiler once.
sudo apt-get install gcc-x86-64-linux-gnu

# Build every C test program with a main() as a freestanding x86_64 ELF.
./scripts/build_x86_64_test_binaries.sh

# Translate and execute a real x86_64 ELF on the current host.
cargo run --features x86_elf --example x86-elf-wasm -- \
  target/x86_64-test-binaries/test_binaries/add_test/main

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
| `arithmetic_test/compiled_test_arithm` | 1.459 ms | 30.658 ms | 1.319 ms/run |

All 12 C test programs with `main()` build as x86_64 ELFs. The current execution matrix is intentionally split by ISA/runtime coverage:

| Programs | Result on the AArch64 path |
| --- | --- |
| `add_test`, `archive/hello_world` | Executed; `add_test` prints `13`, `16`, `19` and both return `0`. |
| `arithmetic_test/compiled_test_arithm` | Executed through stack frames, calls, branches, integer memory operations, and integer divide-by-zero compatibility handling; returns `0`. |
| `archive/io_test`, `fstat_test` | Reach the translated entry point and return `1` with no guest argv/stdin; their I/O libc routines are linkable stubs, not host I/O yet. |
| `GCBench`, `mandelbrot`, `float_test/*`, `sort_example`, `conformance/tst-ieee754` | Rejected before execution at SSE/FP operations (`PXOR`, `MOVSS`, or `MOVSD`). |

The four `.S` fixtures and `riscvminilibc.c` remain RISC-V-specific inputs, so they are recorded by the build manifest rather than falsely assembled as x86_64.
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
- [ ] rvv to wasm simd
- [x] Lazy loaded memory?
- [x] Lazy loaded csr and fp.
