# Fuzzing Targets for DoubleJIT VM

This directory contains fuzzing harnesses for testing the DoubleJIT VM instruction parser using [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html).

## Overview

The fuzzing targets help discover bugs, edge cases, and crashes in the RISC-V instruction decoder, with special focus on the newly implemented Vector Extension (RVV) support.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

## Fuzzing Targets

### 1. `asm` - General Instruction Fuzzing
**File**: `fuzz_targets/asm.rs`

Tests general instruction parsing with arbitrary byte sequences.

**Features**:
- Compressed (16-bit) instruction parsing
- Standard (32-bit) instruction parsing
- Vector instruction opcode testing (0x57)
- Vector load/store opcodes (0x07, 0x27)
- Sequential instruction stream parsing

**Run**:
```bash
cargo fuzz run asm
```

**Run with corpus**:
```bash
cargo fuzz run asm -- -max_len=1024 -runs=1000000
```

### 2. `vector_instructions` - RVV-Specific Fuzzing
**File**: `fuzz_targets/vector_instructions.rs`

Specialized fuzzer focusing on RISC-V Vector Extension instructions.

**Features**:
- VSETVLI/VSETIVLI/VSETVL configuration instructions
- Vector arithmetic instructions (all funct3 variants)
- Vector load/store with different widths
- funct6 field combinations
- Mask bit (vm field) testing
- Register field edge cases

**Run**:
```bash
cargo fuzz run vector_instructions
```

**Recommended for**:
- Testing the new RVV frontend implementation
- Finding edge cases in vector instruction decoding
- Validating funct6/funct3 combinations

### 3. `instruction_stream` - Realistic Execution Simulation
**File**: `fuzz_targets/instruction_stream.rs`

Simulates real execution scenarios with instruction streams.

**Features**:
- Mixed compressed/standard instruction parsing
- Different instruction alignments (16-bit)
- Rapid instruction type changes
- Boundary condition testing (max/min values)
- Sequential parsing stress testing

**Run**:
```bash
cargo fuzz run instruction_stream
```

## Running All Fuzzers

To run all fuzzing targets in parallel:

```bash
#!/bin/bash
cargo fuzz run asm -- -max_total_time=3600 &
cargo fuzz run vector_instructions -- -max_total_time=3600 &
cargo fuzz run instruction_stream -- -max_total_time=3600 &
wait
```

## Corpus Management

### Minimize Corpus
After finding crashes, minimize the corpus:
```bash
cargo fuzz cmin asm
cargo fuzz cmin vector_instructions
cargo fuzz cmin instruction_stream
```

### Merge Corpora
Merge interesting inputs between targets:
```bash
cargo fuzz run asm fuzz/corpus/vector_instructions/*
```

### Triage Crashes
View crashes found by a fuzzer:
```bash
ls fuzz/artifacts/asm/
cargo fuzz run asm fuzz/artifacts/asm/crash-<id>
```

## Coverage Analysis

Generate coverage reports:

```bash
# Install coverage tools
cargo install cargo-cov

# Run with coverage
cargo fuzz coverage asm
cargo cov -- show target/*/release/asm \
    --format=html \
    --instr-profile=fuzz/coverage/asm/coverage.profdata \
    > coverage.html
```

## CI Integration

Example GitHub Actions workflow:

```yaml
name: Fuzz Testing

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target: [asm, vector_instructions, instruction_stream]
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run ${{ matrix.target }} -- -max_total_time=3600
      - uses: actions/upload-artifact@v2
        if: failure()
        with:
          name: fuzz-artifacts
          path: fuzz/artifacts/
```

## Expected Results

### Good Outcomes
- Parser handles all valid RISC-V instructions
- No panics on malformed input
- Graceful error handling for invalid opcodes
- Vector instructions parse correctly with all field combinations

### What We're Looking For
- **Panics**: Unhandled edge cases causing crashes
- **Assertion failures**: Violated invariants in instruction structure
- **Infinite loops**: Parsing getting stuck
- **Memory issues**: Out-of-bounds access, overflows

## Debugging Crashes

When a crash is found:

1. **Reproduce**:
   ```bash
   cargo fuzz run asm fuzz/artifacts/asm/crash-<id>
   ```

2. **Minimize**:
   ```bash
   cargo fuzz tmin asm fuzz/artifacts/asm/crash-<id>
   ```

3. **Debug**:
   ```bash
   rust-lldb target/*/release/asm
   (lldb) run fuzz/artifacts/asm/crash-<id>
   ```

4. **Hexdump**:
   ```bash
   hexdump -C fuzz/artifacts/asm/crash-<id>
   ```

## Performance Tips

- **Use multiple cores**:
  ```bash
  cargo fuzz run asm -- -workers=8
  ```

- **Set memory limit**:
  ```bash
  cargo fuzz run asm -- -rss_limit_mb=4096
  ```

- **Use dictionary** (for structured fuzzing):
  Create `fuzz/fuzz_targets/asm.dict`:
  ```
  # Common opcodes
  "\x37"  # LUI
  "\x57"  # Vector
  "\x07"  # Vector Load
  "\x27"  # Vector Store
  ```

  Then run:
  ```bash
  cargo fuzz run asm -- -dict=fuzz_targets/asm.dict
  ```

## Vector Extension Testing Focus

For RVV testing, prioritize:

1. **Configuration instructions**: VSETVLI, VSETIVLI, VSETVL
2. **Load/Store variants**: Unit-stride, strided, indexed
3. **Arithmetic formats**: VV (vector-vector), VX (vector-scalar), VI (vector-immediate)
4. **Mask operations**: Test with vm=0 and vm=1
5. **Register boundaries**: Test v0, v31 edge cases

## Contributing

When adding new instruction support:

1. Add test cases to relevant fuzzer
2. Run fuzzing for at least 1 hour
3. Document any crashes found
4. Fix issues before merging

## Resources

- [Cargo Fuzz Book](https://rust-fuzz.github.io/book/)
- [libFuzzer Tutorial](https://llvm.org/docs/LibFuzzer.html)
- [RISC-V Vector Spec](https://github.com/riscv/riscv-v-spec)
- [OSS-Fuzz Best Practices](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
