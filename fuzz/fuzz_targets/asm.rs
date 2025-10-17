#![no_main]

use libfuzzer_sys::fuzz_target;
use doublejit_vm::frontend::instruction::Instruction;

fuzz_target!(|data: &[u8]| {
    // Fuzzing strategy: Test instruction parsing with arbitrary byte sequences
    // This will help discover:
    // 1. Parser crashes on malformed instructions
    // 2. Panic conditions in instruction decoding
    // 3. Edge cases in opcode/funct field combinations
    // 4. Vector extension parsing robustness

    // RISC-V instructions are either 16-bit (compressed) or 32-bit
    // We need at least 2 bytes for compressed, 4 bytes for standard
    if data.len() < 2 {
        return;
    }

    // Test compressed instruction parsing (16-bit)
    if data.len() >= 2 {
        let compressed_bytes = &data[0..2];
        let mut padded = [0u8; 4];
        padded[0..2].copy_from_slice(compressed_bytes);

        // Try to parse as compressed instruction
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&padded);
        });
    }

    // Test standard instruction parsing (32-bit)
    if data.len() >= 4 {
        let instr_bytes = &data[0..4];

        // Try to parse the instruction
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(instr_bytes);
        });
    }

    // Test vector instruction parsing specifically
    // Vector instructions use opcode 0b1010111 (0x57)
    if data.len() >= 4 {
        let mut vector_bytes = [0u8; 4];
        vector_bytes[0..4].copy_from_slice(&data[0..4]);

        // Force opcode to be vector opcode to test vector instruction parsing
        vector_bytes[0] = (vector_bytes[0] & 0b10000000) | 0b01010111; // opcode = 0x57

        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&vector_bytes);
        });
    }

    // Test vector load/store instructions
    // Vector loads: opcode 0b0000111 (0x07)
    // Vector stores: opcode 0b0100111 (0x27)
    if data.len() >= 4 {
        let mut vload_bytes = [0u8; 4];
        vload_bytes[0..4].copy_from_slice(&data[0..4]);
        vload_bytes[0] = (vload_bytes[0] & 0b10000000) | 0b00000111; // opcode = 0x07

        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&vload_bytes);
        });

        let mut vstore_bytes = [0u8; 4];
        vstore_bytes[0..4].copy_from_slice(&data[0..4]);
        vstore_bytes[0] = (vstore_bytes[0] & 0b10000000) | 0b00100111; // opcode = 0x27

        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&vstore_bytes);
        });
    }

    // Test sequential instruction parsing (simulating instruction stream)
    if data.len() >= 8 {
        for chunk in data.chunks(4) {
            if chunk.len() == 4 {
                let _ = std::panic::catch_unwind(|| {
                    Instruction::parse(chunk);
                });
            }
        }
    }
});
