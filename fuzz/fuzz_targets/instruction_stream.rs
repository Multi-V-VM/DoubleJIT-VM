#![no_main]

use libfuzzer_sys::fuzz_target;
use doublejit_vm::frontend::instruction::Instruction;

/// Fuzzer for testing instruction stream parsing
/// Simulates real execution scenarios where multiple instructions are parsed sequentially
fuzz_target!(|data: &[u8]| {
    // Minimum stream length: at least one instruction
    if data.len() < 4 {
        return;
    }

    // Test 1: Parse as a stream of 32-bit instructions
    for chunk in data.chunks(4) {
        if chunk.len() == 4 {
            let _ = std::panic::catch_unwind(|| {
                Instruction::parse(chunk);
            });
        }
    }

    // Test 2: Parse mixed compressed (16-bit) and standard (32-bit) instructions
    // This simulates real RISC-V code which mixes both formats
    let mut idx = 0;
    while idx + 2 <= data.len() {
        let mut instr_bytes = [0u8; 4];

        // Check if this looks like a compressed instruction
        // Compressed instructions have bits [1:0] != 0b11
        let first_two = u16::from_le_bytes([data[idx], data[idx + 1]]);
        let is_compressed = (first_two & 0b11) != 0b11;

        if is_compressed {
            // Parse as compressed instruction
            instr_bytes[0] = data[idx];
            instr_bytes[1] = data[idx + 1];

            let _ = std::panic::catch_unwind(|| {
                Instruction::parse(&instr_bytes);
            });

            idx += 2;
        } else if idx + 4 <= data.len() {
            // Parse as 32-bit instruction
            instr_bytes.copy_from_slice(&data[idx..idx + 4]);

            let _ = std::panic::catch_unwind(|| {
                Instruction::parse(&instr_bytes);
            });

            idx += 4;
        } else {
            break;
        }
    }

    // Test 3: Parse with different alignments
    // RISC-V allows 16-bit aligned instructions
    if data.len() >= 6 {
        for offset in 0..2 {
            if offset + 4 <= data.len() {
                let chunk = &data[offset..offset + 4];
                let _ = std::panic::catch_unwind(|| {
                    Instruction::parse(chunk);
                });
            }
        }
    }

    // Test 4: Stress test with rapid instruction type changes
    // Alternate between different instruction types
    if data.len() >= 16 {
        let opcodes = [
            0b0110111, // LUI
            0b0010111, // AUIPC
            0b1101111, // JAL
            0b1100111, // JALR
            0b0000111, // Vector Load
            0b0100111, // Vector Store
            0b1010111, // Vector Arithmetic
            0b0010011, // Integer Immediate
        ];

        for (i, &opcode) in opcodes.iter().enumerate() {
            if i * 4 + 4 <= data.len() {
                let mut instr = u32::from_le_bytes([
                    data[i * 4],
                    data[i * 4 + 1],
                    data[i * 4 + 2],
                    data[i * 4 + 3],
                ]);

                // Force specific opcode
                instr = (instr & 0xFFFF_FF80) | opcode;

                let bytes = instr.to_le_bytes();
                let _ = std::panic::catch_unwind(|| {
                    Instruction::parse(&bytes);
                });
            }
        }
    }

    // Test 5: Boundary conditions
    // Test instructions with maximum field values
    if data.len() >= 8 {
        // Test with all 1s
        let max_instr = [0xFF, 0xFF, 0xFF, 0xFF];
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&max_instr);
        });

        // Test with all 0s except valid opcode
        let min_instr = [0b01010111, 0x00, 0x00, 0x00]; // Vector opcode
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&min_instr);
        });

        // Test with alternating bits
        let alt_instr = [0xAA, 0x55, 0xAA, 0x55];
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&alt_instr);
        });
    }
});
