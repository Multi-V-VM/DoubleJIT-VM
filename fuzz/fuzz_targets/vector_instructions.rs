#![no_main]

use libfuzzer_sys::fuzz_target;
use doublejit_vm::frontend::instruction::Instruction;

/// Specialized fuzzer for RISC-V Vector Extension (RVV) instructions
/// This fuzzer focuses specifically on the Vector Extension opcodes and fields
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Extract fuzzing parameters from input data
    let base_instr = u32::from_le_bytes([
        data[0],
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ]);

    // Test VSETVLI/VSETIVLI/VSETVL instructions (opcode 0x57, funct3=0b111)
    {
        let mut vset_instr = base_instr;
        vset_instr = (vset_instr & 0xFFFF_FF80) | 0b01010111; // Set opcode
        vset_instr = (vset_instr & 0xFFFF_8FFF) | (0b111 << 12); // Set funct3=111

        let bytes = vset_instr.to_le_bytes();
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&bytes);
        });
    }

    // Test vector arithmetic instructions (opcode 0x57, funct3=0b000-0b110)
    if data.len() >= 5 {
        let funct3 = data[4] & 0b111; // Extract funct3 from data
        let mut varith_instr = base_instr;
        varith_instr = (varith_instr & 0xFFFF_FF80) | 0b01010111; // Set opcode
        varith_instr = (varith_instr & 0xFFFF_8FFF) | ((funct3 as u32) << 12); // Set funct3

        let bytes = varith_instr.to_le_bytes();
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&bytes);
        });
    }

    // Test vector load instructions (opcode 0x07)
    {
        let mut vload_instr = base_instr;
        vload_instr = (vload_instr & 0xFFFF_FF80) | 0b00000111; // Set opcode

        // Test different width encodings (funct3 field)
        for width in 0..=7 {
            let mut instr = vload_instr;
            instr = (instr & 0xFFFF_8FFF) | (width << 12);

            let bytes = instr.to_le_bytes();
            let _ = std::panic::catch_unwind(|| {
                Instruction::parse(&bytes);
            });
        }
    }

    // Test vector store instructions (opcode 0x27)
    {
        let mut vstore_instr = base_instr;
        vstore_instr = (vstore_instr & 0xFFFF_FF80) | 0b00100111; // Set opcode

        // Test different width encodings
        for width in 0..=7 {
            let mut instr = vstore_instr;
            instr = (instr & 0xFFFF_8FFF) | (width << 12);

            let bytes = instr.to_le_bytes();
            let _ = std::panic::catch_unwind(|| {
                Instruction::parse(&bytes);
            });
        }
    }

    // Test various funct6 values for vector arithmetic
    if data.len() >= 6 {
        let funct6 = (data[5] & 0b111111) as u32;
        let mut vinstr = base_instr;
        vinstr = (vinstr & 0xFFFF_FF80) | 0b01010111; // opcode
        vinstr = (vinstr & 0xFFFF_8FFF) | (0b000 << 12); // funct3=VV
        vinstr = (vinstr & 0x03FF_FFFF) | (funct6 << 26); // funct6

        let bytes = vinstr.to_le_bytes();
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&bytes);
        });
    }

    // Test mask bit (vm field at bit 25)
    if data.len() >= 7 {
        let vm = (data[6] & 1) as u32;
        let mut vmask_instr = base_instr;
        vmask_instr = (vmask_instr & 0xFFFF_FF80) | 0b01010111;
        vmask_instr = (vmask_instr & 0xFDFF_FFFF) | (vm << 25);

        let bytes = vmask_instr.to_le_bytes();
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&bytes);
        });
    }

    // Test register field combinations
    if data.len() >= 10 {
        let rd = (data[7] & 0b11111) as u32;
        let rs1 = (data[8] & 0b11111) as u32;
        let rs2 = (data[9] & 0b11111) as u32;

        let mut vreg_instr = base_instr;
        vreg_instr = (vreg_instr & 0xFFFF_FF80) | 0b01010111;
        vreg_instr = (vreg_instr & 0xFFFF_FF80) | (rd << 7);
        vreg_instr = (vreg_instr & 0xFFF0_7FFF) | (rs1 << 15);
        vreg_instr = (vreg_instr & 0xFE0F_FFFF) | (rs2 << 20);

        let bytes = vreg_instr.to_le_bytes();
        let _ = std::panic::catch_unwind(|| {
            Instruction::parse(&bytes);
        });
    }
});
