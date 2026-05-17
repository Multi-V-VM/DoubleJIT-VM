use crate::frontend::instruction::{
    Instr, Instruction, RV32Instr, RV64Instr, RVZcsr, Rd, Reg, Rs1, Rs2, Rs3, RV32I, RV32M, RV64I,
    RV64M, RVV, VM,
};
use std::fmt::Write as FmtWrite;

const VECTOR_REGISTER_BYTES: i32 = 256;
const VECTOR_I32_LANES: i64 = (VECTOR_REGISTER_BYTES / 4) as i64;

fn load_op(elem_bytes: i32) -> &'static str {
    match elem_bytes {
        1 => "i32.load8_u",
        2 => "i32.load16_u",
        4 => "i32.load",
        8 => "i64.load",
        _ => unreachable!("unsupported RVV element width"),
    }
}

fn store_op(elem_bytes: i32) -> &'static str {
    match elem_bytes {
        1 => "i32.store8",
        2 => "i32.store16",
        4 => "i32.store",
        8 => "i64.store",
        _ => unreachable!("unsupported RVV element width"),
    }
}

fn vtype_vlmax(vtype: u32) -> i64 {
    let sew_bits = 8_i64 << ((vtype >> 3) & 0x7);
    let (lmul_num, lmul_den) = match vtype & 0x7 {
        0b000 => (1_i64, 1_i64),
        0b001 => (2, 1),
        0b010 => (4, 1),
        0b011 => (8, 1),
        0b111 => (1, 2),
        0b110 => (1, 4),
        0b101 => (1, 8),
        _ => return 0,
    };
    ((i64::from(VECTOR_REGISTER_BYTES) * 8) * lmul_num / sew_bits / lmul_den).max(0)
}

/// WasmEmitter translates RISC-V instructions to WebAssembly Text (WAT) format
pub struct WasmEmitter {
    /// Accumulated WAT code
    wat_code: String,

    /// Number of instructions emitted
    instr_count: usize,

    /// Whether we're inside a basic block
    in_block: bool,

    /// Label counter for branches
    label_counter: usize,

    /// Pending instructions to emit as a bucketized dispatch list
    pending_instrs: Vec<(u64, Instr)>,
}

impl WasmEmitter {
    /// Create a new WasmEmitter
    pub fn new() -> Self {
        Self {
            wat_code: String::new(),
            instr_count: 0,
            in_block: false,
            label_counter: 0,
            pending_instrs: Vec::new(),
        }
    }

    /// Start a new function
    pub fn start_function(&mut self, name: &str) {
        writeln!(
            &mut self.wat_code,
            // Predeclare locals used by vector/SIMD emission and dispatch
            "  (func ${} (export \"{}\") (local $tmp_addr i32) (local $tmp_v1 v128) (local $tmp_v2 v128) (local $tmp_v v128) (local $bucket i32) (local $i i32) (local $vl_i32 i32) (local $tmp_i64 i64)",
            name, name
        )
        .unwrap();
        self.in_block = true;
    }

    /// Start an infinite loop (for interpreter-style execution)
    pub fn start_loop(&mut self) {
        writeln!(&mut self.wat_code, "    (loop $interpreter_loop").unwrap();

        // CRITICAL: Check exit flag at START of loop (before instructions)
        // This ensures we can exit even when instructions use br $interpreter_loop
        writeln!(&mut self.wat_code, "      ;; Check if program should exit").unwrap();
        writeln!(&mut self.wat_code, "      global.get $exit_flag").unwrap();
        writeln!(&mut self.wat_code, "      if").unwrap();
        writeln!(
            &mut self.wat_code,
            "        return  ;; Exit function if exit_flag is set"
        )
        .unwrap();
        writeln!(&mut self.wat_code, "      end").unwrap();

        // If PC becomes 0 unexpectedly, re-seed from $entry_pc (provided by embedding runtime)
        writeln!(&mut self.wat_code, "      ;; Re-seed PC if zero").unwrap();
        writeln!(&mut self.wat_code, "      global.get $pc").unwrap();
        writeln!(&mut self.wat_code, "      i64.eqz").unwrap();
        writeln!(&mut self.wat_code, "      if").unwrap();
        writeln!(&mut self.wat_code, "        global.get $entry_pc").unwrap();
        writeln!(&mut self.wat_code, "        global.set $pc").unwrap();
        writeln!(&mut self.wat_code, "      end").unwrap();

        // Compute dispatch bucket: bucket = ((pc >> 2) & 255)
        writeln!(
            &mut self.wat_code,
            "      ;; Compute dispatch bucket from PC"
        )
        .unwrap();
        writeln!(&mut self.wat_code, "      global.get $pc").unwrap();
        writeln!(&mut self.wat_code, "      i64.const 2").unwrap();
        writeln!(&mut self.wat_code, "      i64.shr_u").unwrap();
        writeln!(&mut self.wat_code, "      i64.const 255").unwrap();
        writeln!(&mut self.wat_code, "      i64.and").unwrap();
        writeln!(&mut self.wat_code, "      i32.wrap_i64").unwrap();
        writeln!(&mut self.wat_code, "      local.set $bucket").unwrap();
    }

    /// End the loop with exit flag check
    pub fn end_loop_with_exit_check(&mut self) {
        // Emit grouped buckets (0..63), placing only matching PC checks in each
        for bucket_id in 0..256 {
            writeln!(
                &mut self.wat_code,
                "      ;; Bucket {}\n      local.get $bucket\n      i32.const {}\n      i32.eq\n      if",
                bucket_id, bucket_id
            )
            .unwrap();

            // Work on a snapshot to avoid borrowing conflicts while emitting
            let items: Vec<(u64, Instr)> = self.pending_instrs.iter().copied().collect();
            for (pc, instr) in items.into_iter() {
                let pc_bucket = ((pc >> 2) & 255) as i32;
                if pc_bucket == bucket_id {
                    let _ = self.emit_instruction_block(pc, instr);
                }
            }

            writeln!(&mut self.wat_code, "      end").unwrap();
        }

        // Loop back
        writeln!(
            &mut self.wat_code,
            "      ;; Loop back to check exit flag and execute next instruction"
        )
        .unwrap();
        writeln!(&mut self.wat_code, "      br $interpreter_loop").unwrap();
        writeln!(&mut self.wat_code, "    )").unwrap(); // Close loop
    }

    /// End the current function
    pub fn end_function(&mut self) {
        writeln!(&mut self.wat_code, "  )").unwrap();
        self.in_block = false;
    }

    /// Get the generated WAT code
    pub fn finalize(self) -> String {
        self.wat_code
    }

    /// Get a fresh label
    fn fresh_label(&mut self) -> String {
        let label = format!("label_{}", self.label_counter);
        self.label_counter += 1;
        label
    }

    /// Emit one RVV instruction into the current function body.
    ///
    /// This is used by custom benchmarks and other straight-line codegen paths
    /// that need the RVV backend without the interpreter-style PC dispatch.
    pub fn emit_rvv_instruction(&mut self, instr: &RVV) -> Result<(), String> {
        self.emit_rvv(instr)
    }

    /// Emit a single RISC-V instruction as WAT
    pub fn emit_instruction(&mut self, pc: u64, instr: &Instruction) -> Result<(), String> {
        self.pending_instrs.push((pc, instr.instr));
        Ok(())
    }

    /// Emit one instruction (PC guard, translation, PC update, and loop back)
    fn emit_instruction_block(&mut self, pc: u64, instr: Instr) -> Result<(), String> {
        // PC guard and increment counter
        writeln!(
            &mut self.wat_code,
            "        ;; PC=0x{:08x}: {:?}\n        global.get $pc\n        i64.const {}\n        i64.eq\n        if\n          global.get $instr_count\n          i64.const 1\n          i64.add\n          global.set $instr_count",
            pc, instr, pc as i64
        )
        .unwrap();

        // (debug watchdog removed for performance)

        // Whether instruction modifies PC
        let modifies_pc = matches!(
            instr,
            Instr::RV32(rv32) if matches!(rv32,
                crate::frontend::instruction::RV32Instr::RV32I(i) if matches!(i,
                    crate::frontend::instruction::RV32I::JAL(_,_) |
                    crate::frontend::instruction::RV32I::JALR(_,_,_) |
                    crate::frontend::instruction::RV32I::BEQ(_,_,_) |
                    crate::frontend::instruction::RV32I::BNE(_,_,_) |
                    crate::frontend::instruction::RV32I::BLT(_,_,_) |
                    crate::frontend::instruction::RV32I::BGE(_,_,_) |
                    crate::frontend::instruction::RV32I::BLTU(_,_,_) |
                    crate::frontend::instruction::RV32I::BGEU(_,_,_)
                )
            )
        );

        match instr {
            Instr::RV32(rv32instr) => match rv32instr {
                RV32Instr::RV32I(rv32i) => self.emit_rv32i(&rv32i)?,
                RV32Instr::RV32M(rv32m) => self.emit_rv32m(&rv32m)?,
                RV32Instr::RVV(rvv) => self.emit_rvv(&rvv)?,
                RV32Instr::RVZcsr(z) => self.emit_zicsr(&z)?,
                _ => {
                    writeln!(
                        &mut self.wat_code,
                        "          ;; TODO: RV32 instruction {:?}",
                        rv32instr
                    )
                    .unwrap();
                }
            },
            Instr::RV64(rv64instr) => match rv64instr {
                RV64Instr::RV64I(rv64i) => self.emit_rv64i(&rv64i)?,
                RV64Instr::RV64M(rv64m) => self.emit_rv64m(&rv64m)?,
                RV64Instr::RV64V(rvv) => self.emit_rvv(&rvv)?,
                RV64Instr::RVZcsr(z) => self.emit_zicsr(&z)?,
                _ => {
                    writeln!(
                        &mut self.wat_code,
                        "          ;; TODO: RV64 instruction {:?}",
                        rv64instr
                    )
                    .unwrap();
                }
            },
            Instr::NOP => {
                writeln!(&mut self.wat_code, "          ;; NOP").unwrap();
            }
            _ => {
                writeln!(
                    &mut self.wat_code,
                    "          ;; TODO: instruction {:?}",
                    instr
                )
                .unwrap();
            }
        }

        if !modifies_pc {
            writeln!(&mut self.wat_code, "          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc").unwrap();
        }
        writeln!(&mut self.wat_code, "          br $interpreter_loop").unwrap();
        writeln!(&mut self.wat_code, "        end").unwrap();

        self.instr_count += 1;
        Ok(())
    }

    /// Emit RV32I instruction
    fn emit_rv32i(&mut self, instr: &RV32I) -> Result<(), String> {
        use crate::frontend::instruction::RV32I::*;

        match instr {
            LUI(Rd(rd), imm) => {
                // rd = imm << 12 (sign-extended)
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        i64.const {}\n        global.set $x{}",
                    (imm_val << 12) as i64,
                    rd_num
                )
                .unwrap();
            }

            AUIPC(Rd(rd), imm) => {
                // rd = pc + (imm << 12)
                // CRITICAL: PC must be the address of THIS instruction when it executes
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $pc\n        i64.const {}\n        i64.add\n        global.set $x{}",
                    (imm_val << 12) as i64, rd_num
                )
                .unwrap();

                // For debugging _start, log AUIPC to x10 (a0) which loads main's address
                if rd_num == 10 {
                    writeln!(
                        &mut self.wat_code,
                        "        ;; DEBUG AUIPC a0: PC + offset\n        global.get $x10\n        i32.wrap_i64\n        call $debug_print"
                    )
                    .unwrap();
                }
            }

            JAL(Rd(rd), imm) => {
                // rd = pc + 4; pc = pc + imm
                // Note: jtype_immediate() already returns the full sign-extended offset
                // Note: x0 is always zero, so don't write to it
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.0 as i32;

                if rd_num == 0 {
                    // x0 is always zero - don't save return address
                    writeln!(
                        &mut self.wat_code,
                        "        ;; Jump (no return address saved to x0)\n        global.get $pc\n        i64.const {}\n        i64.add\n        global.set $pc",
                        imm_val as i64
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut self.wat_code,
                        "        ;; Save return address\n        global.get $pc\n        i64.const 4\n        i64.add\n        global.set $x{}\n        ;; Jump\n        global.get $pc\n        i64.const {}\n        i64.add\n        global.set $pc",
                        rd_num, imm_val as i64
                    )
                    .unwrap();
                }
            }

            JALR(Rd(rd), Rs1(rs1), imm) => {
                // rd = pc + 4; pc = (rs1 + imm) & ~1
                // Note: x0 is always zero, so don't write to it
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode_sext();

                if rd_num == 0 {
                    // x0 is always zero - don't save return address
                    writeln!(
                        &mut self.wat_code,
                        "        ;; Compute target (no return address saved to x0)\n        global.get $x{}\n        i64.const {}\n        i64.add\n        i64.const -2\n        i64.and\n        global.set $pc",
                        rs1_num, imm_val as i64
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut self.wat_code,
                        "        ;; Save return address\n        global.get $pc\n        i64.const 4\n        i64.add\n        global.set $x{}\n        ;; Compute target\n        global.get $x{}\n        i64.const {}\n        i64.add\n        i64.const -2\n        i64.and\n        global.set $pc",
                        rd_num, rs1_num, imm_val as i64
                    )
                    .unwrap();
                }
            }

            BEQ(Rs1(rs1), Rs2(rs2), imm) => {
                // Note: btype_immediate() already returns the full sign-extended offset
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.0 as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.eq\n        if\n          global.get $pc\n          i64.const {}\n          i64.add\n          global.set $pc\n        else\n          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc\n        end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BNE(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.0 as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.ne\n        if\n          global.get $pc\n          i64.const {}\n          i64.add\n          global.set $pc\n        else\n          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc\n        end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BLT(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.0 as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.lt_s\n        if\n          global.get $pc\n          i64.const {}\n          i64.add\n          global.set $pc\n        else\n          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc\n        end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BGE(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.0 as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.ge_s\n        if\n          global.get $pc\n          i64.const {}\n          i64.add\n          global.set $pc\n        else\n          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc\n        end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BLTU(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.0 as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.lt_u\n        if\n          global.get $pc\n          i64.const {}\n          i64.add\n          global.set $pc\n        else\n          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc\n        end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BGEU(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.0 as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.ge_u\n        if\n          global.get $pc\n          i64.const {}\n          i64.add\n          global.set $pc\n        else\n          global.get $pc\n          i64.const 4\n          i64.add\n          global.set $pc\n        end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            LB(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i32.load8_s\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LH(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i32.load16_s\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LW(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i32.load\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LBU(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i32.load8_u\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LHU(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i32.load16_u\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SB(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        global.get $x{}\n        i32.wrap_i64\n        i32.store8",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            SH(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        global.get $x{}\n        i32.wrap_i64\n        i32.store16",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            SW(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        global.get $x{}\n        i32.wrap_i64\n        i32.store",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            ADDI(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();

                // Debug: Print a0 after ADDI if it's calculating main address (immediate = -104)
                if rd_num == 10 && imm_val == -104 {
                    writeln!(
                        &mut self.wat_code,
                        "        ;; DEBUG: a0 after ADDI -104 (should be main address = 0x1059c)\n        global.get $x10\n        i32.wrap_i64\n        call $debug_print"
                    )
                    .unwrap();
                }
            }

            SLTI(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.lt_s\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLTIU(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as u32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.lt_u\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            XORI(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.xor\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            ORI(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.or\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            ANDI(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.and\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.shl\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.shr_u\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRAI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.shr_s\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            ADD(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.add\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SUB(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.sub\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SLL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.const 31\n        i64.and\n        i64.shl\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SLT(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.lt_s\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SLTU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.lt_u\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            XOR(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.xor\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SRL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.const 31\n        i64.and\n        i64.shr_u\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SRA(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.const 31\n        i64.and\n        i64.shr_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            OR(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.or\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            AND(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.and\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            FENCE(_, _, _, _, _) => {
                writeln!(&mut self.wat_code, "        ;; FENCE (no-op in WASM)").unwrap();
            }

            FENCE_TSO => {
                writeln!(&mut self.wat_code, "        ;; FENCE.TSO (no-op in WASM)").unwrap();
            }

            PAUSE => {
                writeln!(&mut self.wat_code, "        ;; PAUSE (no-op in WASM)").unwrap();
            }

            ECALL => {
                // RISC-V syscall convention:
                // a7 (x17) = syscall number
                // a0-a5 (x10-x15) = arguments
                // Result returned in a0 (x10)

                // Generate a switch on syscall number to call WASI functions directly
                writeln!(
                    &mut self.wat_code,
                    "        ;; ECALL - translate RISC-V syscall to handler
        global.get $x17
        i64.const 64
        i64.eq
        if
          ;; write(fd, buf, count) -> fd_write
          global.get $x10  ;; fd
          global.get $x11  ;; buf
          global.get $x12  ;; count
          call $wasi_write
          global.set $x10
        else
          global.get $x17
          i64.const 172
          i64.eq
          if
            ;; getpid() -> return fixed PID
            i64.const 1000
            global.set $x10
          else
            global.get $x17
            i64.const 178
            i64.eq
            if
              ;; gettid() -> return fixed TID
              i64.const 1000
              global.set $x10
            else
              global.get $x17
              i64.const 131
              i64.eq
              if
                ;; sigaltstack(ss, old_ss) -> stub (success)
                i64.const 0
                global.set $x10
              else
                ;; All other syscalls (including exit/93 and exit_group/94) go through syscall handler
                global.get $x17
                global.get $x10
                global.get $x11
                global.get $x12
                global.get $x13
                global.get $x14
                global.get $x15
                call $syscall
                global.set $x10
              end
            end
          end
        end"
                )
                .unwrap();
            }

            EBREAK => {
                writeln!(&mut self.wat_code, "        ;; EBREAK (debug trap)").unwrap();
            }
        }

        Ok(())
    }

    /// Emit RV64I instruction
    fn emit_rv64i(&mut self, instr: &RV64I) -> Result<(), String> {
        use crate::frontend::instruction::RV64I::*;

        match instr {
            LWU(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i32.load\n        i64.extend_i32_u\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LD(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        i64.load\n        global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SD(Rs1(rs1), Rs2(rs2), imm) => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.add\n        call $vaddr_to_offset\n        global.get $x{}\n        i64.store",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            SLLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.shl\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.shr_u\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRAI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i64.const {}\n        i64.shr_s\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            ADDIW(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        i32.const {}\n        i32.add\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, imm_val, rd_num
                )
                .unwrap();
            }

            SLLIW(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        i32.const {}\n        i32.shl\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRLIW(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        i32.const {}\n        i32.shr_u\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRAIW(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        i32.const {}\n        i32.shr_s\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            ADDW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        global.get $x{}\n        i32.wrap_i64\n        i32.add\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SUBW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        global.get $x{}\n        i32.wrap_i64\n        i32.sub\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SLLW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        global.get $x{}\n        i32.wrap_i64\n        i32.const 31\n        i32.and\n        i32.shl\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SRLW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        global.get $x{}\n        i32.wrap_i64\n        i32.const 31\n        i32.and\n        i32.shr_u\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            SRAW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        global.get $x{}\n        i32.wrap_i64\n        i32.const 31\n        i32.and\n        i32.shr_s\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }
        }

        Ok(())
    }

    /// Emit RV32M instruction (multiply/divide extension)
    fn emit_rv32m(&mut self, instr: &RV32M) -> Result<(), String> {
        use crate::frontend::instruction::RV32M::*;

        match instr {
            MUL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        global.get $x{}\n        i64.mul\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            MULH(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; MULH - high part of signed multiplication\n        ;; TODO: implement 128-bit multiplication\n        global.get $x{}\n        global.get $x{}\n        i64.mul\n        i64.const 32\n        i64.shr_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            MULHSU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; MULHSU - TODO\n        i64.const 0\n        global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            MULHU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; MULHU - TODO\n        i64.const 0\n        global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            DIV(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; DIV - signed division with zero check\n        global.get $x{}\n        i64.eqz\n        if\n      i64.const -1\n      global.set $x{}\n        else\n      global.get $x{}\n      global.get $x{}\n      i64.div_s\n      global.set $x{}\n        end",
                    rs2_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            DIVU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; DIVU - unsigned division with zero check\n        global.get $x{}\n        i64.eqz\n        if\n      i64.const -1\n      global.set $x{}\n        else\n      global.get $x{}\n      global.get $x{}\n      i64.div_u\n      global.set $x{}\n        end",
                    rs2_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REM(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; REM - signed remainder with zero check\n        global.get $x{}\n        i64.eqz\n        if\n      global.get $x{}\n      global.set $x{}\n        else\n      global.get $x{}\n      global.get $x{}\n      i64.rem_s\n      global.set $x{}\n        end",
                    rs2_num, rs1_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REMU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; REMU - unsigned remainder with zero check\n        global.get $x{}\n        i64.eqz\n        if\n      global.get $x{}\n      global.set $x{}\n        else\n      global.get $x{}\n      global.get $x{}\n      i64.rem_u\n      global.set $x{}\n        end",
                    rs2_num, rs1_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }
        }

        Ok(())
    }

    /// Emit RV64M instruction
    fn emit_rv64m(&mut self, instr: &RV64M) -> Result<(), String> {
        use crate::frontend::instruction::RV64M::*;

        match instr {
            MULW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        global.get $x{}\n        i32.wrap_i64\n        global.get $x{}\n        i32.wrap_i64\n        i32.mul\n        i64.extend_i32_s\n        global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            DIVW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; DIVW - 32-bit signed division with zero check\n        global.get $x{}\n        i32.wrap_i64\n        i32.eqz\n        if\n      i64.const -1\n      global.set $x{}\n        else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.div_s\n      i64.extend_i32_s\n      global.set $x{}\n        end",
                    rs2_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            DIVUW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; DIVUW - 32-bit unsigned division with zero check\n        global.get $x{}\n        i32.wrap_i64\n        i32.eqz\n        if\n      i64.const -1\n      global.set $x{}\n        else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.div_u\n      i64.extend_i32_s\n      global.set $x{}\n        end",
                    rs2_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REMW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; REMW - 32-bit signed remainder with zero check\n        global.get $x{}\n        i32.wrap_i64\n        i32.eqz\n        if\n      global.get $x{}\n      global.set $x{}\n        else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.rem_s\n      i64.extend_i32_s\n      global.set $x{}\n        end",
                    rs2_num, rs1_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REMUW(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "        ;; REMUW - 32-bit unsigned remainder with zero check\n        global.get $x{}\n        i32.wrap_i64\n        i32.eqz\n        if\n      global.get $x{}\n      global.set $x{}\n        else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.rem_u\n      i64.extend_i32_s\n      global.set $x{}\n        end",
                    rs2_num, rs1_num, rd_num, rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }
        }

        Ok(())
    }

    /// Emit RVV instruction (vector extension)
    fn emit_rvv(&mut self, instr: &RVV) -> Result<(), String> {
        use crate::frontend::instruction::RVV::*;

        match instr {
            VSETVLI(Rd(rd), Rs1(rs1), vtypei) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                self.emit_vsetvl_from_reg("VSETVLI", rd_num, rs1_num, vtypei.decode() as i64)?;
            }

            VSETIVLI(Rd(rd), encoded) => {
                let rd_num = self.reg_num(rd)?;
                let encoded = encoded.decode();
                let avl = i64::from(encoded & 0x1f);
                let vtype = i64::from(encoded >> 5);
                self.emit_vsetvl_from_imm("VSETIVLI", rd_num, avl, vtype)?;
            }

            VSETVL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                self.emit_vsetvl_dynamic(rd_num, rs1_num, rs2_num)?;
            }

            VLE8_V(Rd(vd), Rs1(rs1), VM(true)) => self.emit_vector_load("VLE8.V", vd, rs1, 1)?,
            VLE16_V(Rd(vd), Rs1(rs1), VM(true)) => self.emit_vector_load("VLE16.V", vd, rs1, 2)?,
            VLE32_V(Rd(vd), Rs1(rs1), VM(true)) => self.emit_vector_load("VLE32.V", vd, rs1, 4)?,
            VLE64_V(Rd(vd), Rs1(rs1), VM(true)) => self.emit_vector_load("VLE64.V", vd, rs1, 8)?,
            VSE8_V(Rs3(vs3), Rs1(rs1), VM(true)) => {
                self.emit_vector_store("VSE8.V", vs3, rs1, 1)?
            }
            VSE16_V(Rs3(vs3), Rs1(rs1), VM(true)) => {
                self.emit_vector_store("VSE16.V", vs3, rs1, 2)?
            }
            VSE32_V(Rs3(vs3), Rs1(rs1), VM(true)) => {
                self.emit_vector_store("VSE32.V", vs3, rs1, 4)?
            }
            VSE64_V(Rs3(vs3), Rs1(rs1), VM(true)) => {
                self.emit_vector_store("VSE64.V", vs3, rs1, 8)?
            }

            VADD_VV(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vv("VADD.VV", vd, lhs, rhs, "i32.add")?
            }
            VSUB_VV(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vv("VSUB.VV", vd, lhs, rhs, "i32.sub")?
            }
            VAND_VV(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vv("VAND.VV", vd, lhs, rhs, "i32.and")?
            }
            VOR_VV(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vv("VOR.VV", vd, lhs, rhs, "i32.or")?
            }
            VXOR_VV(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vv("VXOR.VV", vd, lhs, rhs, "i32.xor")?
            }
            VMUL_VV(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vv("VMUL.VV", vd, lhs, rhs, "i32.mul")?
            }

            VADD_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VADD.VX", vd, lhs, rhs, "i32.add", false)?
            }
            VSUB_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VSUB.VX", vd, lhs, rhs, "i32.sub", false)?
            }
            VRSUB_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VRSUB.VX", vd, lhs, rhs, "i32.sub", true)?
            }
            VAND_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VAND.VX", vd, lhs, rhs, "i32.and", false)?
            }
            VOR_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VOR.VX", vd, lhs, rhs, "i32.or", false)?
            }
            VXOR_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VXOR.VX", vd, lhs, rhs, "i32.xor", false)?
            }
            VMUL_VX(Rd(vd), Rs1(lhs), Rs2(rhs), VM(true)) => {
                self.emit_vector_binary_vx("VMUL.VX", vd, lhs, rhs, "i32.mul", false)?
            }

            VADD_VI(Rd(vd), Rs2(lhs), imm, VM(true)) => {
                self.emit_vector_binary_vi("VADD.VI", vd, lhs, imm.decode_sext(), "i32.add", false)?
            }
            VRSUB_VI(Rd(vd), Rs2(lhs), imm, VM(true)) => {
                self.emit_vector_binary_vi("VRSUB.VI", vd, lhs, imm.decode_sext(), "i32.sub", true)?
            }
            VAND_VI(Rd(vd), Rs2(lhs), imm, VM(true)) => {
                self.emit_vector_binary_vi("VAND.VI", vd, lhs, imm.decode_sext(), "i32.and", false)?
            }
            VOR_VI(Rd(vd), Rs2(lhs), imm, VM(true)) => {
                self.emit_vector_binary_vi("VOR.VI", vd, lhs, imm.decode_sext(), "i32.or", false)?
            }
            VXOR_VI(Rd(vd), Rs2(lhs), imm, VM(true)) => {
                self.emit_vector_binary_vi("VXOR.VI", vd, lhs, imm.decode_sext(), "i32.xor", false)?
            }

            VMV_V_V(Rd(vd), Rs1(src)) => self.emit_vector_move_vv(vd, src)?,
            VMV_V_X(Rd(vd), Rs1(src)) => self.emit_vector_splat_x(vd, src)?,
            VMV_V_I(Rd(vd), imm) => self.emit_vector_splat_i(vd, imm.decode_sext())?,
            VMV_X_S(Rd(rd), Rs2(src)) => self.emit_vector_move_x_s(rd, src)?,
            VMV_S_X(Rd(vd), Rs1(src)) => self.emit_vector_move_s_x(vd, src)?,

            // Vector arithmetic - all other vector instructions are stubs for now
            _ => {
                writeln!(
                    &mut self.wat_code,
                    "        ;; Vector instruction: {:?} - TODO",
                    instr
                )
                .unwrap();
            }
        }

        Ok(())
    }

    fn emit_vector_loop_header(&mut self, comment: &str) -> usize {
        let label_id = self.label_counter;
        self.label_counter += 1;
        writeln!(
            &mut self.wat_code,
            "        ;; {}\n        i32.const 0\n        local.set $i\n        global.get $vl\n        i32.wrap_i64\n        local.set $vl_i32\n        block $vector_done_{}\n          loop $vector_loop_{}\n            local.get $i\n            local.get $vl_i32\n            i32.ge_u\n            br_if $vector_done_{}",
            comment, label_id, label_id, label_id
        )
        .unwrap();
        label_id
    }

    fn emit_vector_loop_footer(&mut self, label_id: usize) {
        writeln!(
            &mut self.wat_code,
            "            local.get $i\n            i32.const 1\n            i32.add\n            local.set $i\n            br $vector_loop_{}\n          end\n        end",
            label_id
        )
        .unwrap();
    }

    fn emit_vreg_addr(&mut self, reg_num: i32, elem_bytes: i32) {
        writeln!(
            &mut self.wat_code,
            "            global.get $vreg_base\n            i32.const {}\n            i32.add\n            local.get $i\n            i32.const {}\n            i32.mul\n            i32.add",
            reg_num * VECTOR_REGISTER_BYTES,
            elem_bytes
        )
        .unwrap();
    }

    fn emit_memory_addr(&mut self, base_reg: usize, elem_bytes: i32) {
        writeln!(
            &mut self.wat_code,
            "            global.get $x{}\n            local.get $i\n            i64.extend_i32_u\n            i64.const {}\n            i64.mul\n            i64.add\n            call $vaddr_to_offset",
            base_reg, elem_bytes
        )
        .unwrap();
    }

    fn emit_vector_load(
        &mut self,
        name: &str,
        vd: &Reg,
        rs1: &Reg,
        elem_bytes: i32,
    ) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let rs1_num = self.reg_num(rs1)?;
        let label = self.emit_vector_loop_header(&format!("{} v{}, (x{})", name, vd_num, rs1_num));
        self.emit_vreg_addr(vd_num, elem_bytes);
        self.emit_memory_addr(rs1_num, elem_bytes);
        writeln!(
            &mut self.wat_code,
            "            {}\n            {}",
            load_op(elem_bytes),
            store_op(elem_bytes)
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_store(
        &mut self,
        name: &str,
        vs3: &Reg,
        rs1: &Reg,
        elem_bytes: i32,
    ) -> Result<(), String> {
        let vs3_num = self.reg_num(vs3)? as i32;
        let rs1_num = self.reg_num(rs1)?;
        let label = self.emit_vector_loop_header(&format!("{} v{}, (x{})", name, vs3_num, rs1_num));
        self.emit_memory_addr(rs1_num, elem_bytes);
        self.emit_vreg_addr(vs3_num, elem_bytes);
        writeln!(
            &mut self.wat_code,
            "            {}\n            {}",
            load_op(elem_bytes),
            store_op(elem_bytes)
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_binary_vv(
        &mut self,
        name: &str,
        vd: &Reg,
        lhs: &Reg,
        rhs: &Reg,
        op: &str,
    ) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let lhs_num = self.reg_num(lhs)? as i32;
        let rhs_num = self.reg_num(rhs)? as i32;
        let label = self
            .emit_vector_loop_header(&format!("{} v{}, v{}, v{}", name, vd_num, lhs_num, rhs_num));
        self.emit_vreg_addr(vd_num, 4);
        self.emit_vreg_addr(lhs_num, 4);
        writeln!(&mut self.wat_code, "            i32.load").unwrap();
        self.emit_vreg_addr(rhs_num, 4);
        writeln!(
            &mut self.wat_code,
            "            i32.load\n            {}\n            i32.store",
            op
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_binary_vx(
        &mut self,
        name: &str,
        vd: &Reg,
        lhs: &Reg,
        rhs: &Reg,
        op: &str,
        reverse: bool,
    ) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let lhs_num = self.reg_num(lhs)? as i32;
        let rhs_num = self.reg_num(rhs)?;
        let label = self
            .emit_vector_loop_header(&format!("{} v{}, v{}, x{}", name, vd_num, lhs_num, rhs_num));
        self.emit_vreg_addr(vd_num, 4);
        if reverse {
            writeln!(
                &mut self.wat_code,
                "            global.get $x{}\n            i32.wrap_i64",
                rhs_num
            )
            .unwrap();
            self.emit_vreg_addr(lhs_num, 4);
            writeln!(&mut self.wat_code, "            i32.load").unwrap();
        } else {
            self.emit_vreg_addr(lhs_num, 4);
            writeln!(
                &mut self.wat_code,
                "            i32.load\n            global.get $x{}\n            i32.wrap_i64",
                rhs_num
            )
            .unwrap();
        }
        writeln!(
            &mut self.wat_code,
            "            {}\n            i32.store",
            op
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_binary_vi(
        &mut self,
        name: &str,
        vd: &Reg,
        lhs: &Reg,
        imm: i32,
        op: &str,
        reverse: bool,
    ) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let lhs_num = self.reg_num(lhs)? as i32;
        let label =
            self.emit_vector_loop_header(&format!("{} v{}, v{}, {}", name, vd_num, lhs_num, imm));
        self.emit_vreg_addr(vd_num, 4);
        if reverse {
            writeln!(&mut self.wat_code, "            i32.const {}", imm).unwrap();
            self.emit_vreg_addr(lhs_num, 4);
            writeln!(&mut self.wat_code, "            i32.load").unwrap();
        } else {
            self.emit_vreg_addr(lhs_num, 4);
            writeln!(
                &mut self.wat_code,
                "            i32.load\n            i32.const {}",
                imm
            )
            .unwrap();
        }
        writeln!(
            &mut self.wat_code,
            "            {}\n            i32.store",
            op
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_move_vv(&mut self, vd: &Reg, src: &Reg) -> Result<(), String> {
        self.emit_vector_binary_vi("VMV.V.V", vd, src, 0, "i32.add", false)
    }

    fn emit_vector_splat_x(&mut self, vd: &Reg, src: &Reg) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let src_num = self.reg_num(src)?;
        let label = self.emit_vector_loop_header(&format!("VMV.V.X v{}, x{}", vd_num, src_num));
        self.emit_vreg_addr(vd_num, 4);
        writeln!(
            &mut self.wat_code,
            "            global.get $x{}\n            i32.wrap_i64\n            i32.store",
            src_num
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_splat_i(&mut self, vd: &Reg, imm: i32) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let label = self.emit_vector_loop_header(&format!("VMV.V.I v{}, {}", vd_num, imm));
        self.emit_vreg_addr(vd_num, 4);
        writeln!(
            &mut self.wat_code,
            "            i32.const {}\n            i32.store",
            imm
        )
        .unwrap();
        self.emit_vector_loop_footer(label);
        Ok(())
    }

    fn emit_vector_move_x_s(&mut self, rd: &Reg, src: &Reg) -> Result<(), String> {
        let rd_num = self.reg_num(rd)?;
        let src_num = self.reg_num(src)? as i32;
        writeln!(
            &mut self.wat_code,
            "        ;; VMV.X.S x{}, v{}\n        global.get $vreg_base\n        i32.const {}\n        i32.add\n        i32.load\n        i64.extend_i32_s",
            rd_num,
            src_num,
            src_num * VECTOR_REGISTER_BYTES
        )
        .unwrap();
        if rd_num != 0 {
            writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
        } else {
            writeln!(&mut self.wat_code, "        drop").unwrap();
        }
        Ok(())
    }

    fn emit_vector_move_s_x(&mut self, vd: &Reg, src: &Reg) -> Result<(), String> {
        let vd_num = self.reg_num(vd)? as i32;
        let src_num = self.reg_num(src)?;
        writeln!(
            &mut self.wat_code,
            "        ;; VMV.S.X v{}, x{}\n        global.get $vreg_base\n        i32.const {}\n        i32.add\n        global.get $x{}\n        i32.wrap_i64\n        i32.store",
            vd_num,
            src_num,
            vd_num * VECTOR_REGISTER_BYTES,
            src_num
        )
        .unwrap();
        Ok(())
    }

    fn emit_vsetvl_from_reg(
        &mut self,
        name: &str,
        rd_num: usize,
        rs1_num: usize,
        vtype: i64,
    ) -> Result<(), String> {
        let vlmax = vtype_vlmax(vtype as u32);
        writeln!(&mut self.wat_code, "        ;; {} - configure vector length\n        i64.const {}\n        global.set $vtype", name, vtype).unwrap();
        if rs1_num == 0 && rd_num == 0 {
            writeln!(&mut self.wat_code, "        global.get $vl").unwrap();
            self.emit_i64_min_const(vlmax);
        } else if rs1_num == 0 {
            writeln!(&mut self.wat_code, "        i64.const {}", vlmax).unwrap();
        } else {
            writeln!(&mut self.wat_code, "        global.get $x{}", rs1_num).unwrap();
            self.emit_i64_min_const(vlmax);
        }
        writeln!(&mut self.wat_code, "        global.set $vl").unwrap();
        self.emit_write_vl_to_rd(rd_num);
        Ok(())
    }

    fn emit_vsetvl_from_imm(
        &mut self,
        name: &str,
        rd_num: usize,
        avl: i64,
        vtype: i64,
    ) -> Result<(), String> {
        let vlmax = vtype_vlmax(vtype as u32);
        writeln!(&mut self.wat_code, "        ;; {} - configure vector length\n        i64.const {}\n        global.set $vtype\n        i64.const {}", name, vtype, avl).unwrap();
        self.emit_i64_min_const(vlmax);
        writeln!(&mut self.wat_code, "        global.set $vl").unwrap();
        self.emit_write_vl_to_rd(rd_num);
        Ok(())
    }

    fn emit_vsetvl_dynamic(
        &mut self,
        rd_num: usize,
        rs1_num: usize,
        rs2_num: usize,
    ) -> Result<(), String> {
        writeln!(&mut self.wat_code, "        ;; VSETVL - configure vector length\n        global.get $x{}\n        global.set $vtype", rs2_num).unwrap();
        if rs1_num == 0 && rd_num == 0 {
            writeln!(&mut self.wat_code, "        global.get $vl").unwrap();
        } else if rs1_num == 0 {
            writeln!(&mut self.wat_code, "        i64.const {}", VECTOR_I32_LANES).unwrap();
        } else {
            writeln!(&mut self.wat_code, "        global.get $x{}", rs1_num).unwrap();
        }
        self.emit_i64_min_const(VECTOR_I32_LANES);
        writeln!(&mut self.wat_code, "        global.set $vl").unwrap();
        self.emit_write_vl_to_rd(rd_num);
        Ok(())
    }

    fn emit_i64_min_const(&mut self, upper: i64) {
        writeln!(
            &mut self.wat_code,
            "        local.set $tmp_i64\n        local.get $tmp_i64\n        i64.const {}\n        i64.gt_u\n        if (result i64)\n          i64.const {}\n        else\n          local.get $tmp_i64\n        end",
            upper, upper
        )
        .unwrap();
    }

    fn emit_write_vl_to_rd(&mut self, rd_num: usize) {
        if rd_num != 0 {
            writeln!(
                &mut self.wat_code,
                "        global.get $vl\n        global.set $x{}",
                rd_num
            )
            .unwrap();
        }
    }

    /// Emit Zicsr CSR operations via runtime helpers
    fn emit_zicsr(&mut self, instr: &RVZcsr) -> Result<(), String> {
        use crate::frontend::instruction::RVZcsr::*;

        match instr {
            // rd <- oldcsr; csr <- rs1
            CSRRW(Rd(rd), Rs1(rs1), csr) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let csr_num = csr.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        ;; CSRRW rd, rs1, csr\n        i32.const {}\n        global.get $x{}\n        call $csr_read_write",
                    csr_num, rs1_num
                )
                .unwrap();
                if rd_num != 0 {
                    writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
                } else {
                    // Pop the returned value if x0 (discard)
                    writeln!(&mut self.wat_code, "        drop").unwrap();
                }
            }
            // rd <- oldcsr; if rs1 != x0 then csr <- csr | rs1
            CSRRS(Rd(rd), Rs1(rs1), csr) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let csr_num = csr.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        ;; CSRRS rd, rs1, csr\n        i32.const {}\n        global.get $x{}\n        call $csr_read_set",
                    csr_num, rs1_num
                )
                .unwrap();
                if rd_num != 0 {
                    writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
                } else {
                    writeln!(&mut self.wat_code, "        drop").unwrap();
                }
            }
            // rd <- oldcsr; if rs1 != x0 then csr <- csr & ~rs1
            CSRRC(Rd(rd), Rs1(rs1), csr) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let csr_num = csr.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        ;; CSRRC rd, rs1, csr\n        i32.const {}\n        global.get $x{}\n        call $csr_read_clear",
                    csr_num, rs1_num
                )
                .unwrap();
                if rd_num != 0 {
                    writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
                } else {
                    writeln!(&mut self.wat_code, "        drop").unwrap();
                }
            }
            // Immediate forms (uimm is 5-bit)
            CSRRWI(Rd(rd), uimm, csr) => {
                let rd_num = self.reg_num(rd)?;
                let imm_val = uimm.value() as i64;
                let csr_num = csr.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        ;; CSRRWI rd, uimm, csr\n        i32.const {}\n        i64.const {}\n        call $csr_read_write",
                    csr_num, imm_val
                )
                .unwrap();
                if rd_num != 0 {
                    writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
                } else {
                    writeln!(&mut self.wat_code, "        drop").unwrap();
                }
            }
            CSRRSI(Rd(rd), uimm, csr) => {
                let rd_num = self.reg_num(rd)?;
                let imm_val = uimm.value() as i64;
                let csr_num = csr.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        ;; CSRRSI rd, uimm, csr\n        i32.const {}\n        i64.const {}\n        call $csr_read_set",
                    csr_num, imm_val
                )
                .unwrap();
                if rd_num != 0 {
                    writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
                } else {
                    writeln!(&mut self.wat_code, "        drop").unwrap();
                }
            }
            CSRRCI(Rd(rd), uimm, csr) => {
                let rd_num = self.reg_num(rd)?;
                let imm_val = uimm.value() as i64;
                let csr_num = csr.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "        ;; CSRRCI rd, uimm, csr\n        i32.const {}\n        i64.const {}\n        call $csr_read_clear",
                    csr_num, imm_val
                )
                .unwrap();
                if rd_num != 0 {
                    writeln!(&mut self.wat_code, "        global.set $x{}", rd_num).unwrap();
                } else {
                    writeln!(&mut self.wat_code, "        drop").unwrap();
                }
            }
        }

        Ok(())
    }

    /// Get register number from Reg
    fn reg_num(&self, reg: &Reg) -> Result<usize, String> {
        match reg {
            Reg::X(xx) => Ok(xx.value() as usize),
            Reg::V(xx) => Ok(xx.value() as usize),
            _ => Err(format!("Unsupported register type: {:?}", reg)),
        }
    }
}

impl Default for WasmEmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::instruction::{Imm32, Xx, RVV};

    fn x(n: u32) -> Reg {
        Reg::X(Xx::new(n))
    }

    fn v(n: u32) -> Reg {
        Reg::V(Xx::new(n))
    }

    fn emit_rvv_wat(instr: RVV) -> String {
        let mut emitter = WasmEmitter::new();
        emitter.start_function("test");
        emitter.emit_rvv(&instr).unwrap();
        emitter.end_function();
        emitter.finalize()
    }

    #[test]
    fn test_emitter_creation() {
        let emitter = WasmEmitter::new();
        assert_eq!(emitter.instr_count, 0);
    }

    #[test]
    fn test_function_generation() {
        let mut emitter = WasmEmitter::new();
        emitter.start_function("test");
        emitter.end_function();
        let wat = emitter.finalize();
        assert!(wat.contains("(func $test"));
    }

    #[test]
    fn test_rvv_vsetvli_emits_vl_clamp() {
        let wat = emit_rvv_wat(RVV::VSETVLI(
            Rd(x(1)),
            Rs1(x(2)),
            Imm32::<30, 20>::from(0x0d0 << 20),
        ));
        assert!(wat.contains("global.set $vtype"));
        assert!(wat.contains("i64.const 208"));
        assert!(wat.contains("i64.const 64"));
        assert!(wat.contains("global.set $x1"));
    }

    #[test]
    fn test_rvv_unit_stride_load_emits_vl_loop() {
        let wat = emit_rvv_wat(RVV::VLE32_V(Rd(v(1)), Rs1(x(2)), VM(true)));
        assert!(wat.contains("VLE32.V v1, (x2)"));
        assert!(wat.contains("loop $vector_loop_"));
        assert!(wat.contains("global.get $vl"));
        assert!(wat.contains("i32.load"));
        assert!(wat.contains("i32.store"));
        assert!(wat.contains("i32.const 256"));
    }

    #[test]
    fn test_rvv_integer_vx_emits_scalar_operand() {
        let wat = emit_rvv_wat(RVV::VRSUB_VX(Rd(v(1)), Rs1(v(2)), Rs2(x(3)), VM(true)));
        assert!(wat.contains("VRSUB.VX v1, v2, x3"));
        assert!(wat.contains("global.get $x3"));
        assert!(wat.contains("i32.sub"));
        assert!(wat.contains("i32.store"));
    }

    #[test]
    fn test_rvv_generated_wat_is_valid() {
        let function = emit_rvv_wat(RVV::VLE32_V(Rd(v(1)), Rs1(x(2)), VM(true)));
        let module = format!(
            r#"(module
  (memory 1)
  (global $vreg_base (mut i32) (i32.const 0))
  (global $vl (mut i64) (i64.const 4))
  (global $vtype (mut i64) (i64.const 0))
  (global $x1 (mut i64) (i64.const 0))
  (global $x2 (mut i64) (i64.const 0))
  (func $vaddr_to_offset (param $vaddr i64) (result i32)
    local.get $vaddr
    i32.wrap_i64)
{}
)"#,
            function
        );
        let wasm = wasmer::wat2wasm(module.as_bytes()).unwrap();
        assert!(!wasm.is_empty());
    }
}
