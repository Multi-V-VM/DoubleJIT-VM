use crate::frontend::instruction::{
    Instruction, Instr, RV32Instr, RV64Instr, RV32I, RV64I, RV32M, RV64M, RVV, Reg, Xx, Rd, Rs1, Rs2
};
use std::fmt::Write as FmtWrite;

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
}

impl WasmEmitter {
    /// Create a new WasmEmitter
    pub fn new() -> Self {
        Self {
            wat_code: String::new(),
            instr_count: 0,
            in_block: false,
            label_counter: 0,
        }
    }

    /// Start a new function
    pub fn start_function(&mut self, name: &str) {
        writeln!(
            &mut self.wat_code,
            "  (func ${} (export \"{}\")",
            name, name
        )
        .unwrap();
        self.in_block = true;
    }

    /// Start an infinite loop (for interpreter-style execution)
    pub fn start_loop(&mut self) {
        writeln!(&mut self.wat_code, "    (loop $interpreter_loop").unwrap();
    }

    /// End the loop with exit flag check
    pub fn end_loop_with_exit_check(&mut self) {
        writeln!(&mut self.wat_code, "      ;; Check if program should exit").unwrap();
        writeln!(&mut self.wat_code, "      global.get $exit_flag").unwrap();
        writeln!(&mut self.wat_code, "      i32.const 0").unwrap();
        writeln!(&mut self.wat_code, "      i32.eq").unwrap();
        writeln!(&mut self.wat_code, "      br_if $interpreter_loop").unwrap();
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

    /// Emit a single RISC-V instruction as WAT
    pub fn emit_instruction(&mut self, pc: u64, instr: &Instruction) -> Result<(), String> {
        // Wrap instruction in PC check - only execute if PC matches
        writeln!(
            &mut self.wat_code,
            "      ;; PC=0x{:08x}: {:?}\n      global.get $pc\n      i64.const {}\n      i64.eq\n      if\n        ;; Increment execution counter\n        global.get $instr_count\n        i64.const 1\n        i64.add\n        global.set $instr_count",
            pc, instr.instr, pc as i64
        )
        .unwrap();

        // Check if this instruction modifies PC (branches/jumps)
        // Note: RV64 programs also use RV32I base instructions including jumps/branches
        let modifies_pc = matches!(
            &instr.instr,
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

        match &instr.instr {
            Instr::RV32(rv32instr) => match rv32instr {
                RV32Instr::RV32I(rv32i) => self.emit_rv32i(rv32i)?,
                RV32Instr::RV32M(rv32m) => self.emit_rv32m(rv32m)?,
                RV32Instr::RVV(rvv) => self.emit_rvv(rvv)?,
                _ => {
                    writeln!(&mut self.wat_code, "    ;; TODO: RV32 instruction {:?}", rv32instr)
                        .unwrap();
                }
            },
            Instr::RV64(rv64instr) => match rv64instr {
                RV64Instr::RV64I(rv64i) => self.emit_rv64i(rv64i)?,
                RV64Instr::RV64M(rv64m) => self.emit_rv64m(rv64m)?,
                RV64Instr::RV64V(rvv) => self.emit_rvv(rvv)?,
                _ => {
                    writeln!(&mut self.wat_code, "    ;; TODO: RV64 instruction {:?}", rv64instr)
                        .unwrap();
                }
            },
            Instr::NOP => {
                writeln!(&mut self.wat_code, "    ;; NOP").unwrap();
            }
            _ => {
                writeln!(&mut self.wat_code, "    ;; TODO: instruction {:?}", instr.instr)
                    .unwrap();
            }
        }

        // Update PC to next instruction (PC += 4)
        // Skip this for branch/jump instructions since they set PC themselves
        if !modifies_pc {
            writeln!(
                &mut self.wat_code,
                "        global.get $pc\n        i64.const 4\n        i64.add\n        global.set $pc"
            )
            .unwrap();
        }

        // Close the if block
        writeln!(&mut self.wat_code, "      end").unwrap();

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
                    "    i64.const {}\n    global.set $x{}",
                    (imm_val << 12) as i64,
                    rd_num
                )
                .unwrap();
            }

            AUIPC(Rd(rd), imm) => {
                // rd = pc + (imm << 12)
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $pc\n    i64.const {}\n    i64.add\n    global.set $x{}",
                    (imm_val << 12) as i64,
                    rd_num
                )
                .unwrap();
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
                        "    ;; Jump (no return address saved to x0)\n    global.get $pc\n    i64.const {}\n    i64.add\n    global.set $pc",
                        imm_val as i64
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut self.wat_code,
                        "    ;; Save return address\n    global.get $pc\n    i64.const 4\n    i64.add\n    global.set $x{}\n    ;; Jump\n    global.get $pc\n    i64.const {}\n    i64.add\n    global.set $pc",
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
                        "    ;; Compute target (no return address saved to x0)\n    global.get $x{}\n    i64.const {}\n    i64.add\n    i64.const -2\n    i64.and\n    global.set $pc",
                        rs1_num, imm_val as i64
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut self.wat_code,
                        "    ;; Save return address\n    global.get $pc\n    i64.const 4\n    i64.add\n    global.set $x{}\n    ;; Compute target\n    global.get $x{}\n    i64.const {}\n    i64.add\n    i64.const -2\n    i64.and\n    global.set $pc",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.eq\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    else\n      global.get $pc\n      i64.const 4\n      i64.add\n      global.set $pc\n    end",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.ne\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    else\n      global.get $pc\n      i64.const 4\n      i64.add\n      global.set $pc\n    end",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.lt_s\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    else\n      global.get $pc\n      i64.const 4\n      i64.add\n      global.set $pc\n    end",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.ge_s\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    else\n      global.get $pc\n      i64.const 4\n      i64.add\n      global.set $pc\n    end",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.lt_u\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    else\n      global.get $pc\n      i64.const 4\n      i64.add\n      global.set $pc\n    end",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.ge_u\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    else\n      global.get $pc\n      i64.const 4\n      i64.add\n      global.set $pc\n    end",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i32.load8_s\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i32.load16_s\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i32.load\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i32.load8_u\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i32.load16_u\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    global.get $x{}\n    i32.wrap_i64\n    i32.store8",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    global.get $x{}\n    i32.wrap_i64\n    i32.store16",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    global.get $x{}\n    i32.wrap_i64\n    i32.store",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLTI(Rd(rd), Rs1(rs1), imm) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.decode() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.lt_s\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.lt_u\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.xor\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.or\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.and\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shl\n    global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shr_u\n    global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRAI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shr_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.add\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.sub\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.const 31\n    i64.and\n    i64.shl\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.lt_s\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.lt_u\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.xor\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.const 31\n    i64.and\n    i64.shr_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.const 31\n    i64.and\n    i64.shr_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.or\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.and\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            FENCE(_, _, _, _, _) => {
                writeln!(&mut self.wat_code, "    ;; FENCE (no-op in WASM)").unwrap();
            }

            FENCE_TSO => {
                writeln!(&mut self.wat_code, "    ;; FENCE.TSO (no-op in WASM)").unwrap();
            }

            PAUSE => {
                writeln!(&mut self.wat_code, "    ;; PAUSE (no-op in WASM)").unwrap();
            }

            ECALL => {
                // RISC-V syscall convention:
                // a7 (x17) = syscall number
                // a0-a5 (x10-x15) = arguments
                // Result returned in a0 (x10)
                writeln!(
                    &mut self.wat_code,
                    "    ;; ECALL - RISC-V syscall\n    global.get $x17\n    global.get $x10\n    global.get $x11\n    global.get $x12\n    global.get $x13\n    global.get $x14\n    global.get $x15\n    call $syscall\n    global.set $x10"
                )
                .unwrap();
            }

            EBREAK => {
                writeln!(&mut self.wat_code, "    ;; EBREAK (debug trap)").unwrap();
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i32.load\n    i64.extend_i32_u\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    i64.load\n    global.set $x{}",
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
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    call $vaddr_to_offset\n    global.get $x{}\n    i64.store",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            SLLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shl\n    global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRLI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shr_u\n    global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRAI(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shr_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.add\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, imm_val, rd_num
                )
                .unwrap();
            }

            SLLIW(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.shl\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRLIW(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.shr_u\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, shamt.0, rd_num
                )
                .unwrap();
            }

            SRAIW(Rd(rd), Rs1(rs1), shamt) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.shr_s\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.add\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.sub\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.const 31\n    i32.and\n    i32.shl\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.const 31\n    i32.and\n    i32.shr_u\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.const 31\n    i32.and\n    i32.shr_s\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    global.get $x{}\n    global.get $x{}\n    i64.mul\n    global.set $x{}",
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
                    "    ;; MULH - high part of signed multiplication\n    ;; TODO: implement 128-bit multiplication\n    global.get $x{}\n    global.get $x{}\n    i64.mul\n    i64.const 32\n    i64.shr_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            MULHSU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; MULHSU - TODO\n    i64.const 0\n    global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            MULHU(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; MULHU - TODO\n    i64.const 0\n    global.set $x{}",
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
                    "    ;; DIV - signed division with zero check\n    global.get $x{}\n    i64.eqz\n    if\n      i64.const -1\n      global.set $x{}\n    else\n      global.get $x{}\n      global.get $x{}\n      i64.div_s\n      global.set $x{}\n    end",
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
                    "    ;; DIVU - unsigned division with zero check\n    global.get $x{}\n    i64.eqz\n    if\n      i64.const -1\n      global.set $x{}\n    else\n      global.get $x{}\n      global.get $x{}\n      i64.div_u\n      global.set $x{}\n    end",
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
                    "    ;; REM - signed remainder with zero check\n    global.get $x{}\n    i64.eqz\n    if\n      global.get $x{}\n      global.set $x{}\n    else\n      global.get $x{}\n      global.get $x{}\n      i64.rem_s\n      global.set $x{}\n    end",
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
                    "    ;; REMU - unsigned remainder with zero check\n    global.get $x{}\n    i64.eqz\n    if\n      global.get $x{}\n      global.set $x{}\n    else\n      global.get $x{}\n      global.get $x{}\n      i64.rem_u\n      global.set $x{}\n    end",
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
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.mul\n    i64.extend_i32_s\n    global.set $x{}",
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
                    "    ;; DIVW - 32-bit signed division with zero check\n    global.get $x{}\n    i32.wrap_i64\n    i32.eqz\n    if\n      i64.const -1\n      global.set $x{}\n    else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.div_s\n      i64.extend_i32_s\n      global.set $x{}\n    end",
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
                    "    ;; DIVUW - 32-bit unsigned division with zero check\n    global.get $x{}\n    i32.wrap_i64\n    i32.eqz\n    if\n      i64.const -1\n      global.set $x{}\n    else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.div_u\n      i64.extend_i32_s\n      global.set $x{}\n    end",
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
                    "    ;; REMW - 32-bit signed remainder with zero check\n    global.get $x{}\n    i32.wrap_i64\n    i32.eqz\n    if\n      global.get $x{}\n      global.set $x{}\n    else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.rem_s\n      i64.extend_i32_s\n      global.set $x{}\n    end",
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
                    "    ;; REMUW - 32-bit unsigned remainder with zero check\n    global.get $x{}\n    i32.wrap_i64\n    i32.eqz\n    if\n      global.get $x{}\n      global.set $x{}\n    else\n      global.get $x{}\n      i32.wrap_i64\n      global.get $x{}\n      i32.wrap_i64\n      i32.rem_u\n      i64.extend_i32_s\n      global.set $x{}\n    end",
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
            VSETVLI(Rd(rd), Rs1(rs1), _) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; VSETVLI - configure vector length\n    global.get $x{}\n    global.set $vl\n    global.get $vl\n    global.set $x{}",
                    rs1_num, rd_num
                )
                .unwrap();
            }

            VSETIVLI(Rd(rd), _) => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; VSETIVLI - configure vector length (immediate)\n    ;; TODO: parse immediate\n    i64.const 0\n    global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            VSETVL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; VSETVL - configure vector length\n    global.get $x{}\n    global.set $vl\n    global.get $x{}\n    global.set $vtype\n    global.get $vl\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            // Vector arithmetic - all other vector instructions are stubs for now
            _ => {
                writeln!(
                    &mut self.wat_code,
                    "    ;; Vector instruction: {:?} - TODO",
                    instr
                )
                .unwrap();
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
}
