use crate::frontend::instruction::{Instruction, RV32I, RV64I, RV32M, RV64M, RVV, Reg, Xx};
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
        // Add PC update comment
        writeln!(
            &mut self.wat_code,
            "    ;; PC=0x{:08x}: {:?}",
            pc, instr
        )
        .unwrap();

        match instr {
            Instruction::RV32I(rv32i) => self.emit_rv32i(rv32i)?,
            Instruction::RV64I(rv64i) => self.emit_rv64i(rv64i)?,
            Instruction::RV32M(rv32m) => self.emit_rv32m(rv32m)?,
            Instruction::RV64M(rv64m) => self.emit_rv64m(rv64m)?,
            Instruction::RV32A(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV32A atomic instructions")
                    .unwrap();
            }
            Instruction::RV64A(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV64A atomic instructions")
                    .unwrap();
            }
            Instruction::RV32F(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV32F float instructions")
                    .unwrap();
            }
            Instruction::RV64F(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV64F float instructions")
                    .unwrap();
            }
            Instruction::RV32D(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV32D double instructions")
                    .unwrap();
            }
            Instruction::RV64D(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV64D double instructions")
                    .unwrap();
            }
            Instruction::RV64V(rvv) => self.emit_rvv(rvv)?,
            Instruction::RV32Zifencei(_) => {
                writeln!(&mut self.wat_code, "    ;; FENCE.I (no-op in WASM)").unwrap();
            }
            Instruction::RV64Zifencei(_) => {
                writeln!(&mut self.wat_code, "    ;; FENCE.I (no-op in WASM)").unwrap();
            }
            Instruction::RV32Zicsr(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV32 CSR instructions")
                    .unwrap();
            }
            Instruction::RV64Zicsr(_) => {
                writeln!(&mut self.wat_code, "    ;; TODO: RV64 CSR instructions")
                    .unwrap();
            }
            _ => {
                return Err(format!("Unsupported instruction: {:?}", instr));
            }
        }

        // Update PC
        writeln!(
            &mut self.wat_code,
            "    global.get $pc\n    i64.const 4\n    i64.add\n    global.set $pc"
        )
        .unwrap();

        self.instr_count += 1;
        Ok(())
    }

    /// Emit RV32I instruction
    fn emit_rv32i(&mut self, instr: &RV32I) -> Result<(), String> {
        use crate::frontend::instruction::RV32I::*;

        match instr {
            LUI { rd, imm } => {
                // rd = imm << 12 (sign-extended)
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    i64.const {}\n    global.set $x{}",
                    (imm_val << 12) as i64,
                    rd_num
                )
                .unwrap();
            }

            AUIPC { rd, imm } => {
                // rd = pc + (imm << 12)
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $pc\n    i64.const {}\n    i64.add\n    global.set $x{}",
                    (imm_val << 12) as i64,
                    rd_num
                )
                .unwrap();
            }

            JAL { rd, imm } => {
                // rd = pc + 4; pc = pc + imm
                let rd_num = self.reg_num(rd)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    ;; Save return address\n    global.get $pc\n    i64.const 4\n    i64.add\n    global.set $x{}\n    ;; Jump\n    global.get $pc\n    i64.const {}\n    i64.add\n    global.set $pc",
                    rd_num, imm_val as i64
                )
                .unwrap();
            }

            JALR { rd, rs1, imm } => {
                // rd = pc + 4; pc = (rs1 + imm) & ~1
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    ;; Save return address\n    global.get $pc\n    i64.const 4\n    i64.add\n    global.set $x{}\n    ;; Compute target\n    global.get $x{}\n    i64.const {}\n    i64.add\n    i64.const -2\n    i64.and\n    global.set $pc",
                    rd_num, rs1_num, imm_val as i64
                )
                .unwrap();
            }

            BEQ { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.eq\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BNE { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.ne\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BLT { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.lt_s\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BGE { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.ge_s\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BLTU { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.lt_u\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            BGEU { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.ge_u\n    if\n      global.get $pc\n      i64.const {}\n      i64.add\n      global.set $pc\n    end",
                    rs1_num, rs2_num, imm_val as i64
                )
                .unwrap();
            }

            LB { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i32.load8_s\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LH { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i32.load16_s\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LW { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i32.load\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LBU { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i32.load8_u\n    i64.extend_i32_u\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LHU { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i32.load16_u\n    i64.extend_i32_u\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SB { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.store8",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            SH { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.store16",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            SW { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.store",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            ADDI { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLTI { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.lt_s\n    i64.extend_i32_u\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLTIU { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as u32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.lt_u\n    i64.extend_i32_u\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            XORI { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.xor\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            ORI { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.or\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            ANDI { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.and\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SLLI { rd, rs1, shamt } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shl\n    global.set $x{}",
                    rs1_num, shamt.value(), rd_num
                )
                .unwrap();
            }

            SRLI { rd, rs1, shamt } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shr_u\n    global.set $x{}",
                    rs1_num, shamt.value(), rd_num
                )
                .unwrap();
            }

            SRAI { rd, rs1, shamt } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.shr_s\n    global.set $x{}",
                    rs1_num, shamt.value(), rd_num
                )
                .unwrap();
            }

            ADD { rd, rs1, rs2 } => {
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

            SUB { rd, rs1, rs2 } => {
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

            SLL { rd, rs1, rs2 } => {
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

            SLT { rd, rs1, rs2 } => {
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

            SLTU { rd, rs1, rs2 } => {
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

            XOR { rd, rs1, rs2 } => {
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

            SRL { rd, rs1, rs2 } => {
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

            SRA { rd, rs1, rs2 } => {
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

            OR { rd, rs1, rs2 } => {
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

            AND { rd, rs1, rs2 } => {
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

            FENCE { .. } => {
                writeln!(&mut self.wat_code, "    ;; FENCE (no-op in WASM)").unwrap();
            }

            ECALL => {
                writeln!(
                    &mut self.wat_code,
                    "    ;; ECALL\n    global.get $x10\n    global.get $x11\n    global.get $x12\n    global.get $x13\n    global.get $x14\n    global.get $x15\n    global.get $x16\n    call $syscall\n    global.set $x10"
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
            LWU { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i32.load\n    i64.extend_i32_u\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            LD { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    i64.load\n    global.set $x{}",
                    rs1_num, imm_val as i64, rd_num
                )
                .unwrap();
            }

            SD { rs1, rs2, imm } => {
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i64.const {}\n    i64.add\n    i32.wrap_i64\n    global.get $x{}\n    i64.store",
                    rs1_num, imm_val as i64, rs2_num
                )
                .unwrap();
            }

            ADDIW { rd, rs1, imm } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let imm_val = imm.value() as i32;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.add\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, imm_val, rd_num
                )
                .unwrap();
            }

            SLLIW { rd, rs1, shamt } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.shl\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, shamt.value(), rd_num
                )
                .unwrap();
            }

            SRLIW { rd, rs1, shamt } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.shr_u\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, shamt.value(), rd_num
                )
                .unwrap();
            }

            SRAIW { rd, rs1, shamt } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    i32.const {}\n    i32.shr_s\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, shamt.value(), rd_num
                )
                .unwrap();
            }

            ADDW { rd, rs1, rs2 } => {
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

            SUBW { rd, rs1, rs2 } => {
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

            SLLW { rd, rs1, rs2 } => {
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

            SRLW { rd, rs1, rs2 } => {
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

            SRAW { rd, rs1, rs2 } => {
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
            MUL { rd, rs1, rs2 } => {
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

            MULH { rd, rs1, rs2 } => {
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

            MULHSU { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; MULHSU - TODO\n    i64.const 0\n    global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            MULHU { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; MULHU - TODO\n    i64.const 0\n    global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            DIV { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.div_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            DIVU { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.div_u\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REM { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.rem_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REMU { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    global.get $x{}\n    i64.rem_u\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
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
            MULW { rd, rs1, rs2 } => {
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

            DIVW { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.div_s\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            DIVUW { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.div_u\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REMW { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.rem_s\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
                )
                .unwrap();
            }

            REMUW { rd, rs1, rs2 } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                let rs2_num = self.reg_num(rs2)?;
                writeln!(
                    &mut self.wat_code,
                    "    global.get $x{}\n    i32.wrap_i64\n    global.get $x{}\n    i32.wrap_i64\n    i32.rem_u\n    i64.extend_i32_s\n    global.set $x{}",
                    rs1_num, rs2_num, rd_num
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
            VSETVLI { rd, rs1, .. } => {
                let rd_num = self.reg_num(rd)?;
                let rs1_num = self.reg_num(rs1)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; VSETVLI - configure vector length\n    global.get $x{}\n    global.set $vl\n    global.get $vl\n    global.set $x{}",
                    rs1_num, rd_num
                )
                .unwrap();
            }

            VSETIVLI { rd, .. } => {
                let rd_num = self.reg_num(rd)?;
                writeln!(
                    &mut self.wat_code,
                    "    ;; VSETIVLI - configure vector length (immediate)\n    ;; TODO: parse immediate\n    i64.const 0\n    global.set $x{}",
                    rd_num
                )
                .unwrap();
            }

            VSETVL { rd, rs1, rs2 } => {
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
            Reg::X(xx) => Ok(xx.inner() as usize),
            Reg::V(xx) => Ok(xx.inner() as usize),
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
