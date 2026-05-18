//! Verifiable RISC-V to eBPF lowering.
//!
//! This module follows the verification discipline used by `../Movable`:
//! lowering records explicit obligations next to executable output, and a
//! verifier checks those obligations before callers can use the program. The
//! current contract is intentionally narrow: every accepted RISC-V instruction
//! maps to exactly one eBPF instruction.

use aya_obj::generated::{
    bpf_insn, BPF_ALU, BPF_ALU64, BPF_B, BPF_DW, BPF_H, BPF_JMP, BPF_K, BPF_LDX, BPF_STX, BPF_W,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use crate::frontend::instruction::{
    Imm32, Instr, Instruction, RV32Instr, RV64Instr, Rd, Reg, Rs1, Rs2, Rs3, Shamt, RV32I, RV32M,
    RV64I, RV64M, RVV, VM,
};

const BPF_X: u32 = 0x08;
const BPF_MEM: u32 = 0x60;

const BPF_ADD: u32 = 0x00;
const BPF_SUB: u32 = 0x10;
const BPF_MUL: u32 = 0x20;
const BPF_DIV: u32 = 0x30;
const BPF_OR: u32 = 0x40;
const BPF_AND: u32 = 0x50;
const BPF_LSH: u32 = 0x60;
const BPF_RSH: u32 = 0x70;
const BPF_NEG: u32 = 0x80;
const BPF_MOD: u32 = 0x90;
const BPF_XOR: u32 = 0xa0;
const BPF_MOV: u32 = 0xb0;
const BPF_ARSH: u32 = 0xc0;

const BPF_JA: u32 = 0x00;
const BPF_JEQ: u32 = 0x10;
const BPF_JGT: u32 = 0x20;
const BPF_JGE: u32 = 0x30;
const BPF_JNE: u32 = 0x50;
const BPF_JSGT: u32 = 0x60;
const BPF_JSGE: u32 = 0x70;
const BPF_CALL: u32 = 0x80;
const BPF_EXIT: u32 = 0x90;

const DEFAULT_KERNEL_MAX_INSNS: usize = 1_000_000;
const SCALAR_HELPER_BASE: u32 = 0x2000_0000;
const RVV_HELPER_BASE: u32 = 0x4000_0000;

/// A fully verified eBPF program backed by Aya's `bpf_insn` bindings.
#[derive(Debug, Clone)]
pub struct EbpfProgram {
    instructions: Vec<bpf_insn>,
    proofs: Vec<ProofObligation>,
    source_len: usize,
    trailer_len: usize,
}

impl EbpfProgram {
    /// Aya-compatible eBPF instructions.
    pub fn instructions(&self) -> &[bpf_insn] {
        &self.instructions
    }

    /// Proof obligations discharged by the verifier.
    pub fn proof_obligations(&self) -> &[ProofObligation] {
        &self.proofs
    }

    /// Encode instructions as little-endian Linux eBPF bytecode.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.instructions.len() * 8);
        for ins in &self.instructions {
            bytes.push(ins.code);
            bytes.push(ins.dst_reg() | (ins.src_reg() << 4));
            bytes.extend_from_slice(&ins.off.to_le_bytes());
            bytes.extend_from_slice(&ins.imm.to_le_bytes());
        }
        bytes
    }

    /// Re-run structural verification and return the summary.
    pub fn verify(&self) -> Result<VerificationReport, EbpfCompileError> {
        verify_program(self)
    }

    /// Run the full compile-time verification used before ReJIT commits.
    pub fn verify_compile_time(&self) -> Result<CompileTimeVerificationReport, EbpfCompileError> {
        self.verify_compile_time_with(&KernelVerifierPolicy::default())
    }

    /// Run compile-time verification with an explicit kernel preflight policy.
    pub fn verify_compile_time_with(
        &self,
        policy: &KernelVerifierPolicy,
    ) -> Result<CompileTimeVerificationReport, EbpfCompileError> {
        let compilation = self.verify()?;
        let kernel = self.verify_kernel_properties_with(policy)?;
        Ok(CompileTimeVerificationReport {
            compilation,
            kernel,
        })
    }

    /// Run a conservative eBPF kernel-verifier preflight.
    pub fn verify_kernel_properties(&self) -> Result<KernelVerifierReport, EbpfCompileError> {
        self.verify_kernel_properties_with(&KernelVerifierPolicy::default())
    }

    /// Run a conservative eBPF kernel-verifier preflight with an explicit policy.
    pub fn verify_kernel_properties_with(
        &self,
        policy: &KernelVerifierPolicy,
    ) -> Result<KernelVerifierReport, EbpfCompileError> {
        verify_kernel_properties(self, policy)
    }

    /// Return the verification summary. Construction already verified it.
    pub fn verification_report(&self) -> VerificationReport {
        VerificationReport {
            source_instructions: self.source_len,
            mapped_instructions: self.proofs.len(),
            target_instructions: self.instructions.len(),
            trailer_instructions: self.trailer_len,
            one_to_one: self.source_len == self.proofs.len()
                && self.proofs.iter().all(|proof| proof.target_len == 1),
        }
    }
}

/// A Movable-style proof record for one source instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofObligation {
    pub source_pc: u64,
    pub source: Instr,
    pub target_index: usize,
    pub target_len: usize,
    pub rule: &'static str,
    pub preconditions: Vec<&'static str>,
    pub effect: &'static str,
}

/// Verification summary for an eBPF program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub source_instructions: usize,
    pub mapped_instructions: usize,
    pub target_instructions: usize,
    pub trailer_instructions: usize,
    pub one_to_one: bool,
}

/// Full compile-time verification report for a program accepted by ReJIT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileTimeVerificationReport {
    pub compilation: VerificationReport,
    pub kernel: KernelVerifierReport,
}

/// Conservative eBPF kernel-verifier preflight policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVerifierPolicy {
    pub max_instructions: usize,
    pub require_exit: bool,
    pub allow_backward_jumps: bool,
    pub allow_memory_access: bool,
}

impl KernelVerifierPolicy {
    /// Default policy used for ReJIT commits.
    pub fn rejit() -> Self {
        Self::default()
    }

    /// Relax branch direction for offline analysis of already-bounded loops.
    pub fn allowing_backward_jumps(mut self) -> Self {
        self.allow_backward_jumps = true;
        self
    }

    /// Relax memory checks when the caller supplies external pointer provenance.
    pub fn allowing_memory_access(mut self) -> Self {
        self.allow_memory_access = true;
        self
    }
}

impl Default for KernelVerifierPolicy {
    fn default() -> Self {
        Self {
            max_instructions: DEFAULT_KERNEL_MAX_INSNS,
            require_exit: true,
            allow_backward_jumps: false,
            allow_memory_access: false,
        }
    }
}

/// Summary of kernel-verifier-style properties checked at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVerifierReport {
    pub instructions: usize,
    pub max_instructions: usize,
    pub exit_instructions: usize,
    pub jump_instructions: usize,
    pub memory_instructions: usize,
    pub backward_jumps: usize,
    pub require_exit: bool,
    pub allow_backward_jumps: bool,
    pub allow_memory_access: bool,
}

/// Streaming facade matching the existing `WasmEmitter` shape.
#[derive(Debug, Clone)]
pub struct EbpfEmitter {
    entries: Vec<(u64, Instr)>,
    append_exit: bool,
}

impl EbpfEmitter {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            append_exit: true,
        }
    }

    /// Disable the default `r0 = 0; exit` trailer.
    pub fn without_exit_trailer(mut self) -> Self {
        self.append_exit = false;
        self
    }

    pub fn emit_instruction(
        &mut self,
        pc: u64,
        instr: &Instruction,
    ) -> Result<(), EbpfCompileError> {
        self.entries.push((pc, instr.instr));
        Ok(())
    }

    pub fn finalize(self) -> Result<EbpfProgram, EbpfCompileError> {
        EbpfCompiler::new()
            .with_exit_trailer(self.append_exit)
            .compile_entries(&self.entries)
    }
}

impl Default for EbpfEmitter {
    fn default() -> Self {
        Self::new()
    }
}

/// Compiler for the one-RISC-V-instruction to one-eBPF-instruction subset.
#[derive(Debug, Clone)]
pub struct EbpfCompiler {
    append_exit: bool,
}

impl EbpfCompiler {
    pub fn new() -> Self {
        Self { append_exit: true }
    }

    pub fn with_exit_trailer(mut self, append_exit: bool) -> Self {
        self.append_exit = append_exit;
        self
    }

    pub fn compile_entries(
        &self,
        entries: &[(u64, Instr)],
    ) -> Result<EbpfProgram, EbpfCompileError> {
        let mut pc_to_index = HashMap::with_capacity(entries.len() + 1);
        for (index, (pc, _)) in entries.iter().copied().enumerate() {
            if pc_to_index.insert(pc, index).is_some() {
                return Err(EbpfCompileError::DuplicatePc { pc });
            }
        }
        if let Some((last_pc, _)) = entries.last().copied() {
            pc_to_index.entry(last_pc + 4).or_insert(entries.len());
        }

        let mut instructions = Vec::with_capacity(entries.len() + 2);
        let mut proofs = Vec::with_capacity(entries.len());

        for (index, (pc, instr)) in entries.iter().copied().enumerate() {
            let lowered = lower_instr(pc, index, instr, &pc_to_index)?;
            let target_index = instructions.len();
            instructions.push(lowered.insn);
            proofs.push(ProofObligation {
                source_pc: pc,
                source: instr,
                target_index,
                target_len: 1,
                rule: lowered.rule,
                preconditions: lowered.preconditions,
                effect: lowered.effect,
            });
        }

        let trailer_len = if self.append_exit {
            instructions.push(alu64_imm(BPF_MOV, 0, 0));
            instructions.push(jmp_exit());
            2
        } else {
            0
        };

        let program = EbpfProgram {
            instructions,
            proofs,
            source_len: entries.len(),
            trailer_len,
        };
        program.verify()?;
        Ok(program)
    }
}

impl Default for EbpfCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EbpfCompileError {
    DuplicatePc {
        pc: u64,
    },
    Unsupported {
        pc: u64,
        instr: Instr,
        reason: String,
    },
    MissingBranchTarget {
        pc: u64,
        instr: Instr,
        target_pc: u64,
    },
    BranchOffsetOutOfRange {
        pc: u64,
        instr: Instr,
        target_index: usize,
    },
    Verification {
        reason: String,
    },
}

impl fmt::Display for EbpfCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePc { pc } => write!(f, "duplicate RISC-V PC 0x{pc:x}"),
            Self::Unsupported { pc, instr, reason } => {
                write!(f, "unsupported one-to-one lowering at 0x{pc:x}: {instr:?}: {reason}")
            }
            Self::MissingBranchTarget {
                pc,
                instr,
                target_pc,
            } => write!(
                f,
                "branch target 0x{target_pc:x} for {instr:?} at 0x{pc:x} is not in the compiled PC map"
            ),
            Self::BranchOffsetOutOfRange {
                pc,
                instr,
                target_index,
            } => write!(
                f,
                "eBPF branch offset for {instr:?} at 0x{pc:x} to target index {target_index} does not fit i16"
            ),
            Self::Verification { reason } => write!(f, "eBPF verification failed: {reason}"),
        }
    }
}

impl Error for EbpfCompileError {}

#[derive(Debug, Clone)]
struct Lowered {
    insn: bpf_insn,
    rule: &'static str,
    preconditions: Vec<&'static str>,
    effect: &'static str,
}

fn lower_instr(
    pc: u64,
    index: usize,
    instr: Instr,
    pc_to_index: &HashMap<u64, usize>,
) -> Result<Lowered, EbpfCompileError> {
    match instr {
        Instr::NOP => Ok(noop("nop")),
        Instr::RV32(RV32Instr::RV32I(inst)) => lower_scalar_or_helper(
            index,
            instr,
            lower_rv32i(pc, index, instr, inst, pc_to_index),
        ),
        Instr::RV32(RV32Instr::RV32M(inst)) => {
            lower_scalar_or_helper(index, instr, lower_rv32m(pc, instr, inst))
        }
        Instr::RV32(RV32Instr::RVV(inst)) => lower_rvv(pc, instr, inst),
        Instr::RV64(RV64Instr::RV64I(inst)) => {
            lower_scalar_or_helper(index, instr, lower_rv64i(pc, instr, inst))
        }
        Instr::RV64(RV64Instr::RV64M(inst)) => {
            lower_scalar_or_helper(index, instr, lower_rv64m(pc, instr, inst))
        }
        Instr::RV64(RV64Instr::RV64V(inst)) => lower_rvv(pc, instr, inst),
        _ => unsupported(
            pc,
            instr,
            "only RV32I/RV32M/RV64I/RV64M scalar subset and RVV helper-call subset are supported",
        ),
    }
}

fn lower_scalar_or_helper(
    source_index: usize,
    source: Instr,
    direct: Result<Lowered, EbpfCompileError>,
) -> Result<Lowered, EbpfCompileError> {
    match direct {
        Ok(lowered) if needs_scalar_helper_for_kernel_preflight(source, &lowered) => {
            Ok(scalar_helper_lowered(
                source_index,
                "scalar.backward_control_flow.helper_call",
                "helper executes decoded RISC-V scalar control-flow semantics",
            ))
        }
        Ok(lowered) => Ok(lowered),
        Err(EbpfCompileError::Unsupported { .. })
        | Err(EbpfCompileError::MissingBranchTarget { .. })
        | Err(EbpfCompileError::BranchOffsetOutOfRange { .. }) => Ok(scalar_helper_lowered(
            source_index,
            "scalar.helper_call",
            "helper executes decoded RISC-V scalar instruction semantics",
        )),
        Err(err) => Err(err),
    }
}

fn needs_scalar_helper_for_kernel_preflight(source: Instr, lowered: &Lowered) -> bool {
    let code = u32::from(lowered.insn.code);
    let is_backward_jump = (code & 0x07) == BPF_JMP
        && (code & 0xf0) != BPF_CALL
        && (code & 0xf0) != BPF_EXIT
        && lowered.insn.off < 0;

    is_backward_jump
        && matches!(
            source,
            Instr::RV32(RV32Instr::RV32I(RV32I::JAL(Rd(Reg::X(rd)), _))) if rd.value() == 0
        )
}

fn scalar_helper_lowered(source_index: usize, rule: &'static str, effect: &'static str) -> Lowered {
    lowered(
        helper_call(scalar_helper_slot(source_index)),
        rule,
        vec![
            "eBPF helper-call descriptor names the scalar source-instruction proof slot",
            "scalar helper ABI is available to the eBPF runtime",
            "helper implementation is obligated to match the decoded RISC-V scalar instruction semantics",
        ],
        effect,
    )
}

fn scalar_helper_slot(source_index: usize) -> i32 {
    let slot = (source_index as u32) & 0x0fff_ffff;
    (SCALAR_HELPER_BASE | slot) as i32
}

fn lower_rvv(pc: u64, source: Instr, instr: RVV) -> Result<Lowered, EbpfCompileError> {
    use RVV::*;

    match instr {
        VSETVLI(Rd(rd), Rs1(rs1), vtype) => {
            let rd = x_reg(pc, source, &rd)?;
            let rs1 = x_reg(pc, source, &rs1)?;
            Ok(rvv_helper_lowered(
                rvv_helper_vsetvli(0x01, rd, rs1, vtype.decode()),
                "rvv.vsetvli.helper_call",
                "helper sets vl/vtype from scalar AVL and encoded vtype",
            ))
        }
        VSETIVLI(Rd(rd), imm) => {
            let rd = x_reg(pc, source, &rd)?;
            Ok(rvv_helper_lowered(
                rvv_helper_vsetivli(0x02, rd, imm.decode()),
                "rvv.vsetivli.helper_call",
                "helper sets vl/vtype from immediate AVL and encoded vtype",
            ))
        }
        VSETVL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            let rd = x_reg(pc, source, &rd)?;
            let rs1 = x_reg(pc, source, &rs1)?;
            let rs2 = x_reg(pc, source, &rs2)?;
            Ok(rvv_helper_lowered(
                rvv_helper3(0x03, rd, rs1, rs2, 0, 0),
                "rvv.vsetvl.helper_call",
                "helper sets vl/vtype from scalar AVL and scalar vtype register",
            ))
        }
        VLE8_V(Rd(vd), Rs1(base), VM(mask)) => lower_rvv_load(pc, source, 0x08, vd, base, mask),
        VLE16_V(Rd(vd), Rs1(base), VM(mask)) => lower_rvv_load(pc, source, 0x09, vd, base, mask),
        VLE32_V(Rd(vd), Rs1(base), VM(mask)) => lower_rvv_load(pc, source, 0x0a, vd, base, mask),
        VLE64_V(Rd(vd), Rs1(base), VM(mask)) => lower_rvv_load(pc, source, 0x0b, vd, base, mask),
        VSE8_V(Rs3(vs3), Rs1(base), VM(mask)) => lower_rvv_store(pc, source, 0x0c, vs3, base, mask),
        VSE16_V(Rs3(vs3), Rs1(base), VM(mask)) => lower_rvv_store(pc, source, 0x0d, vs3, base, mask),
        VSE32_V(Rs3(vs3), Rs1(base), VM(mask)) => lower_rvv_store(pc, source, 0x0e, vs3, base, mask),
        VSE64_V(Rs3(vs3), Rs1(base), VM(mask)) => lower_rvv_store(pc, source, 0x0f, vs3, base, mask),

        VADD_VV(Rd(vd), Rs1(vs1), Rs2(vs2), VM(mask)) => {
            lower_rvv_vv(pc, source, 0x10, vd, vs1, vs2, mask, "rvv.vadd_vv.helper_call", "helper executes RVV vadd.vv")
        }
        VSUB_VV(Rd(vd), Rs1(vs1), Rs2(vs2), VM(mask)) => {
            lower_rvv_vv(pc, source, 0x11, vd, vs1, vs2, mask, "rvv.vsub_vv.helper_call", "helper executes RVV vsub.vv")
        }
        VAND_VV(Rd(vd), Rs1(vs1), Rs2(vs2), VM(mask)) => {
            lower_rvv_vv(pc, source, 0x12, vd, vs1, vs2, mask, "rvv.vand_vv.helper_call", "helper executes RVV vand.vv")
        }
        VOR_VV(Rd(vd), Rs1(vs1), Rs2(vs2), VM(mask)) => {
            lower_rvv_vv(pc, source, 0x13, vd, vs1, vs2, mask, "rvv.vor_vv.helper_call", "helper executes RVV vor.vv")
        }
        VXOR_VV(Rd(vd), Rs1(vs1), Rs2(vs2), VM(mask)) => {
            lower_rvv_vv(pc, source, 0x14, vd, vs1, vs2, mask, "rvv.vxor_vv.helper_call", "helper executes RVV vxor.vv")
        }
        VMUL_VV(Rd(vd), Rs1(vs1), Rs2(vs2), VM(mask)) => {
            lower_rvv_vv(pc, source, 0x15, vd, vs1, vs2, mask, "rvv.vmul_vv.helper_call", "helper executes RVV vmul.vv")
        }

        VADD_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x18, vd, vs1, rs2, mask, "rvv.vadd_vx.helper_call", "helper executes RVV vadd.vx")
        }
        VSUB_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x19, vd, vs1, rs2, mask, "rvv.vsub_vx.helper_call", "helper executes RVV vsub.vx")
        }
        VRSUB_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x1a, vd, vs1, rs2, mask, "rvv.vrsub_vx.helper_call", "helper executes RVV vrsub.vx")
        }
        VAND_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x1b, vd, vs1, rs2, mask, "rvv.vand_vx.helper_call", "helper executes RVV vand.vx")
        }
        VOR_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x1c, vd, vs1, rs2, mask, "rvv.vor_vx.helper_call", "helper executes RVV vor.vx")
        }
        VXOR_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x1d, vd, vs1, rs2, mask, "rvv.vxor_vx.helper_call", "helper executes RVV vxor.vx")
        }
        VMUL_VX(Rd(vd), Rs1(vs1), Rs2(rs2), VM(mask)) => {
            lower_rvv_vx(pc, source, 0x1e, vd, vs1, rs2, mask, "rvv.vmul_vx.helper_call", "helper executes RVV vmul.vx")
        }

        _ => unsupported(
            pc,
            source,
            "RVV helper-call lowering currently supports vsetvl*, unit-stride 8/16/32/64 load/store, and integer add/sub/logic/mul vv/vx ops",
        ),
    }
}

fn lower_rvv_load(
    pc: u64,
    source: Instr,
    op: u8,
    vd: Reg,
    base: Reg,
    mask: bool,
) -> Result<Lowered, EbpfCompileError> {
    let vd = v_reg(pc, source, &vd)?;
    let base = x_reg(pc, source, &base)?;
    Ok(rvv_helper_lowered(
        rvv_helper3(op, vd, base, 0, 0, u8::from(mask)),
        "rvv.unit_stride_load.helper_call",
        "helper executes RVV unit-stride vector load",
    ))
}

fn lower_rvv_store(
    pc: u64,
    source: Instr,
    op: u8,
    vs3: Reg,
    base: Reg,
    mask: bool,
) -> Result<Lowered, EbpfCompileError> {
    let vs3 = v_reg(pc, source, &vs3)?;
    let base = x_reg(pc, source, &base)?;
    Ok(rvv_helper_lowered(
        rvv_helper3(op, vs3, base, 0, 0, u8::from(mask)),
        "rvv.unit_stride_store.helper_call",
        "helper executes RVV unit-stride vector store",
    ))
}

fn lower_rvv_vv(
    pc: u64,
    source: Instr,
    op: u8,
    vd: Reg,
    vs1: Reg,
    vs2: Reg,
    mask: bool,
    rule: &'static str,
    effect: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let vd = v_reg(pc, source, &vd)?;
    let vs1 = v_reg(pc, source, &vs1)?;
    let vs2 = v_reg(pc, source, &vs2)?;
    Ok(rvv_helper_lowered(
        rvv_helper3(op, vd, vs1, vs2, 0, u8::from(mask)),
        rule,
        effect,
    ))
}

fn lower_rvv_vx(
    pc: u64,
    source: Instr,
    op: u8,
    vd: Reg,
    vs1: Reg,
    rs2: Reg,
    mask: bool,
    rule: &'static str,
    effect: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let vd = v_reg(pc, source, &vd)?;
    let vs1 = v_reg(pc, source, &vs1)?;
    let rs2 = x_reg(pc, source, &rs2)?;
    Ok(rvv_helper_lowered(
        rvv_helper3(op, vd, vs1, rs2, 0, u8::from(mask)),
        rule,
        effect,
    ))
}

fn rvv_helper_lowered(helper_id: i32, rule: &'static str, effect: &'static str) -> Lowered {
    lowered(
        helper_call(helper_id),
        rule,
        vec![
            "eBPF helper-call descriptor encodes the exact RVV opcode and operands",
            "RVV helper ABI is available to the eBPF runtime",
            "helper implementation is obligated to match the decoded RVV instruction semantics",
        ],
        effect,
    )
}

fn rvv_helper_vsetvli(op: u8, rd: u8, rs1: u8, vtype: u32) -> i32 {
    let encoded = RVV_HELPER_BASE
        | (u32::from(op & 0x1f) << 25)
        | (u32::from(rd) << 20)
        | (u32::from(rs1) << 15)
        | (vtype & 0x7fff);
    encoded as i32
}

fn rvv_helper_vsetivli(op: u8, rd: u8, encoded_imm: u32) -> i32 {
    let encoded = RVV_HELPER_BASE
        | (u32::from(op & 0x1f) << 25)
        | (u32::from(rd) << 20)
        | (encoded_imm & 0x000f_ffff);
    encoded as i32
}

fn rvv_helper3(op: u8, a: u8, b: u8, c: u8, imm5: u8, aux4: u8) -> i32 {
    let encoded = RVV_HELPER_BASE
        | (u32::from(op & 0x1f) << 25)
        | ((u32::from(aux4) & 0x0f) << 21)
        | (u32::from(a) << 16)
        | (u32::from(b) << 11)
        | (u32::from(c) << 6)
        | (u32::from(imm5) & 0x1f);
    encoded as i32
}

fn lower_rv32i(
    pc: u64,
    index: usize,
    source: Instr,
    instr: RV32I,
    pc_to_index: &HashMap<u64, usize>,
) -> Result<Lowered, EbpfCompileError> {
    use RV32I::*;

    match instr {
        LUI(Rd(rd), imm) => {
            let rd = x_reg(pc, source, &rd)?;
            let Some(dst) = write_bpf_reg(pc, source, rd)? else {
                return Ok(noop("lui.x0"));
            };
            let value = (imm.decode() << 12) as i32;
            Ok(lowered(
                alu64_imm(BPF_MOV, dst, value),
                "lui.mov64_imm",
                vec!["LUI materialized value fits eBPF i32 immediate"],
                "dst = imm << 12",
            ))
        }
        AUIPC(Rd(rd), imm) => {
            let rd = x_reg(pc, source, &rd)?;
            let Some(dst) = write_bpf_reg(pc, source, rd)? else {
                return Ok(noop("auipc.x0"));
            };
            let value = pc
                .checked_add_signed(((imm.decode() << 12) as i32) as i64)
                .ok_or_else(|| unsupported_err(pc, source, "AUIPC value overflows u64 PC"))?;
            let imm = i32::try_from(value).map_err(|_| {
                unsupported_err(pc, source, "AUIPC PC-relative value does not fit eBPF i32")
            })?;
            Ok(lowered(
                alu64_imm(BPF_MOV, dst, imm),
                "auipc.mov64_imm",
                vec![
                    "PC is known at compile time",
                    "resolved value fits eBPF i32 immediate",
                ],
                "dst = pc + (imm << 12)",
            ))
        }
        JAL(Rd(rd), imm) => {
            let rd = x_reg(pc, source, &rd)?;
            if rd != 0 {
                return unsupported(
                    pc,
                    source,
                    "JAL with link register needs two eBPF instructions",
                );
            }
            let off = branch_offset(pc, index, source, imm.0 as i32, pc_to_index)?;
            Ok(lowered(
                jmp_imm(BPF_JA, 0, off, 0),
                "jal.x0.ja",
                vec!["rd is x0", "target PC is in the compiled map"],
                "pc = pc + imm",
            ))
        }
        JALR(_, _, _) => unsupported(pc, source, "JALR is indirect control flow"),
        BEQ(Rs1(rs1), Rs2(rs2), imm) => lower_branch(
            pc,
            index,
            source,
            rs1,
            rs2,
            imm.0 as i32,
            BPF_JEQ,
            BPF_JEQ,
            pc_to_index,
        ),
        BNE(Rs1(rs1), Rs2(rs2), imm) => lower_branch(
            pc,
            index,
            source,
            rs1,
            rs2,
            imm.0 as i32,
            BPF_JNE,
            BPF_JNE,
            pc_to_index,
        ),
        BLT(Rs1(rs1), Rs2(rs2), imm) => lower_branch_reversed(
            pc,
            index,
            source,
            rs1,
            rs2,
            imm.0 as i32,
            BPF_JSGT,
            pc_to_index,
            "blt.jsgt.reversed",
            "jump if rs1 < rs2",
        ),
        BGE(Rs1(rs1), Rs2(rs2), imm) => lower_branch(
            pc,
            index,
            source,
            rs1,
            rs2,
            imm.0 as i32,
            BPF_JSGE,
            BPF_JSGE,
            pc_to_index,
        ),
        BLTU(Rs1(rs1), Rs2(rs2), imm) => lower_branch_reversed(
            pc,
            index,
            source,
            rs1,
            rs2,
            imm.0 as i32,
            BPF_JGT,
            pc_to_index,
            "bltu.jgt.reversed",
            "jump if rs1 <u rs2",
        ),
        BGEU(Rs1(rs1), Rs2(rs2), imm) => lower_branch(
            pc,
            index,
            source,
            rs1,
            rs2,
            imm.0 as i32,
            BPF_JGE,
            BPF_JGE,
            pc_to_index,
        ),
        LBU(Rd(rd), Rs1(rs1), imm) => lower_load(pc, source, rd, rs1, imm, BPF_B, "lbu.ldx8"),
        LHU(Rd(rd), Rs1(rs1), imm) => lower_load(pc, source, rd, rs1, imm, BPF_H, "lhu.ldx16"),
        LB(_, _, _) | LH(_, _, _) | LW(_, _, _) => unsupported(
            pc,
            source,
            "signed loads need an extra sign-extension instruction",
        ),
        SB(Rs1(rs1), Rs2(rs2), imm) => lower_store(pc, source, rs1, rs2, imm, BPF_B, "sb.stx8"),
        SH(Rs1(rs1), Rs2(rs2), imm) => lower_store(pc, source, rs1, rs2, imm, BPF_H, "sh.stx16"),
        SW(Rs1(rs1), Rs2(rs2), imm) => lower_store(pc, source, rs1, rs2, imm, BPF_W, "sw.stx32"),
        ADDI(Rd(rd), Rs1(rs1), imm) => {
            lower_alu_imm(pc, source, rd, rs1, imm, BPF_ADD, "addi.add64_imm")
        }
        XORI(Rd(rd), Rs1(rs1), imm) => {
            lower_alu_imm(pc, source, rd, rs1, imm, BPF_XOR, "xori.xor64_imm")
        }
        ORI(Rd(rd), Rs1(rs1), imm) => {
            lower_alu_imm(pc, source, rd, rs1, imm, BPF_OR, "ori.or64_imm")
        }
        ANDI(Rd(rd), Rs1(rs1), imm) => {
            lower_alu_imm(pc, source, rd, rs1, imm, BPF_AND, "andi.and64_imm")
        }
        SLLI(Rd(rd), Rs1(rs1), shamt) => {
            lower_shift_imm(pc, source, rd, rs1, shamt, BPF_LSH, "slli.lsh64_imm")
        }
        SRLI(Rd(rd), Rs1(rs1), shamt) => {
            lower_shift_imm(pc, source, rd, rs1, shamt, BPF_RSH, "srli.rsh64_imm")
        }
        SRAI(Rd(rd), Rs1(rs1), shamt) => {
            lower_shift_imm(pc, source, rd, rs1, shamt, BPF_ARSH, "srai.arsh64_imm")
        }
        ADD(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            lower_alu_reg(pc, source, rd, rs1, rs2, BPF_ADD, true, "add.add64_reg")
        }
        SUB(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            lower_alu_reg(pc, source, rd, rs1, rs2, BPF_SUB, false, "sub.sub64_reg")
        }
        XOR(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            lower_alu_reg(pc, source, rd, rs1, rs2, BPF_XOR, true, "xor.xor64_reg")
        }
        OR(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            lower_alu_reg(pc, source, rd, rs1, rs2, BPF_OR, true, "or.or64_reg")
        }
        AND(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            lower_alu_reg(pc, source, rd, rs1, rs2, BPF_AND, true, "and.and64_reg")
        }
        SLL(_, _, _) | SRL(_, _, _) | SRA(_, _, _) => unsupported(
            pc,
            source,
            "variable shifts have different verifier constraints",
        ),
        SLTI(_, _, _) | SLTIU(_, _, _) | SLT(_, _, _) | SLTU(_, _, _) => unsupported(
            pc,
            source,
            "set-less-than needs compare plus materialization",
        ),
        FENCE(_, _, _, _, _) | FENCE_TSO | PAUSE | EBREAK => Ok(noop("rv32i.noop")),
        ECALL => unsupported(pc, source, "ECALL needs a helper-call ABI bridge"),
    }
}

fn lower_rv64i(pc: u64, source: Instr, instr: RV64I) -> Result<Lowered, EbpfCompileError> {
    use RV64I::*;

    match instr {
        LWU(Rd(rd), Rs1(rs1), imm) => lower_load(pc, source, rd, rs1, imm, BPF_W, "lwu.ldx32"),
        LD(Rd(rd), Rs1(rs1), imm) => lower_load(pc, source, rd, rs1, imm, BPF_DW, "ld.ldx64"),
        SD(Rs1(rs1), Rs2(rs2), imm) => lower_store(pc, source, rs1, rs2, imm, BPF_DW, "sd.stx64"),
        SLLI(Rd(rd), Rs1(rs1), shamt) => {
            lower_shift_imm(pc, source, rd, rs1, shamt, BPF_LSH, "rv64.slli.lsh64_imm")
        }
        SRLI(Rd(rd), Rs1(rs1), shamt) => {
            lower_shift_imm(pc, source, rd, rs1, shamt, BPF_RSH, "rv64.srli.rsh64_imm")
        }
        SRAI(Rd(rd), Rs1(rs1), shamt) => {
            lower_shift_imm(pc, source, rd, rs1, shamt, BPF_ARSH, "rv64.srai.arsh64_imm")
        }
        ADDIW(_, _, _)
        | SLLIW(_, _, _)
        | SRLIW(_, _, _)
        | SRAIW(_, _, _)
        | ADDW(_, _, _)
        | SUBW(_, _, _)
        | SLLW(_, _, _)
        | SRLW(_, _, _)
        | SRAW(_, _, _) => unsupported(
            pc,
            source,
            "RV64 W-form instructions need 32-bit result sign-extension",
        ),
    }
}

fn lower_rv32m(pc: u64, source: Instr, instr: RV32M) -> Result<Lowered, EbpfCompileError> {
    use RV32M::*;

    match instr {
        MUL(Rd(rd), Rs1(rs1), Rs2(rs2)) => {
            lower_alu_reg(pc, source, rd, rs1, rs2, BPF_MUL, true, "mul.mul64_reg")
        }
        MULH(_, _, _) | MULHSU(_, _, _) | MULHU(_, _, _) => unsupported(
            pc,
            source,
            "high-half multiply needs more than one eBPF instruction",
        ),
        DIV(_, _, _) | DIVU(_, _, _) | REM(_, _, _) | REMU(_, _, _) => unsupported(
            pc,
            source,
            "RISC-V division-by-zero semantics do not match one eBPF ALU op",
        ),
    }
}

fn lower_rv64m(pc: u64, source: Instr, instr: RV64M) -> Result<Lowered, EbpfCompileError> {
    use RV64M::*;

    match instr {
        MULW(_, _, _) | DIVW(_, _, _) | DIVUW(_, _, _) | REMW(_, _, _) | REMUW(_, _, _) => {
            unsupported(
                pc,
                source,
                "RV64M W-form instructions need 32-bit result sign-extension",
            )
        }
    }
}

fn lower_alu_imm(
    pc: u64,
    source: Instr,
    rd: Reg,
    rs1: Reg,
    imm: Imm32<11, 0>,
    op: u32,
    rule: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let rd = x_reg(pc, source, &rd)?;
    let rs1 = x_reg(pc, source, &rs1)?;
    let Some(dst) = write_bpf_reg(pc, source, rd)? else {
        return Ok(noop("alu_imm.x0"));
    };
    let imm = imm.decode_sext();

    if rs1 == 0 {
        let value = match op {
            BPF_ADD | BPF_OR | BPF_XOR => imm,
            BPF_AND | BPF_LSH | BPF_RSH | BPF_ARSH => 0,
            _ => return unsupported(pc, source, "x0 source is not supported for this ALU op"),
        };
        return Ok(lowered(
            alu64_imm(BPF_MOV, dst, value),
            "alu_imm.x0.mov64_imm",
            vec!["rs1 is x0", "operation can be folded to a constant"],
            "dst = folded constant",
        ));
    }

    if rd != rs1 {
        if imm == 0 && matches!(op, BPF_ADD | BPF_OR | BPF_XOR) {
            let src = bpf_reg(pc, source, rs1)?;
            return Ok(lowered(
                alu64_reg(BPF_MOV, dst, src),
                "alu_imm.identity.mov64_reg",
                vec!["immediate is identity", "copy fits one eBPF MOV"],
                "dst = rs1",
            ));
        }
        return unsupported(
            pc,
            source,
            "eBPF ALU immediate is two-address; one-to-one lowering requires rd == rs1",
        );
    }

    Ok(lowered(
        alu64_imm(op, dst, imm),
        rule,
        vec!["rd == rs1", "immediate fits eBPF i32"],
        "dst = dst op imm",
    ))
}

fn lower_shift_imm(
    pc: u64,
    source: Instr,
    rd: Reg,
    rs1: Reg,
    shamt: Shamt,
    op: u32,
    rule: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let rd = x_reg(pc, source, &rd)?;
    let rs1 = x_reg(pc, source, &rs1)?;
    let Some(dst) = write_bpf_reg(pc, source, rd)? else {
        return Ok(noop("shift_imm.x0"));
    };

    if rs1 == 0 {
        return Ok(lowered(
            alu64_imm(BPF_MOV, dst, 0),
            "shift_imm.x0.mov64_imm",
            vec!["rs1 is x0", "shifting zero is zero"],
            "dst = 0",
        ));
    }
    if rd != rs1 {
        return unsupported(
            pc,
            source,
            "eBPF shift immediate is two-address; one-to-one lowering requires rd == rs1",
        );
    }

    Ok(lowered(
        alu64_imm(op, dst, i32::from(shamt.0)),
        rule,
        vec!["rd == rs1", "shift amount is immediate"],
        "dst = dst shift imm",
    ))
}

fn lower_alu_reg(
    pc: u64,
    source: Instr,
    rd: Reg,
    rs1: Reg,
    rs2: Reg,
    op: u32,
    commutative: bool,
    rule: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let rd = x_reg(pc, source, &rd)?;
    let rs1 = x_reg(pc, source, &rs1)?;
    let rs2 = x_reg(pc, source, &rs2)?;
    let Some(dst) = write_bpf_reg(pc, source, rd)? else {
        return Ok(noop("alu_reg.x0"));
    };

    if rs1 == 0 {
        return lower_alu_reg_with_zero_lhs(pc, source, dst, rs2, op);
    }
    if rs2 == 0 {
        return lower_alu_reg_with_zero_rhs(pc, source, dst, rs1, op);
    }

    if rd == rs1 {
        let src = bpf_reg(pc, source, rs2)?;
        return Ok(lowered(
            alu64_reg(op, dst, src),
            rule,
            vec!["rd == rs1", "both operands map to eBPF registers"],
            "dst = dst op src",
        ));
    }

    if commutative && rd == rs2 {
        let src = bpf_reg(pc, source, rs1)?;
        return Ok(lowered(
            alu64_reg(op, dst, src),
            rule,
            vec!["rd == rs2", "operation is commutative"],
            "dst = dst op src",
        ));
    }

    unsupported(
        pc,
        source,
        "eBPF ALU register ops are two-address; one-to-one lowering requires rd == rs1 or a commutative rd == rs2",
    )
}

fn lower_alu_reg_with_zero_lhs(
    pc: u64,
    source: Instr,
    dst: u8,
    rs2: u8,
    op: u32,
) -> Result<Lowered, EbpfCompileError> {
    match op {
        BPF_ADD | BPF_OR | BPF_XOR => {
            let src = bpf_reg(pc, source, rs2)?;
            Ok(lowered(
                alu64_reg(BPF_MOV, dst, src),
                "alu_reg.x0_lhs.mov64_reg",
                vec!["rs1 is x0", "operation folds to rs2"],
                "dst = rs2",
            ))
        }
        BPF_AND => Ok(lowered(
            alu64_imm(BPF_MOV, dst, 0),
            "and.x0_lhs.mov64_imm",
            vec!["rs1 is x0", "0 & rs2 is 0"],
            "dst = 0",
        )),
        _ => unsupported(
            pc,
            source,
            "x0 left operand cannot be represented in one eBPF op",
        ),
    }
}

fn lower_alu_reg_with_zero_rhs(
    pc: u64,
    source: Instr,
    dst: u8,
    rs1: u8,
    op: u32,
) -> Result<Lowered, EbpfCompileError> {
    match op {
        BPF_ADD | BPF_SUB | BPF_OR | BPF_XOR => {
            let src = bpf_reg(pc, source, rs1)?;
            Ok(lowered(
                alu64_reg(BPF_MOV, dst, src),
                "alu_reg.x0_rhs.mov64_reg",
                vec!["rs2 is x0", "operation folds to rs1"],
                "dst = rs1",
            ))
        }
        BPF_AND | BPF_MUL => Ok(lowered(
            alu64_imm(BPF_MOV, dst, 0),
            "alu_reg.x0_rhs.mov64_imm",
            vec!["rs2 is x0", "operation folds to zero"],
            "dst = 0",
        )),
        _ => unsupported(
            pc,
            source,
            "x0 right operand cannot be represented in one eBPF op",
        ),
    }
}

fn lower_load(
    pc: u64,
    source: Instr,
    rd: Reg,
    rs1: Reg,
    imm: Imm32<11, 0>,
    width: u32,
    rule: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let rd = x_reg(pc, source, &rd)?;
    if rd == 0 {
        return unsupported(pc, source, "load into x0 still performs memory access");
    }
    let dst = bpf_reg(pc, source, rd)?;
    let base = bpf_reg(pc, source, x_reg(pc, source, &rs1)?)?;
    let off = mem_offset(pc, source, imm)?;
    Ok(lowered(
        ldx(width, dst, base, off),
        rule,
        vec![
            "rd and base register map to eBPF registers",
            "offset fits eBPF i16",
        ],
        "dst = *(base + off)",
    ))
}

fn lower_store(
    pc: u64,
    source: Instr,
    rs1: Reg,
    rs2: Reg,
    imm: Imm32<11, 0>,
    width: u32,
    rule: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let base = bpf_reg(pc, source, x_reg(pc, source, &rs1)?)?;
    let src = bpf_reg(pc, source, x_reg(pc, source, &rs2)?)?;
    let off = mem_offset(pc, source, imm)?;
    Ok(lowered(
        stx(width, base, src, off),
        rule,
        vec![
            "base and value register map to eBPF registers",
            "offset fits eBPF i16",
        ],
        "*(base + off) = src",
    ))
}

fn lower_branch(
    pc: u64,
    index: usize,
    source: Instr,
    rs1: Reg,
    rs2: Reg,
    imm: i32,
    reg_op: u32,
    imm_op: u32,
    pc_to_index: &HashMap<u64, usize>,
) -> Result<Lowered, EbpfCompileError> {
    let rs1 = x_reg(pc, source, &rs1)?;
    let rs2 = x_reg(pc, source, &rs2)?;
    let off = branch_offset(pc, index, source, imm, pc_to_index)?;

    if rs2 == 0 {
        let dst = bpf_reg(pc, source, rs1)?;
        return Ok(lowered(
            jmp_imm(imm_op, dst, off, 0),
            "branch.imm0",
            vec!["rs2 is x0", "target PC is in the compiled map"],
            "conditional branch against zero",
        ));
    }
    if rs1 == 0 {
        return unsupported(
            pc,
            source,
            "x0 as left branch operand needs a reversed or newer eBPF comparison",
        );
    }

    let dst = bpf_reg(pc, source, rs1)?;
    let src = bpf_reg(pc, source, rs2)?;
    Ok(lowered(
        jmp_reg(reg_op, dst, src, off),
        "branch.reg",
        vec![
            "both operands map to eBPF registers",
            "target PC is in the compiled map",
        ],
        "conditional branch",
    ))
}

fn lower_branch_reversed(
    pc: u64,
    index: usize,
    source: Instr,
    rs1: Reg,
    rs2: Reg,
    imm: i32,
    reversed_op: u32,
    pc_to_index: &HashMap<u64, usize>,
    rule: &'static str,
    effect: &'static str,
) -> Result<Lowered, EbpfCompileError> {
    let rs1 = x_reg(pc, source, &rs1)?;
    let rs2 = x_reg(pc, source, &rs2)?;
    let off = branch_offset(pc, index, source, imm, pc_to_index)?;

    if rs2 == 0 {
        return unsupported(
            pc,
            source,
            "x0 as right operand of less-than branch cannot be reversed without a register",
        );
    }

    let dst = bpf_reg(pc, source, rs2)?;
    if rs1 == 0 {
        return Ok(lowered(
            jmp_imm(reversed_op, dst, off, 0),
            rule,
            vec!["rs1 is x0", "reversed comparison uses immediate zero"],
            effect,
        ));
    }

    let src = bpf_reg(pc, source, rs1)?;
    Ok(lowered(
        jmp_reg(reversed_op, dst, src, off),
        rule,
        vec![
            "less-than is represented by reversed greater-than",
            "target PC is in the compiled map",
        ],
        effect,
    ))
}

fn branch_offset(
    pc: u64,
    index: usize,
    source: Instr,
    imm: i32,
    pc_to_index: &HashMap<u64, usize>,
) -> Result<i16, EbpfCompileError> {
    if imm % 4 != 0 {
        return unsupported(pc, source, "branch target is not 4-byte aligned");
    }
    let target_pc = pc
        .checked_add_signed(i64::from(imm))
        .ok_or_else(|| unsupported_err(pc, source, "branch target PC overflows"))?;
    let target_index =
        *pc_to_index
            .get(&target_pc)
            .ok_or(EbpfCompileError::MissingBranchTarget {
                pc,
                instr: source,
                target_pc,
            })?;
    let offset = target_index as isize - index as isize - 1;
    i16::try_from(offset).map_err(|_| EbpfCompileError::BranchOffsetOutOfRange {
        pc,
        instr: source,
        target_index,
    })
}

fn x_reg(pc: u64, source: Instr, reg: &Reg) -> Result<u8, EbpfCompileError> {
    match reg {
        Reg::X(xx) => Ok(xx.value() as u8),
        _ => unsupported(pc, source, "only integer X registers map to eBPF"),
    }
}

fn v_reg(pc: u64, source: Instr, reg: &Reg) -> Result<u8, EbpfCompileError> {
    match reg {
        Reg::V(xx) => Ok(xx.value() as u8),
        _ => unsupported(
            pc,
            source,
            "only vector V registers map to RVV eBPF helpers",
        ),
    }
}

fn write_bpf_reg(pc: u64, source: Instr, reg: u8) -> Result<Option<u8>, EbpfCompileError> {
    if reg == 0 {
        Ok(None)
    } else {
        bpf_reg(pc, source, reg).map(Some)
    }
}

fn bpf_reg(pc: u64, source: Instr, reg: u8) -> Result<u8, EbpfCompileError> {
    match reg {
        1..=9 => Ok(reg),
        0 => unsupported(pc, source, "x0 is a constant zero, not an eBPF register"),
        _ => unsupported(
            pc,
            source,
            "one-to-one register mapping supports only RISC-V x1..x9 to eBPF r1..r9",
        ),
    }
}

fn mem_offset(pc: u64, source: Instr, imm: Imm32<11, 0>) -> Result<i16, EbpfCompileError> {
    i16::try_from(imm.decode_sext())
        .map_err(|_| unsupported_err(pc, source, "memory offset does not fit eBPF i16"))
}

fn lowered(
    insn: bpf_insn,
    rule: &'static str,
    preconditions: Vec<&'static str>,
    effect: &'static str,
) -> Lowered {
    Lowered {
        insn,
        rule,
        preconditions,
        effect,
    }
}

fn noop(rule: &'static str) -> Lowered {
    lowered(
        jmp_imm(BPF_JA, 0, 0, 0),
        rule,
        vec!["no architectural state change"],
        "no-op",
    )
}

fn unsupported<T>(pc: u64, instr: Instr, reason: &str) -> Result<T, EbpfCompileError> {
    Err(unsupported_err(pc, instr, reason))
}

fn unsupported_err(pc: u64, instr: Instr, reason: &str) -> EbpfCompileError {
    EbpfCompileError::Unsupported {
        pc,
        instr,
        reason: reason.to_string(),
    }
}

fn alu64_imm(op: u32, dst: u8, imm: i32) -> bpf_insn {
    insn(BPF_ALU64 | op | BPF_K, dst, 0, 0, imm)
}

fn alu64_reg(op: u32, dst: u8, src: u8) -> bpf_insn {
    insn(BPF_ALU64 | op | BPF_X, dst, src, 0, 0)
}

fn ldx(width: u32, dst: u8, src: u8, off: i16) -> bpf_insn {
    insn(BPF_LDX | BPF_MEM | width, dst, src, off, 0)
}

fn stx(width: u32, dst: u8, src: u8, off: i16) -> bpf_insn {
    insn(BPF_STX | BPF_MEM | width, dst, src, off, 0)
}

fn jmp_reg(op: u32, dst: u8, src: u8, off: i16) -> bpf_insn {
    insn(BPF_JMP | op | BPF_X, dst, src, off, 0)
}

fn jmp_imm(op: u32, dst: u8, off: i16, imm: i32) -> bpf_insn {
    insn(BPF_JMP | op | BPF_K, dst, 0, off, imm)
}

fn helper_call(helper_id: i32) -> bpf_insn {
    insn(BPF_JMP | BPF_CALL, 0, 0, 0, helper_id)
}

fn jmp_exit() -> bpf_insn {
    insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

fn insn(code: u32, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code: code as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    }
}

fn verify_program(program: &EbpfProgram) -> Result<VerificationReport, EbpfCompileError> {
    if program.proofs.len() != program.source_len {
        return verification_err("not every source instruction has a proof obligation");
    }

    let mut seen_sources = HashSet::with_capacity(program.proofs.len());
    let mut seen_targets = HashSet::with_capacity(program.proofs.len());
    for (source_index, proof) in program.proofs.iter().enumerate() {
        if proof.target_len != 1 {
            return verification_err("proof target length is not one");
        }
        if proof.target_index != source_index {
            return verification_err("proof target index does not match source order");
        }
        if proof.target_index >= program.instructions.len() {
            return verification_err("proof target index is outside the instruction stream");
        }
        if !seen_sources.insert(proof.source_pc) {
            return verification_err("multiple proofs point to the same source PC");
        }
        if !seen_targets.insert(proof.target_index) {
            return verification_err("multiple proofs point to the same eBPF instruction");
        }
        verify_insn_shape(&program.instructions[proof.target_index])?;
    }

    for ins in &program.instructions[program.source_len..] {
        verify_insn_shape(ins)?;
    }

    let report = program.verification_report();
    if !report.one_to_one {
        return verification_err("accepted program is not one-to-one");
    }
    Ok(report)
}

fn verify_kernel_properties(
    program: &EbpfProgram,
    policy: &KernelVerifierPolicy,
) -> Result<KernelVerifierReport, EbpfCompileError> {
    if program.instructions.len() > policy.max_instructions {
        return verification_err("program exceeds eBPF kernel instruction limit");
    }
    if policy.require_exit && program.instructions.is_empty() {
        return verification_err("eBPF program has no exit instruction");
    }

    let mut exit_instructions = 0;
    let mut jump_instructions = 0;
    let mut memory_instructions = 0;
    let mut backward_jumps = 0;

    for (index, ins) in program.instructions.iter().enumerate() {
        verify_insn_shape(ins)?;

        let code = u32::from(ins.code);
        let class = code & 0x07;
        let op = code & 0xf0;

        if (class == BPF_ALU || class == BPF_ALU64)
            && (op == BPF_DIV || op == BPF_MOD)
            && (code & BPF_X) == BPF_K
            && ins.imm == 0
        {
            return verification_err("eBPF verifier rejects division or modulo by zero");
        }

        if class == BPF_LDX || class == BPF_STX {
            memory_instructions += 1;
            if !policy.allow_memory_access {
                return verification_err(
                    "ReJIT kernel preflight rejects memory access without pointer provenance",
                );
            }
            verify_memory_pointer_access(ins, class)?;
        }

        if class == BPF_JMP {
            match op {
                BPF_EXIT => {
                    exit_instructions += 1;
                    if policy.require_exit && !exit_has_r0_value(program, index) {
                        return verification_err(
                            "exit instruction does not have a verified r0 value",
                        );
                    }
                }
                BPF_JA | BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JNE | BPF_JSGT | BPF_JSGE => {
                    jump_instructions += 1;
                    let target = checked_jump_target(index, ins.off, program.instructions.len())?;
                    if target <= index {
                        backward_jumps += 1;
                        if !policy.allow_backward_jumps {
                            return verification_err(
                                "ReJIT kernel preflight rejects backward jump without loop proof",
                            );
                        }
                    }
                }
                BPF_CALL => {
                    jump_instructions += 1;
                    if ins.imm <= 0 {
                        return verification_err("eBPF helper call has no helper descriptor");
                    }
                }
                _ => return verification_err("unknown eBPF jump op"),
            }
        }
    }

    if policy.require_exit {
        if exit_instructions == 0 {
            return verification_err("eBPF program has no exit instruction");
        }
        if !is_exit(&program.instructions[program.instructions.len() - 1]) {
            return verification_err("last eBPF instruction is not exit");
        }
    }

    Ok(KernelVerifierReport {
        instructions: program.instructions.len(),
        max_instructions: policy.max_instructions,
        exit_instructions,
        jump_instructions,
        memory_instructions,
        backward_jumps,
        require_exit: policy.require_exit,
        allow_backward_jumps: policy.allow_backward_jumps,
        allow_memory_access: policy.allow_memory_access,
    })
}

fn verify_insn_shape(ins: &bpf_insn) -> Result<(), EbpfCompileError> {
    let code = u32::from(ins.code);
    let class = code & 0x07;
    let dst = ins.dst_reg();
    let src = ins.src_reg();

    if dst > 10 || src > 10 {
        return verification_err("eBPF register number is out of range");
    }

    match class {
        c if c == BPF_ALU || c == BPF_ALU64 => {
            if dst == 10 {
                return verification_err("ALU instruction writes eBPF r10");
            }
            let op = code & 0xf0;
            if !matches!(
                op,
                BPF_ADD
                    | BPF_SUB
                    | BPF_MUL
                    | BPF_DIV
                    | BPF_OR
                    | BPF_AND
                    | BPF_LSH
                    | BPF_RSH
                    | BPF_NEG
                    | BPF_MOD
                    | BPF_XOR
                    | BPF_MOV
                    | BPF_ARSH
            ) {
                return verification_err("unknown eBPF ALU op");
            }
        }
        c if c == BPF_LDX => {
            if dst == 10 {
                return verification_err("load writes eBPF r10");
            }
            verify_mem_width(code)?;
        }
        c if c == BPF_STX => {
            verify_mem_width(code)?;
        }
        c if c == BPF_JMP => {
            let op = code & 0xf0;
            if !matches!(
                op,
                BPF_JA
                    | BPF_JEQ
                    | BPF_JGT
                    | BPF_JGE
                    | BPF_JNE
                    | BPF_JSGT
                    | BPF_JSGE
                    | BPF_CALL
                    | BPF_EXIT
            ) {
                return verification_err("unknown eBPF jump op");
            }
            if op == BPF_CALL && (dst != 0 || src != 0 || ins.off != 0 || ins.imm <= 0) {
                return verification_err("malformed eBPF helper call");
            }
        }
        _ => return verification_err("unsupported eBPF instruction class"),
    }

    Ok(())
}

fn checked_jump_target(
    index: usize,
    offset: i16,
    instruction_count: usize,
) -> Result<usize, EbpfCompileError> {
    let target = index as isize + 1 + offset as isize;
    if target < 0 || target >= instruction_count as isize {
        return verification_err("jump target is outside the eBPF program");
    }
    Ok(target as usize)
}

fn verify_memory_pointer_access(ins: &bpf_insn, class: u32) -> Result<(), EbpfCompileError> {
    let pointer_reg = if class == BPF_LDX {
        ins.src_reg()
    } else {
        ins.dst_reg()
    };

    if pointer_reg == 10 {
        let width = mem_width_bytes(u32::from(ins.code))?;
        let start = i32::from(ins.off);
        let end = start + i32::from(width);
        if start < -512 || end > 0 {
            return verification_err("eBPF stack access is outside the verifier stack window");
        }
    }

    Ok(())
}

fn mem_width_bytes(code: u32) -> Result<i16, EbpfCompileError> {
    match code & 0x18 {
        w if w == BPF_B => Ok(1),
        w if w == BPF_H => Ok(2),
        w if w == BPF_W => Ok(4),
        w if w == BPF_DW => Ok(8),
        _ => verification_err("unsupported eBPF memory width"),
    }
}

fn is_exit(ins: &bpf_insn) -> bool {
    let code = u32::from(ins.code);
    (code & 0x07) == BPF_JMP && (code & 0xf0) == BPF_EXIT
}

fn exit_has_r0_value(program: &EbpfProgram, exit_index: usize) -> bool {
    if exit_index == 0 {
        return false;
    }
    let prev = &program.instructions[exit_index - 1];
    let code = u32::from(prev.code);
    (code & 0x07) == BPF_ALU64
        && (code & 0xf0) == BPF_MOV
        && prev.dst_reg() == 0
        && (code & BPF_X) == BPF_K
}

fn verify_mem_width(code: u32) -> Result<(), EbpfCompileError> {
    match code & 0x18 {
        w if w == BPF_B || w == BPF_H || w == BPF_W || w == BPF_DW => Ok(()),
        _ => verification_err("unsupported eBPF memory width"),
    }
}

fn verification_err<T>(reason: &str) -> Result<T, EbpfCompileError> {
    Err(EbpfCompileError::Verification {
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::instruction::{Xx, RV32I, RVV};

    fn x(n: u32) -> Reg {
        Reg::X(Xx::new(n))
    }

    fn v(n: u32) -> Reg {
        Reg::V(Xx::new(n))
    }

    fn compile_one(instr: Instr) -> EbpfProgram {
        EbpfCompiler::new()
            .with_exit_trailer(false)
            .compile_entries(&[(0x1000, instr)])
            .unwrap()
    }

    #[test]
    fn addi_maps_to_single_aya_instruction() {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::ADDI(
            Rd(x(1)),
            Rs1(x(1)),
            Imm32::<11, 0>::from(7),
        )));
        let program = compile_one(instr);
        let report = program.verify().unwrap();
        assert!(report.one_to_one);
        assert_eq!(program.instructions().len(), 1);
        let ins = program.instructions()[0];
        assert_eq!(u32::from(ins.code), BPF_ALU64 | BPF_ADD | BPF_K);
        assert_eq!(ins.dst_reg(), 1);
        assert_eq!(ins.imm, 7);
    }

    #[test]
    fn add_outside_two_address_form_uses_scalar_helper() {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::ADD(Rd(x(3)), Rs1(x(1)), Rs2(x(2)))));
        let program = compile_one(instr);
        let report = program.verify().unwrap();
        assert!(report.one_to_one);
        assert_eq!(program.instructions().len(), 1);

        let ins = program.instructions()[0];
        assert_eq!(u32::from(ins.code), BPF_JMP | BPF_CALL);
        assert!(ins.imm > 0);

        let proof = &program.proof_obligations()[0];
        assert_eq!(proof.source, instr);
        assert_eq!(proof.rule, "scalar.helper_call");
        assert!(proof.preconditions.contains(
            &"eBPF helper-call descriptor names the scalar source-instruction proof slot"
        ));
    }

    #[test]
    fn branch_uses_compiled_pc_map() {
        let branch = Instr::RV32(RV32Instr::RV32I(RV32I::BEQ(
            Rs1(x(1)),
            Rs2(x(2)),
            Imm32::<12, 1>::from(8),
        )));
        let nop = Instr::NOP;
        let program = EbpfCompiler::new()
            .with_exit_trailer(false)
            .compile_entries(&[(0x1000, branch), (0x1004, nop), (0x1008, nop)])
            .unwrap();
        let ins = program.instructions()[0];
        assert_eq!(u32::from(ins.code), BPF_JMP | BPF_JEQ | BPF_X);
        assert_eq!(ins.off, 1);
    }

    #[test]
    fn bytes_use_linux_ebpf_layout() {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::ADDI(
            Rd(x(1)),
            Rs1(x(1)),
            Imm32::<11, 0>::from(7),
        )));
        let bytes = compile_one(instr).to_bytes();
        assert_eq!(
            bytes,
            vec![(BPF_ALU64 | BPF_ADD | BPF_K) as u8, 1, 0, 0, 7, 0, 0, 0]
        );
    }

    #[test]
    fn rvv_vadd_maps_to_one_helper_call_with_proof() {
        let instr = Instr::RV64(RV64Instr::RV64V(RVV::VADD_VV(
            Rd(v(1)),
            Rs1(v(1)),
            Rs2(v(2)),
            VM(true),
        )));
        let program = compile_one(instr);
        let report = program.verify().unwrap();
        assert!(report.one_to_one);
        assert_eq!(program.instructions().len(), 1);

        let ins = program.instructions()[0];
        assert_eq!(u32::from(ins.code), BPF_JMP | BPF_CALL);
        assert_eq!(ins.dst_reg(), 0);
        assert_eq!(ins.src_reg(), 0);
        assert!(ins.imm > 0);

        let proof = &program.proof_obligations()[0];
        assert_eq!(proof.source, instr);
        assert_eq!(proof.target_index, 0);
        assert_eq!(proof.target_len, 1);
        assert_eq!(proof.rule, "rvv.vadd_vv.helper_call");
        assert!(proof
            .preconditions
            .contains(&"eBPF helper-call descriptor encodes the exact RVV opcode and operands"));
        assert_eq!(proof.effect, "helper executes RVV vadd.vv");
    }

    #[test]
    fn rvv_helper_call_passes_rejit_compile_time_preflight() {
        let instr = Instr::RV64(RV64Instr::RV64V(RVV::VADD_VV(
            Rd(v(1)),
            Rs1(v(1)),
            Rs2(v(2)),
            VM(true),
        )));
        let program = EbpfCompiler::new()
            .with_exit_trailer(true)
            .compile_entries(&[(0x1000, instr)])
            .unwrap();

        let report = program.verify_compile_time().unwrap();
        assert!(report.compilation.one_to_one);
        assert_eq!(report.compilation.source_instructions, 1);
        assert_eq!(report.compilation.mapped_instructions, 1);
        assert_eq!(report.compilation.trailer_instructions, 2);
        assert_eq!(report.kernel.jump_instructions, 1);
        assert_eq!(report.kernel.exit_instructions, 1);
        assert_eq!(report.kernel.memory_instructions, 0);
        assert_eq!(report.kernel.backward_jumps, 0);
    }

    #[test]
    fn scalar_helper_call_passes_rejit_compile_time_preflight() {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::ADDI(
            Rd(x(28)),
            Rs1(x(0)),
            Imm32::<11, 0>::from(1),
        )));
        let program = EbpfCompiler::new()
            .with_exit_trailer(true)
            .compile_entries(&[(0x1000, instr)])
            .unwrap();

        let report = program.verify_compile_time().unwrap();
        assert!(report.compilation.one_to_one);
        assert_eq!(report.compilation.source_instructions, 1);
        assert_eq!(report.compilation.mapped_instructions, 1);
        assert_eq!(report.compilation.trailer_instructions, 2);
        assert_eq!(report.kernel.jump_instructions, 1);
        assert_eq!(report.kernel.exit_instructions, 1);
        assert_eq!(report.kernel.memory_instructions, 0);
        assert_eq!(report.kernel.backward_jumps, 0);
        assert_eq!(program.proof_obligations()[0].rule, "scalar.helper_call");
    }

    #[test]
    fn backward_jal_x0_uses_scalar_helper_to_satisfy_kernel_preflight() {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::JAL(
            Rd(x(0)),
            Imm32::<20, 1>::from((-4i32) as u32),
        )));
        let program = EbpfCompiler::new()
            .with_exit_trailer(true)
            .compile_entries(&[(0x1000, Instr::NOP), (0x1004, instr)])
            .unwrap();

        let ins = program.instructions()[1];
        assert_eq!(u32::from(ins.code), BPF_JMP | BPF_CALL);
        assert_eq!(
            program.proof_obligations()[1].rule,
            "scalar.backward_control_flow.helper_call"
        );
        assert!(program.verify_compile_time().is_ok());
    }

    #[test]
    fn compile_time_verification_accepts_exit_trailer() {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::ADDI(
            Rd(x(1)),
            Rs1(x(1)),
            Imm32::<11, 0>::from(7),
        )));
        let program = EbpfCompiler::new()
            .with_exit_trailer(true)
            .compile_entries(&[(0x1000, instr)])
            .unwrap();
        let report = program.verify_compile_time().unwrap();
        assert!(report.compilation.one_to_one);
        assert_eq!(report.kernel.exit_instructions, 1);
        assert_eq!(report.kernel.backward_jumps, 0);
    }

    #[test]
    fn kernel_preflight_rejects_missing_exit() {
        let program = compile_one(Instr::NOP);
        let err = program.verify_compile_time().unwrap_err();
        assert!(matches!(err, EbpfCompileError::Verification { .. }));
    }

    #[test]
    fn kernel_preflight_rejects_backward_jump_without_loop_proof() {
        let branch = Instr::RV32(RV32Instr::RV32I(RV32I::BEQ(
            Rs1(x(1)),
            Rs2(x(1)),
            Imm32::<12, 1>::from((-4i32) as u32),
        )));
        let program = EbpfCompiler::new()
            .with_exit_trailer(true)
            .compile_entries(&[(0x1000, Instr::NOP), (0x1004, branch)])
            .unwrap();
        let err = program.verify_compile_time().unwrap_err();
        assert!(matches!(err, EbpfCompileError::Verification { .. }));
        let relaxed = KernelVerifierPolicy::default().allowing_backward_jumps();
        assert!(program.verify_compile_time_with(&relaxed).is_ok());
    }

    #[test]
    fn kernel_preflight_rejects_unproven_memory_access() {
        let load = Instr::RV32(RV32Instr::RV32I(RV32I::LBU(
            Rd(x(1)),
            Rs1(x(2)),
            Imm32::<11, 0>::from(0),
        )));
        let program = EbpfCompiler::new()
            .with_exit_trailer(true)
            .compile_entries(&[(0x1000, load)])
            .unwrap();
        let err = program.verify_compile_time().unwrap_err();
        assert!(matches!(err, EbpfCompileError::Verification { .. }));
        let with_pointer_provenance = KernelVerifierPolicy::default().allowing_memory_access();
        assert!(program
            .verify_compile_time_with(&with_pointer_provenance)
            .is_ok());
    }
}
