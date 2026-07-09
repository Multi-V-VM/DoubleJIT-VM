//! x86/x86_64 leaf-block lowering to the project's Aya-backed eBPF format.

use crate::frontend::x86::{
    DecodedX86Instruction, X86DecodeError, X86Frontend, X86Instruction, X86Mode, X86Register,
    X86Width,
};
use aya_obj::generated::{bpf_insn, BPF_ALU, BPF_ALU64, BPF_JMP};
use core::fmt;

const BPF_X: u8 = 0x08;
const BPF_K: u8 = 0x00;
const BPF_ADD: u8 = 0x00;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;
const BPF_EXIT: u8 = 0x90;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86EbpfSourceMap {
    pub x86_offset: usize,
    pub x86_instruction: X86Instruction,
    pub ebpf_index: usize,
}

/// Linux-layout eBPF generated from one straight-line x86/x86_64 leaf block.
#[derive(Debug, Clone)]
pub struct X86EbpfProgram {
    mode: X86Mode,
    instructions: Vec<bpf_insn>,
    source_map: Vec<X86EbpfSourceMap>,
}

impl X86EbpfProgram {
    pub fn mode(&self) -> X86Mode {
        self.mode
    }

    pub fn instructions(&self) -> &[bpf_insn] {
        &self.instructions
    }

    pub fn source_map(&self) -> &[X86EbpfSourceMap] {
        &self.source_map
    }

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X86EbpfError {
    Decode(X86DecodeError),
    UnsupportedRegister {
        offset: usize,
        register: X86Register,
    },
    ImmediateOutOfRange {
        offset: usize,
        value: u64,
    },
}

impl fmt::Display for X86EbpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "{error}"),
            Self::UnsupportedRegister { offset, register } => write!(
                f,
                "x86 register {register:?} at byte {offset} has no eBPF register mapping"
            ),
            Self::ImmediateOutOfRange { offset, value } => write!(
                f,
                "x86_64 immediate 0x{value:x} at byte {offset} needs eBPF LD_IMM64, which is outside the verified ALU subset"
            ),
        }
    }
}

impl std::error::Error for X86EbpfError {}

impl From<X86DecodeError> for X86EbpfError {
    fn from(value: X86DecodeError) -> Self {
        Self::Decode(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct X86EbpfCompiler {
    mode: X86Mode,
}

impl X86EbpfCompiler {
    pub fn new(mode: X86Mode) -> Self {
        Self { mode }
    }

    pub fn compile(&self, bytes: &[u8]) -> Result<X86EbpfProgram, X86EbpfError> {
        let decoded = X86Frontend::new(self.mode).decode(bytes)?;
        self.compile_decoded(&decoded)
    }

    pub fn compile_decoded(
        &self,
        decoded: &[DecodedX86Instruction],
    ) -> Result<X86EbpfProgram, X86EbpfError> {
        let mut instructions = Vec::with_capacity(decoded.len());
        let mut source_map = Vec::with_capacity(decoded.len());

        for decoded_instruction in decoded {
            if matches!(decoded_instruction.instruction, X86Instruction::Ret) {
                instructions.push(insn((BPF_JMP as u8) | BPF_EXIT, 0, 0, 0, 0));
                break;
            }

            let ebpf_index = instructions.len();
            instructions.push(lower_instruction(decoded_instruction)?);
            source_map.push(X86EbpfSourceMap {
                x86_offset: decoded_instruction.offset,
                x86_instruction: decoded_instruction.instruction,
                ebpf_index,
            });
        }

        Ok(X86EbpfProgram {
            mode: self.mode,
            instructions,
            source_map,
        })
    }
}

fn lower_instruction(decoded: &DecodedX86Instruction) -> Result<bpf_insn, X86EbpfError> {
    match decoded.instruction {
        X86Instruction::MovImm { dst, width, value } => {
            let dst = bpf_register(decoded.offset, dst)?;
            Ok(insn(
                alu_class(width) | BPF_MOV | BPF_K,
                dst,
                0,
                0,
                immediate(decoded.offset, width, value)?,
            ))
        }
        X86Instruction::MovReg { dst, src, width } => Ok(insn(
            alu_class(width) | BPF_MOV | BPF_X,
            bpf_register(decoded.offset, dst)?,
            bpf_register(decoded.offset, src)?,
            0,
            0,
        )),
        X86Instruction::AddImm { dst, width, value } => Ok(insn(
            alu_class(width) | BPF_ADD | BPF_K,
            bpf_register(decoded.offset, dst)?,
            0,
            0,
            value,
        )),
        X86Instruction::Xor { dst, src, width } => Ok(insn(
            alu_class(width) | BPF_XOR | BPF_X,
            bpf_register(decoded.offset, dst)?,
            bpf_register(decoded.offset, src)?,
            0,
            0,
        )),
        X86Instruction::Ret => unreachable!("ret is emitted as the eBPF exit trailer"),
    }
}

fn alu_class(width: X86Width) -> u8 {
    match width {
        X86Width::W32 => BPF_ALU as u8,
        X86Width::W64 => BPF_ALU64 as u8,
    }
}

fn immediate(offset: usize, width: X86Width, value: u64) -> Result<i32, X86EbpfError> {
    match width {
        X86Width::W32 => Ok(value as u32 as i32),
        X86Width::W64 => {
            let signed = value as i64;
            i32::try_from(signed).map_err(|_| X86EbpfError::ImmediateOutOfRange { offset, value })
        }
    }
}

fn bpf_register(offset: usize, register: X86Register) -> Result<u8, X86EbpfError> {
    let mapped = match register {
        X86Register::Rax => 0,
        X86Register::Rcx => 1,
        X86Register::Rdx => 2,
        X86Register::Rbx => 3,
        X86Register::Rsi => 4,
        X86Register::Rdi => 5,
        X86Register::R8 => 6,
        X86Register::R9 => 7,
        X86Register::R10 => 8,
        X86Register::R11 => 9,
        unsupported => {
            return Err(X86EbpfError::UnsupportedRegister {
                offset,
                register: unsupported,
            })
        }
    };
    Ok(mapped)
}

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_mov_add_ret_lowers_to_linux_ebpf() {
        let bytes = [0x48, 0xc7, 0xc0, 40, 0, 0, 0, 0x48, 0x83, 0xc0, 2, 0xc3];
        let program = X86EbpfCompiler::new(X86Mode::X86_64)
            .compile(&bytes)
            .unwrap();
        assert_eq!(program.instructions().len(), 3);
        assert_eq!(
            program.instructions()[0].code,
            (BPF_ALU64 as u8) | BPF_MOV | BPF_K
        );
        assert_eq!(program.instructions()[1].imm, 2);
        assert_eq!(program.instructions()[2].code, (BPF_JMP as u8) | BPF_EXIT);
        assert_eq!(program.to_bytes().len(), 24);
    }
}
