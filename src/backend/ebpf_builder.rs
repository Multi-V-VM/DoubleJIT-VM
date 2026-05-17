use crate::frontend::elf::{ElfFile, SectionHeader};
use crate::frontend::instruction::{Instr, Instruction};
use crate::middleend::{
    CompileTimeVerificationReport, EbpfCompileError, EbpfCompiler, EbpfProgram,
    KernelVerifierPolicy,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Aya-backed backend that compiles executable RISC-V instructions to eBPF.
///
/// This builder emits raw `aya_obj::generated::bpf_insn` instructions through
/// `EbpfProgram`. Loading into the kernel is intentionally left to callers so
/// the compiler can be tested without root privileges or a specific program
/// type.
#[derive(Debug, Clone, Default)]
pub struct AyaEbpfBuilder {
    compiler: EbpfCompiler,
}

impl AyaEbpfBuilder {
    pub fn new() -> Self {
        Self {
            compiler: EbpfCompiler::new(),
        }
    }

    pub fn with_exit_trailer(mut self, append_exit: bool) -> Self {
        self.compiler = self.compiler.with_exit_trailer(append_exit);
        self
    }

    pub fn compile_entries(
        &self,
        entries: &[(u64, Instr)],
    ) -> Result<EbpfProgram, EbpfCompileError> {
        self.compiler.compile_entries(entries)
    }

    pub fn compile_elf(&self, elf_file: &ElfFile<'_>) -> Result<EbpfProgram, EbpfCompileError> {
        let entries = collect_executable_instructions(elf_file);
        self.compile_entries(&entries)
    }
}

/// Verified eBPF block stored after a successful ReJIT operation.
#[derive(Debug, Clone)]
pub struct VerifiedRejitBlock {
    pub start_pc: u64,
    pub end_pc: u64,
    pub program: EbpfProgram,
    pub verification: CompileTimeVerificationReport,
}

/// ReJIT cache for eBPF blocks.
///
/// Replacement is atomic from the cache's perspective: a candidate block is
/// compiled and verified first, then committed only if both one-to-one
/// compilation correctness and the kernel preflight succeed.
#[derive(Debug, Clone)]
pub struct EbpfRejitCache {
    blocks: HashMap<u64, VerifiedRejitBlock>,
    builder: AyaEbpfBuilder,
    kernel_policy: KernelVerifierPolicy,
}

impl EbpfRejitCache {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            builder: AyaEbpfBuilder::new(),
            kernel_policy: KernelVerifierPolicy::rejit(),
        }
    }

    pub fn with_kernel_policy(mut self, policy: KernelVerifierPolicy) -> Self {
        self.kernel_policy = policy;
        self
    }

    pub fn with_builder(mut self, builder: AyaEbpfBuilder) -> Self {
        self.builder = builder;
        self
    }

    pub fn rejit_block(
        &mut self,
        entries: &[(u64, Instr)],
    ) -> Result<&VerifiedRejitBlock, EbpfRejitError> {
        let (start_pc, end_pc) = block_range(entries)?;
        let program = self.builder.compile_entries(entries)?;
        let verification = program.verify_compile_time_with(&self.kernel_policy)?;

        let block = VerifiedRejitBlock {
            start_pc,
            end_pc,
            program,
            verification,
        };
        self.blocks.insert(start_pc, block);
        Ok(self
            .blocks
            .get(&start_pc)
            .expect("verified ReJIT block was just inserted"))
    }

    pub fn get(&self, start_pc: u64) -> Option<&VerifiedRejitBlock> {
        self.blocks.get(&start_pc)
    }

    pub fn invalidate_range(&mut self, start_pc: u64, end_pc: u64) {
        self.blocks
            .retain(|_, block| block.end_pc < start_pc || block.start_pc > end_pc);
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl Default for EbpfRejitCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum EbpfRejitError {
    EmptyBlock,
    Compile(EbpfCompileError),
}

impl fmt::Display for EbpfRejitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBlock => write!(f, "cannot ReJIT an empty eBPF block"),
            Self::Compile(err) => write!(f, "{err}"),
        }
    }
}

impl Error for EbpfRejitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EmptyBlock => None,
            Self::Compile(err) => Some(err),
        }
    }
}

impl From<EbpfCompileError> for EbpfRejitError {
    fn from(value: EbpfCompileError) -> Self {
        Self::Compile(value)
    }
}

/// Collect 4-byte RISC-V instructions from executable ELF sections.
pub fn collect_executable_instructions(elf_file: &ElfFile<'_>) -> Vec<(u64, Instr)> {
    let mut entries = Vec::new();

    for section in elf_file.section_iter() {
        let (flags, offset, size, vaddr) = match section {
            SectionHeader::SectionHeader32(h) => (
                u64::from(h.flags),
                h.offset as usize,
                h.size as usize,
                u64::from(h.address),
            ),
            SectionHeader::SectionHeader64(h) => {
                (h.flags, h.offset as usize, h.size as usize, h.address)
            }
        };
        if flags & 0x4 == 0 {
            continue;
        }

        let section_data = &elf_file.input[offset..offset + size];
        let mut pc = vaddr;
        let mut cursor = 0;
        while cursor + 4 <= section_data.len() {
            let instr = Instruction::parse(&section_data[cursor..cursor + 4]);
            entries.push((pc, instr.instr));
            pc += 4;
            cursor += 4;
        }
    }

    entries.sort_by_key(|(pc, _)| *pc);
    entries
}

fn block_range(entries: &[(u64, Instr)]) -> Result<(u64, u64), EbpfRejitError> {
    let (start_pc, _) = entries.first().ok_or(EbpfRejitError::EmptyBlock)?;
    let (end_pc, _) = entries.last().ok_or(EbpfRejitError::EmptyBlock)?;
    Ok((*start_pc, *end_pc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::instruction::{Imm32, Instr, RV32Instr, Rd, Reg, Rs1, Rs2, Xx, RV32I};

    fn x(n: u32) -> Reg {
        Reg::X(Xx::new(n))
    }

    fn addi() -> Instr {
        Instr::RV32(RV32Instr::RV32I(RV32I::ADDI(
            Rd(x(1)),
            Rs1(x(1)),
            Imm32::<11, 0>::from(1),
        )))
    }

    #[test]
    fn rejit_commits_only_after_compile_time_verification() {
        let mut cache = EbpfRejitCache::new();
        let block = cache.rejit_block(&[(0x1000, addi())]).unwrap();
        assert_eq!(block.start_pc, 0x1000);
        assert_eq!(block.end_pc, 0x1000);
        assert!(block.verification.compilation.one_to_one);
        assert_eq!(block.verification.kernel.exit_instructions, 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn failed_rejit_does_not_replace_existing_block() {
        let mut cache = EbpfRejitCache::new();
        cache.rejit_block(&[(0x1000, addi())]).unwrap();
        let previous = cache.get(0x1000).unwrap().program.to_bytes();

        let unsupported = Instr::RV32(RV32Instr::RV32I(RV32I::ADD(Rd(x(3)), Rs1(x(1)), Rs2(x(2)))));
        let err = cache.rejit_block(&[(0x1000, unsupported)]).unwrap_err();
        assert!(matches!(err, EbpfRejitError::Compile(_)));
        assert_eq!(cache.get(0x1000).unwrap().program.to_bytes(), previous);
    }

    #[test]
    fn rejit_rejects_backward_jump_without_loop_proof() {
        let mut cache = EbpfRejitCache::new();
        let branch = Instr::RV32(RV32Instr::RV32I(RV32I::BEQ(
            Rs1(x(1)),
            Rs2(x(1)),
            Imm32::<12, 1>::from((-4i32) as u32),
        )));
        let err = cache
            .rejit_block(&[(0x1000, Instr::NOP), (0x1004, branch)])
            .unwrap_err();
        assert!(matches!(err, EbpfRejitError::Compile(_)));
        assert!(cache.is_empty());
    }
}
