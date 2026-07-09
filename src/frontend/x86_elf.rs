//! ELF-aware x86_64 frontend used by the non-leaf eBPF/WASM path.
//!
//! The raw-byte frontend in `x86` remains intentionally tiny. This module
//! loads real x86_64 ELF segments and follows reachable direct control flow so
//! the backend can model stack frames, branches, and calls.

use core::fmt;
use goblin::elf::{header::EM_X86_64, program_header::{PF_X, PT_LOAD}, Elf};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone)]
pub struct X86ElfSegment {
    pub address: u64,
    pub executable: bool,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodedElfX86Instruction {
    pub address: u64,
    pub instruction: Instruction,
}

#[derive(Debug, Clone)]
pub struct X86ElfImage {
    entry: u64,
    segments: Vec<X86ElfSegment>,
    symbols: BTreeMap<u64, String>,
    symbol_addresses: BTreeMap<String, u64>,
    symbol_sizes: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86ElfError {
    pub address: Option<u64>,
    pub reason: String,
}

impl fmt::Display for X86ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            Some(address) => write!(f, "x86 ELF error at 0x{address:x}: {}", self.reason),
            None => write!(f, "x86 ELF error: {}", self.reason),
        }
    }
}

impl std::error::Error for X86ElfError {}

impl X86ElfImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, X86ElfError> {
        let elf = Elf::parse(bytes).map_err(|error| fail(None, error.to_string()))?;
        if !elf.is_64 || elf.header.e_machine != EM_X86_64 {
            return Err(fail(None, "input is not a 64-bit x86 ELF"));
        }

        let mut segments = Vec::new();
        for header in &elf.program_headers {
            if header.p_type != PT_LOAD || header.p_memsz == 0 {
                continue;
            }
            let start = usize::try_from(header.p_offset)
                .map_err(|_| fail(Some(header.p_vaddr), "segment offset exceeds host address size"))?;
            let file_size = usize::try_from(header.p_filesz)
                .map_err(|_| fail(Some(header.p_vaddr), "segment size exceeds host address size"))?;
            let end = start
                .checked_add(file_size)
                .ok_or_else(|| fail(Some(header.p_vaddr), "segment range overflow"))?;
            let raw = bytes
                .get(start..end)
                .ok_or_else(|| fail(Some(header.p_vaddr), "truncated loadable segment"))?;
            let memory_size = usize::try_from(header.p_memsz)
                .map_err(|_| fail(Some(header.p_vaddr), "memory segment exceeds host address size"))?;
            let mut image = vec![0; memory_size];
            image[..raw.len()].copy_from_slice(raw);
            segments.push(X86ElfSegment {
                address: header.p_vaddr,
                executable: header.p_flags & PF_X != 0,
                bytes: image,
            });
        }

        if segments.is_empty() {
            return Err(fail(None, "ELF has no loadable segments"));
        }

        let mut symbols = BTreeMap::new();
        let mut symbol_addresses = BTreeMap::new();
        let mut symbol_sizes = BTreeMap::new();
        for symbol in &elf.syms {
            if symbol.st_value == 0 {
                continue;
            }
            if let Some(name) = elf.strtab.get_at(symbol.st_name).filter(|name| !name.is_empty()) {
                symbols.entry(symbol.st_value).or_insert_with(|| name.to_string());
                symbol_addresses.entry(name.to_string()).or_insert(symbol.st_value);
                symbol_sizes.entry(name.to_string()).or_insert(symbol.st_size);
            }
        }

        Ok(Self {
            entry: elf.entry,
            segments,
            symbols,
            symbol_addresses,
            symbol_sizes,
        })
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn segments(&self) -> &[X86ElfSegment] {
        &self.segments
    }

    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbol_addresses.get(name).copied()
    }

    pub fn symbol_size(&self, name: &str) -> Option<u64> {
        self.symbol_sizes.get(name).copied()
    }

    pub fn symbol_addresses(&self) -> &BTreeMap<String, u64> {
        &self.symbol_addresses
    }

    pub fn symbol_at(&self, address: u64) -> Option<&str> {
        self.symbols.get(&address).map(String::as_str)
    }

    pub fn c_string_at(&self, address: u64) -> Option<&[u8]> {
        let segment = self.segment_at(address)?;
        let offset = usize::try_from(address.checked_sub(segment.address)?).ok()?;
        let bytes = segment.bytes.get(offset..)?;
        let end = bytes.iter().position(|byte| *byte == 0)?;
        Some(&bytes[..end])
    }

    pub fn decode_reachable(
        &self,
        entry: u64,
    ) -> Result<Vec<DecodedElfX86Instruction>, X86ElfError> {
        let mut pending = VecDeque::from([entry]);
        let mut decoded = BTreeMap::new();

        while let Some(address) = pending.pop_front() {
            if decoded.contains_key(&address) {
                continue;
            }
            let bytes = self.executable_bytes_at(address)?;
            let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                return Err(fail(Some(address), "invalid x86 instruction"));
            }
            let next = instruction.next_ip();
            let flow = instruction.flow_control();
            decoded.insert(
                address,
                DecodedElfX86Instruction {
                    address,
                    instruction,
                },
            );

            match flow {
                FlowControl::Next => pending.push_back(next),
                FlowControl::ConditionalBranch => {
                    pending.push_back(instruction.near_branch_target());
                    pending.push_back(next);
                }
                FlowControl::UnconditionalBranch => pending.push_back(instruction.near_branch_target()),
                FlowControl::Call => {
                    pending.push_back(instruction.near_branch_target());
                    pending.push_back(next);
                }
                FlowControl::Return => {}
                FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                    return Err(fail(
                        Some(address),
                        "indirect control flow is not supported by the translated x86 ABI",
                    ));
                }
                FlowControl::Exception | FlowControl::Interrupt | FlowControl::XbeginXabortXend => {
                    return Err(fail(
                        Some(address),
                        &format!("unsupported control flow {:?}", instruction.mnemonic()),
                    ));
                }
            }
        }

        Ok(decoded.into_values().collect())
    }

    pub fn main_or_entry(&self) -> u64 {
        self.symbol_address("main").unwrap_or(self.entry)
    }

    fn executable_bytes_at(&self, address: u64) -> Result<&[u8], X86ElfError> {
        let segment = self
            .segment_at(address)
            .filter(|segment| segment.executable)
            .ok_or_else(|| fail(Some(address), "address is not in an executable load segment"))?;
        let offset = usize::try_from(address - segment.address)
            .map_err(|_| fail(Some(address), "address offset exceeds host address size"))?;
        segment
            .bytes
            .get(offset..)
            .ok_or_else(|| fail(Some(address), "address is outside its load segment"))
    }

    fn segment_at(&self, address: u64) -> Option<&X86ElfSegment> {
        self.segments.iter().find(|segment| {
            address >= segment.address
                && address.saturating_sub(segment.address) < segment.bytes.len() as u64
        })
    }
}

fn fail(address: Option<u64>, reason: impl Into<String>) -> X86ElfError {
    X86ElfError {
        address,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_a_non_elf_input() {
        let error = X86ElfImage::parse(b"not an elf").unwrap_err();
        assert!(error.reason.contains("Malformed"));
    }
}
