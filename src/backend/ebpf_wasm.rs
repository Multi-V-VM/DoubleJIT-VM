//! eBPF ALU to WebAssembly lowering for portable, host-native execution.
//!
//! The project already models eBPF with Aya's Linux-layout `bpf_insn`. This
//! backend keeps that representation and lowers a verified straight-line ALU
//! subset into WAT. Wasmer then compiles the resulting WASM to the host ISA
//! (AArch64 on the Parallels VM, x86-64 on an x86 host).

use crate::backend::wasm_builder::{OptLevel, WasmBuilder};
use aya_obj::generated::{bpf_insn, BPF_ALU, BPF_ALU64, BPF_JMP};
use core::fmt;
use std::fmt::Write as _;
use wasmer::{imports, Function, Instance, Module, Store, Value};

const BPF_X: u8 = 0x08;
const BPF_ADD: u8 = 0x00;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;
const BPF_EXIT: u8 = 0x90;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EbpfWasmError {
    InvalidRegister { index: usize, register: u8 },
    UnsupportedInstruction { index: usize, code: u8 },
    MissingExit,
    InstructionAfterExit { index: usize },
    Runtime(String),
}

impl fmt::Display for EbpfWasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRegister { index, register } => {
                write!(
                    f,
                    "eBPF instruction {index} uses unsupported register r{register}"
                )
            }
            Self::UnsupportedInstruction { index, code } => {
                write!(
                    f,
                    "eBPF instruction {index} has unsupported code 0x{code:02x}"
                )
            }
            Self::MissingExit => write!(f, "eBPF program has no terminal exit"),
            Self::InstructionAfterExit { index } => {
                write!(f, "eBPF instruction {index} appears after terminal exit")
            }
            Self::Runtime(error) => write!(f, "WASM runtime error: {error}"),
        }
    }
}

impl std::error::Error for EbpfWasmError {}

/// A portable WASM artifact generated from Linux eBPF instructions.
#[derive(Debug, Clone)]
pub struct EbpfWasmArtifact {
    wat: String,
}

/// A prepared instance which can execute an emitted program repeatedly without
/// recompiling the WebAssembly module on every call.
pub struct EbpfWasmRuntime {
    store: Store,
    _module: Module,
    _instance: Instance,
    run: Function,
}

impl EbpfWasmArtifact {
    pub fn wat(&self) -> &str {
        &self.wat
    }

    pub fn wasm_bytes(&self) -> Result<Vec<u8>, EbpfWasmError> {
        wasmer::wat2wasm(self.wat.as_bytes())
            .map(|bytes| bytes.to_vec())
            .map_err(|error| EbpfWasmError::Runtime(error.to_string()))
    }

    /// Compile and instantiate the emitted WASM with the project's Wasmer
    /// backend. Keep the returned runtime for hot-call measurements or a
    /// long-lived translated function.
    pub fn prepare(&self) -> Result<EbpfWasmRuntime, EbpfWasmError> {
        let mut builder = WasmBuilder::with_opt_level(OptLevel::None)
            .map_err(|error| EbpfWasmError::Runtime(error.to_string()))?;
        let module = builder
            .compile_wat(&self.wat)
            .map_err(|error| EbpfWasmError::Runtime(error.to_string()))?;
        let mut store = builder.into_store();
        let instance = Instance::new(&mut store, &module, &imports! {})
            .map_err(|error| EbpfWasmError::Runtime(error.to_string()))?;
        let run = instance
            .exports
            .get_function("run")
            .map_err(|error| EbpfWasmError::Runtime(error.to_string()))?
            .clone();
        Ok(EbpfWasmRuntime {
            store,
            _module: module,
            _instance: instance,
            run,
        })
    }

    /// Compile, instantiate, and execute the emitted program once.
    pub fn execute(&self) -> Result<i64, EbpfWasmError> {
        self.prepare()?.execute()
    }
}

impl EbpfWasmRuntime {
    /// Execute the already prepared `run() -> i64` export.
    pub fn execute(&mut self) -> Result<i64, EbpfWasmError> {
        let result = self
            .run
            .call(&mut self.store, &[])
            .map_err(|error| EbpfWasmError::Runtime(error.to_string()))?;
        match result.first() {
            Some(Value::I64(value)) => Ok(*value),
            _ => Err(EbpfWasmError::Runtime(
                "run did not return an i64 value".to_string(),
            )),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EbpfWasmCompiler;

impl EbpfWasmCompiler {
    pub fn new() -> Self {
        Self
    }

    pub fn compile(&self, instructions: &[bpf_insn]) -> Result<EbpfWasmArtifact, EbpfWasmError> {
        let mut wat = String::from("(module\n  (func $run (export \"run\") (result i64)\n");
        for register in 0..10 {
            writeln!(&mut wat, "    (local $r{register} i64)").unwrap();
        }

        let mut saw_exit = false;
        for (index, instruction) in instructions.iter().enumerate() {
            if saw_exit {
                return Err(EbpfWasmError::InstructionAfterExit { index });
            }
            let code = instruction.code;
            let class = code & 0x07;
            if class == BPF_JMP as u8 && code & 0xf0 == BPF_EXIT {
                writeln!(&mut wat, "    local.get $r0\n    return").unwrap();
                saw_exit = true;
                continue;
            }

            match class {
                value if value == BPF_ALU as u8 => emit_alu(&mut wat, index, instruction, true)?,
                value if value == BPF_ALU64 as u8 => emit_alu(&mut wat, index, instruction, false)?,
                _ => return Err(EbpfWasmError::UnsupportedInstruction { index, code }),
            }
        }

        if !saw_exit {
            return Err(EbpfWasmError::MissingExit);
        }
        wat.push_str("  )\n)\n");
        Ok(EbpfWasmArtifact { wat })
    }
}

fn emit_alu(
    wat: &mut String,
    index: usize,
    instruction: &bpf_insn,
    is_32_bit: bool,
) -> Result<(), EbpfWasmError> {
    let dst = instruction.dst_reg();
    let src = instruction.src_reg();
    validate_register(index, dst)?;
    validate_register(index, src)?;

    let code = instruction.code;
    let op = code & 0xf0;
    let source_is_register = code & BPF_X != 0;
    if !matches!(op, BPF_MOV | BPF_ADD | BPF_XOR) {
        return Err(EbpfWasmError::UnsupportedInstruction { index, code });
    }

    if op == BPF_MOV {
        emit_operand(wat, instruction, source_is_register, is_32_bit);
        emit_store(wat, dst, is_32_bit);
        return Ok(());
    }

    writeln!(wat, "    local.get $r{dst}").unwrap();
    if is_32_bit {
        writeln!(wat, "    i32.wrap_i64").unwrap();
    }
    emit_operand(wat, instruction, source_is_register, is_32_bit);
    match (op, is_32_bit) {
        (BPF_ADD, true) => writeln!(wat, "    i32.add").unwrap(),
        (BPF_ADD, false) => writeln!(wat, "    i64.add").unwrap(),
        (BPF_XOR, true) => writeln!(wat, "    i32.xor").unwrap(),
        (BPF_XOR, false) => writeln!(wat, "    i64.xor").unwrap(),
        _ => unreachable!("the operation was checked above"),
    }
    emit_store(wat, dst, is_32_bit);
    Ok(())
}

fn emit_operand(
    wat: &mut String,
    instruction: &bpf_insn,
    source_is_register: bool,
    is_32_bit: bool,
) {
    if source_is_register {
        writeln!(wat, "    local.get $r{}", instruction.src_reg()).unwrap();
        if is_32_bit {
            writeln!(wat, "    i32.wrap_i64").unwrap();
        }
    } else if is_32_bit {
        writeln!(wat, "    i32.const {}", instruction.imm).unwrap();
    } else {
        writeln!(wat, "    i64.const {}", instruction.imm).unwrap();
    }
}

fn emit_store(wat: &mut String, dst: u8, is_32_bit: bool) {
    if is_32_bit {
        writeln!(wat, "    i64.extend_i32_u").unwrap();
    }
    writeln!(wat, "    local.set $r{dst}").unwrap();
}

fn validate_register(index: usize, register: u8) -> Result<(), EbpfWasmError> {
    if register > 9 {
        return Err(EbpfWasmError::InvalidRegister { index, register });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::x86_ebpf::X86EbpfCompiler;
    use crate::frontend::x86::X86Mode;

    #[test]
    fn executes_x86_64_ebpf_on_the_host_wasm_backend() {
        let bytes = [0x48, 0xc7, 0xc0, 40, 0, 0, 0, 0x48, 0x83, 0xc0, 2, 0xc3];
        let ebpf = X86EbpfCompiler::new(X86Mode::X86_64)
            .compile(&bytes)
            .unwrap();
        let artifact = EbpfWasmCompiler::new()
            .compile(ebpf.instructions())
            .unwrap();
        assert_eq!(artifact.execute().unwrap(), 42);
        assert!(!artifact.wasm_bytes().unwrap().is_empty());
    }

    #[test]
    fn keeps_x86_32_results_zero_extended() {
        let bytes = [0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3];
        let ebpf = X86EbpfCompiler::new(X86Mode::X86).compile(&bytes).unwrap();
        let artifact = EbpfWasmCompiler::new()
            .compile(ebpf.instructions())
            .unwrap();
        assert_eq!(artifact.execute().unwrap(), 0xffff_ffff);
    }
}
