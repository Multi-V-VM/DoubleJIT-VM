//! x86_64 ELF to host-native WebAssembly execution backend.
//!
//! This is the non-leaf companion to `x86_ebpf`: it retains the eBPF/WASM
//! project's portable execution target while modelling the state that a real
//! x86 userspace function needs (registers, stack memory, direct control flow,
//! and a small libc hostcall ABI).

use crate::backend::wasm_builder::{OptLevel, WasmBuilder};
use crate::frontend::x86_elf::{DecodedElfX86Instruction, X86ElfError, X86ElfImage};
use core::fmt;
use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use wasmer::{imports, Function, Instance, Module, Store, Value};

const STACK_TOP: u64 = 64 * 1024 * 1024;
const STACK_SENTINEL: u64 = STACK_TOP - 8;
const HEAP_BASE: u64 = 48 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X86ElfWasmError {
    Elf(X86ElfError),
    UnsupportedInstruction { address: u64, instruction: String },
    UnsupportedOperand { address: u64, operand: String },
    MissingBranchTarget { address: u64, target: u64 },
    Runtime(String),
}

impl fmt::Display for X86ElfWasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => write!(f, "{error}"),
            Self::UnsupportedInstruction {
                address,
                instruction,
            } => write!(f, "unsupported x86 instruction at 0x{address:x}: {instruction}"),
            Self::UnsupportedOperand { address, operand } => {
                write!(f, "unsupported x86 operand at 0x{address:x}: {operand}")
            }
            Self::MissingBranchTarget { address, target } => write!(
                f,
                "x86 control flow at 0x{address:x} targets 0x{target:x}, which was not decoded"
            ),
            Self::Runtime(error) => write!(f, "WASM runtime error: {error}"),
        }
    }
}

impl std::error::Error for X86ElfWasmError {}

impl From<X86ElfError> for X86ElfWasmError {
    fn from(value: X86ElfError) -> Self {
        Self::Elf(value)
    }
}

#[derive(Debug, Clone)]
pub struct X86ElfWasmArtifact {
    wat: String,
    strings: BTreeMap<u64, String>,
    instruction_count: usize,
}

pub struct X86ElfWasmRuntime {
    store: Store,
    _module: Module,
    _instance: Instance,
    run: Function,
}

impl X86ElfWasmArtifact {
    pub fn wat(&self) -> &str {
        &self.wat
    }

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Compile and instantiate the translated ELF on the current Wasmer
    /// native backend. The returned instance is reusable for hot execution.
    pub fn prepare(&self) -> Result<X86ElfWasmRuntime, X86ElfWasmError> {
        let mut builder = WasmBuilder::with_opt_level(OptLevel::None)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        let module = builder
            .compile_wat(&self.wat)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        let mut store = builder.into_store();
        let strings = Arc::new(self.strings.clone());
        let printf_strings = Arc::clone(&strings);
        let puts_strings = Arc::clone(&strings);
        let printf = Function::new_typed(
            &mut store,
            move |format: i64, arg1: i64, arg2: i64, arg3: i64, arg4: i64, arg5: i64| -> i64 {
                let args = [arg1, arg2, arg3, arg4, arg5];
                match printf_strings.get(&(format as u64)) {
                    Some(format) => {
                        let output = render_printf(format, &args, &printf_strings);
                        print!("{output}");
                        output.len() as i64
                    }
                    None => -1,
                }
            },
        );
        let puts = Function::new_typed(&mut store, move |value: i64| -> i64 {
            match puts_strings.get(&(value as u64)) {
                Some(string) => {
                    println!("{string}");
                    string.len() as i64 + 1
                }
                None => -1,
            }
        });
        let import_object = imports! {
            "env" => {
                "doublejit_printf" => printf,
                "doublejit_puts" => puts,
            }
        };
        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        let run = instance
            .exports
            .get_function("run")
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?
            .clone();
        Ok(X86ElfWasmRuntime {
            store,
            _module: module,
            _instance: instance,
            run,
        })
    }

    /// Compile, instantiate, and execute `main()` once.
    pub fn execute(&self) -> Result<i64, X86ElfWasmError> {
        self.prepare()?.execute()
    }
}

impl X86ElfWasmRuntime {
    /// Execute the already translated x86 ELF entry point.
    pub fn execute(&mut self) -> Result<i64, X86ElfWasmError> {
        let result = self
            .run
            .call(&mut self.store, &[])
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        match result.first() {
            Some(Value::I64(value)) => Ok(*value),
            _ => Err(X86ElfWasmError::Runtime(
                "translated main did not return an i64".to_string(),
            )),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct X86ElfWasmCompiler;

impl X86ElfWasmCompiler {
    pub fn new() -> Self {
        Self
    }

    pub fn compile_bytes(&self, bytes: &[u8]) -> Result<X86ElfWasmArtifact, X86ElfWasmError> {
        let image = X86ElfImage::parse(bytes)?;
        self.compile(&image)
    }

    pub fn compile(&self, image: &X86ElfImage) -> Result<X86ElfWasmArtifact, X86ElfWasmError> {
        let entry = image.main_or_entry();
        let instructions = image.decode_reachable(entry)?;
        let addresses = instructions
            .iter()
            .enumerate()
            .map(|(index, decoded)| (decoded.address, index))
            .collect::<BTreeMap<_, _>>();
        let strings = collect_strings(image);

        let mut wat = String::new();
        wat.push_str("(module\n");
        wat.push_str("  (import \"env\" \"doublejit_printf\" (func $doublejit_printf (param i64 i64 i64 i64 i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_puts\" (func $doublejit_puts (param i64) (result i64)))\n");
        writeln!(
            &mut wat,
            "  (memory (export \"memory\") {})",
            memory_pages(image)
        )
        .unwrap();
        writeln!(&mut wat, "  (global $heap (mut i32) (i32.const {HEAP_BASE}))").unwrap();
        emit_data_segments(&mut wat, image);
        wat.push_str("  (func $run (export \"run\") (result i64)\n");
        for register in X86Register::ALL {
            writeln!(&mut wat, "    (local ${} i64)", register.name()).unwrap();
        }
        wat.push_str("    (local $pc i32)\n    (local $tmp i64)\n    (local $zf i32)\n    (local $sf i32)\n    (local $cf i32)\n");
        writeln!(&mut wat, "    (local.set $rsp (i64.const {STACK_SENTINEL}))").unwrap();
        writeln!(&mut wat, "    (i64.store (i32.const {STACK_SENTINEL}) (i64.const -1))").unwrap();
        let entry_index = branch_index(entry, entry, &addresses)?;
        writeln!(&mut wat, "    (local.set $pc (i32.const {entry_index}))").unwrap();
        wat.push_str("    (loop $dispatch\n");
        for (index, decoded) in instructions.iter().enumerate() {
            writeln!(&mut wat, "      (if (i32.eq (local.get $pc) (i32.const {index}))").unwrap();
            wat.push_str("        (then\n");
            emit_instruction(&mut wat, decoded, index, &addresses, image)?;
            wat.push_str("        )\n      )\n");
        }
        wat.push_str("      unreachable\n    )\n    unreachable\n  )\n)\n");

        Ok(X86ElfWasmArtifact {
            wat,
            strings,
            instruction_count: instructions.len(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum X86Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl X86Register {
    const ALL: [Self; 16] = [
        Self::Rax,
        Self::Rcx,
        Self::Rdx,
        Self::Rbx,
        Self::Rsp,
        Self::Rbp,
        Self::Rsi,
        Self::Rdi,
        Self::R8,
        Self::R9,
        Self::R10,
        Self::R11,
        Self::R12,
        Self::R13,
        Self::R14,
        Self::R15,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Rax => "rax",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rbx => "rbx",
            Self::Rsp => "rsp",
            Self::Rbp => "rbp",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::R15 => "r15",
        }
    }
}

fn emit_instruction(
    wat: &mut String,
    decoded: &DecodedElfX86Instruction,
    index: usize,
    addresses: &BTreeMap<u64, usize>,
    image: &X86ElfImage,
) -> Result<(), X86ElfWasmError> {
    let instruction = &decoded.instruction;
    let next = index + 1;
    match instruction.mnemonic() {
        Mnemonic::Endbr64 | Mnemonic::Nop => transition(wat, next),
        Mnemonic::Push => {
            let source = operand_expr(decoded.address, instruction, 0)?;
            wat.push_str("          (local.set $rsp (i64.sub (local.get $rsp) (i64.const 8)))\n");
            writeln!(wat, "          (i64.store (i32.wrap_i64 (local.get $rsp)) {source})").unwrap();
            transition(wat, next);
        }
        Mnemonic::Pop => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            writeln!(wat, "          {}", write_destination(&destination, "(i64.load (i32.wrap_i64 (local.get $rsp)))")).unwrap();
            wat.push_str("          (local.set $rsp (i64.add (local.get $rsp) (i64.const 8)))\n");
            transition(wat, next);
        }
        Mnemonic::Leave => {
            wat.push_str("          (local.set $rsp (local.get $rbp))\n");
            wat.push_str("          (local.set $rbp (i64.load (i32.wrap_i64 (local.get $rsp))))\n");
            wat.push_str("          (local.set $rsp (i64.add (local.get $rsp) (i64.const 8)))\n");
            transition(wat, next);
        }
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsxd => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let source = operand_expr(decoded.address, instruction, 1)?;
            let value = if instruction.mnemonic() == Mnemonic::Movsxd {
                "(i64.extend_i32_s (i32.wrap_i64 ".to_string() + &source + "))"
            } else {
                source
            };
            writeln!(wat, "          {}", write_destination(&destination, &value)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Lea => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let source = memory_address(decoded.address, instruction)?;
            writeln!(wat, "          {}", write_destination(&destination, &format!("(i64.extend_i32_u {source})"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Xor | Mnemonic::And | Mnemonic::Or => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let left = destination.read_expression();
            let right = operand_expr(decoded.address, instruction, 1)?;
            let op = match instruction.mnemonic() {
                Mnemonic::Add => "i64.add",
                Mnemonic::Sub => "i64.sub",
                Mnemonic::Xor => "i64.xor",
                Mnemonic::And => "i64.and",
                Mnemonic::Or => "i64.or",
                _ => unreachable!(),
            };
            let value = format!("({op} {left} {right})");
            writeln!(wat, "          {}", write_destination(&destination, &value)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let left = destination.read_expression();
            let right = operand_expr(decoded.address, instruction, 1)?;
            let op = match instruction.mnemonic() {
                Mnemonic::Shl => "i64.shl",
                Mnemonic::Shr => "i64.shr_u",
                Mnemonic::Sar => "i64.shr_s",
                _ => unreachable!(),
            };
            let value = format!("({op} {left} {right})");
            writeln!(wat, "          {}", write_destination(&destination, &value)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Imul => {
            if instruction.op_count() == 1 {
                let right = operand_expr(decoded.address, instruction, 0)?;
                let left = "(local.get $rax)";
                let high = signed_mul_high(left, &right);
                writeln!(wat, "          (local.set $rdx {high})").unwrap();
                writeln!(wat, "          (local.set $rax (i64.mul {left} {right}))").unwrap();
                transition(wat, next);
                return Ok(());
            }
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let left = if instruction.op_count() == 3 {
                operand_expr(decoded.address, instruction, 1)?
            } else {
                destination.read_expression()
            };
            let right_index = if instruction.op_count() == 3 { 2 } else { 1 };
            let right = operand_expr(decoded.address, instruction, right_index)?;
            writeln!(wat, "          {}", write_destination(&destination, &format!("(i64.mul {left} {right})"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Mul => {
            let right = operand_expr(decoded.address, instruction, 0)?;
            let left = "(local.get $rax)";
            writeln!(wat, "          (local.set $rdx {})", unsigned_mul_high(left, &right)).unwrap();
            writeln!(wat, "          (local.set $rax (i64.mul {left} {right}))").unwrap();
            transition(wat, next);
        }
        Mnemonic::Div | Mnemonic::Idiv => {
            let raw_divisor = operand_expr(decoded.address, instruction, 0)?;
            let signed = instruction.mnemonic() == Mnemonic::Idiv;
            let width = operand_width(instruction, 0).unwrap_or(64);
            let divisor = width_expression(&raw_divisor, width, signed);
            let dividend = width_expression("(local.get $rax)", width, signed);
            let quotient = if signed { "i64.div_s" } else { "i64.div_u" };
            let remainder = if signed { "i64.rem_s" } else { "i64.rem_u" };
            let rax = Destination::Register { register: X86Register::Rax, width };
            let rdx = Destination::Register { register: X86Register::Rdx, width };
            writeln!(wat, "          (local.set $tmp {dividend})").unwrap();
            writeln!(wat, "          (if (i64.eqz {divisor})").unwrap();
            writeln!(wat, "            (then {} {})", write_destination(&rdx, "(local.get $tmp)"), write_destination(&rax, "(i64.const -1)")).unwrap();
            writeln!(wat, "            (else {} {}))", write_destination(&rax, &format!("({quotient} (local.get $tmp) {divisor})")), write_destination(&rdx, &format!("({remainder} (local.get $tmp) {divisor})"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Cqo => {
            wat.push_str("          (local.set $rdx (i64.shr_s (local.get $rax) (i64.const 63)))\n");
            transition(wat, next);
        }
        Mnemonic::Cdq => {
            wat.push_str("          (local.set $rdx (i64.extend_i32_s (i32.shr_s (i32.wrap_i64 (local.get $rax)) (i32.const 31))))\n");
            transition(wat, next);
        }
        Mnemonic::Cdqe => {
            wat.push_str("          (local.set $rax (i64.extend_i32_s (i32.wrap_i64 (local.get $rax))))\n");
            transition(wat, next);
        }
        Mnemonic::Cmovs | Mnemonic::Cmovns | Mnemonic::Cmove | Mnemonic::Cmovne => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let source = operand_expr(decoded.address, instruction, 1)?;
            let condition = match instruction.mnemonic() {
                Mnemonic::Cmovs => "(local.get $sf)",
                Mnemonic::Cmovns => "(i32.eqz (local.get $sf))",
                Mnemonic::Cmove => "(local.get $zf)",
                Mnemonic::Cmovne => "(i32.eqz (local.get $zf))",
                _ => unreachable!(),
            };
            writeln!(wat, "          (if {condition} (then {}))", write_destination(&destination, &source)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Sete | Mnemonic::Setne | Mnemonic::Setl | Mnemonic::Setle | Mnemonic::Setg
        | Mnemonic::Setge | Mnemonic::Setb | Mnemonic::Setbe | Mnemonic::Seta | Mnemonic::Setae => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let condition = condition_expression(instruction.mnemonic()).unwrap();
            writeln!(wat, "          {}", write_destination(&destination, &format!("(if (result i64) {condition} (then (i64.const 1)) (else (i64.const 0)))"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Cmp | Mnemonic::Test => {
            let left = operand_expr(decoded.address, instruction, 0)?;
            let right = operand_expr(decoded.address, instruction, 1)?;
            if instruction.mnemonic() == Mnemonic::Cmp {
                let width = operand_width(instruction, 0).unwrap_or(64);
                let left_unsigned = width_expression(&left, width, false);
                let right_unsigned = width_expression(&right, width, false);
                let left_signed = width_expression(&left, width, true);
                let right_signed = width_expression(&right, width, true);
                writeln!(wat, "          (local.set $zf (i64.eq {left_unsigned} {right_unsigned}))").unwrap();
                writeln!(wat, "          (local.set $sf (i64.lt_s {left_signed} {right_signed}))").unwrap();
                writeln!(wat, "          (local.set $cf (i64.lt_u {left_unsigned} {right_unsigned}))").unwrap();
            } else {
                writeln!(wat, "          (local.set $zf (i64.eqz (i64.and {left} {right})))").unwrap();
                wat.push_str("          (local.set $sf (i32.const 0))\n          (local.set $cf (i32.const 0))\n");
            }
            transition(wat, next);
        }
        Mnemonic::Jmp => jump(wat, decoded.address, instruction.near_branch_target(), addresses)?,
        Mnemonic::Ja | Mnemonic::Jae | Mnemonic::Jb | Mnemonic::Jbe | Mnemonic::Je
        | Mnemonic::Jg | Mnemonic::Jge | Mnemonic::Jl | Mnemonic::Jle | Mnemonic::Jne
        | Mnemonic::Js | Mnemonic::Jns => {
            let target = branch_index(decoded.address, instruction.near_branch_target(), addresses)?;
            let condition = condition_expression(instruction.mnemonic()).unwrap();
            writeln!(wat, "          (if {condition} (then (local.set $pc (i32.const {target}))) (else (local.set $pc (i32.const {next}))))").unwrap();
            wat.push_str("          (br $dispatch)\n");
        }
        Mnemonic::Call => {
            let target = instruction.near_branch_target();
            if let Some(symbol) = image.symbol_at(target) {
                if emit_libc_call(wat, symbol)? {
                    transition(wat, next);
                    return Ok(());
                }
            }
            let target = branch_index(decoded.address, target, addresses)?;
            writeln!(wat, "          (local.set $rsp (i64.sub (local.get $rsp) (i64.const 8)))").unwrap();
            writeln!(wat, "          (i64.store (i32.wrap_i64 (local.get $rsp)) (i64.const {next}))").unwrap();
            writeln!(wat, "          (local.set $pc (i32.const {target}))").unwrap();
            wat.push_str("          (br $dispatch)\n");
        }
        Mnemonic::Ret => {
            wat.push_str("          (local.set $tmp (i64.load (i32.wrap_i64 (local.get $rsp))))\n");
            wat.push_str("          (local.set $rsp (i64.add (local.get $rsp) (i64.const 8)))\n");
            wat.push_str("          (if (i64.eq (local.get $tmp) (i64.const -1))\n");
            wat.push_str("            (then (local.get $rax) return)\n");
            wat.push_str("            (else (local.set $pc (i32.wrap_i64 (local.get $tmp))) (br $dispatch))\n          )\n");
        }
        mnemonic => {
            return Err(X86ElfWasmError::UnsupportedInstruction {
                address: decoded.address,
                instruction: format!("{mnemonic:?}"),
            });
        }
    }
    Ok(())
}

fn emit_libc_call(wat: &mut String, symbol: &str) -> Result<bool, X86ElfWasmError> {
    match symbol {
        "printf" => {
            wat.push_str("          (local.set $rax (call $doublejit_printf (local.get $rdi) (local.get $rsi) (local.get $rdx) (local.get $rcx) (local.get $r8) (local.get $r9)))\n");
        }
        "puts" => {
            wat.push_str("          (local.set $rax (call $doublejit_puts (local.get $rdi)))\n");
        }
        "exit" => {
            wat.push_str("          (local.get $rdi)\n          return\n");
        }
        "malloc" => {
            wat.push_str("          (local.set $rax (i64.extend_i32_u (global.get $heap)))\n");
            wat.push_str("          (global.set $heap (i32.add (global.get $heap) (i32.wrap_i64 (local.get $rdi))))\n");
        }
        "calloc" => {
            wat.push_str("          (local.set $rax (i64.extend_i32_u (global.get $heap)))\n");
            wat.push_str("          (global.set $heap (i32.add (global.get $heap) (i32.mul (i32.wrap_i64 (local.get $rdi)) (i32.wrap_i64 (local.get $rsi)))))\n");
        }
        "free" => wat.push_str("          (local.set $rax (i64.const 0))\n"),
        _ => return Ok(false),
    }
    Ok(true)
}

fn jump(
    wat: &mut String,
    address: u64,
    target: u64,
    addresses: &BTreeMap<u64, usize>,
) -> Result<(), X86ElfWasmError> {
    let target = branch_index(address, target, addresses)?;
    writeln!(wat, "          (local.set $pc (i32.const {target}))").unwrap();
    wat.push_str("          (br $dispatch)\n");
    Ok(())
}

fn transition(wat: &mut String, target: usize) {
    writeln!(wat, "          (local.set $pc (i32.const {target}))").unwrap();
    wat.push_str("          (br $dispatch)\n");
}

fn branch_index(
    address: u64,
    target: u64,
    addresses: &BTreeMap<u64, usize>,
) -> Result<usize, X86ElfWasmError> {
    addresses
        .get(&target)
        .copied()
        .ok_or(X86ElfWasmError::MissingBranchTarget { address, target })
}

fn condition_expression(mnemonic: Mnemonic) -> Option<&'static str> {
    Some(match mnemonic {
        Mnemonic::Ja | Mnemonic::Seta => {
            "(i32.and (i32.eqz (local.get $zf)) (i32.eqz (local.get $cf)))"
        }
        Mnemonic::Jae | Mnemonic::Setae => "(i32.eqz (local.get $cf))",
        Mnemonic::Jb | Mnemonic::Setb => "(local.get $cf)",
        Mnemonic::Jbe | Mnemonic::Setbe => "(i32.or (local.get $zf) (local.get $cf))",
        Mnemonic::Je | Mnemonic::Sete => "(local.get $zf)",
        Mnemonic::Jg | Mnemonic::Setg => {
            "(i32.and (i32.eqz (local.get $zf)) (i32.eqz (local.get $sf)))"
        }
        Mnemonic::Jge | Mnemonic::Setge => "(i32.eqz (local.get $sf))",
        Mnemonic::Jl | Mnemonic::Setl => "(local.get $sf)",
        Mnemonic::Jle | Mnemonic::Setle => "(i32.or (local.get $zf) (local.get $sf))",
        Mnemonic::Jne | Mnemonic::Setne => "(i32.eqz (local.get $zf))",
        Mnemonic::Js => "(local.get $sf)",
        Mnemonic::Jns => "(i32.eqz (local.get $sf))",
        _ => return None,
    })
}

#[derive(Debug, Clone)]
enum Destination {
    Register { register: X86Register, width: u32 },
    Memory { address: String, width: u32 },
}

impl Destination {
    fn read_expression(&self) -> String {
        match self {
            Self::Register { register, width } => read_register(*register, *width),
            Self::Memory { address, width } => read_memory(address, *width),
        }
    }
}

fn operand_destination(address: u64, instruction: &Instruction, index: u32) -> Result<Destination, X86ElfWasmError> {
    match instruction.op_kind(index) {
        OpKind::Register => {
            let register = register(instruction.op_register(index)).ok_or_else(|| unsupported_operand(address, "non-general-purpose register"))?;
            Ok(Destination::Register { register: register.0, width: register.1 })
        }
        OpKind::Memory => Ok(Destination::Memory {
            address: memory_address(address, instruction)?,
            width: instruction.memory_size().size() as u32 * 8,
        }),
        kind => Err(unsupported_operand(address, &format!("destination {kind:?}"))),
    }
}

fn operand_expr(address: u64, instruction: &Instruction, index: u32) -> Result<String, X86ElfWasmError> {
    match instruction.op_kind(index) {
        OpKind::Register => {
            let (register, width) = register(instruction.op_register(index))
                .ok_or_else(|| unsupported_operand(address, "non-general-purpose register"))?;
            Ok(read_register(register, width))
        }
        OpKind::Memory => Ok(read_memory(
            &memory_address(address, instruction)?,
            instruction.memory_size().size() as u32 * 8,
        )),
        OpKind::Immediate8 => Ok(i64_const(instruction.immediate8() as i64)),
        OpKind::Immediate16 => Ok(i64_const(instruction.immediate16() as i64)),
        OpKind::Immediate32 => Ok(i64_const(instruction.immediate32() as i64)),
        OpKind::Immediate64 => Ok(i64_const(instruction.immediate64() as i64)),
        OpKind::Immediate8to16 => Ok(i64_const(instruction.immediate8to16() as i64)),
        OpKind::Immediate8to32 => Ok(i64_const(instruction.immediate8to32() as i64)),
        OpKind::Immediate8to64 => Ok(i64_const(instruction.immediate8to64())),
        OpKind::Immediate32to64 => Ok(i64_const(instruction.immediate32to64())),
        kind => Err(unsupported_operand(address, &format!("source {kind:?}"))),
    }
}

fn operand_width(instruction: &Instruction, index: u32) -> Option<u32> {
    match instruction.op_kind(index) {
        OpKind::Register => register(instruction.op_register(index)).map(|(_, width)| width),
        OpKind::Memory => Some(instruction.memory_size().size() as u32 * 8),
        _ => None,
    }
}

fn width_expression(value: &str, width: u32, signed: bool) -> String {
    match (width, signed) {
        (64, _) => value.to_string(),
        (32, false) => format!("(i64.extend_i32_u (i32.wrap_i64 {value}))"),
        (32, true) => format!("(i64.extend_i32_s (i32.wrap_i64 {value}))"),
        (16, false) => format!("(i64.and {value} (i64.const 65535))"),
        (16, true) => format!("(i64.extend_i32_s (i32.shr_s (i32.shl (i32.wrap_i64 {value}) (i32.const 16)) (i32.const 16)))"),
        (8, false) => format!("(i64.and {value} (i64.const 255))"),
        (8, true) => format!("(i64.extend_i32_s (i32.shr_s (i32.shl (i32.wrap_i64 {value}) (i32.const 24)) (i32.const 24)))"),
        _ => unreachable!("the ELF lowering only accepts 32-bit and 64-bit operands"),
    }
}

fn unsigned_mul_high(left: &str, right: &str) -> String {
    let mask = "(i64.const 4294967295)";
    let a0 = format!("(i64.and {left} {mask})");
    let a1 = format!("(i64.shr_u {left} (i64.const 32))");
    let b0 = format!("(i64.and {right} {mask})");
    let b1 = format!("(i64.shr_u {right} (i64.const 32))");
    let p0 = format!("(i64.mul {a0} {b0})");
    let p1 = format!("(i64.mul {a0} {b1})");
    let p2 = format!("(i64.mul {a1} {b0})");
    let p3 = format!("(i64.mul {a1} {b1})");
    let carry = format!(
        "(i64.shr_u (i64.add (i64.add (i64.shr_u {p0} (i64.const 32)) (i64.and {p1} {mask})) (i64.and {p2} {mask})) (i64.const 32))"
    );
    format!(
        "(i64.add (i64.add (i64.add {p3} (i64.shr_u {p1} (i64.const 32))) (i64.shr_u {p2} (i64.const 32))) {carry})"
    )
}

fn signed_mul_high(left: &str, right: &str) -> String {
    let unsigned = unsigned_mul_high(left, right);
    let left_adjustment = format!("(if (result i64) (i64.lt_s {left} (i64.const 0)) (then {right}) (else (i64.const 0)))");
    let right_adjustment = format!("(if (result i64) (i64.lt_s {right} (i64.const 0)) (then {left}) (else (i64.const 0)))");
    format!("(i64.sub (i64.sub {unsigned} {left_adjustment}) {right_adjustment})")
}

fn memory_address(address: u64, instruction: &Instruction) -> Result<String, X86ElfWasmError> {
    if instruction.is_ip_rel_memory_operand() {
        return Ok(format!("(i32.const {})", instruction.ip_rel_memory_address()));
    }
    let base = if instruction.memory_base() == Register::None {
        "(i32.const 0)".to_string()
    } else {
        let (register, _) = register(instruction.memory_base())
            .ok_or_else(|| unsupported_operand(address, "non-general-purpose memory base"))?;
        format!("(i32.wrap_i64 (local.get ${}))", register.name())
    };
    let displacement = instruction.memory_displacement64() as i64;
    let with_displacement = format!("(i32.add {base} (i32.const {displacement}))");
    if instruction.memory_index() == Register::None {
        return Ok(with_displacement);
    }
    let (index, _) = register(instruction.memory_index())
        .ok_or_else(|| unsupported_operand(address, "non-general-purpose memory index"))?;
    Ok(format!(
        "(i32.add {with_displacement} (i32.mul (i32.wrap_i64 (local.get ${})) (i32.const {})))",
        index.name(),
        instruction.memory_index_scale()
    ))
}

fn write_destination(destination: &Destination, value: &str) -> String {
    match destination {
        Destination::Register { register, width } => match width {
            64 => format!("(local.set ${} {value})", register.name()),
            32 => format!(
                "(local.set ${} (i64.extend_i32_u (i32.wrap_i64 {value})))",
                register.name()
            ),
            16 => format!(
                "(local.set ${} (i64.or (i64.and (local.get ${}) (i64.const -65536)) (i64.and {value} (i64.const 65535))))",
                register.name(), register.name()
            ),
            8 => format!(
                "(local.set ${} (i64.or (i64.and (local.get ${}) (i64.const -256)) (i64.and {value} (i64.const 255))))",
                register.name(), register.name()
            ),
            _ => unreachable!("unsupported register widths are rejected by register()"),
        },
        Destination::Memory { address, width } => match width {
            64 => format!("(i64.store {address} {value})"),
            32 => format!("(i32.store {address} (i32.wrap_i64 {value}))"),
            16 => format!("(i32.store16 {address} (i32.wrap_i64 {value}))"),
            8 => format!("(i32.store8 {address} (i32.wrap_i64 {value}))"),
            _ => unreachable!("unsupported memory widths are rejected by read_memory()"),
        },
    }
}

fn read_register(register: X86Register, width: u32) -> String {
    match width {
        64 => format!("(local.get ${})", register.name()),
        32 => format!("(i64.extend_i32_u (i32.wrap_i64 (local.get ${})))", register.name()),
        16 => format!("(i64.and (local.get ${}) (i64.const 65535))", register.name()),
        8 => format!("(i64.and (local.get ${}) (i64.const 255))", register.name()),
        _ => unreachable!("unsupported register widths are rejected by register()"),
    }
}

fn read_memory(address: &str, width: u32) -> String {
    match width {
        64 => format!("(i64.load {address})"),
        32 => format!("(i64.extend_i32_u (i32.load {address}))"),
        16 => format!("(i64.extend_i32_u (i32.load16_u {address}))"),
        8 => format!("(i64.extend_i32_u (i32.load8_u {address}))"),
        _ => unreachable!("unsupported memory widths are rejected by read_memory()"),
    }
}

fn register(register: Register) -> Option<(X86Register, u32)> {
    use Register::*;
    Some(match register {
        RAX => (X86Register::Rax, 64), EAX => (X86Register::Rax, 32), AX => (X86Register::Rax, 16), AL => (X86Register::Rax, 8),
        RCX => (X86Register::Rcx, 64), ECX => (X86Register::Rcx, 32), CX => (X86Register::Rcx, 16), CL => (X86Register::Rcx, 8),
        RDX => (X86Register::Rdx, 64), EDX => (X86Register::Rdx, 32), DX => (X86Register::Rdx, 16), DL => (X86Register::Rdx, 8),
        RBX => (X86Register::Rbx, 64), EBX => (X86Register::Rbx, 32), BX => (X86Register::Rbx, 16), BL => (X86Register::Rbx, 8),
        RSP => (X86Register::Rsp, 64), ESP => (X86Register::Rsp, 32), SP => (X86Register::Rsp, 16), SPL => (X86Register::Rsp, 8),
        RBP => (X86Register::Rbp, 64), EBP => (X86Register::Rbp, 32), BP => (X86Register::Rbp, 16), BPL => (X86Register::Rbp, 8),
        RSI => (X86Register::Rsi, 64), ESI => (X86Register::Rsi, 32), SI => (X86Register::Rsi, 16), SIL => (X86Register::Rsi, 8),
        RDI => (X86Register::Rdi, 64), EDI => (X86Register::Rdi, 32), DI => (X86Register::Rdi, 16), DIL => (X86Register::Rdi, 8),
        R8 => (X86Register::R8, 64), R8D => (X86Register::R8, 32), R8W => (X86Register::R8, 16), R8L => (X86Register::R8, 8),
        R9 => (X86Register::R9, 64), R9D => (X86Register::R9, 32), R9W => (X86Register::R9, 16), R9L => (X86Register::R9, 8),
        R10 => (X86Register::R10, 64), R10D => (X86Register::R10, 32), R10W => (X86Register::R10, 16), R10L => (X86Register::R10, 8),
        R11 => (X86Register::R11, 64), R11D => (X86Register::R11, 32), R11W => (X86Register::R11, 16), R11L => (X86Register::R11, 8),
        R12 => (X86Register::R12, 64), R12D => (X86Register::R12, 32), R12W => (X86Register::R12, 16), R12L => (X86Register::R12, 8),
        R13 => (X86Register::R13, 64), R13D => (X86Register::R13, 32), R13W => (X86Register::R13, 16), R13L => (X86Register::R13, 8),
        R14 => (X86Register::R14, 64), R14D => (X86Register::R14, 32), R14W => (X86Register::R14, 16), R14L => (X86Register::R14, 8),
        R15 => (X86Register::R15, 64), R15D => (X86Register::R15, 32), R15W => (X86Register::R15, 16), R15L => (X86Register::R15, 8),
        _ => return std::option::Option::None,
    })
}

fn collect_strings(image: &X86ElfImage) -> BTreeMap<u64, String> {
    let mut strings = BTreeMap::new();
    for segment in image.segments() {
        for offset in 0..segment.bytes.len() {
            if !segment.bytes[offset].is_ascii_graphic() && !segment.bytes[offset].is_ascii_whitespace() {
                continue;
            }
            let Some(end) = segment.bytes[offset..].iter().take(1024).position(|byte| *byte == 0) else {
                continue;
            };
            let raw = &segment.bytes[offset..offset + end];
            if raw.iter().all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace()) {
                if let Ok(value) = std::str::from_utf8(raw) {
                    strings.insert(segment.address + offset as u64, value.to_string());
                }
            }
        }
    }
    strings
}

fn memory_pages(image: &X86ElfImage) -> u64 {
    let image_end = image
        .segments()
        .iter()
        .map(|segment| segment.address.saturating_add(segment.bytes.len() as u64))
        .max()
        .unwrap_or(0);
    let bytes = image_end.max(STACK_TOP + 65536);
    bytes.div_ceil(65536)
}

fn emit_data_segments(wat: &mut String, image: &X86ElfImage) {
    for segment in image.segments() {
        let Some(last) = segment.bytes.iter().rposition(|byte| *byte != 0) else {
            continue;
        };
        write!(wat, "  (data (i32.const {}) \"", segment.address).unwrap();
        for byte in &segment.bytes[..=last] {
            write!(wat, "\\{:02x}", byte).unwrap();
        }
        wat.push_str("\")\n");
    }
}

fn i64_const(value: i64) -> String {
    format!("(i64.const {value})")
}

fn unsupported_operand(address: u64, operand: &str) -> X86ElfWasmError {
    X86ElfWasmError::UnsupportedOperand {
        address,
        operand: operand.to_string(),
    }
}

fn render_printf(format: &str, args: &[i64], strings: &BTreeMap<u64, String>) -> String {
    let mut output = String::new();
    let mut chars = format.chars().peekable();
    let mut arg_index = 0;
    while let Some(character) = chars.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            output.push('%');
            continue;
        }
        while matches!(chars.peek(), Some('l' | 'z' | 'h')) {
            chars.next();
        }
        let value = args.get(arg_index).copied().unwrap_or_default();
        arg_index += 1;
        match chars.next() {
            Some('d') | Some('i') => output.push_str(&(value as i64).to_string()),
            Some('u') => output.push_str(&(value as u64).to_string()),
            Some('x') | Some('X') => output.push_str(&format!("{value:x}")),
            Some('p') => output.push_str(&format!("0x{value:x}")),
            Some('c') => output.push(char::from_u32(value as u32).unwrap_or('?')),
            Some('s') => output.push_str(strings.get(&(value as u64)).map(String::as_str).unwrap_or("<unknown-string>")),
            Some(other) => {
                output.push('%');
                output.push(other);
            }
            None => output.push('%'),
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_integer_libc_subset() {
        let strings = BTreeMap::from([(7, "hello".to_string())]);
        assert_eq!(render_printf("x=%d %s\\n", &[42, 7], &strings), "x=42 hello\\n");
    }
}
