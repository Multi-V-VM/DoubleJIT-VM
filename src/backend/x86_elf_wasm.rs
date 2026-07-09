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
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::time::{SystemTime, UNIX_EPOCH};
use wasmer::{imports, Function, FunctionEnv, FunctionEnvMut, Instance, Memory, Module, Store, Value};

const STACK_TOP: u64 = 128 * 1024 * 1024;
const STACK_SENTINEL: u64 = STACK_TOP - 8;
const HEAP_BASE: u64 = 8 * 1024 * 1024;
const ARG_BASE: u64 = STACK_TOP - 1024 * 1024;

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
    symbols: BTreeMap<String, X86ElfWasmMemoryRegion>,
    instruction_count: usize,
}

/// A named, guest-addressable data region retained by the translated ELF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X86ElfWasmMemoryRegion {
    pub address: u64,
    pub size: u64,
}

pub struct X86ElfWasmRuntime {
    store: Store,
    _module: Module,
    _instance: Instance,
    memory: Memory,
    run: Function,
}

struct HostHeap {
    memory: Option<Memory>,
    next: u64,
    allocations: BTreeMap<u64, u64>,
    free_blocks: Vec<(u64, u64)>,
    strings: BTreeMap<u64, String>,
    files: BTreeMap<i64, File>,
    next_file: i64,
    stdin: Vec<u8>,
    stdin_offset: usize,
    errno: i32,
    errno_address: Option<u64>,
}

impl HostHeap {
    fn new(strings: BTreeMap<u64, String>) -> Self {
        Self {
            memory: None,
            next: HEAP_BASE,
            allocations: BTreeMap::new(),
            free_blocks: Vec::new(),
            strings,
            files: BTreeMap::new(),
            next_file: 3,
            stdin: std::env::var("DOUBLEJIT_STDIN")
                .unwrap_or_default()
                .into_bytes(),
            stdin_offset: 0,
            errno: 0,
            errno_address: None,
        }
    }
}

fn allocation_size(request: i64) -> Option<u64> {
    let request = u64::try_from(request).ok()?.max(1);
    request.checked_add(15).map(|value| value & !15)
}

fn host_allocate(env: &mut FunctionEnvMut<HostHeap>, request: i64) -> i64 {
    let Some(size) = allocation_size(request) else {
        return -1;
    };
    let heap = env.data_mut();
    if let Some(index) = heap
        .free_blocks
        .iter()
        .position(|(_, available)| *available >= size)
    {
        let (pointer, available) = heap.free_blocks.swap_remove(index);
        if available > size {
            heap.free_blocks.push((pointer + size, available - size));
        }
        heap.allocations.insert(pointer, size);
        return pointer as i64;
    }

    let Some(end) = heap.next.checked_add(size) else {
        return -1;
    };
    if end >= STACK_SENTINEL {
        return -1;
    }
    let pointer = heap.next;
    heap.next = end;
    heap.allocations.insert(pointer, size);
    pointer as i64
}

fn host_malloc(mut env: FunctionEnvMut<HostHeap>, request: i64) -> i64 {
    host_allocate(&mut env, request)
}

fn host_calloc(mut env: FunctionEnvMut<HostHeap>, count: i64, size: i64) -> i64 {
    let Some(request) = count.checked_mul(size) else {
        return -1;
    };
    let pointer = host_allocate(&mut env, request);
    if pointer < 0 {
        return pointer;
    }
    let Some(memory) = env.data().memory.clone() else {
        return -1;
    };
    let Some(byte_count) = allocation_size(request) else {
        return -1;
    };
    let bytes = vec![0; byte_count as usize];
    if memory.view(&env).write(pointer as u64, &bytes).is_err() {
        return -1;
    }
    pointer
}

fn host_free(mut env: FunctionEnvMut<HostHeap>, pointer: i64) {
    if pointer <= 0 {
        return;
    }
    let heap = env.data_mut();
    if let Some(size) = heap.allocations.remove(&(pointer as u64)) {
        heap.free_blocks.push((pointer as u64, size));
    }
}

fn write_host_time(env: &FunctionEnvMut<HostHeap>, pointer: i64, seconds: i64, fraction: i64) -> bool {
    let Some(memory) = env.data().memory.clone() else {
        return false;
    };
    let Ok(pointer) = u64::try_from(pointer) else {
        return false;
    };
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&seconds.to_le_bytes());
    bytes[8..].copy_from_slice(&fraction.to_le_bytes());
    memory.view(env).write(pointer, &bytes).is_ok()
}

fn host_gettimeofday(env: FunctionEnvMut<HostHeap>, timeval: i64, _timezone: i64) -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return -1;
    };
    if write_host_time(
        &env,
        timeval,
        duration.as_secs() as i64,
        duration.subsec_micros() as i64,
    ) {
        0
    } else {
        -1
    }
}

fn host_clock_gettime(env: FunctionEnvMut<HostHeap>, _clock: i64, timespec: i64) -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return -1;
    };
    if write_host_time(
        &env,
        timespec,
        duration.as_secs() as i64,
        duration.subsec_nanos() as i64,
    ) {
        0
    } else {
        -1
    }
}

fn guest_bytes(env: &FunctionEnvMut<HostHeap>, pointer: i64, length: usize) -> Option<Vec<u8>> {
    let memory = env.data().memory.clone()?;
    let pointer = u64::try_from(pointer).ok()?;
    memory
        .view(env)
        .copy_range_to_vec(pointer..pointer.checked_add(length as u64)?)
        .ok()
}

fn guest_string(env: &FunctionEnvMut<HostHeap>, pointer: i64) -> Option<String> {
    if let Some(bytes) = guest_bytes(env, pointer, 4096) {
        let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        return Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
    }
    env.data().strings.get(&(pointer as u64)).cloned()
}

fn write_guest(env: &FunctionEnvMut<HostHeap>, pointer: i64, bytes: &[u8]) -> bool {
    let Some(memory) = env.data().memory.clone() else {
        return false;
    };
    let Ok(pointer) = u64::try_from(pointer) else {
        return false;
    };
    memory.view(env).write(pointer, bytes).is_ok()
}

fn write_stdout(bytes: &[u8]) -> bool {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes).and_then(|_| stdout.flush()).is_ok()
}

fn format_strings(env: &FunctionEnvMut<HostHeap>, args: &[i64]) -> BTreeMap<u64, String> {
    let mut strings = env.data().strings.clone();
    for argument in args {
        if let Some(value) = guest_string(env, *argument) {
            strings.insert(*argument as u64, value);
        }
    }
    strings
}

fn host_printf(
    env: FunctionEnvMut<HostHeap>,
    format: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    arg5: i64,
    float0: f64,
    float1: f64,
    float2: f64,
    float3: f64,
    float4: f64,
    float5: f64,
    float6: f64,
    float7: f64,
) -> i64 {
    let Some(format) = guest_string(&env, format) else {
        return -1;
    };
    let integers = [arg1, arg2, arg3, arg4, arg5];
    let strings = format_strings(&env, &integers);
    let output = render_printf(
        &format,
        &integers,
        &[float0, float1, float2, float3, float4, float5, float6, float7],
        &strings,
    );
    if write_stdout(output.as_bytes()) {
        output.len() as i64
    } else {
        -1
    }
}

fn host_puts(env: FunctionEnvMut<HostHeap>, value: i64) -> i64 {
    let Some(value) = guest_string(&env, value) else {
        return -1;
    };
    let mut output = value;
    output.push('\n');
    if write_stdout(output.as_bytes()) {
        output.len() as i64
    } else {
        -1
    }
}

fn write_stream(env: &mut FunctionEnvMut<HostHeap>, stream: i64, bytes: &[u8]) -> bool {
    if stream <= 2 {
        return write_stdout(bytes);
    }
    match env.data_mut().files.get_mut(&stream) {
        Some(file) => file.write_all(bytes).is_ok(),
        None => false,
    }
}

fn host_fprintf(
    mut env: FunctionEnvMut<HostHeap>,
    stream: i64,
    format: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    float0: f64,
    float1: f64,
    float2: f64,
    float3: f64,
    float4: f64,
    float5: f64,
    float6: f64,
    float7: f64,
) -> i64 {
    let Some(format) = guest_string(&env, format) else {
        return -1;
    };
    let integers = [arg1, arg2, arg3, arg4];
    let strings = format_strings(&env, &integers);
    let output = render_printf(
        &format,
        &integers,
        &[float0, float1, float2, float3, float4, float5, float6, float7],
        &strings,
    );
    if write_stream(&mut env, stream, output.as_bytes()) {
        output.len() as i64
    } else {
        -1
    }
}

fn host_fopen(mut env: FunctionEnvMut<HostHeap>, path: i64, mode: i64) -> i64 {
    let Some(path) = guest_string(&env, path) else {
        return 0;
    };
    let Some(mode) = guest_string(&env, mode) else {
        return 0;
    };
    let mut options = OpenOptions::new();
    let readable = mode.contains('r') || mode.contains('+');
    let writable = mode.contains('w') || mode.contains('a') || mode.contains('+');
    options.read(readable).write(writable);
    if mode.contains('w') {
        options.create(true).truncate(true);
    }
    if mode.contains('a') {
        options.create(true).append(true);
    }
    match options.open(path) {
        Ok(file) => {
            let heap = env.data_mut();
            let handle = heap.next_file;
            heap.next_file += 1;
            heap.files.insert(handle, file);
            heap.errno = 0;
            handle
        }
        Err(_) => {
            env.data_mut().errno = 2;
            0
        }
    }
}

fn host_fclose(mut env: FunctionEnvMut<HostHeap>, stream: i64) -> i64 {
    match env.data_mut().files.remove(&stream) {
        Some(mut file) => match file.flush() {
            Ok(()) => 0,
            Err(_) => -1,
        },
        None => -1,
    }
}

fn host_fflush(mut env: FunctionEnvMut<HostHeap>, stream: i64) -> i64 {
    if stream <= 2 {
        return if std::io::stdout().flush().is_ok() { 0 } else { -1 };
    }
    match env.data_mut().files.get_mut(&stream) {
        Some(file) => if file.flush().is_ok() { 0 } else { -1 },
        None => -1,
    }
}

fn host_fwrite(mut env: FunctionEnvMut<HostHeap>, pointer: i64, size: i64, count: i64, stream: i64) -> i64 {
    let Some(total) = size.checked_mul(count).and_then(|value| usize::try_from(value).ok()) else {
        return 0;
    };
    let Some(bytes) = guest_bytes(&env, pointer, total) else {
        return 0;
    };
    if write_stream(&mut env, stream, &bytes) { count } else { 0 }
}

fn host_scanf(mut env: FunctionEnvMut<HostHeap>, format: i64, destination: i64) -> i64 {
    let Some(format) = guest_string(&env, format) else {
        return 0;
    };
    let (token, specifier) = {
        let heap = env.data_mut();
        let input = std::str::from_utf8(&heap.stdin[heap.stdin_offset..]).unwrap_or("");
        let Some(token) = input.split_whitespace().next() else {
            return 0;
        };
        heap.stdin_offset += input.find(token).unwrap_or_default() + token.len();
        (token.to_string(), format.chars().last().unwrap_or_default())
    };
    match specifier {
        'd' | 'i' => match token.parse::<i32>() {
            Ok(value) if write_guest(&env, destination, &value.to_le_bytes()) => 1,
            _ => 0,
        },
        'f' => match token.parse::<f64>() {
            Ok(value) if format.contains("lf") && write_guest(&env, destination, &value.to_le_bytes()) => 1,
            Ok(value) if write_guest(&env, destination, &(value as f32).to_le_bytes()) => 1,
            _ => 0,
        },
        _ => 0,
    }
}

fn host_atoi(env: FunctionEnvMut<HostHeap>, value: i64) -> i64 {
    guest_string(&env, value)
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or_default()
}

fn host_putchar(_env: FunctionEnvMut<HostHeap>, value: i64) -> i64 {
    if write_stdout(&[value as u8]) { value } else { -1 }
}

fn host_open(mut env: FunctionEnvMut<HostHeap>, path: i64, flags: i64, _mode: i64) -> i64 {
    let Some(path) = guest_string(&env, path) else {
        return -1;
    };
    let mut options = OpenOptions::new();
    let write = flags & 3 != 0;
    options.read(!write).write(write);
    match options.open(path) {
        Ok(file) => {
            let heap = env.data_mut();
            let handle = heap.next_file;
            heap.next_file += 1;
            heap.files.insert(handle, file);
            heap.errno = 0;
            handle
        }
        Err(_) => {
            env.data_mut().errno = 2;
            -1
        }
    }
}

fn host_fstat(env: FunctionEnvMut<HostHeap>, handle: i64, stat: i64) -> i64 {
    let metadata = if handle <= 2 {
        std::fs::metadata("/dev/stdout")
    } else {
        env.data()
            .files
            .get(&handle)
            .and_then(|file| file.metadata().ok())
            .ok_or_else(|| std::io::Error::from_raw_os_error(9))
    };
    let Ok(metadata) = metadata else {
        return -1;
    };
    let mode = if metadata.is_dir() { 0o040755_u32 } else { 0o100644_u32 };
    let mut bytes = [0_u8; 144];
    bytes[8..16].copy_from_slice(&1_u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&1_u64.to_le_bytes());
    bytes[24..28].copy_from_slice(&mode.to_le_bytes());
    bytes[48..56].copy_from_slice(&(metadata.len() as i64).to_le_bytes());
    if write_guest(&env, stat, &bytes) { 0 } else { -1 }
}

fn host_strerror(mut env: FunctionEnvMut<HostHeap>, errno: i64) -> i64 {
    let message = match errno {
        0 => "Success",
        2 => "No such file or directory",
        _ => "Unknown error",
    };
    let pointer = host_allocate(&mut env, message.len() as i64 + 1);
    if pointer < 0 || !write_guest(&env, pointer, format!("{message}\0").as_bytes()) {
        return 0;
    }
    pointer
}

fn host_errno_location(mut env: FunctionEnvMut<HostHeap>) -> i64 {
    if let Some(pointer) = env.data().errno_address {
        return pointer as i64;
    }
    let pointer = host_allocate(&mut env, 4);
    if pointer < 0 || !write_guest(&env, pointer, &env.data().errno.to_le_bytes()) {
        return 0;
    }
    env.data_mut().errno_address = Some(pointer as u64);
    pointer
}

fn host_pow(_env: FunctionEnvMut<HostHeap>, base: f64, exponent: f64) -> f64 {
    base.powf(exponent)
}

impl X86ElfWasmArtifact {
    pub fn wat(&self) -> &str {
        &self.wat
    }

    pub fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Return the address and ELF symbol size of a migratable data object.
    pub fn symbol_region(&self, name: &str) -> Option<X86ElfWasmMemoryRegion> {
        self.symbols.get(name).copied().filter(|region| region.size != 0)
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
        let heap_env = FunctionEnv::new(&mut store, HostHeap::new(self.strings.clone()));
        let printf = Function::new_typed_with_env(&mut store, &heap_env, host_printf);
        let puts = Function::new_typed_with_env(&mut store, &heap_env, host_puts);
        let malloc = Function::new_typed_with_env(&mut store, &heap_env, host_malloc);
        let calloc = Function::new_typed_with_env(&mut store, &heap_env, host_calloc);
        let free = Function::new_typed_with_env(&mut store, &heap_env, host_free);
        let gettimeofday = Function::new_typed_with_env(&mut store, &heap_env, host_gettimeofday);
        let clock_gettime = Function::new_typed_with_env(&mut store, &heap_env, host_clock_gettime);
        let fprintf = Function::new_typed_with_env(&mut store, &heap_env, host_fprintf);
        let fopen = Function::new_typed_with_env(&mut store, &heap_env, host_fopen);
        let fclose = Function::new_typed_with_env(&mut store, &heap_env, host_fclose);
        let fflush = Function::new_typed_with_env(&mut store, &heap_env, host_fflush);
        let fwrite = Function::new_typed_with_env(&mut store, &heap_env, host_fwrite);
        let scanf = Function::new_typed_with_env(&mut store, &heap_env, host_scanf);
        let atoi = Function::new_typed_with_env(&mut store, &heap_env, host_atoi);
        let putchar = Function::new_typed_with_env(&mut store, &heap_env, host_putchar);
        let open = Function::new_typed_with_env(&mut store, &heap_env, host_open);
        let fstat = Function::new_typed_with_env(&mut store, &heap_env, host_fstat);
        let strerror = Function::new_typed_with_env(&mut store, &heap_env, host_strerror);
        let errno_location = Function::new_typed_with_env(&mut store, &heap_env, host_errno_location);
        let pow = Function::new_typed_with_env(&mut store, &heap_env, host_pow);
        let no_op_int = Function::new_typed(&mut store, |_value: i64| -> i64 { 0 });
        let import_object = imports! {
            "env" => {
                "doublejit_printf" => printf,
                "doublejit_puts" => puts,
                "doublejit_malloc" => malloc,
                "doublejit_calloc" => calloc,
                "doublejit_free" => free,
                "doublejit_gettimeofday" => gettimeofday,
                "doublejit_clock_gettime" => clock_gettime,
                "doublejit_fprintf" => fprintf,
                "doublejit_fopen" => fopen,
                "doublejit_fclose" => fclose,
                "doublejit_fflush" => fflush,
                "doublejit_fwrite" => fwrite,
                "doublejit_scanf" => scanf,
                "doublejit_atoi" => atoi,
                "doublejit_putchar" => putchar,
                "doublejit_open" => open,
                "doublejit_fstat" => fstat,
                "doublejit_strerror" => strerror,
                "doublejit_errno_location" => errno_location,
                "doublejit_pow" => pow,
                "doublejit_fenv_noop" => no_op_int,
            }
        };
        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        let memory = instance
            .exports
            .get_memory("memory")
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?
            .clone();
        heap_env.as_mut(&mut store).memory = Some(memory.clone());
        let run = instance
            .exports
            .get_function("run")
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?
            .clone();
        Ok(X86ElfWasmRuntime {
            store,
            _module: module,
            _instance: instance,
            memory,
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
        self.execute_with_args(&[])
    }

    /// Execute with a conventional guest `argc`/`argv` vector in WASM memory.
    pub fn execute_with_args(&mut self, args: &[String]) -> Result<i64, X86ElfWasmError> {
        let pointers_bytes = (args.len() + 1)
            .checked_mul(8)
            .ok_or_else(|| X86ElfWasmError::Runtime("guest argv is too large".to_string()))?;
        let mut cursor = ARG_BASE + pointers_bytes as u64;
        let mut pointers = Vec::with_capacity(args.len());
        for arg in args {
            let bytes = arg.as_bytes();
            let end = cursor
                .checked_add(bytes.len() as u64 + 1)
                .ok_or_else(|| X86ElfWasmError::Runtime("guest argv is too large".to_string()))?;
            if end >= STACK_SENTINEL {
                return Err(X86ElfWasmError::Runtime(
                    "guest argv overlaps the translated stack".to_string(),
                ));
            }
            let mut terminated = bytes.to_vec();
            terminated.push(0);
            self.memory
                .view(&self.store)
                .write(cursor, &terminated)
                .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
            pointers.push(cursor);
            cursor = end;
        }
        let mut raw_pointers = Vec::with_capacity(pointers_bytes);
        for pointer in pointers {
            raw_pointers.extend_from_slice(&pointer.to_le_bytes());
        }
        raw_pointers.extend_from_slice(&0_u64.to_le_bytes());
        self.memory
            .view(&self.store)
            .write(ARG_BASE, &raw_pointers)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        let result = self
            .run
            .call(
                &mut self.store,
                &[Value::I64(args.len() as i64), Value::I64(ARG_BASE as i64)],
            )
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))?;
        match result.first() {
            Some(Value::I64(value)) => Ok(*value),
            _ => Err(X86ElfWasmError::Runtime(
                "translated main did not return an i64".to_string(),
            )),
        }
    }

    /// Copy an explicitly named guest region into a migration checkpoint.
    pub fn snapshot_region(
        &self,
        region: X86ElfWasmMemoryRegion,
    ) -> Result<Vec<u8>, X86ElfWasmError> {
        let end = region
            .address
            .checked_add(region.size)
            .ok_or_else(|| X86ElfWasmError::Runtime("migration region overflows guest memory".to_string()))?;
        self.memory
            .view(&self.store)
            .copy_range_to_vec(region.address..end)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))
    }

    /// Restore a checkpoint into the corresponding guest data region.
    pub fn restore_region(
        &mut self,
        region: X86ElfWasmMemoryRegion,
        checkpoint: &[u8],
    ) -> Result<(), X86ElfWasmError> {
        if checkpoint.len() as u64 != region.size {
            return Err(X86ElfWasmError::Runtime(format!(
                "checkpoint size {} does not match region size {}",
                checkpoint.len(),
                region.size
            )));
        }
        self.memory
            .view(&self.store)
            .write(region.address, checkpoint)
            .map_err(|error| X86ElfWasmError::Runtime(error.to_string()))
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
        let symbols = image
            .symbol_addresses()
            .iter()
            .filter_map(|(name, address)| {
                image.symbol_size(name).map(|size| {
                    (
                        name.clone(),
                        X86ElfWasmMemoryRegion {
                            address: *address,
                            size,
                        },
                    )
                })
            })
            .collect();

        let mut wat = String::new();
        wat.push_str("(module\n");
        wat.push_str("  (import \"env\" \"doublejit_printf\" (func $doublejit_printf (param i64 i64 i64 i64 i64 i64 f64 f64 f64 f64 f64 f64 f64 f64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_puts\" (func $doublejit_puts (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_malloc\" (func $doublejit_malloc (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_calloc\" (func $doublejit_calloc (param i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_free\" (func $doublejit_free (param i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_gettimeofday\" (func $doublejit_gettimeofday (param i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_clock_gettime\" (func $doublejit_clock_gettime (param i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fprintf\" (func $doublejit_fprintf (param i64 i64 i64 i64 i64 i64 f64 f64 f64 f64 f64 f64 f64 f64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fopen\" (func $doublejit_fopen (param i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fclose\" (func $doublejit_fclose (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fflush\" (func $doublejit_fflush (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fwrite\" (func $doublejit_fwrite (param i64 i64 i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_scanf\" (func $doublejit_scanf (param i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_atoi\" (func $doublejit_atoi (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_putchar\" (func $doublejit_putchar (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_open\" (func $doublejit_open (param i64 i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fstat\" (func $doublejit_fstat (param i64 i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_strerror\" (func $doublejit_strerror (param i64) (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_errno_location\" (func $doublejit_errno_location (result i64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_pow\" (func $doublejit_pow (param f64 f64) (result f64)))\n");
        wat.push_str("  (import \"env\" \"doublejit_fenv_noop\" (func $doublejit_fenv_noop (param i64) (result i64)))\n");
        writeln!(
            &mut wat,
            "  (memory (export \"memory\") {})",
            memory_pages(image)
        )
        .unwrap();
        writeln!(&mut wat, "  (global $heap (mut i32) (i32.const {HEAP_BASE}))").unwrap();
        emit_data_segments(&mut wat, image);
        wat.push_str("  (func $run (export \"run\") (param $guest_argc i64) (param $guest_argv i64) (result i64)\n");
        for register in X86Register::ALL {
            writeln!(&mut wat, "    (local ${} i64)", register.name()).unwrap();
        }
        for register in XmmRegister::ALL {
            writeln!(&mut wat, "    (local ${} f64)", register.name()).unwrap();
        }
        wat.push_str("    (local $pc i32)\n    (local $tmp i64)\n    (local $zf i32)\n    (local $sf i32)\n    (local $cf i32)\n    (local $pf i32)\n");
        wat.push_str("    (local.set $rdi (local.get $guest_argc))\n    (local.set $rsi (local.get $guest_argv))\n");
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
            symbols,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmmRegister {
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
}

impl XmmRegister {
    const ALL: [Self; 16] = [
        Self::Xmm0, Self::Xmm1, Self::Xmm2, Self::Xmm3, Self::Xmm4, Self::Xmm5,
        Self::Xmm6, Self::Xmm7, Self::Xmm8, Self::Xmm9, Self::Xmm10, Self::Xmm11,
        Self::Xmm12, Self::Xmm13, Self::Xmm14, Self::Xmm15,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Xmm0 => "xmm0", Self::Xmm1 => "xmm1", Self::Xmm2 => "xmm2", Self::Xmm3 => "xmm3",
            Self::Xmm4 => "xmm4", Self::Xmm5 => "xmm5", Self::Xmm6 => "xmm6", Self::Xmm7 => "xmm7",
            Self::Xmm8 => "xmm8", Self::Xmm9 => "xmm9", Self::Xmm10 => "xmm10", Self::Xmm11 => "xmm11",
            Self::Xmm12 => "xmm12", Self::Xmm13 => "xmm13", Self::Xmm14 => "xmm14", Self::Xmm15 => "xmm15",
        }
    }
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
        Mnemonic::Movsq => {
            wat.push_str("          (block $movsq_done\n            (loop $movsq_loop\n");
            wat.push_str("              (br_if $movsq_done (i64.eqz (local.get $rcx)))\n");
            wat.push_str("              (i64.store (i32.wrap_i64 (local.get $rdi)) (i64.load (i32.wrap_i64 (local.get $rsi))))\n");
            wat.push_str("              (local.set $rsi (i64.add (local.get $rsi) (i64.const 8)))\n");
            wat.push_str("              (local.set $rdi (i64.add (local.get $rdi) (i64.const 8)))\n");
            wat.push_str("              (local.set $rcx (i64.sub (local.get $rcx) (i64.const 1)))\n");
            wat.push_str("              (br $movsq_loop)\n            )\n          )\n");
            transition(wat, next);
        }
        Mnemonic::Pxor | Mnemonic::Xorpd | Mnemonic::Xorps | Mnemonic::Vpxor | Mnemonic::Vpxord | Mnemonic::Vpxorq | Mnemonic::Vxorpd | Mnemonic::Vxorps => {
            let destination = xmm_destination(decoded.address, instruction, 0)?;
            let first_source = xmm_operand(decoded.address, instruction, 1, false)?;
            let source_index = if instruction.op_count() == 3 { 2 } else { 1 };
            let second_source = xmm_operand(decoded.address, instruction, source_index, false)?;
            let zeroing = if instruction.op_count() == 3 {
                first_source == second_source
            } else {
                destination.read_expression() == first_source
            };
            if !zeroing {
                return Err(X86ElfWasmError::UnsupportedInstruction {
                    address: decoded.address,
                    instruction: "PXOR/XORPD with distinct XMM registers".to_string(),
                });
            }
            writeln!(wat, "          {}", write_xmm_destination(&destination, "(f64.const 0)")).unwrap();
            transition(wat, next);
        }
        Mnemonic::Movq | Mnemonic::Vmovq => {
            if instruction.op_kind(0) == OpKind::Register && xmm_register(instruction.op_register(0)).is_some() {
                let destination = xmm_destination(decoded.address, instruction, 0)?;
                if instruction.op_kind(1) == OpKind::Register && xmm_register(instruction.op_register(1)).is_some() {
                    let source = xmm_operand(decoded.address, instruction, 1, false)?;
                    writeln!(wat, "          {}", write_xmm_destination(&destination, &source)).unwrap();
                } else {
                    let source = operand_expr(decoded.address, instruction, 1)?;
                    writeln!(wat, "          {}", write_xmm_destination(&destination, &format!("(f64.reinterpret_i64 {source})"))).unwrap();
                }
            } else if instruction.op_kind(1) == OpKind::Register && xmm_register(instruction.op_register(1)).is_some() {
                let destination = operand_destination(decoded.address, instruction, 0)?;
                let source = xmm_operand(decoded.address, instruction, 1, false)?;
                writeln!(wat, "          {}", write_destination(&destination, &format!("(i64.reinterpret_f64 {source})"))).unwrap();
            } else {
                let destination = operand_destination(decoded.address, instruction, 0)?;
                let source = operand_expr(decoded.address, instruction, 1)?;
                writeln!(wat, "          {}", write_destination(&destination, &source)).unwrap();
            }
            transition(wat, next);
        }
        Mnemonic::Movsd | Mnemonic::Movss | Mnemonic::Movapd | Mnemonic::Movaps | Mnemonic::Vmovsd | Mnemonic::Vmovss | Mnemonic::Vmovapd | Mnemonic::Vmovaps => {
            let single = matches!(instruction.mnemonic(), Mnemonic::Movss | Mnemonic::Vmovss | Mnemonic::Movaps | Mnemonic::Vmovaps);
            let destination = xmm_destination(decoded.address, instruction, 0)?.with_scalar_kind(single);
            let source_index = if instruction.op_count() == 3 { 2 } else { 1 };
            let source = xmm_operand(decoded.address, instruction, source_index, single)?;
            writeln!(wat, "          {}", write_xmm_destination(&destination, &source)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Addsd | Mnemonic::Subsd | Mnemonic::Mulsd | Mnemonic::Divsd
        | Mnemonic::Addss | Mnemonic::Mulss | Mnemonic::Divss | Mnemonic::Vaddsd
        | Mnemonic::Vsubsd | Mnemonic::Vmulsd | Mnemonic::Vdivsd | Mnemonic::Vaddss
        | Mnemonic::Vsubss | Mnemonic::Vmulss | Mnemonic::Vdivss => {
            let single = matches!(instruction.mnemonic(), Mnemonic::Addss | Mnemonic::Mulss | Mnemonic::Divss | Mnemonic::Vaddss | Mnemonic::Vsubss | Mnemonic::Vmulss | Mnemonic::Vdivss);
            let destination = xmm_destination(decoded.address, instruction, 0)?;
            let left = if instruction.op_count() == 3 {
                xmm_operand(decoded.address, instruction, 1, single)?
            } else {
                destination.read_expression()
            };
            let right_index = if instruction.op_count() == 3 { 2 } else { 1 };
            let right = xmm_operand(decoded.address, instruction, right_index, single)?;
            let operation = match instruction.mnemonic() {
                Mnemonic::Addsd | Mnemonic::Addss | Mnemonic::Vaddsd | Mnemonic::Vaddss => "add",
                Mnemonic::Subsd | Mnemonic::Vsubsd | Mnemonic::Vsubss => "sub",
                Mnemonic::Mulsd | Mnemonic::Mulss | Mnemonic::Vmulsd | Mnemonic::Vmulss => "mul",
                Mnemonic::Divsd | Mnemonic::Divss | Mnemonic::Vdivsd | Mnemonic::Vdivss => "div",
                _ => unreachable!(),
            };
            let value = if single {
                format!("(f64.promote_f32 (f32.{operation} (f32.demote_f64 {left}) (f32.demote_f64 {right})))")
            } else {
                format!("(f64.{operation} {left} {right})")
            };
            writeln!(wat, "          {}", write_xmm_destination(&destination, &value)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Vzeroupper => transition(wat, next),
        Mnemonic::Cvtsi2sd => {
            let destination = xmm_destination(decoded.address, instruction, 0)?;
            let source = operand_expr(decoded.address, instruction, 1)?;
            let width = operand_width(instruction, 1).unwrap_or(64);
            let signed = width_expression(&source, width, true);
            writeln!(wat, "          {}", write_xmm_destination(&destination, &format!("(f64.convert_i64_s {signed})"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Cvtsd2ss => {
            let destination = xmm_destination(decoded.address, instruction, 0)?;
            let source = xmm_operand(decoded.address, instruction, 1, false)?;
            writeln!(wat, "          {}", write_xmm_destination(&destination, &format!("(f64.promote_f32 (f32.demote_f64 {source}))"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Cvtss2sd => {
            let destination = xmm_destination(decoded.address, instruction, 0)?;
            let source = xmm_operand(decoded.address, instruction, 1, true)?;
            writeln!(wat, "          {}", write_xmm_destination(&destination, &source)).unwrap();
            transition(wat, next);
        }
        Mnemonic::Cvttsd2si => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let source = xmm_operand(decoded.address, instruction, 1, false)?;
            writeln!(wat, "          {}", write_destination(&destination, &format!("(i64.trunc_sat_f64_s {source})"))).unwrap();
            transition(wat, next);
        }
        Mnemonic::Comisd | Mnemonic::Ucomisd | Mnemonic::Comiss | Mnemonic::Ucomiss
        | Mnemonic::Vcomisd | Mnemonic::Vucomisd | Mnemonic::Vcomiss | Mnemonic::Vucomiss => {
            let single = matches!(instruction.mnemonic(), Mnemonic::Comiss | Mnemonic::Ucomiss | Mnemonic::Vcomiss | Mnemonic::Vucomiss);
            let left = xmm_operand(decoded.address, instruction, 0, single)?;
            let right = xmm_operand(decoded.address, instruction, 1, single)?;
            writeln!(wat, "          (local.set $zf (f64.eq {left} {right}))").unwrap();
            writeln!(wat, "          (local.set $cf (f64.lt {left} {right}))").unwrap();
            wat.push_str("          (local.set $sf (i32.const 0))\n          (local.set $pf (i32.const 0))\n");
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
        Mnemonic::Not => {
            let destination = operand_destination(decoded.address, instruction, 0)?;
            let value = format!("(i64.xor {} (i64.const -1))", destination.read_expression());
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
        | Mnemonic::Setge | Mnemonic::Setb | Mnemonic::Setbe | Mnemonic::Seta | Mnemonic::Setae
        | Mnemonic::Setp | Mnemonic::Setnp => {
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
        | Mnemonic::Js | Mnemonic::Jns | Mnemonic::Jp => {
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
            wat.push_str("          (local.set $rax (call $doublejit_printf (local.get $rdi) (local.get $rsi) (local.get $rdx) (local.get $rcx) (local.get $r8) (local.get $r9) (local.get $xmm0) (local.get $xmm1) (local.get $xmm2) (local.get $xmm3) (local.get $xmm4) (local.get $xmm5) (local.get $xmm6) (local.get $xmm7)))\n");
        }
        "puts" => {
            wat.push_str("          (local.set $rax (call $doublejit_puts (local.get $rdi)))\n");
        }
        "exit" => {
            wat.push_str("          (local.get $rdi)\n          return\n");
        }
        "malloc" => {
            wat.push_str("          (local.set $rax (call $doublejit_malloc (local.get $rdi)))\n");
        }
        "calloc" => {
            wat.push_str("          (local.set $rax (call $doublejit_calloc (local.get $rdi) (local.get $rsi)))\n");
        }
        "free" => wat.push_str("          (call $doublejit_free (local.get $rdi))\n          (local.set $rax (i64.const 0))\n"),
        "gettimeofday" => {
            wat.push_str("          (local.set $rax (call $doublejit_gettimeofday (local.get $rdi) (local.get $rsi)))\n");
        }
        "clock_gettime" => {
            wat.push_str("          (local.set $rax (call $doublejit_clock_gettime (local.get $rdi) (local.get $rsi)))\n");
        }
        "fprintf" => {
            wat.push_str("          (local.set $rax (call $doublejit_fprintf (local.get $rdi) (local.get $rsi) (local.get $rdx) (local.get $rcx) (local.get $r8) (local.get $r9) (local.get $xmm0) (local.get $xmm1) (local.get $xmm2) (local.get $xmm3) (local.get $xmm4) (local.get $xmm5) (local.get $xmm6) (local.get $xmm7)))\n");
        }
        "fopen" => {
            wat.push_str("          (local.set $rax (call $doublejit_fopen (local.get $rdi) (local.get $rsi)))\n");
        }
        "fclose" => {
            wat.push_str("          (local.set $rax (call $doublejit_fclose (local.get $rdi)))\n");
        }
        "fflush" => {
            wat.push_str("          (local.set $rax (call $doublejit_fflush (local.get $rdi)))\n");
        }
        "fwrite" => {
            wat.push_str("          (local.set $rax (call $doublejit_fwrite (local.get $rdi) (local.get $rsi) (local.get $rdx) (local.get $rcx)))\n");
        }
        "scanf" | "__isoc99_scanf" => {
            wat.push_str("          (local.set $rax (call $doublejit_scanf (local.get $rdi) (local.get $rsi)))\n");
        }
        "atoi" => {
            wat.push_str("          (local.set $rax (call $doublejit_atoi (local.get $rdi)))\n");
        }
        "putchar" => {
            wat.push_str("          (local.set $rax (call $doublejit_putchar (local.get $rdi)))\n");
        }
        "open" => {
            wat.push_str("          (local.set $rax (call $doublejit_open (local.get $rdi) (local.get $rsi) (local.get $rdx)))\n");
        }
        "fstat" => {
            wat.push_str("          (local.set $rax (call $doublejit_fstat (local.get $rdi) (local.get $rsi)))\n");
        }
        "strerror" => {
            wat.push_str("          (local.set $rax (call $doublejit_strerror (local.get $rdi)))\n");
        }
        "__errno_location" => {
            wat.push_str("          (local.set $rax (call $doublejit_errno_location))\n");
        }
        "pow" => {
            wat.push_str("          (local.set $xmm0 (call $doublejit_pow (local.get $xmm0) (local.get $xmm1)))\n");
            wat.push_str("          (local.set $rax (i64.const 0))\n");
        }
        "feclearexcept" | "fetestexcept" | "fesetround" => {
            wat.push_str("          (local.set $rax (call $doublejit_fenv_noop (local.get $rdi)))\n");
        }
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
        Mnemonic::Jp | Mnemonic::Setp => "(local.get $pf)",
        Mnemonic::Setnp => "(i32.eqz (local.get $pf))",
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

#[derive(Debug, Clone)]
enum XmmDestination {
    Register(XmmRegister),
    Memory { address: String, single: bool },
}

impl XmmDestination {
    fn with_scalar_kind(self, single: bool) -> Self {
        match self {
            Self::Memory { address, .. } => Self::Memory { address, single },
            Self::Register(_) => self,
        }
    }

    fn read_expression(&self) -> String {
        match self {
            Self::Register(register) => format!("(local.get ${})", register.name()),
            Self::Memory { address, single } => read_xmm_memory(address, *single),
        }
    }
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

fn xmm_destination(
    address: u64,
    instruction: &Instruction,
    index: u32,
) -> Result<XmmDestination, X86ElfWasmError> {
    match instruction.op_kind(index) {
        OpKind::Register => xmm_register(instruction.op_register(index))
            .map(XmmDestination::Register)
            .ok_or_else(|| unsupported_operand(address, "non-XMM destination register")),
        OpKind::Memory => Ok(XmmDestination::Memory {
            address: memory_address(address, instruction)?,
            single: instruction.memory_size().size() == 4,
        }),
        kind => Err(unsupported_operand(address, &format!("XMM destination {kind:?}"))),
    }
}

fn xmm_operand(
    address: u64,
    instruction: &Instruction,
    index: u32,
    single: bool,
) -> Result<String, X86ElfWasmError> {
    match instruction.op_kind(index) {
        OpKind::Register => xmm_register(instruction.op_register(index))
            .map(|register| format!("(local.get ${})", register.name()))
            .ok_or_else(|| unsupported_operand(address, "non-XMM source register")),
        OpKind::Memory => Ok(read_xmm_memory(&memory_address(address, instruction)?, single)),
        kind => Err(unsupported_operand(address, &format!("XMM source {kind:?}"))),
    }
}

fn write_xmm_destination(destination: &XmmDestination, value: &str) -> String {
    match destination {
        XmmDestination::Register(register) => format!("(local.set ${} {value})", register.name()),
        XmmDestination::Memory { address, single } => {
            if *single {
                format!("(f32.store {address} (f32.demote_f64 {value}))")
            } else {
                format!("(f64.store {address} {value})")
            }
        }
    }
}

fn read_xmm_memory(address: &str, single: bool) -> String {
    if single {
        format!("(f64.promote_f32 (f32.load {address}))")
    } else {
        format!("(f64.load {address})")
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

fn xmm_register(register: Register) -> Option<XmmRegister> {
    use Register::*;
    Some(match register {
        XMM0 => XmmRegister::Xmm0,
        XMM1 => XmmRegister::Xmm1,
        XMM2 => XmmRegister::Xmm2,
        XMM3 => XmmRegister::Xmm3,
        XMM4 => XmmRegister::Xmm4,
        XMM5 => XmmRegister::Xmm5,
        XMM6 => XmmRegister::Xmm6,
        XMM7 => XmmRegister::Xmm7,
        XMM8 => XmmRegister::Xmm8,
        XMM9 => XmmRegister::Xmm9,
        XMM10 => XmmRegister::Xmm10,
        XMM11 => XmmRegister::Xmm11,
        XMM12 => XmmRegister::Xmm12,
        XMM13 => XmmRegister::Xmm13,
        XMM14 => XmmRegister::Xmm14,
        XMM15 => XmmRegister::Xmm15,
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

fn render_printf(
    format: &str,
    args: &[i64],
    float_args: &[f64],
    strings: &BTreeMap<u64, String>,
) -> String {
    let mut output = String::new();
    let mut chars = format.chars().peekable();
    let mut arg_index = 0;
    let mut float_index = 0;
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
        while matches!(chars.peek(), Some('-' | '+' | ' ' | '#' | '0')) {
            chars.next();
        }
        while matches!(chars.peek(), Some('0'..='9')) {
            chars.next();
        }
        let mut precision = None;
        if chars.peek() == Some(&'.') {
            chars.next();
            let mut value = String::new();
            while let Some('0'..='9') = chars.peek() {
                value.push(chars.next().unwrap());
            }
            precision = value.parse::<usize>().ok().or(Some(0));
        }
        while matches!(chars.peek(), Some('l' | 'z' | 'h' | 'j' | 't' | 'L')) {
            chars.next();
        }
        match chars.next() {
            Some('d') | Some('i') => {
                let value = args.get(arg_index).copied().unwrap_or_default();
                arg_index += 1;
                output.push_str(&value.to_string());
            }
            Some('u') => {
                let value = args.get(arg_index).copied().unwrap_or_default();
                arg_index += 1;
                output.push_str(&(value as u64).to_string());
            }
            Some('x') | Some('X') => {
                let value = args.get(arg_index).copied().unwrap_or_default();
                arg_index += 1;
                output.push_str(&format!("{value:x}"));
            }
            Some('p') => {
                let value = args.get(arg_index).copied().unwrap_or_default();
                arg_index += 1;
                output.push_str(&format!("0x{value:x}"));
            }
            Some('c') => {
                let value = args.get(arg_index).copied().unwrap_or_default();
                arg_index += 1;
                output.push(char::from_u32(value as u32).unwrap_or('?'));
            }
            Some('s') => {
                let value = args.get(arg_index).copied().unwrap_or_default();
                arg_index += 1;
                output.push_str(strings.get(&(value as u64)).map(String::as_str).unwrap_or("<unknown-string>"));
            }
            Some('f') | Some('F') => {
                let value = float_args.get(float_index).copied().unwrap_or_default();
                float_index += 1;
                let precision = precision.unwrap_or(6);
                output.push_str(&format!("{value:.precision$}"));
            }
            Some('e') | Some('E') => {
                let value = float_args.get(float_index).copied().unwrap_or_default();
                float_index += 1;
                let precision = precision.unwrap_or(6);
                output.push_str(&format!("{value:.precision$e}"));
            }
            Some('g') | Some('G') => {
                let value = float_args.get(float_index).copied().unwrap_or_default();
                float_index += 1;
                output.push_str(&value.to_string());
            }
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
        assert_eq!(
            render_printf("x=%d %s %.2f\\n", &[42, 7], &[1.5], &strings),
            "x=42 hello 1.50\\n"
        );
    }
}
