//! Direct userspace eBPF ALU -> x86-64 JIT, without a WASM intermediate.
//!
//! This executes a restricted userspace eBPF subset
//! with r0 set to a runtime input (zero by default), r1..r9 zero, and returns r0.
//! Optional native operations fuse checked hardware idioms. This is not a Linux kernel BPF
//! loader/verifier or a complete x86 ABI emulator. Code generation is portable;
//! execution currently requires an x86-64 Linux host.

use aya_obj::generated::bpf_insn;
use core::fmt;

// x86 encoding numbers: RAX, RCX, RDX, RBX, RSI, RDI, R8, R9, R10, R11.
// Neither the stack pointer nor the frame pointer can be addressed by BPF.
const REGISTERS: [u8; 10] = [0, 1, 2, 3, 6, 7, 8, 9, 10, 11];

#[derive(Debug)]
pub enum EbpfX86Error {
    InvalidRegister { index: usize, register: u8 },
    UnsupportedInstruction { index: usize, code: u8 },
    InvalidEncoding { index: usize },
    MissingExit,
    InstructionAfterExit { index: usize },
    UnsupportedHost,
    UnsupportedTarget(String),
    Memory(std::io::Error),
    BufferTooSmall { required: usize, actual: usize },
}

impl fmt::Display for EbpfX86Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRegister { index, register } => write!(
                f,
                "eBPF instruction {index} uses unsupported register r{register}"
            ),
            Self::UnsupportedInstruction { index, code } => write!(
                f,
                "eBPF instruction {index} has unsupported code 0x{code:02x}"
            ),
            Self::InvalidEncoding { index } => {
                write!(
                    f,
                    "eBPF instruction {index} has invalid operands or reserved fields"
                )
            }
            Self::MissingExit => write!(f, "eBPF program has no terminal exit"),
            Self::InstructionAfterExit { index } => {
                write!(f, "eBPF instruction {index} appears after terminal exit")
            }
            Self::UnsupportedTarget(message) => write!(f, "{message}"),
            Self::UnsupportedHost => write!(f, "native eBPF execution requires x86-64 Linux"),
            Self::Memory(error) => write!(f, "JIT executable memory: {error}"),
            Self::BufferTooSmall { required, actual } => {
                write!(f, "JIT needs {required} buffer bytes, got {actual}")
            }
        }
    }
}

impl std::error::Error for EbpfX86Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Memory(error) => Some(error),
            _ => None,
        }
    }
}

/// Validated machine code with an `extern "C" fn(u64) -> u64` ABI.
/// The bytes are private so arbitrary code cannot enter the safe JIT API.
#[derive(Debug, Clone)]
pub struct EbpfX86Artifact {
    code: Vec<u8>,
    fusions: Vec<RotateFusion>,
    optimizations: Vec<NativeOptimization>,
    required_memory: usize,
}

/// Inspectable vanilla-eBPF sequence replaced by one native ROL instruction.
/// This records a checked rewrite, not a formal or kernel-verifier proof.
#[derive(Debug, Clone)]
pub struct RotateFusion {
    pub ebpf_index: usize,
    pub width: u8,
    pub count: u8,
    pub destination: u8,
    pub temporary: u8,
    pub proof_sequence: Vec<bpf_insn>,
}

impl EbpfX86Artifact {
    pub fn machine_code(&self) -> &[u8] {
        &self.code
    }

    pub fn optimizations(&self) -> &[NativeOptimization] {
        &self.optimizations
    }
    pub fn required_memory(&self) -> usize {
        self.required_memory
    }

    pub fn fusions(&self) -> &[RotateFusion] {
        &self.fusions
    }

    /// Allocate writable memory, copy code, then change it to read/execute.
    /// The returned owner keeps the mapping alive for repeated calls.
    pub fn prepare(&self) -> Result<EbpfX86Runtime, EbpfX86Error> {
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        {
            let mut memory =
                memmap2::MmapMut::map_anon(self.code.len()).map_err(EbpfX86Error::Memory)?;
            memory.copy_from_slice(&self.code);
            let memory = memory.make_exec().map_err(EbpfX86Error::Memory)?;
            Ok(EbpfX86Runtime {
                memory,
                required_memory: self.required_memory,
            })
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
        Err(EbpfX86Error::UnsupportedHost)
    }

    pub fn execute(&self) -> Result<u64, EbpfX86Error> {
        self.prepare()?.execute()
    }
}

/// An owned RX mapping; dropping it releases the generated code.
pub struct EbpfX86Runtime {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    memory: memmap2::Mmap,
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    required_memory: usize,
}

impl EbpfX86Runtime {
    /// Run with r0 = 0, preserving the original no-input API.
    pub fn execute(&self) -> Result<u64, EbpfX86Error> {
        self.execute_with_input(0)
    }

    /// Set r0 to `input` and reset r1..r9 on every call.
    pub fn execute_with_input(&self, input: u64) -> Result<u64, EbpfX86Error> {
        self.execute_with_memory(input, &mut [])
    }

    /// Memory instructions may only access fixed validated offsets from r10.
    /// r10 is an immutable buffer base, not the kernel eBPF stack pointer.
    pub fn execute_with_memory(&self, input: u64, buffer: &mut [u8]) -> Result<u64, EbpfX86Error> {
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        {
            if buffer.len() < self.required_memory {
                return Err(EbpfX86Error::BufferTooSmall {
                    required: self.required_memory,
                    actual: buffer.len(),
                });
            }
            // SAFETY: codegen validates all instructions and fixed buffer offsets;
            // only forward skip-MOV branches exist. r10 cannot be modified or
            // exposed as an integer. The checked exclusive slice outlives the call.
            // Code is immutable RX, the generated function preserves the SysV ABI.
            let run: unsafe extern "C" fn(u64, *mut u8) -> u64 =
                unsafe { core::mem::transmute(self.memory.as_ptr()) };
            Ok(unsafe { run(input, buffer.as_mut_ptr()) })
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
        {
            let _ = (input, buffer);
            Err(EbpfX86Error::UnsupportedHost)
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EbpfX86Compiler {
    native_ops: bool,
    policy: NativeOpPolicy,
    no_optional_isa: bool,
}

impl EbpfX86Compiler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable Kops-inspired bytecode recovery. Unmatched patterns use the
    /// ordinary emitter; all bytecode is validated before any rewrite.
    pub fn with_native_ops(mut self, enabled: bool) -> Self {
        self.native_ops = enabled;
        self
    }

    /// Compile the validated userspace eBPF subset. See the native-ops docs
    /// for the bounded-buffer ABI and the supported branch shape.
    pub fn compile(&self, instructions: &[bpf_insn]) -> Result<EbpfX86Artifact, EbpfX86Error> {
        codegen::compile(self, instructions, &[])
    }

    /// Compile x86-produced bytecode including explicit prefetch hints.
    pub fn compile_program(
        &self,
        program: &super::X86EbpfProgram,
    ) -> Result<EbpfX86Artifact, EbpfX86Error> {
        codegen::compile(self, program.instructions(), program.prefetch_hints())
    }

    /// Hints are (index of a canonical JA +0, buffer offset). Both are checked.
    pub fn compile_with_prefetch_hints(
        &self,
        instructions: &[bpf_insn],
        hints: &[(usize, u16)],
    ) -> Result<EbpfX86Artifact, EbpfX86Error> {
        codegen::compile(self, instructions, hints)
    }

    pub fn with_policy(mut self, policy: NativeOpPolicy) -> Self {
        self.native_ops = true;
        self.policy = policy;
        self
    }

    /// Disable optional BMI1/MOVBE instructions even if this CPU has them.
    pub fn without_optional_isa(mut self) -> Self {
        self.no_optional_isa = true;
        self
    }
}

#[path = "ebpf_x86_codegen.rs"]
pub(crate) mod codegen;

fn register(index: usize, register: u8) -> Result<u8, EbpfX86Error> {
    REGISTERS
        .get(register as usize)
        .copied()
        .ok_or(EbpfX86Error::InvalidRegister { index, register })
}

fn emit_reg(code: &mut Vec<u8>, wide: bool, opcode: u8, dst: u8, src: u8) {
    let rex = 0x40 | (u8::from(wide) << 3) | ((src >> 3) << 2) | (dst >> 3);
    if rex != 0x40 {
        code.push(rex);
    }
    code.extend_from_slice(&[opcode, 0xc0 | ((src & 7) << 3) | (dst & 7)]);
}

/// Independent profitability switches. Prefetch is emitted only at explicit hints.
#[derive(Debug, Clone, Copy)]
pub struct NativeOpPolicy {
    pub rotate: bool,
    pub select: bool,
    pub extract: bool,
    pub lea: bool,
    pub endian: bool,
    pub bulk_copy: bool,
    pub prefetch: bool,
    pub alu: bool,
}
impl Default for NativeOpPolicy {
    fn default() -> Self {
        Self {
            select: false,
            prefetch: false,
            ..Self::all()
        }
    }
}
impl NativeOpPolicy {
    /// Enable every family for explicit experiments. This is not a speed claim:
    /// CMOV can lose to predictable branches, and prefetch can hurt hot data.
    pub fn all() -> Self {
        Self {
            rotate: true,
            select: true,
            extract: true,
            lea: true,
            endian: true,
            bulk_copy: true,
            prefetch: true,
            alu: true,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOpKind {
    RotateLeft,
    RotateRight,
    Select,
    BitExtract,
    Lea,
    EndianLoad,
    BulkCopy,
    Prefetch,
    AluFold,
    SignExtend,
}
#[derive(Debug, Clone)]
pub struct NativeOptimization {
    pub kind: NativeOpKind,
    pub ebpf_index: usize,
    pub proof_sequence: Vec<bpf_insn>,
}
