mod address_map;
#[cfg(feature = "ebpf")]
mod emit_ebpf;
mod emit_wasm;
mod wasm_module;

pub use address_map::{AddressMap, LinearMemory, MemorySegment};
#[cfg(feature = "ebpf")]
pub use emit_ebpf::{
    CompileTimeVerificationReport, EbpfCompileError, EbpfCompiler, EbpfEmitter, EbpfProgram,
    KernelVerifierPolicy, KernelVerifierReport, ProofObligation, VerificationReport,
};
pub use emit_wasm::WasmEmitter;
pub use wasm_module::{CsrState, RiscVState, WasmModule};
