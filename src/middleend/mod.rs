mod address_map;
#[cfg(feature = "ebpf")]
mod emit_ebpf;
#[cfg(feature = "wasm")]
mod emit_wasm;
#[cfg(feature = "wasm")]
mod wasm_module;

pub use address_map::{AddressMap, LinearMemory, MemorySegment};
#[cfg(feature = "ebpf")]
pub use emit_ebpf::{
    CompileTimeVerificationReport, EbpfCompileError, EbpfCompiler, EbpfEmitter, EbpfProgram,
    KernelVerifierPolicy, KernelVerifierReport, ProofObligation, VerificationReport,
};
#[cfg(feature = "wasm")]
pub use emit_wasm::WasmEmitter;
#[cfg(feature = "wasm")]
pub use wasm_module::{CsrState, RiscVState, WasmModule};
