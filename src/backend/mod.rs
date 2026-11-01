#[cfg(feature = "ebpf")]
pub mod ebpf_builder;
#[cfg(all(feature = "ebpf", feature = "wasm"))]
pub mod ebpf_wasm;
#[cfg(feature = "ebpf")]
pub mod ebpf_x86;
#[cfg(feature = "wasm")]
pub mod wasm_builder;
#[cfg(feature = "ebpf")]
pub mod x86_ebpf;
#[cfg(feature = "x86_elf")]
pub mod actor_migration;
#[cfg(feature = "x86_elf")]
pub mod x86_elf_wasm;

#[cfg(feature = "ebpf")]
pub use ebpf_builder::{
    collect_executable_instructions, AyaEbpfBuilder, EbpfRejitCache, EbpfRejitError,
    VerifiedRejitBlock,
};
#[cfg(all(feature = "ebpf", feature = "wasm"))]
pub use ebpf_wasm::{EbpfWasmArtifact, EbpfWasmCompiler, EbpfWasmError};
#[cfg(feature = "ebpf")]
pub use ebpf_x86::{
    EbpfX86Artifact, EbpfX86Compiler, EbpfX86Error, EbpfX86Runtime,
    NativeOpKind, NativeOpPolicy, NativeOptimization, RotateFusion,
};
#[cfg(feature = "wasm")]
pub use wasm_builder::{OptLevel, RiscVRuntime, RuntimeBuilder, WasmBuilder};
#[cfg(feature = "ebpf")]
pub use x86_ebpf::{X86EbpfCompiler, X86EbpfError, X86EbpfProgram, X86EbpfSourceMap};
#[cfg(feature = "x86_elf")]
pub use actor_migration::{
    ActorCrashPoint, ActorMigrationPhase, ActorOwner, PmrActorCheckpoint,
    X86ActorReplayMigration,
};
#[cfg(feature = "x86_elf")]
pub use x86_elf_wasm::{
    X86ElfWasmArtifact, X86ElfWasmCompiler, X86ElfWasmError, X86ElfWasmMemoryRegion,
    X86ElfWasmRuntime,
};

#[cfg(feature = "ebpf")]
pub mod risc_ebpf;
#[cfg(feature = "ebpf")]
pub mod ebpf_native;
#[cfg(feature = "ebpf")]
pub use risc_ebpf::{Arm64EbpfCompiler, RiscV64EbpfCompiler, RiscEbpfProgram, RiscDecodeError};
#[cfg(feature = "ebpf")]
pub use ebpf_native::{EbpfNativeCompiler, NativeTarget, EbpfNativeArtifact, EbpfNativeRuntime, EbpfNativeError};
