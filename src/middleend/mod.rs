mod address_map;
mod wasm_module;
mod emit_wasm;

pub use address_map::{AddressMap, MemorySegment, LinearMemory};
pub use wasm_module::{WasmModule, RiscVState, CsrState};
pub use emit_wasm::WasmEmitter;