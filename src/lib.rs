#![allow(clippy::needless_doctest_main)]
#![cfg_attr(documenting, feature(doc_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod codegen;
pub mod frontend;
pub mod middleend;
pub mod backend;
#[cfg(feature = "ebpf")]
pub use frontend::x86::{
    DecodedX86Instruction, X86DecodeError, X86Frontend, X86Instruction, X86Mode, X86Register,
    X86Width,
};
mod runtime;
pub mod tools;
