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
mod runtime;
pub mod tools;
