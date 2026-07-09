#[allow(unreachable_code)]
pub mod binary;
pub mod cache;
pub mod elf;
pub mod instruction;
pub mod page;
pub mod v;
#[cfg(feature = "ebpf")]
pub mod x86;
#[cfg(feature = "x86_elf")]
pub mod x86_elf;

static mut BIT_LENGTH: i8 = 0;
static mut IS_E: bool = false;
pub const VLEN: i32 = 2048;
pub const ELEN: i32 = 2048;
