//! Direct AArch64 and RV64I userspace JITs. No WASM dependency.
use super::ebpf_x86::codegen::{is_branch, is_load, is_store, live_after, size, validate};
use super::ebpf_x86::{EbpfX86Error, NativeOpKind, NativeOpPolicy, NativeOptimization};
use aya_obj::generated::bpf_insn;
/// Shared validation/runtime error type used by the direct native backends.
pub type EbpfNativeError = EbpfX86Error;
#[path = "ebpf_native_emit.rs"]
mod emit;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTarget {
    Arm64,
    RiscV64,
}
impl NativeTarget {
    pub fn host() -> Option<Self> {
        if cfg!(all(target_arch = "aarch64", target_os = "linux")) {
            Some(Self::Arm64)
        } else if cfg!(all(target_arch = "riscv64", target_os = "linux")) {
            Some(Self::RiscV64)
        } else {
            None
        }
    }
}
#[derive(Debug, Clone)]
pub struct EbpfNativeArtifact {
    target: NativeTarget,
    code: Vec<u8>,
    required_memory: usize,
    optimizations: Vec<NativeOptimization>,
}
impl EbpfNativeArtifact {
    pub fn target(&self) -> NativeTarget {
        self.target
    }
    pub fn machine_code(&self) -> &[u8] {
        &self.code
    }
    pub fn required_memory(&self) -> usize {
        self.required_memory
    }
    pub fn optimizations(&self) -> &[NativeOptimization] {
        &self.optimizations
    }
    pub fn prepare(&self) -> Result<EbpfNativeRuntime, EbpfX86Error> {
        if NativeTarget::host() != Some(self.target) {
            return Err(EbpfX86Error::UnsupportedTarget(format!(
                "{:?} requires a matching 64-bit Linux host",
                self.target
            )));
        }
        let mut memory =
            memmap2::MmapMut::map_anon(self.code.len()).map_err(EbpfX86Error::Memory)?;
        memory.copy_from_slice(&self.code);
        let memory = memory.make_exec().map_err(EbpfX86Error::Memory)?;
        // Both ISAs require instruction-cache synchronization after code writes.
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        unsafe {
            unsafe extern "C" {
                fn __clear_cache(begin: *mut u8, end: *mut u8);
            }
            __clear_cache(
                memory.as_ptr() as *mut u8,
                memory.as_ptr().add(memory.len()) as *mut u8,
            );
        }
        #[cfg(all(target_arch = "riscv64", target_os = "linux"))]
        {
            // Linux RISC-V syscall 244 (arch-specific base) + 15 = 259.
            // flags=0 flushes across threads (fence.i alone does not cover migration).
            let status = unsafe {
                libc::syscall(
                    259 as libc::c_long,
                    memory.as_ptr(),
                    memory.as_ptr().add(memory.len()),
                    0,
                )
            };
            if status != 0 {
                return Err(EbpfX86Error::Memory(std::io::Error::last_os_error()));
            }
        }
        Ok(EbpfNativeRuntime {
            memory,
            required_memory: self.required_memory,
        })
    }
    pub fn execute(&self, input: u64) -> Result<u64, EbpfX86Error> {
        self.prepare()?.execute_with_input(input)
    }
}
pub struct EbpfNativeRuntime {
    memory: memmap2::Mmap,
    required_memory: usize,
}
impl EbpfNativeRuntime {
    pub fn execute_with_input(&self, input: u64) -> Result<u64, EbpfX86Error> {
        self.execute_with_memory(input, &mut [])
    }
    pub fn execute_with_memory(&self, input: u64, buffer: &mut [u8]) -> Result<u64, EbpfX86Error> {
        if buffer.len() < self.required_memory {
            return Err(EbpfX86Error::BufferTooSmall {
                required: self.required_memory,
                actual: buffer.len(),
            });
        }
        // SAFETY: private construction requires matching host ISA and complete
        // validation. Only fixed checked buffer offsets, bounded forward skip-MOV
        // branches, and ABI-volatile integer registers are emitted. Cache flush
        // finished before this owned RX mapping was made callable.
        let run: unsafe extern "C" fn(u64, *mut u8) -> u64 =
            unsafe { core::mem::transmute(self.memory.as_ptr()) };
        Ok(unsafe { run(input, buffer.as_mut_ptr()) })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct EbpfNativeCompiler {
    target: NativeTarget,
    enabled: bool,
    policy: NativeOpPolicy,
}
impl EbpfNativeCompiler {
    pub fn new(target: NativeTarget) -> Self {
        Self {
            target,
            enabled: false,
            policy: NativeOpPolicy::default(),
        }
    }
    pub fn with_native_ops(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
    pub fn with_policy(mut self, policy: NativeOpPolicy) -> Self {
        self.enabled = true;
        self.policy = policy;
        self
    }
    pub fn compile(&self, p: &[bpf_insn]) -> Result<EbpfNativeArtifact, EbpfX86Error> {
        self.compile_with_prefetch_hints(p, &[])
    }
    pub fn compile_with_prefetch_hints(
        &self,
        p: &[bpf_insn],
        hints: &[(usize, u16)],
    ) -> Result<EbpfNativeArtifact, EbpfX86Error> {
        let required_memory = validate(p, hints)?;
        let live = live_after(p);
        let mut emitter = emit::Emitter::new(self.target);
        emitter.prologue();
        let mut optimizations = vec![];
        let mut i = 0;
        let mut blocked_bulk = 0;
        while i < p.len() {
            let a = &p[i];
            let class = a.code & 7;
            let wide = class == 7;
            let bits = if wide { 64 } else { 32 };
            let mut n = 1;
            let mut kind = None;
            let before = emitter.words.len();
            if is_branch(a) {
                emitter.select(a, &p[i + 1], self.enabled && self.policy.select);
                n = 2;
                if self.target == NativeTarget::Arm64 && self.enabled && self.policy.select {
                    kind = Some(NativeOpKind::Select);
                }
            } else if self.enabled {
                if self.policy.rotate && i + 4 < p.len() {
                    let b = &p[i + 1];
                    let c = &p[i + 2];
                    let d = &p[i + 3];
                    let dst = a.src_reg();
                    let temp = a.dst_reg();
                    let left = b.code == class | 0x60 && c.code == class | 0x70;
                    let right = b.code == class | 0x70 && c.code == class | 0x60;
                    if matches!(class, 4 | 7)
                        && a.code == class | 0xb8
                        && dst != temp
                        && (left || right)
                        && b.dst_reg() == dst
                        && c.dst_reg() == temp
                        && d.code == class | 0x48
                        && d.dst_reg() == dst
                        && d.src_reg() == temp
                        && b.imm > 0
                        && c.imm > 0
                        && b.imm + c.imm == bits
                        && live[i + 3] & (1 << temp) == 0
                    {
                        emitter.rotate(dst, wide, b.imm as u8, left);
                        n = 4;
                        kind = Some(if left {
                            NativeOpKind::RotateLeft
                        } else {
                            NativeOpKind::RotateRight
                        });
                    }
                }
                if kind.is_none()
                    && self.policy.alu
                    && self.target == NativeTarget::RiscV64
                    && class == 4
                    && a.code != 0xdc
                    && i + 2 < p.len()
                {
                    let l = &p[i + 1];
                    let r = &p[i + 2];
                    if l.code == 0x67
                        && r.code == 0xc7
                        && l.dst_reg() == a.dst_reg()
                        && r.dst_reg() == a.dst_reg()
                        && l.imm == 32
                        && r.imm == 32
                    {
                        emitter.word(a);
                        n = 3;
                        kind = Some(NativeOpKind::SignExtend);
                    }
                }
                if kind.is_none()
                    && self.policy.alu
                    && a.code == 0x67
                    && a.imm == 32
                    && i + 1 < p.len()
                {
                    let b = &p[i + 1];
                    if b.code == 0xc7 && b.dst_reg() == a.dst_reg() && b.imm == 32 {
                        emitter.sign_extend_word(a.dst_reg());
                        n = 2;
                        kind = Some(NativeOpKind::SignExtend);
                    }
                }
                if kind.is_none()
                    && self.policy.extract
                    && matches!(a.code, 0x74 | 0x77)
                    && i + 1 < p.len()
                {
                    let b = &p[i + 1];
                    let mask = if wide {
                        b.imm as i64 as u64
                    } else {
                        b.imm as u32 as u64
                    };
                    if b.code == class | 0x50
                        && b.dst_reg() == a.dst_reg()
                        && mask != 0
                        && mask & mask.wrapping_add(1) == 0
                    {
                        emitter.extract(a.dst_reg(), wide, a.imm as u8, mask.trailing_ones() as u8);
                        n = 2;
                        kind = Some(NativeOpKind::BitExtract);
                    }
                }
                if kind.is_none()
                    && self.policy.lea
                    && matches!(a.code, 0x64 | 0x67)
                    && (0..=3).contains(&a.imm)
                    && i + 1 < p.len()
                {
                    let b = &p[i + 1];
                    if b.code == class | 8
                        && b.dst_reg() == a.dst_reg()
                        && b.src_reg() != a.dst_reg()
                    {
                        emitter.lea(a.dst_reg(), b.src_reg(), wide, a.imm as u8);
                        n = 2;
                        kind = Some(NativeOpKind::Lea);
                    }
                }
                if kind.is_none()
                    && self.policy.bulk_copy
                    && self.target == NativeTarget::Arm64
                    && a.code == 0x79
                    && i >= blocked_bulk
                    && i + 1 < p.len()
                {
                    let src = a.off as i32;
                    let dst = p[i + 1].off as i32;
                    let temp = a.dst_reg();
                    let mut pairs = 0;
                    while i + 2 * pairs + 1 < p.len() {
                        let l = &p[i + 2 * pairs];
                        let s = &p[i + 2 * pairs + 1];
                        if l.code != 0x79
                            || s.code != 0x7b
                            || l.dst_reg() != temp
                            || s.src_reg() != temp
                            || l.off as i32 != src + 8 * pairs as i32
                            || s.off as i32 != dst + 8 * pairs as i32
                        {
                            break;
                        }
                        pairs += 1;
                    }
                    let disjoint = src + 8 * pairs as i32 <= dst || dst + 8 * pairs as i32 <= src;
                    if pairs >= 2 && !disjoint {
                        blocked_bulk = i + 2 * pairs;
                    }
                    if pairs >= 2
                        && pairs % 2 == 0
                        && disjoint
                        && live[i + 2 * pairs - 1] & (1 << temp) == 0
                    {
                        for j in 0..pairs / 2 {
                            emitter.copy_pair(src + 16 * j as i32, dst + 16 * j as i32);
                        }
                        n = 2 * pairs;
                        kind = Some(NativeOpKind::BulkCopy);
                    }
                }
                if kind.is_none()
                    && self.policy.prefetch
                    && self.target == NativeTarget::Arm64
                    && a.code == 5
                {
                    if let Some(&(_, off)) = hints.iter().find(|&&(index, _)| index == i) {
                        emitter.prefetch(off);
                        kind = Some(NativeOpKind::Prefetch);
                    }
                }
                if kind.is_none()
                    && self.policy.alu
                    && matches!(class, 4 | 7)
                    && a.code & 8 == 0
                    && matches!(a.code & 0xf0, 0 | 0x40 | 0x50 | 0xa0)
                {
                    let mut v = a.imm;
                    while let Some(b) = p.get(i + n) {
                        if b.code != a.code || b.dst_reg() != a.dst_reg() {
                            break;
                        }
                        v = match a.code & 0xf0 {
                            0 => {
                                if wide {
                                    if let Ok(x) = i32::try_from(v as i64 + b.imm as i64) {
                                        x
                                    } else {
                                        break;
                                    }
                                } else {
                                    v.wrapping_add(b.imm)
                                }
                            }
                            0x40 => v | b.imm,
                            0x50 => v & b.imm,
                            _ => v ^ b.imm,
                        };
                        n += 1;
                    }
                    if n > 1 {
                        let mut folded = *a;
                        folded.imm = v;
                        emitter.scalar(&folded);
                        kind = Some(NativeOpKind::AluFold);
                    }
                }
            }
            if let Some(kind) = kind {
                // RV64I lacks several single-instruction idioms: only retain
                // rotate/extract/LEA replacements when native code is smaller.
                let mut plain = emit::Emitter::new(self.target);
                if matches!(
                    kind,
                    NativeOpKind::RotateLeft
                        | NativeOpKind::RotateRight
                        | NativeOpKind::BitExtract
                        | NativeOpKind::Lea
                ) {
                    for a in &p[i..i + n] {
                        plain.scalar(a);
                    }
                }
                if self.target == NativeTarget::RiscV64
                    && !plain.words.is_empty()
                    && emitter.words.len() - before >= plain.words.len()
                {
                    emitter.words.truncate(before);
                    emitter.words.extend(plain.words);
                } else {
                    optimizations.push(NativeOptimization {
                        kind,
                        ebpf_index: i,
                        proof_sequence: p[i..i + n].to_vec(),
                    });
                }
            } else if !is_branch(a) {
                emitter.scalar(a);
            }
            i += n;
        }
        Ok(EbpfNativeArtifact {
            target: self.target,
            code: emitter
                .words
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
            required_memory,
            optimizations,
        })
    }
}
