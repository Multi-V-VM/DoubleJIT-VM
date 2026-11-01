//! Validated native-operation selection for the userspace backend.
use super::*;

fn bad(index: usize) -> EbpfX86Error {
    EbpfX86Error::InvalidEncoding { index }
}
fn unsupported(index: usize, code: u8) -> EbpfX86Error {
    EbpfX86Error::UnsupportedInstruction { index, code }
}
pub(crate) fn is_load(p: &bpf_insn) -> bool {
    matches!(p.code, 0x61 | 0x69 | 0x71 | 0x79)
}
pub(crate) fn is_store(p: &bpf_insn) -> bool {
    matches!(p.code, 0x63 | 0x6b | 0x73 | 0x7b)
}
pub(crate) fn size(p: &bpf_insn) -> usize {
    match p.code & 0x18 {
        0 => 4,
        8 => 2,
        16 => 1,
        _ => 8,
    }
}
pub(crate) fn is_mov(p: &bpf_insn) -> bool {
    matches!(p.code, 0xb4 | 0xb7 | 0xbc | 0xbf)
}
pub(crate) fn is_branch(p: &bpf_insn) -> bool {
    matches!(p.code & 7, 5 | 6)
        && matches!(
            p.code & 0xf0,
            0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70 | 0xa0 | 0xb0 | 0xc0 | 0xd0
        )
}
fn cc(p: &bpf_insn) -> u8 {
    match p.code & 0xf0 {
        0x10 => 4,
        0x20 => 7,
        0x30 => 3,
        0x40 | 0x50 => 5,
        0x60 => 15,
        0x70 => 13,
        0xa0 => 2,
        0xb0 => 6,
        0xc0 => 12,
        0xd0 => 14,
        _ => unreachable!(),
    }
}

pub(crate) fn validate(p: &[bpf_insn], hints: &[(usize, u16)]) -> Result<usize, EbpfX86Error> {
    let mut required = 0;
    let mut exited = false;
    for (i, ins) in p.iter().enumerate() {
        if exited {
            return Err(EbpfX86Error::InstructionAfterExit { index: i });
        }
        if ins.code == 0x95 || ins.code == 0x05 {
            if ins.dst_reg() != 0 || ins.src_reg() != 0 || ins.off != 0 || ins.imm != 0 {
                return Err(bad(i));
            }
            exited = ins.code == 0x95;
        } else if is_load(ins) || is_store(ins) {
            let (base, value) = if is_load(ins) {
                (ins.src_reg(), ins.dst_reg())
            } else {
                (ins.dst_reg(), ins.src_reg())
            };
            if base != 10 {
                return Err(unsupported(i, ins.code));
            }
            register(i, value)?;
            if ins.off < 0 || ins.imm != 0 {
                return Err(bad(i));
            }
            required = required.max(ins.off as usize + size(ins));
        } else if ins.code == 0xdc {
            register(i, ins.dst_reg())?;
            if ins.src_reg() != 0 || ins.off != 0 || !matches!(ins.imm, 16 | 32 | 64) {
                return Err(bad(i));
            }
        } else if is_branch(ins) {
            register(i, ins.dst_reg())?;
            register(i, ins.src_reg())?;
            if ins.off != 1
                || p.get(i + 1).is_none_or(|next| !is_mov(next))
                || (ins.code & 8 != 0 && ins.imm != 0)
                || (ins.code & 8 == 0 && ins.src_reg() != 0)
            {
                return Err(bad(i));
            }
        } else {
            if !matches!(ins.code & 7, 4 | 7)
                || !matches!(
                    ins.code & 0xf0,
                    0x00 | 0x10 | 0x40 | 0x50 | 0x60 | 0x70 | 0xa0 | 0xb0 | 0xc0
                )
            {
                return Err(unsupported(i, ins.code));
            }
            register(i, ins.dst_reg())?;
            register(i, ins.src_reg())?;
            let reg = ins.code & 8 != 0;
            if ins.off != 0 || (reg && ins.imm != 0) || (!reg && ins.src_reg() != 0) {
                return Err(bad(i));
            }
            if matches!(ins.code & 0xf0, 0x60 | 0x70 | 0xc0)
                && !reg
                && !(0..if ins.code & 7 == 7 { 64 } else { 32 }).contains(&ins.imm)
            {
                return Err(bad(i));
            }
        }
    }
    if !exited {
        return Err(EbpfX86Error::MissingExit);
    }
    let mut seen = std::collections::HashSet::new();
    for &(i, offset) in hints {
        if p.get(i).is_none_or(|ins| ins.code != 0x05) || !seen.insert(i) {
            return Err(bad(i));
        }
        required = required.max(offset as usize + 1);
    }
    Ok(required)
}

pub(crate) fn live_after(p: &[bpf_insn]) -> Vec<u16> {
    let mut after = vec![0; p.len()];
    let mut live = 0;
    for (i, ins) in p.iter().enumerate().rev() {
        after[i] = live;
        if ins.code == 0x95 {
            live = 1;
        } else if ins.code == 0x05 {
        }
        // no-op, prefetch has no register effects
        else if is_branch(ins) {
            live |= after[i + 1] | (1 << ins.dst_reg()); // union taken and fallthrough paths
            if ins.code & 8 != 0 {
                live |= 1 << ins.src_reg();
            }
        } else if is_store(ins) {
            live |= 1 << ins.src_reg();
        } else if is_load(ins) {
            live &= !(1 << ins.dst_reg());
        } else {
            live &= !(1 << ins.dst_reg());
            if !is_mov(ins) {
                live |= 1 << ins.dst_reg();
            }
            if ins.code != 0xdc && ins.code & 8 != 0 {
                live |= 1 << ins.src_reg();
            }
        }
    }
    after
}

// disp32 [r12+offset], with no guest-controlled addressing arithmetic.
fn mem(code: &mut Vec<u8>, op: &[u8], reg: u8, wide: bool, offset: i32) {
    code.push(0x41 | ((reg >> 3) << 2) | (u8::from(wide) << 3));
    code.extend_from_slice(op);
    code.extend_from_slice(&[0x84 | ((reg & 7) << 3), 0x24]);
    code.extend_from_slice(&offset.to_le_bytes());
}
fn imm(code: &mut Vec<u8>, wide: bool, dst: u8, value: i32) {
    emit_reg(code, wide, 0xc7, dst, 0);
    code.extend_from_slice(&value.to_le_bytes());
}
fn bswap(code: &mut Vec<u8>, dst: u8, bits: i32) {
    let rex = 0x40 | (u8::from(bits == 64) << 3) | (dst >> 3);
    if rex != 0x40 {
        code.push(rex);
    }
    code.extend_from_slice(&[0x0f, 0xc8 | (dst & 7)]);
    if bits == 16 {
        emit_reg(code, false, 0xc1, dst, 5);
        code.push(16);
    }
}
fn compare(code: &mut Vec<u8>, p: &bpf_insn) {
    let wide = p.code & 7 == 5;
    let dst = REGISTERS[p.dst_reg() as usize];
    let test = p.code & 0xf0 == 0x40;
    if p.code & 8 != 0 {
        emit_reg(
            code,
            wide,
            if test { 0x85 } else { 0x39 },
            dst,
            REGISTERS[p.src_reg() as usize],
        );
    } else {
        emit_reg(
            code,
            wide,
            if test { 0xf7 } else { 0x81 },
            dst,
            if test { 0 } else { 7 },
        );
        code.extend_from_slice(&p.imm.to_le_bytes());
    }
}
fn scalar(code: &mut Vec<u8>, p: &bpf_insn) {
    if p.code == 0x95 {
        code.extend_from_slice(&[0x41, 0x5d, 0x41, 0x5c, 0x5b, 0xc3]);
        return;
    }
    if p.code == 0x05 {
        return;
    }
    let dst = REGISTERS.get(p.dst_reg() as usize).copied().unwrap_or(12);
    let src = REGISTERS.get(p.src_reg() as usize).copied().unwrap_or(12);
    if is_load(p) {
        mem(
            code,
            match size(p) {
                1 => &[0x0f, 0xb6],
                2 => &[0x0f, 0xb7],
                _ => &[0x8b],
            },
            dst,
            size(p) == 8,
            p.off as i32,
        );
        return;
    }
    if is_store(p) {
        if size(p) == 2 {
            code.push(0x66);
        }
        mem(
            code,
            if size(p) == 1 { &[0x88] } else { &[0x89] },
            src,
            size(p) == 8,
            p.off as i32,
        );
        return;
    }
    if p.code == 0xdc {
        bswap(code, dst, p.imm);
        return;
    }
    let wide = p.code & 7 == 7;
    let op = p.code & 0xf0;
    if matches!(op, 0x60 | 0x70 | 0xc0) {
        let ext = match op {
            0x60 => 4,
            0x70 => 5,
            _ => 7,
        };
        if p.code & 8 != 0 {
            // Save guest RCX; capture destination before loading CL. R13 is a
            // private, callee-saved scratch and cannot be named by guest code.
            emit_reg(code, true, 0x89, 13, dst);
            code.push(0x51);
            emit_reg(code, false, 0x89, 1, src);
            emit_reg(code, wide, 0xd3, 13, ext);
            code.push(0x59);
            emit_reg(code, wide, 0x89, dst, 13);
        } else {
            emit_reg(code, wide, 0xc1, dst, ext);
            code.push(p.imm as u8);
        }
    } else if p.code & 8 != 0 {
        emit_reg(
            code,
            wide,
            match op {
                0 => 0x01,
                0x10 => 0x29,
                0x40 => 0x09,
                0x50 => 0x21,
                0xa0 => 0x31,
                0xb0 => 0x89,
                _ => unreachable!(),
            },
            dst,
            src,
        );
    } else {
        emit_reg(
            code,
            wide,
            if op == 0xb0 { 0xc7 } else { 0x81 },
            dst,
            match op {
                0 | 0xb0 => 0,
                0x10 => 5,
                0x40 => 1,
                0x50 => 4,
                0xa0 => 6,
                _ => unreachable!(),
            },
        );
        code.extend_from_slice(&p.imm.to_le_bytes());
    }
}
fn lea(code: &mut Vec<u8>, wide: bool, dst: u8, base: u8, shift: u8, disp: i32) {
    code.push(0x40 | (u8::from(wide) << 3) | ((dst >> 3) << 2) | ((dst >> 3) << 1) | (base >> 3));
    code.extend_from_slice(&[
        0x8d,
        0x84 | ((dst & 7) << 3),
        (shift << 6) | ((dst & 7) << 3) | (base & 7),
    ]);
    code.extend_from_slice(&disp.to_le_bytes());
}
fn bextr(code: &mut Vec<u8>, wide: bool, dst: u8, start: u8, length: u8, initialize: bool) {
    if initialize {
        imm(code, false, 13, i32::from(start) | (i32::from(length) << 8));
    }
    code.extend_from_slice(&[
        0xc4,
        ((!((dst >> 3) & 1) & 1) << 7) | 0x40 | ((!((dst >> 3) & 1) & 1) << 5) | 2,
        (u8::from(wide) << 7) | ((!13_u8 & 15) << 3),
        0xf7,
        0xc0 | ((dst & 7) << 3) | (dst & 7),
    ]);
}
fn extensions(disabled: bool) -> (bool, bool) {
    if disabled {
        return (false, false);
    }
    #[cfg(target_arch = "x86_64")]
    {
        (
            std::is_x86_feature_detected!("bmi1"),
            std::is_x86_feature_detected!("movbe"),
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (false, false)
    }
}

pub(super) fn compile(
    compiler: &EbpfX86Compiler,
    p: &[bpf_insn],
    hints: &[(usize, u16)],
) -> Result<EbpfX86Artifact, EbpfX86Error> {
    let required_memory = validate(p, hints)?;
    let live = live_after(p);
    let (bmi1, movbe) = extensions(compiler.no_optional_isa);
    let mut code = vec![0xf3, 0x0f, 0x1e, 0xfa, 0x53, 0x41, 0x54, 0x41, 0x55];
    emit_reg(&mut code, true, 0x89, 12, 6); // buffer argument RSI -> private R12
    emit_reg(&mut code, true, 0x89, 0, 7); // scalar argument RDI -> guest RAX
    for r in REGISTERS.into_iter().skip(1) {
        emit_reg(&mut code, false, 0x31, r, r);
    }
    let mut fusions = Vec::new();
    let mut optimizations = Vec::new();
    let mut i = 0;
    let mut blocked_bulk_until = 0;
    let mut extract_control = None;
    while i < p.len() {
        let a = &p[i];
        if is_branch(a) || matches!(a.code, 0x6c | 0x6f | 0x7c | 0x7f | 0xcc | 0xcf) {
            extract_control = None;
        }
        let wide = a.code & 7 == 7;
        let class = a.code & 7;
        let bits = if wide { 64 } else { 32 };
        let dst = REGISTERS.get(a.dst_reg() as usize).copied().unwrap_or(12);
        let mut selected = None;
        let mut count = 1;
        if is_branch(a) {
            compare(&mut code, a);
            let mv = &p[i + 1];
            if compiler.native_ops && compiler.policy.select {
                let src = if mv.code & 8 != 0 {
                    if mv.code & 7 == 4 {
                        emit_reg(&mut code, false, 0x89, 13, REGISTERS[mv.src_reg() as usize]);
                        13
                    } else {
                        REGISTERS[mv.src_reg() as usize]
                    }
                } else {
                    imm(&mut code, mv.code & 7 == 7, 13, mv.imm);
                    13
                };
                let d = REGISTERS[mv.dst_reg() as usize];
                code.push(0x48 | ((d >> 3) << 2) | (src >> 3));
                code.extend_from_slice(&[
                    0x0f,
                    0x40 | (cc(a) ^ 1),
                    0xc0 | ((d & 7) << 3) | (src & 7),
                ]);
                selected = Some(NativeOpKind::Select);
            } else {
                let mut body = Vec::new();
                scalar(&mut body, mv);
                code.extend_from_slice(&[0x70 | cc(a), body.len() as u8]);
                code.extend(body);
            }
            count = 2;
        } else if compiler.native_ops {
            let policy = compiler.policy;
            // Structural branch/MOV units are consumed above; no rewrite can
            // reach across a branch, so no target can enter a fused region.
            if policy.rotate && i + 4 < p.len() {
                let b = &p[i + 1];
                let c = &p[i + 2];
                let d = &p[i + 3];
                let target = a.src_reg();
                let tmp = a.dst_reg();
                let left = b.code == class | 0x60 && c.code == class | 0x70;
                let right = b.code == class | 0x70 && c.code == class | 0x60;
                if a.code == class | 0xb8
                    && matches!(class, 4 | 7)
                    && tmp != target
                    && (left || right)
                    && b.dst_reg() == target
                    && c.dst_reg() == tmp
                    && d.code == class | 0x48
                    && d.dst_reg() == target
                    && d.src_reg() == tmp
                    && b.imm > 0
                    && c.imm > 0
                    && b.imm + c.imm == bits
                    && live[i + 3] & (1 << tmp) == 0
                {
                    emit_reg(
                        &mut code,
                        wide,
                        0xc1,
                        REGISTERS[target as usize],
                        if left { 0 } else { 1 },
                    );
                    code.push(b.imm as u8);
                    selected = Some(if left {
                        NativeOpKind::RotateLeft
                    } else {
                        NativeOpKind::RotateRight
                    });
                    count = 4;
                    if left {
                        fusions.push(RotateFusion {
                            ebpf_index: i,
                            width: bits as u8,
                            count: b.imm as u8,
                            destination: target,
                            temporary: tmp,
                            proof_sequence: p[i..i + 4].to_vec(),
                        });
                    }
                }
            }
            if selected.is_none()
                && policy.lea
                && matches!(a.code, 0x64 | 0x67)
                && (0..=3).contains(&a.imm)
                && i + 1 < p.len()
            {
                let b = &p[i + 1];
                if b.code == class | 8 && b.dst_reg() == a.dst_reg() && b.src_reg() != a.dst_reg() {
                    let mut disp = 0;
                    count = 2;
                    if let Some(c) = p.get(i + 2) {
                        if c.code == class && c.dst_reg() == a.dst_reg() {
                            disp = c.imm;
                            count = 3;
                        }
                    }
                    lea(
                        &mut code,
                        wide,
                        dst,
                        REGISTERS[b.src_reg() as usize],
                        a.imm as u8,
                        disp,
                    );
                    selected = Some(NativeOpKind::Lea);
                }
            }
            if selected.is_none()
                && policy.extract
                && bmi1
                && matches!(a.code, 0x74 | 0x77)
                && i + 1 < p.len()
            {
                let b = &p[i + 1];
                let mask = if wide {
                    b.imm as i64 as u64
                } else {
                    b.imm as u32 as u64
                };
                let len = mask.trailing_ones();
                if b.code == class | 0x50
                    && b.dst_reg() == a.dst_reg()
                    && mask != 0
                    && mask & (mask.wrapping_add(1)) == 0
                {
                    let control = a.imm | ((len as i32) << 8);
                    bextr(
                        &mut code,
                        wide,
                        dst,
                        a.imm as u8,
                        len as u8,
                        extract_control != Some(control),
                    );
                    extract_control = Some(control);
                    selected = Some(NativeOpKind::BitExtract);
                    count = 2;
                }
            }
            if selected.is_none()
                && policy.endian
                && movbe
                && is_load(a)
                && matches!(size(a), 4 | 8)
                && i + 1 < p.len()
            {
                let b = &p[i + 1];
                if b.code == 0xdc && b.dst_reg() == a.dst_reg() && b.imm == size(a) as i32 * 8 {
                    mem(
                        &mut code,
                        &[0x0f, 0x38, 0xf0],
                        dst,
                        size(a) == 8,
                        a.off as i32,
                    );
                    selected = Some(NativeOpKind::EndianLoad);
                    count = 2;
                }
            }
            if selected.is_none() && policy.bulk_copy && a.code == 0x79 && i >= blocked_bulk_until {
                let tmp = a.dst_reg();
                let src = a.off as i32;
                if let Some(first_store) = p.get(i + 1) {
                    let dest = first_store.off as i32;
                    let mut n = 0;
                    while i + 2 * n + 1 < p.len() {
                        let ld = &p[i + 2 * n];
                        let st = &p[i + 2 * n + 1];
                        if ld.code != 0x79
                            || st.code != 0x7b
                            || ld.dst_reg() != tmp
                            || st.src_reg() != tmp
                            || ld.off as i32 != src + 8 * n as i32
                            || st.off as i32 != dest + 8 * n as i32
                        {
                            break;
                        }
                        n += 1;
                    }
                    // SIMD widening changes load/store ordering: reject all
                    // overlap and require the removed scalar temporary dead.
                    if n >= 2 && src + 8 * n as i32 > dest && dest + 8 * n as i32 > src {
                        blocked_bulk_until = i + 2 * n;
                    }
                    if n >= 2
                        && n % 2 == 0
                        && (src + 8 * n as i32 <= dest || dest + 8 * n as i32 <= src)
                        && live[i + 2 * n - 1] & (1 << tmp) == 0
                    {
                        for pair in 0..n / 2 {
                            code.push(0xf3);
                            mem(&mut code, &[0x0f, 0x6f], 0, false, src + 16 * pair as i32);
                            code.push(0xf3);
                            mem(&mut code, &[0x0f, 0x7f], 0, false, dest + 16 * pair as i32);
                        }
                        selected = Some(NativeOpKind::BulkCopy);
                        count = 2 * n;
                    }
                }
            }
            if selected.is_none() && policy.prefetch && a.code == 0x05 {
                if let Some(&(_, offset)) = hints.iter().find(|&&(index, _)| index == i) {
                    mem(&mut code, &[0x0f, 0x18], 1, false, offset as i32);
                    selected = Some(NativeOpKind::Prefetch);
                }
            }
            if selected.is_none()
                && policy.alu
                && matches!(class, 4 | 7)
                && a.code & 8 == 0
                && matches!(a.code & 0xf0, 0 | 0x40 | 0x50 | 0xa0)
            {
                let mut value = a.imm;
                let op = a.code & 0xf0;
                while let Some(b) = p.get(i + count) {
                    if b.code != a.code || b.dst_reg() != a.dst_reg() {
                        break;
                    }
                    value = match op {
                        0 => {
                            if wide {
                                let sum = value as i64 + b.imm as i64;
                                if let Ok(sum) = i32::try_from(sum) {
                                    sum
                                } else {
                                    break;
                                }
                            } else {
                                value.wrapping_add(b.imm)
                            }
                        }
                        0x40 => value | b.imm,
                        0x50 => value & b.imm,
                        0xa0 => value ^ b.imm,
                        _ => unreachable!(),
                    };
                    count += 1;
                }
                if count > 1 {
                    let mut folded = *a;
                    folded.imm = value;
                    scalar(&mut code, &folded);
                    selected = Some(NativeOpKind::AluFold);
                }
            }
        }
        if let Some(kind) = selected {
            optimizations.push(NativeOptimization {
                kind,
                ebpf_index: i,
                proof_sequence: p[i..i + count].to_vec(),
            });
        } else if !is_branch(a) {
            scalar(&mut code, a);
        }
        i += count;
    }
    Ok(EbpfX86Artifact {
        code,
        fusions,
        optimizations,
        required_memory,
    })
}
