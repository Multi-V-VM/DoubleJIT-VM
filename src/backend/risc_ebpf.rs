//! Leaf-function frontends. These deliberately do not change the older
//! one-to-one RISC-V verification/compiler contract.
use aya_obj::generated::bpf_insn;
use core::fmt;
#[derive(Debug, Clone)]
pub struct RiscEbpfProgram {
    instructions: Vec<bpf_insn>,
    source_offsets: Vec<usize>,
}
impl RiscEbpfProgram {
    pub fn instructions(&self) -> &[bpf_insn] {
        &self.instructions
    }
    /// One source offset for each emitted BPF instruction, including expansions.
    pub fn source_offsets(&self) -> &[usize] {
        &self.source_offsets
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.instructions
            .iter()
            .flat_map(|i| {
                let mut v = vec![i.code, i.dst_reg() | (i.src_reg() << 4)];
                v.extend(i.off.to_le_bytes());
                v.extend(i.imm.to_le_bytes());
                v
            })
            .collect()
    }
}
#[derive(Debug, Clone)]
pub struct RiscDecodeError {
    pub offset: usize,
    pub reason: String,
}
impl fmt::Display for RiscDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RISC leaf decode at byte {}: {}",
            self.offset, self.reason
        )
    }
}
impl std::error::Error for RiscDecodeError {}
fn error(offset: usize, reason: &str) -> RiscDecodeError {
    RiscDecodeError {
        offset,
        reason: reason.into(),
    }
}
fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    }
}
fn words(bytes: &[u8]) -> Result<Vec<u32>, RiscDecodeError> {
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(error(bytes.len(), "expected nonempty 4-byte instructions"));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .collect())
}
fn constant(out: &mut Vec<bpf_insn>, dst: u8, value: u64) {
    if let Ok(imm) = i32::try_from(value as i64) {
        out.push(ins(0xb7, dst, 0, 0, imm));
        return;
    }
    out.push(ins(0xb7, dst, 0, 0, (value >> 48) as i32));
    for shift in [32, 16, 0] {
        out.push(ins(0x67, dst, 0, 0, 16));
        let v = ((value >> shift) & 65535) as i32;
        if v != 0 {
            out.push(ins(0x47, dst, 0, 0, v));
        }
    }
}
fn move_reg(out: &mut Vec<bpf_insn>, dst: u8, src: Option<u8>, wide: bool) {
    out.push(ins(
        if wide { 7 } else { 4 } | 0xb0 | if src.is_some() { 8 } else { 0 },
        dst,
        src.unwrap_or(0),
        0,
        0,
    ));
}
// r9 is reserved frontend scratch, allowing true three-address operations even
// when destination aliases the RHS of a noncommutative operation.
fn binary(out: &mut Vec<bpf_insn>, dst: u8, lhs: Option<u8>, rhs: Option<u8>, op: u8, wide: bool) {
    let rhs = if rhs == Some(dst) && lhs != Some(dst) {
        move_reg(out, 9, rhs, true);
        Some(9)
    } else {
        rhs
    };
    if lhs != Some(dst) {
        move_reg(out, dst, lhs, wide);
    }
    out.push(ins(
        if wide { 7 } else { 4 } | op | if rhs.is_some() { 8 } else { 0 },
        dst,
        rhs.unwrap_or(0),
        0,
        0,
    ));
}
fn immediate(out: &mut Vec<bpf_insn>, dst: u8, lhs: Option<u8>, op: u8, value: i32, wide: bool) {
    if op == 0 && value == 0 {
        move_reg(out, dst, lhs, wide);
        return;
    }
    if lhs != Some(dst) {
        move_reg(out, dst, lhs, wide);
    }
    out.push(ins(if wide { 7 } else { 4 } | op, dst, 0, 0, value));
}
fn sign_extend(out: &mut Vec<bpf_insn>, dst: u8, bits: u8) {
    out.push(ins(0x67, dst, 0, 0, 64 - bits as i32));
    out.push(ins(0xc7, dst, 0, 0, 64 - bits as i32));
}
fn finish_instruction(out: &[bpf_insn], map: &mut Vec<usize>, offset: usize) {
    map.resize(out.len(), offset);
}
fn arm_reg(reg: u32, offset: usize) -> Result<Option<u8>, RiscDecodeError> {
    match reg {
        0..=8 => Ok(Some(reg as u8)),
        31 => Ok(None),
        _ => Err(error(
            offset,
            "ARM leaf supports x0..x8 and ZR; x20 is reserved for buffer addressing",
        )),
    }
}
fn rv_reg(reg: u32, offset: usize) -> Result<Option<u8>, RiscDecodeError> {
    match reg {
        0 => Ok(None),
        10..=17 => Ok(Some((reg - 10) as u8)),
        5 => Ok(Some(8)),
        _ => Err(error(
            offset,
            "RV64 leaf supports a0..a7, t0 and x0; s0 is reserved for buffer addressing",
        )),
    }
}
#[derive(Debug, Default, Clone, Copy)]
pub struct Arm64EbpfCompiler;
impl Arm64EbpfCompiler {
    pub fn new() -> Self {
        Self
    }
    pub fn compile(&self, bytes: &[u8]) -> Result<RiscEbpfProgram, RiscDecodeError> {
        let words = words(bytes)?;
        let mut out = vec![];
        let mut map = vec![];
        let mut ret = false;
        for (index, &w) in words.iter().enumerate() {
            let at = index * 4;
            if ret {
                return Err(error(at, "instructions after RET"));
            }
            if w == 0xd65f03c0 {
                out.push(ins(0x95, 0, 0, 0, 0));
                ret = true;
                finish_instruction(&out, &mut map, at);
                continue;
            }
            let wide = w >> 31 != 0;
            let rd = w & 31;
            let rn = (w >> 5) & 31;
            let rm = (w >> 16) & 31;
            if w & 0x1f800000 == 0x12800000 {
                // MOVN/MOVZ/MOVK
                let dst =
                    arm_reg(rd, at)?.ok_or_else(|| error(at, "destination ZR unsupported"))?;
                let op = (w >> 29) & 3;
                let shift = ((w >> 21) & 3) * 16;
                if op == 1 || (!wide && shift >= 32) {
                    return Err(error(at, "invalid wide immediate"));
                }
                let mask = if wide { u64::MAX } else { u32::MAX as u64 };
                let value = (((w >> 5) & 65535) as u64) << shift;
                if op == 3 {
                    constant(&mut out, 9, !(65535_u64 << shift) & mask);
                    out.push(ins(0x5f, dst, 9, 0, 0));
                    constant(&mut out, 9, value);
                    out.push(ins(0x4f, dst, 9, 0, 0));
                } else {
                    constant(&mut out, dst, if op == 0 { !value & mask } else { value });
                }
            } else if w & 0x1f000000 == 0x11000000 {
                // ADD/SUB immediate, no SP/flags
                if w & (1 << 29) != 0 || rd == 31 || rn == 31 || w & (1 << 23) != 0 {
                    return Err(error(at, "SP/flag-setting ADD/SUB unsupported"));
                }
                let dst = arm_reg(rd, at)?.unwrap();
                let lhs = arm_reg(rn, at)?;
                let value = (((w >> 10) & 4095) << if w & (1 << 22) != 0 { 12 } else { 0 }) as i32;
                immediate(
                    &mut out,
                    dst,
                    lhs,
                    if w & (1 << 30) != 0 { 0x10 } else { 0 },
                    value,
                    wide,
                );
            } else if w & 0x1f200000 == 0x0b000000 || w & 0x1f000000 == 0x0a000000 {
                let logical = w & 0x1f000000 == 0x0a000000;
                if (!logical && w & (1 << 29) != 0) || (logical && w & (1 << 21) != 0) {
                    return Err(error(at, "flags/inverted operands unsupported"));
                }
                let dst =
                    arm_reg(rd, at)?.ok_or_else(|| error(at, "destination ZR unsupported"))?;
                let lhs = arm_reg(rn, at)?;
                let mut rhs = arm_reg(rm, at)?;
                let shift = (w >> 10) & 63;
                let kind = (w >> 22) & 3;
                if !wide && shift >= 32 || kind == 3 {
                    return Err(error(at, "unsupported shifted operand"));
                }
                let op = if logical {
                    match (w >> 29) & 3 {
                        0 => 0x50,
                        1 => 0x40,
                        2 => 0xa0,
                        _ => return Err(error(at, "flag-setting logical unsupported")),
                    }
                } else {
                    if w & (1 << 30) != 0 {
                        0x10
                    } else {
                        0
                    }
                };
                if shift != 0 {
                    move_reg(&mut out, 9, rhs, wide);
                    out.push(ins(
                        if wide { 7 } else { 4 }
                            | match kind {
                                0 => 0x60,
                                1 => 0x70,
                                _ => 0xc0,
                            },
                        9,
                        0,
                        0,
                        shift as i32,
                    ));
                    rhs = Some(9);
                }
                // Save/restore alias handling may also need r9; the shifted RHS
                // already in r9 is never overwritten by moving lhs into dst.
                if logical && op == 0x40 && lhs.is_none() && shift == 0 {
                    move_reg(&mut out, dst, rhs, wide);
                } else {
                    binary(&mut out, dst, lhs, rhs, op, wide);
                }
            } else if w & 0x7f800000 == 0x53000000 || w & 0x7f800000 == 0x13000000 {
                // UBFM/SBFM aliases
                let dst =
                    arm_reg(rd, at)?.ok_or_else(|| error(at, "destination ZR unsupported"))?;
                let src = arm_reg(rn, at)?;
                let r = (w >> 16) & 63;
                let s = (w >> 10) & 63;
                let bits = if wide { 64 } else { 32 };
                if ((w >> 22) & 1) != u32::from(wide) || r >= bits || s >= bits {
                    return Err(error(at, "invalid bitfield width"));
                }
                if s == bits - 1 {
                    immediate(
                        &mut out,
                        dst,
                        src,
                        if w & (1 << 30) != 0 { 0x70 } else { 0xc0 },
                        r as i32,
                        wide,
                    );
                } else if w & (1 << 30) != 0 && s + 1 == r {
                    immediate(&mut out, dst, src, 0x60, (bits - r) as i32, wide);
                } else if w & (1 << 30) != 0 && s >= r {
                    immediate(&mut out, dst, src, 0x70, r as i32, wide);
                    constant(&mut out, 9, (1_u64 << (s - r + 1)) - 1);
                    out.push(ins(if wide { 7 } else { 4 } | 0x58, dst, 9, 0, 0));
                } else {
                    return Err(error(at, "unsupported bitfield form"));
                }
            } else if matches!(
                w & 0xffc00000,
                0xf9400000
                    | 0xf9000000
                    | 0xb9400000
                    | 0xb9000000
                    | 0x79400000
                    | 0x79000000
                    | 0x39400000
                    | 0x39000000
            ) {
                if rn != 20 {
                    return Err(error(at, "buffer loads/stores require x20 base"));
                }
                let reg =
                    arm_reg(rd, at)?.ok_or_else(|| error(at, "memory ZR operand unsupported"))?;
                let size = 1_u32 << (w >> 30);
                let offset = ((w >> 10) & 4095) * size;
                let off =
                    i16::try_from(offset).map_err(|_| error(at, "buffer offset exceeds i16"))?;
                let sz = match size {
                    1 => 0x10,
                    2 => 8,
                    4 => 0,
                    _ => 0x18,
                };
                out.push(if w & (1 << 22) != 0 {
                    ins(0x61 | sz, reg, 10, off, 0)
                } else {
                    ins(0x63 | sz, 10, reg, off, 0)
                });
            } else {
                return Err(error(
                    at,
                    &format!("unsupported ARM64 instruction {w:#010x}"),
                ));
            }
            finish_instruction(&out, &mut map, at);
        }
        if !ret {
            return Err(error(bytes.len(), "missing RET"));
        }
        Ok(RiscEbpfProgram {
            instructions: out,
            source_offsets: map,
        })
    }
}
#[derive(Debug, Default, Clone, Copy)]
pub struct RiscV64EbpfCompiler;
impl RiscV64EbpfCompiler {
    pub fn new() -> Self {
        Self
    }
    pub fn compile(&self, bytes: &[u8]) -> Result<RiscEbpfProgram, RiscDecodeError> {
        let words = words(bytes)?;
        let mut out = vec![];
        let mut map = vec![];
        let mut ret = false;
        for (index, &w) in words.iter().enumerate() {
            let at = index * 4;
            if ret {
                return Err(error(at, "instructions after RET"));
            }
            if w == 0x00008067 {
                out.push(ins(0x95, 0, 0, 0, 0));
                ret = true;
                finish_instruction(&out, &mut map, at);
                continue;
            }
            let opcode = w & 127;
            let rd = (w >> 7) & 31;
            let rs1 = (w >> 15) & 31;
            let rs2 = (w >> 20) & 31;
            let f3 = (w >> 12) & 7;
            let f7 = w >> 25;
            if matches!(opcode, 0x13 | 0x1b | 0x33 | 0x3b | 0x37) {
                let destination = rv_reg(rd, at)?;
                let dst = destination.unwrap_or(9); // writes to x0 have no observable effect
                let word = matches!(opcode, 0x1b | 0x3b);
                let wide = !word;
                if opcode == 0x37 {
                    constant(&mut out, dst, (w & 0xfffff000) as i32 as i64 as u64);
                } else if opcode == 0x13 || opcode == 0x1b {
                    let src = rv_reg(rs1, at)?;
                    let value = (w as i32) >> 20;
                    let op = match f3 {
                        0 => 0,
                        4 if !word => 0xa0,
                        6 if !word => 0x40,
                        7 if !word => 0x50,
                        1 => 0x60,
                        5 => {
                            if w & (1 << 30) != 0 {
                                0xc0
                            } else {
                                0x70
                            }
                        }
                        _ => return Err(error(at, "unsupported immediate operation")),
                    };
                    let value = if matches!(f3, 1 | 5) {
                        let top = w >> if word { 25 } else { 26 };
                        let expected = if op == 0xc0 {
                            if word {
                                0x20
                            } else {
                                0x10
                            }
                        } else {
                            0
                        };
                        if top != expected {
                            return Err(error(at, "invalid shift encoding"));
                        }
                        ((w >> 20) & if word { 31 } else { 63 }) as i32
                    } else {
                        value
                    };
                    immediate(&mut out, dst, src, op, value, wide);
                } else {
                    let lhs = rv_reg(rs1, at)?;
                    let rhs = rv_reg(rs2, at)?;
                    let op = match (f7, f3) {
                        (0, 0) => 0,
                        (0x20, 0) => 0x10,
                        (0, 1) => 0x60,
                        (0, 5) => 0x70,
                        (0x20, 5) => 0xc0,
                        (0, 4) if !word => 0xa0,
                        (0, 6) if !word => 0x40,
                        (0, 7) if !word => 0x50,
                        _ => return Err(error(at, "unsupported register operation")),
                    };
                    if destination.is_none() {
                        // validate operands/encoding, then discard x0 write
                        finish_instruction(&out, &mut map, at);
                        continue;
                    }
                    binary(&mut out, dst, lhs, rhs, op, wide);
                }
                if word {
                    sign_extend(&mut out, dst, 32);
                }
            } else if opcode == 3 || opcode == 0x23 {
                if rs1 != 8 {
                    return Err(error(at, "buffer loads/stores require s0 base"));
                }
                let value = if opcode == 3 {
                    (w as i32) >> 20
                } else {
                    (((w & 0xfe000000) | ((w >> 7 & 31) << 20)) as i32) >> 20
                };
                if value < 0 {
                    return Err(error(at, "negative buffer offset"));
                }
                let bytes = 1_u8 << (f3 & 3);
                let sz = match bytes {
                    1 => 0x10,
                    2 => 8,
                    4 => 0,
                    _ => 0x18,
                };
                if opcode == 3 {
                    if f3 == 7 {
                        return Err(error(at, "reserved load"));
                    }
                    let dst = rv_reg(rd, at)?.unwrap_or(9);
                    out.push(ins(0x61 | sz, dst, 10, value as i16, 0));
                    if f3 < 3 {
                        sign_extend(&mut out, dst, bytes * 8);
                    }
                } else {
                    if f3 > 3 {
                        return Err(error(at, "reserved store"));
                    }
                    let src = rv_reg(rs2, at)?;
                    if src.is_none() {
                        constant(&mut out, 9, 0);
                    }
                    out.push(ins(0x63 | sz, 10, src.unwrap_or(9), value as i16, 0));
                }
            } else {
                return Err(error(at,&format!("unsupported RV64 instruction {w:#010x}; compressed, calls and jumps are not supported")));
            }
            finish_instruction(&out, &mut map, at);
        }
        if !ret {
            return Err(error(bytes.len(), "missing RET"));
        }
        Ok(RiscEbpfProgram {
            instructions: out,
            source_offsets: map,
        })
    }
}
