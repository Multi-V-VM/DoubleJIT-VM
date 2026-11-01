use super::*;
pub(super) struct Emitter {
    pub words: Vec<u32>,
    target: NativeTarget,
}
impl Emitter {
    pub fn new(target: NativeTarget) -> Self {
        Self {
            words: vec![],
            target,
        }
    }
    fn push(&mut self, w: u32) {
        self.words.push(w);
    }
    fn r(&self, bpf: u8) -> u32 {
        match self.target {
            NativeTarget::Arm64 => bpf as u32,
            NativeTarget::RiscV64 => [10, 12, 13, 14, 15, 16, 17, 5, 6, 7][bpf as usize],
        }
    }
    fn ai(&mut self, rd: u32, value: u64, wide: bool) {
        self.push(if wide { 0xd2800000 } else { 0x52800000 } | ((value as u32 & 65535) << 5) | rd);
        for hw in 1..if wide { 4 } else { 2 } {
            let v = ((value >> (16 * hw)) & 65535) as u32;
            if v != 0 {
                self.push(if wide { 0xf2800000 } else { 0x72800000 } | (hw << 21) | (v << 5) | rd);
            }
        }
    }
    fn amov(&mut self, d: u32, s: u32, wide: bool) {
        self.push(if wide { 0xaa0003e0 } else { 0x2a0003e0 } | s << 16 | d);
    }
    fn ashift(&mut self, d: u32, s: u32, wide: bool, op: u8, k: u32) {
        let bits = if wide { 64 } else { 32 };
        let (r, m) = if op == 0x60 {
            ((bits - k) % bits, bits - 1 - k)
        } else {
            (k, bits - 1)
        };
        self.push(
            if op == 0xc0 {
                if wide {
                    0x93400000
                } else {
                    0x13000000
                }
            } else {
                if wide {
                    0xd3400000
                } else {
                    0x53000000
                }
            } | r << 16
                | m << 10
                | s << 5
                | d,
        );
    }
    fn ri(&mut self, opcode: u32, f: u32, d: u32, s: u32, value: i32) {
        self.push(((value as u32 & 4095) << 20) | (s << 15) | (f << 12) | (d << 7) | opcode);
    }
    fn rr(&mut self, f7: u32, f: u32, d: u32, a: u32, b: u32) {
        self.push(f7 << 25 | b << 20 | a << 15 | f << 12 | d << 7 | 0x33);
    }
    fn rconst(&mut self, d: u32, value: i32) {
        if (-2048..=2047).contains(&value) {
            self.ri(0x13, 0, d, 0, value);
        } else {
            let hi = (((value as i64 + 2048) >> 12) as u32) & 0xfffff;
            self.push(hi << 12 | d << 7 | 0x37);
            self.ri(0x1b, 0, d, d, value);
        }
    }
    fn rzext(&mut self, d: u32) {
        self.ri(0x13, 1, d, d, 32);
        self.ri(0x13, 5, d, d, 32);
    }
    pub fn prologue(&mut self) {
        match self.target {
            NativeTarget::Arm64 => {
                self.push(0xd503245f);
                self.amov(10, 1, true);
                for r in 1..10 {
                    self.amov(r, 31, true);
                }
            }
            NativeTarget::RiscV64 => {
                for r in 1..10 {
                    self.ri(0x13, 0, self.r(r), 0, 0);
                }
            }
        }
    }
    fn aaddr(&mut self, offset: i32, scale: i32, limit: i32) -> (u32, u32) {
        if offset % scale == 0 && offset / scale <= limit {
            (10, (offset / scale) as u32)
        } else {
            self.ai(11, offset as u64, true);
            self.push(0x8b000000 | 11 << 16 | 10 << 5 | 11);
            (11, 0)
        }
    }
    fn raddr(&mut self, offset: i32) -> (u32, i32) {
        if offset <= 2047 {
            (11, offset)
        } else {
            self.rconst(31, offset);
            self.rr(0, 0, 31, 11, 31);
            (31, 0)
        }
    }
    fn memory(&mut self, p: &bpf_insn) {
        let load = is_load(p);
        let count = size(p);
        let reg = self.r(if load { p.dst_reg() } else { p.src_reg() });
        match self.target {
            NativeTarget::Arm64 => {
                let (base, off) = self.aaddr(p.off as i32, count as i32, 4095);
                self.push(
                    (count.trailing_zeros() << 30)
                        | 0x39000000
                        | if load { 0x00400000 } else { 0 }
                        | off << 10
                        | base << 5
                        | reg,
                );
            }
            NativeTarget::RiscV64 => {
                // Bytewise accesses are valid for arbitrary slice alignment,
                // including CPUs without native misaligned loads/stores.
                if load {
                    self.ri(0x13, 0, reg, 0, 0);
                    for j in (0..count).rev() {
                        let (base, off) = self.raddr(p.off as i32 + j as i32);
                        self.ri(3, 4, 28, base, off);
                        if j != count - 1 {
                            self.ri(0x13, 1, reg, reg, 8);
                        }
                        self.rr(0, 6, reg, reg, 28);
                    }
                } else {
                    self.ri(0x13, 0, 28, reg, 0);
                    for j in 0..count {
                        let (base, off) = self.raddr(p.off as i32 + j as i32);
                        let v = off as u32;
                        self.push(
                            (v >> 5 & 127) << 25 | 28 << 20 | base << 15 | (v & 31) << 7 | 0x23,
                        );
                        if j + 1 < count {
                            self.ri(0x13, 5, 28, 28, 8);
                        }
                    }
                }
            }
        }
    }
    pub fn scalar(&mut self, p: &bpf_insn) {
        if p.code == 0x95 {
            self.push(if self.target == NativeTarget::Arm64 {
                0xd65f03c0
            } else {
                0x00008067
            });
            return;
        }
        if p.code == 5 {
            return;
        }
        if is_load(p) || is_store(p) {
            self.memory(p);
            return;
        }
        let d = self.r(p.dst_reg());
        let wide = p.code & 7 == 7;
        let reg = p.code & 8 != 0;
        let op = p.code & 0xf0;
        if p.code == 0xdc {
            match self.target {
                NativeTarget::Arm64 => {
                    self.push(
                        match p.imm {
                            64 => 0xdac00c00,
                            32 => 0x5ac00800,
                            _ => 0x5ac00400,
                        } | d << 5
                            | d,
                    );
                    if p.imm == 16 {
                        self.push(0x53000000 | 15 << 10 | d << 5 | d);
                    }
                }
                NativeTarget::RiscV64 => {
                    self.ri(0x13, 0, 28, d, 0);
                    self.ri(0x13, 0, d, 0, 0);
                    for j in 0..p.imm / 8 {
                        self.ri(0x13, 7, 29, 28, 255);
                        if j > 0 {
                            self.ri(0x13, 1, d, d, 8);
                        }
                        self.rr(0, 6, d, d, 29);
                        self.ri(0x13, 5, 28, 28, 8);
                    }
                }
            }
            return;
        }
        match self.target {
            NativeTarget::Arm64 => {
                if op == 0xb0 {
                    if reg {
                        self.amov(d, self.r(p.src_reg()), wide);
                    } else {
                        self.ai(d, p.imm as i64 as u64, wide);
                    }
                    return;
                }
                if matches!(op, 0x60 | 0x70 | 0xc0) && !reg {
                    self.ashift(d, d, wide, op, p.imm as u32);
                    return;
                }
                if matches!(op, 0 | 0x10) && !reg && (0..=4095).contains(&p.imm) {
                    self.push(
                        if wide { 0x91000000 } else { 0x11000000 }
                            | if op == 0x10 { 1 << 30 } else { 0 }
                            | (p.imm as u32) << 10
                            | d << 5
                            | d,
                    );
                    return;
                }
                let rhs = if reg {
                    self.r(p.src_reg())
                } else {
                    self.ai(11, p.imm as i64 as u64, wide);
                    11
                };
                let base = match op {
                    0 => 0x0b000000,
                    0x10 => 0x4b000000,
                    0x40 => 0x2a000000,
                    0x50 => 0x0a000000,
                    0xa0 => 0x4a000000,
                    0x60 => 0x1ac02000,
                    0x70 => 0x1ac02400,
                    0xc0 => 0x1ac02800,
                    _ => unreachable!(),
                };
                self.push(base | if wide { 1 << 31 } else { 0 } | rhs << 16 | d << 5 | d);
            }
            NativeTarget::RiscV64 => {
                if op == 0xb0 {
                    if reg {
                        self.ri(0x13, 0, d, self.r(p.src_reg()), 0);
                    } else {
                        self.rconst(d, p.imm);
                    }
                    if !wide {
                        self.rzext(d);
                    }
                    return;
                }
                if matches!(op, 0x60 | 0x70 | 0xc0) {
                    if !wide {
                        if op == 0xc0 {
                            self.ri(0x1b, 0, d, d, 0);
                        } else {
                            self.rzext(d);
                        }
                    }
                    if reg {
                        let src = self.r(p.src_reg());
                        let count = if !wide {
                            self.ri(0x13, 7, 29, src, 31);
                            29
                        } else {
                            src
                        };
                        self.rr(
                            if op == 0xc0 { 0x20 } else { 0 },
                            if op == 0x60 { 1 } else { 5 },
                            d,
                            d,
                            count,
                        );
                    } else {
                        self.ri(
                            0x13,
                            if op == 0x60 { 1 } else { 5 },
                            d,
                            d,
                            p.imm | if op == 0xc0 { 0x400 } else { 0 },
                        );
                    }
                } else {
                    let signed = if op == 0x10 {
                        -(p.imm as i64)
                    } else {
                        p.imm as i64
                    };
                    if !reg && (-2048..=2047).contains(&signed) {
                        self.ri(
                            0x13,
                            match op {
                                0 | 0x10 => 0,
                                0x40 => 6,
                                0x50 => 7,
                                0xa0 => 4,
                                _ => unreachable!(),
                            },
                            d,
                            d,
                            signed as i32,
                        );
                    } else {
                        let rhs = if reg {
                            self.r(p.src_reg())
                        } else {
                            self.rconst(31, p.imm);
                            31
                        };
                        self.rr(
                            if op == 0x10 { 0x20 } else { 0 },
                            match op {
                                0 | 0x10 => 0,
                                0x40 => 6,
                                0x50 => 7,
                                0xa0 => 4,
                                _ => unreachable!(),
                            },
                            d,
                            d,
                            rhs,
                        );
                    }
                }
                if !wide {
                    self.rzext(d);
                }
            }
        }
    }
    // Fuse ALU32 followed by explicit sign extension into RV64 *W operations.
    pub fn word(&mut self, p: &bpf_insn) {
        let d = self.r(p.dst_reg());
        let op = p.code & 0xf0;
        let reg = p.code & 8 != 0;
        if op == 0xb0 {
            if reg {
                self.ri(0x1b, 0, d, self.r(p.src_reg()), 0);
            } else {
                self.rconst(d, p.imm);
            }
            return;
        }
        if matches!(op, 0x40 | 0x50 | 0xa0) {
            let mut wide = *p;
            wide.code |= 3;
            self.scalar(&wide);
            self.ri(0x1b, 0, d, d, 0);
            return;
        }
        if matches!(op, 0x60 | 0x70 | 0xc0) && !reg {
            self.ri(
                0x1b,
                if op == 0x60 { 1 } else { 5 },
                d,
                d,
                p.imm | if op == 0xc0 { 0x400 } else { 0 },
            );
            return;
        }
        let value = if op == 0x10 {
            -(p.imm as i64)
        } else {
            p.imm as i64
        };
        if !reg && matches!(op, 0 | 0x10) && (-2048..=2047).contains(&value) {
            self.ri(0x1b, 0, d, d, value as i32);
            return;
        }
        let rhs = if reg {
            self.r(p.src_reg())
        } else {
            self.rconst(31, p.imm);
            31
        };
        let f = match op {
            0 | 0x10 => 0,
            0x60 => 1,
            0x70 | 0xc0 => 5,
            _ => unreachable!(),
        };
        self.rr(
            if matches!(op, 0x10 | 0xc0) { 0x20 } else { 0 },
            f,
            d,
            d,
            rhs,
        );
        *self.words.last_mut().unwrap() |= 8; // OP -> OP-32
    }
    pub fn sign_extend_word(&mut self, dst: u8) {
        let d = self.r(dst);
        match self.target {
            NativeTarget::Arm64 => self.push(0x93400000 | 31 << 10 | d << 5 | d),
            NativeTarget::RiscV64 => self.ri(0x1b, 0, d, d, 0),
        }
    }
    pub fn rotate(&mut self, dst: u8, wide: bool, count: u8, left: bool) {
        let d = self.r(dst);
        let bits = if wide { 64 } else { 32 };
        let k = if left {
            bits - count as u32
        } else {
            count as u32
        };
        match self.target {
            NativeTarget::Arm64 => self
                .push(if wide { 0x93c00000 } else { 0x13800000 } | d << 16 | k << 10 | d << 5 | d),
            NativeTarget::RiscV64 => {
                if !wide {
                    self.rzext(d);
                }
                self.ri(0x13, 5, 28, d, k as i32);
                self.ri(0x13, 1, d, d, (bits - k) as i32);
                self.rr(0, 6, d, d, 28);
                if !wide {
                    self.rzext(d);
                }
            }
        }
    }
    pub fn extract(&mut self, dst: u8, wide: bool, start: u8, length: u8) {
        let d = self.r(dst);
        let bits = if wide { 64 } else { 32 };
        let len = u32::from(length).min(bits - u32::from(start));
        match self.target {
            NativeTarget::Arm64 => self.push(
                if wide { 0xd3400000 } else { 0x53000000 }
                    | u32::from(start) << 16
                    | (u32::from(start) + len - 1) << 10
                    | d << 5
                    | d,
            ),
            NativeTarget::RiscV64 => {
                let left = 64 - u32::from(start) - len;
                if left != 0 {
                    self.ri(0x13, 1, d, d, left as i32);
                }
                let right = 64 - len;
                if right != 0 {
                    self.ri(0x13, 5, d, d, right as i32);
                }
            }
        }
    }
    pub fn lea(&mut self, dst: u8, base: u8, wide: bool, shift: u8) {
        let d = self.r(dst);
        let b = self.r(base);
        match self.target {
            NativeTarget::Arm64 => self.push(
                if wide { 0x8b000000 } else { 0x0b000000 }
                    | d << 16
                    | u32::from(shift) << 10
                    | b << 5
                    | d,
            ),
            NativeTarget::RiscV64 => {
                self.ri(0x13, 1, d, d, shift as i32);
                self.rr(0, 0, d, b, d);
                if !wide {
                    self.rzext(d);
                }
            }
        }
    }
    pub fn copy_pair(&mut self, src: i32, dst: i32) {
        let (base, off) = self.aaddr(src, 8, 63);
        self.push(0xa9400000 | off << 15 | 13 << 10 | base << 5 | 12);
        let (base, off) = self.aaddr(dst, 8, 63);
        self.push(0xa9000000 | off << 15 | 13 << 10 | base << 5 | 12);
    }
    pub fn prefetch(&mut self, offset: u16) {
        let (base, off) = self.aaddr(offset as i32, 8, 4095);
        self.push(0xf9800000 | off << 10 | base << 5);
    }
    pub fn select(&mut self, p: &bpf_insn, mv: &bpf_insn, optimize: bool) {
        let wide = p.code & 7 == 5;
        let op = p.code & 0xf0;
        let lhs = self.r(p.dst_reg());
        match self.target {
            NativeTarget::Arm64 => {
                let rhs = if p.code & 8 != 0 {
                    self.r(p.src_reg())
                } else {
                    self.ai(11, p.imm as i64 as u64, wide);
                    11
                };
                self.push(
                    if op == 0x40 {
                        if wide {
                            0xea00001f
                        } else {
                            0x6a00001f
                        }
                    } else {
                        if wide {
                            0xeb00001f
                        } else {
                            0x6b00001f
                        }
                    } | rhs << 16
                        | lhs << 5,
                );
                let cc = match op {
                    0x10 => 0,
                    0x20 => 8,
                    0x30 => 2,
                    0x40 | 0x50 => 1,
                    0x60 => 12,
                    0x70 => 10,
                    0xa0 => 3,
                    0xb0 => 9,
                    0xc0 => 11,
                    0xd0 => 13,
                    _ => unreachable!(),
                };
                if optimize {
                    if mv.code & 8 != 0 {
                        self.amov(12, self.r(mv.src_reg()), mv.code & 7 == 7);
                    } else {
                        self.ai(12, mv.imm as i64 as u64, mv.code & 7 == 7);
                    }
                    let dst = self.r(mv.dst_reg());
                    self.push(0x9a800000 | dst << 16 | (cc ^ 1) << 12 | 12 << 5 | dst);
                } else {
                    let mut body = Self::new(self.target);
                    body.scalar(mv);
                    self.push(0x54000000 | ((body.words.len() as u32 + 1) << 5) | cc);
                    self.words.extend(body.words);
                }
            }
            NativeTarget::RiscV64 => {
                self.ri(0x13, 0, 28, lhs, 0);
                if p.code & 8 != 0 {
                    self.ri(0x13, 0, 29, self.r(p.src_reg()), 0);
                } else {
                    self.rconst(29, p.imm);
                }
                if !wide {
                    if matches!(op, 0x60 | 0x70 | 0xc0 | 0xd0) {
                        self.ri(0x1b, 0, 28, 28, 0);
                        self.ri(0x1b, 0, 29, 29, 0);
                    } else {
                        self.rzext(28);
                        self.rzext(29);
                    }
                }
                let (funct, a, b) = match op {
                    0x10 => (0, 28, 29),
                    0x50 => (1, 28, 29),
                    0x20 => (6, 29, 28),
                    0x30 => (7, 28, 29),
                    0xa0 => (6, 28, 29),
                    0xb0 => (7, 29, 28),
                    0x60 => (4, 29, 28),
                    0x70 => (5, 28, 29),
                    0xc0 => (4, 28, 29),
                    0xd0 => (5, 29, 28),
                    0x40 => {
                        self.rr(0, 7, 28, 28, 29);
                        (1, 28, 0)
                    }
                    _ => unreachable!(),
                };
                let mut body = Self::new(self.target);
                body.scalar(mv);
                let offset = (body.words.len() as u32 + 1) * 4;
                self.push(
                    ((offset >> 12) & 1) << 31
                        | ((offset >> 5) & 63) << 25
                        | b << 20
                        | a << 15
                        | funct << 12
                        | ((offset >> 1) & 15) << 8
                        | ((offset >> 11) & 1) << 7
                        | 0x63,
                );
                self.words.extend(body.words);
            }
        }
    }
}
