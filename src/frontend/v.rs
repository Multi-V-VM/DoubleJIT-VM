use crate::frontend::VLEN;

pub struct V {
    vstart: u64,
    vtype: u64,
    vl: u64,
    vlenb: u64,
    vill: bool,
    vma: bool,
    vta: bool,
    vlmul: f64,
    vsew: u64,
    vlmax: u64,
}

impl V {
    pub fn new()->Self{
        let mut r = Self {
            vstart: 0,
            vtype: 0,
            vl: 0,
            vlenb: VLEN as u64 >> 3,
            vill: false,
            vma: false,
            vta: false,
            vlmul: 0.0,
            vsew: 0,
            vlmax: 0,
        };
        // Default to illegal configuration
        r.set_vl(0, 0, 0, u64::MAX);
        r
    }
    pub fn set_vl(&mut self, rd: usize, rs1: usize, avl: u64, new_type: u64) {
        if self.vtype != new_type {
            self.vtype = new_type;
            self.vsew = 1 << (((new_type >> 3) & 0x7) + 3);
            self.vlmul = match new_type & 0x7 {
                0b000 => 1.0,
                0b001 => 2.0,
                0b010 => 4.0,
                0b011 => 8.0,
                0b111 => 0.5,
                0b110 => 0.25,
                0b101 => 0.125,
                _ => 0.0625,
            };
            self.vlmax = ((VLEN as u64 / self.vsew) as f64 * self.vlmul) as u64;
            self.vta = ((new_type >> 6) & 0x1) != 0;
            self.vma = ((new_type >> 7) & 0x1) != 0;
            self.vill = self.vlmul == 0.0625
                || (new_type >> 8) != 0
                || self.vsew as f64 > if self.vlmul > 1.0 { 1.0 } else { self.vlmul } * ELEN as f64;
            if self.vill {
                self.vlmax = 0;
                self.vtype = 1 << 63;
            }
        }
        if self.vlmax == 0 {
            self.vl = 0;
        } else if rd == 0 && rs1 == 0 {
            self.vl = std::cmp::min(self.vl, self.vlmax);
        } else if rd != 0 && rs1 == 0 {
            self.vl = self.vlmax;
        } else if rs1 != 0 {
            self.vl = std::cmp::min(avl, self.vlmax);
        }
        self.vstart = 0;
    }

    pub fn vl(&self) -> u64 {
        self.vl
    }

    pub fn vlmax(&self) -> u64 {
        self.vlmax
    }

    pub fn vsew(&self) -> u64 {
        self.vsew
    }

    pub fn vlmul(&self) -> f64 {
        self.vlmul
    }

    pub fn vta(&self) -> bool {
        self.vta
    }

    pub fn vma(&self) -> bool {
        self.vma
    }

    pub fn vill(&self) -> bool {
        self.vill
    }

    pub fn vlenb(&self) -> u64 {
        self.vlenb
    }
}