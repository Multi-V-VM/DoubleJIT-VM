use aya_obj::generated::bpf_insn;
#[cfg(test)]
pub fn ins(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    }
}
pub fn run(p: &[bpf_insn], input: u64, memory: &mut [u8]) -> u64 {
    let mut r = [0_u64; 10];
    r[0] = input;
    let mut pc = 0;
    while pc < p.len() {
        let a = &p[pc];
        pc += 1;
        let d = a.dst_reg() as usize;
        let s = a.src_reg() as usize;
        if a.code == 0x95 {
            return r[0];
        }
        if a.code == 5 {
            continue;
        }
        if matches!(
            a.code,
            0x61 | 0x69 | 0x71 | 0x79 | 0x63 | 0x6b | 0x73 | 0x7b
        ) {
            let len = match a.code & 0x18 {
                0 => 4,
                8 => 2,
                16 => 1,
                _ => 8,
            };
            let off = a.off as usize;
            if a.code & 7 == 1 {
                let mut v = [0_u8; 8];
                v[..len].copy_from_slice(&memory[off..off + len]);
                r[d] = u64::from_le_bytes(v);
            } else {
                memory[off..off + len].copy_from_slice(&r[s].to_le_bytes()[..len]);
            }
            continue;
        }
        if a.code == 0xdc {
            r[d] = match a.imm {
                16 => (r[d] as u16).swap_bytes() as u64,
                32 => (r[d] as u32).swap_bytes() as u64,
                _ => r[d].swap_bytes(),
            };
            continue;
        }
        let wide = matches!(a.code & 7, 5 | 7);
        let mask = if wide { u64::MAX } else { u32::MAX as u64 };
        let x = r[d] & mask;
        let y = (if a.code & 8 != 0 {
            r[s]
        } else {
            a.imm as i64 as u64
        }) & mask;
        if matches!(a.code & 7, 5 | 6) {
            let sx = if wide { x as i64 } else { x as i32 as i64 };
            let sy = if wide { y as i64 } else { y as i32 as i64 };
            let take = match a.code & 0xf0 {
                0x10 => x == y,
                0x20 => x > y,
                0x30 => x >= y,
                0x40 => x & y != 0,
                0x50 => x != y,
                0x60 => sx > sy,
                0x70 => sx >= sy,
                0xa0 => x < y,
                0xb0 => x <= y,
                0xc0 => sx < sy,
                0xd0 => sx <= sy,
                _ => panic!(),
            };
            if take {
                pc += 1;
            }
            continue;
        }
        r[d] = (match a.code & 0xf0 {
            0 => x.wrapping_add(y),
            0x10 => x.wrapping_sub(y),
            0x40 => x | y,
            0x50 => x & y,
            0x60 => x << ((y & if wide { 63 } else { 31 }) as u32),
            0x70 => x >> ((y & if wide { 63 } else { 31 }) as u32),
            0xc0 => {
                if wide {
                    ((x as i64) >> ((y & 63) as u32)) as u64
                } else {
                    ((x as i32) >> ((y & 31) as u32)) as u32 as u64
                }
            }
            0xa0 => x ^ y,
            0xb0 => y,
            _ => panic!("unsupported reference instruction"),
        }) & mask;
    }
    panic!("missing exit")
}
