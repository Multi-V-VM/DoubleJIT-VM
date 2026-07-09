//! Small, deterministic x86/x86_64 frontend for the eBPF-to-WASM pipeline.
//!
//! This intentionally decodes a straight-line arithmetic subset rather than
//! pretending to execute a complete x86 userspace ABI. The supported subset is
//! sufficient for leaf arithmetic functions and maps directly to eBPF ALU
//! instructions: register moves, immediate moves, add-immediate, xor, and ret.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Mode {
    X86,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Width {
    W32,
    W64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl X86Register {
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Rax,
            1 => Self::Rcx,
            2 => Self::Rdx,
            3 => Self::Rbx,
            4 => Self::Rsp,
            5 => Self::Rbp,
            6 => Self::Rsi,
            7 => Self::Rdi,
            8 => Self::R8,
            9 => Self::R9,
            10 => Self::R10,
            11 => Self::R11,
            12 => Self::R12,
            13 => Self::R13,
            14 => Self::R14,
            _ => Self::R15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Instruction {
    MovImm {
        dst: X86Register,
        width: X86Width,
        value: u64,
    },
    MovReg {
        dst: X86Register,
        src: X86Register,
        width: X86Width,
    },
    AddImm {
        dst: X86Register,
        width: X86Width,
        value: i32,
    },
    Xor {
        dst: X86Register,
        src: X86Register,
        width: X86Width,
    },
    Ret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedX86Instruction {
    pub offset: usize,
    pub length: usize,
    pub instruction: X86Instruction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86DecodeError {
    pub offset: usize,
    pub reason: String,
}

impl fmt::Display for X86DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "x86 decode error at byte {}: {}",
            self.offset, self.reason
        )
    }
}

impl std::error::Error for X86DecodeError {}

#[derive(Debug, Clone, Copy)]
pub struct X86Frontend {
    mode: X86Mode,
}

impl X86Frontend {
    pub fn new(mode: X86Mode) -> Self {
        Self { mode }
    }

    pub fn mode(&self) -> X86Mode {
        self.mode
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Vec<DecodedX86Instruction>, X86DecodeError> {
        let mut decoded = Vec::new();
        let mut cursor = 0;

        while cursor < bytes.len() {
            let start = cursor;
            let mut rex = 0_u8;
            if self.mode == X86Mode::X86_64 && (0x40..=0x4f).contains(&bytes[cursor]) {
                rex = bytes[cursor];
                cursor += 1;
                if cursor == bytes.len() {
                    return Err(error(start, "truncated REX prefix"));
                }
            }

            let opcode = bytes[cursor];
            cursor += 1;
            let width = if self.mode == X86Mode::X86_64 && rex & 0x08 != 0 {
                X86Width::W64
            } else {
                X86Width::W32
            };

            let instruction = match opcode {
                0xb8..=0xbf => {
                    let register = register_from_low3(opcode & 0x07, rex & 0x01 != 0);
                    let imm_len = if width == X86Width::W64 { 8 } else { 4 };
                    let immediate = read_unsigned(bytes, &mut cursor, imm_len, start)?;
                    X86Instruction::MovImm {
                        dst: register,
                        width,
                        value: immediate,
                    }
                }
                0xc7 => {
                    let modrm = read_u8(bytes, &mut cursor, start)?;
                    if modrm >> 6 != 0b11 || (modrm >> 3) & 0x07 != 0 {
                        return Err(error(start, "only C7 /0 register mov is supported"));
                    }
                    let dst = register_from_low3(modrm & 0x07, rex & 0x01 != 0);
                    let imm = read_signed(bytes, &mut cursor, 4, start)?;
                    X86Instruction::MovImm {
                        dst,
                        width,
                        value: if width == X86Width::W64 {
                            imm as u64
                        } else {
                            imm as u32 as u64
                        },
                    }
                }
                0x05 => X86Instruction::AddImm {
                    dst: X86Register::Rax,
                    width,
                    value: read_signed(bytes, &mut cursor, 4, start)? as i32,
                },
                0x81 | 0x83 => {
                    let modrm = read_u8(bytes, &mut cursor, start)?;
                    if modrm >> 6 != 0b11 || (modrm >> 3) & 0x07 != 0 {
                        return Err(error(
                            start,
                            "only ADD /0 with register operands is supported",
                        ));
                    }
                    let immediate_len = if opcode == 0x81 { 4 } else { 1 };
                    X86Instruction::AddImm {
                        dst: register_from_low3(modrm & 0x07, rex & 0x01 != 0),
                        width,
                        value: read_signed(bytes, &mut cursor, immediate_len, start)? as i32,
                    }
                }
                0x31 | 0x89 | 0x8b => {
                    let modrm = read_u8(bytes, &mut cursor, start)?;
                    if modrm >> 6 != 0b11 {
                        return Err(error(
                            start,
                            "memory operands are not supported in this frontend",
                        ));
                    }
                    let rm = register_from_low3(modrm & 0x07, rex & 0x01 != 0);
                    let reg = register_from_low3((modrm >> 3) & 0x07, rex & 0x04 != 0);
                    match opcode {
                        0x31 => X86Instruction::Xor {
                            dst: rm,
                            src: reg,
                            width,
                        },
                        0x89 => X86Instruction::MovReg {
                            dst: rm,
                            src: reg,
                            width,
                        },
                        _ => X86Instruction::MovReg {
                            dst: reg,
                            src: rm,
                            width,
                        },
                    }
                }
                0xc3 => X86Instruction::Ret,
                _ => return Err(error(start, &format!("unsupported opcode 0x{opcode:02x}"))),
            };

            decoded.push(DecodedX86Instruction {
                offset: start,
                length: cursor - start,
                instruction,
            });
            if matches!(instruction, X86Instruction::Ret) {
                if cursor != bytes.len() {
                    return Err(error(
                        cursor,
                        "bytes after ret are not part of a single leaf block",
                    ));
                }
                return Ok(decoded);
            }
        }

        Err(error(bytes.len(), "missing terminal ret"))
    }
}

fn register_from_low3(low: u8, extension: bool) -> X86Register {
    X86Register::from_code(low | if extension { 8 } else { 0 })
}

fn read_u8(bytes: &[u8], cursor: &mut usize, start: usize) -> Result<u8, X86DecodeError> {
    if let Some(value) = bytes.get(*cursor).copied() {
        *cursor += 1;
        Ok(value)
    } else {
        Err(error(start, "truncated instruction"))
    }
}

fn read_unsigned(
    bytes: &[u8],
    cursor: &mut usize,
    width: usize,
    start: usize,
) -> Result<u64, X86DecodeError> {
    let end = cursor
        .checked_add(width)
        .ok_or_else(|| error(start, "instruction length overflow"))?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or_else(|| error(start, "truncated immediate"))?;
    *cursor = end;
    let mut value = 0_u64;
    for (index, byte) in raw.iter().copied().enumerate() {
        value |= u64::from(byte) << (index * 8);
    }
    Ok(value)
}

fn read_signed(
    bytes: &[u8],
    cursor: &mut usize,
    width: usize,
    start: usize,
) -> Result<i64, X86DecodeError> {
    let unsigned = read_unsigned(bytes, cursor, width, start)?;
    let shift = 64 - width * 8;
    Ok(((unsigned << shift) as i64) >> shift)
}

fn error(offset: usize, reason: &str) -> X86DecodeError {
    X86DecodeError {
        offset,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x86_leaf_arithmetic() {
        let bytes = [0xb8, 40, 0, 0, 0, 0x83, 0xc0, 2, 0xc3];
        let decoded = X86Frontend::new(X86Mode::X86).decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 3);
        assert!(matches!(decoded[2].instruction, X86Instruction::Ret));
    }

    #[test]
    fn decodes_x86_64_rex_w_leaf_arithmetic() {
        let bytes = [0x48, 0xc7, 0xc0, 40, 0, 0, 0, 0x48, 0x83, 0xc0, 2, 0xc3];
        let decoded = X86Frontend::new(X86Mode::X86_64).decode(&bytes).unwrap();
        assert!(matches!(
            decoded[0].instruction,
            X86Instruction::MovImm {
                width: X86Width::W64,
                ..
            }
        ));
        assert!(matches!(decoded[2].instruction, X86Instruction::Ret));
    }
}
