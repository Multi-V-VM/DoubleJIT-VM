#![cfg(feature = "ebpf")]

use aya_obj::generated::bpf_insn;
use doublejit_vm::backend::{EbpfX86Compiler, EbpfX86Error};

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off,
        imm,
    }
}

fn exit() -> bpf_insn {
    insn(0x95, 0, 0, 0, 0)
}

#[test]
fn rejects_incomplete_and_unsupported_programs() {
    let compiler = EbpfX86Compiler::new();
    for program in [vec![], vec![insn(0xb7, 0, 0, 0, 42)]] {
        assert!(matches!(
            compiler.compile(&program),
            Err(EbpfX86Error::MissingExit)
        ));
    }
    assert!(matches!(
        compiler.compile(&[exit(), exit()]),
        Err(EbpfX86Error::InstructionAfterExit { index: 1 })
    ));
    // Stack pointer / invalid registers, jumps, helpers, loads, stores,
    // LD_IMM64, unsupported arithmetic and a noncanonical EXIT opcode.
    for code in [0x85, 0x79, 0x7b, 0x18, 0x37, 0x9d] {
        assert!(matches!(
            compiler.compile(&[insn(code, 0, 0, 0, 0), exit()]),
            Err(EbpfX86Error::UnsupportedInstruction { index: 0, .. })
        ));
    }
    for register in 10..=15 {
        for instruction in [insn(0xb7, register, 0, 0, 0), insn(0xbf, 0, register, 0, 0)] {
            assert!(matches!(
                compiler.compile(&[instruction, exit()]),
                Err(EbpfX86Error::InvalidRegister { index: 0, .. })
            ));
        }
    }
    for instruction in [
        insn(0xb7, 0, 0, 1, 0),
        insn(0xb7, 0, 1, 0, 0),
        insn(0xbf, 0, 1, 0, 1),
        insn(0x95, 1, 0, 0, 0),
        insn(0x95, 0, 1, 0, 0),
        insn(0x95, 0, 0, 1, 0),
        insn(0x95, 0, 0, 0, 1),
    ] {
        assert!(matches!(
            compiler.compile(&[instruction, exit()]),
            Err(EbpfX86Error::InvalidEncoding { index: 0 })
        ));
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
#[test]
fn emits_code_but_refuses_execution_on_other_hosts() {
    let artifact = EbpfX86Compiler::new().compile(&[exit()]).unwrap();
    assert!(!artifact.machine_code().is_empty());
    assert!(matches!(
        artifact.execute(),
        Err(EbpfX86Error::UnsupportedHost)
    ));
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod native {
    use super::*;
    #[cfg(feature = "wasm")]
    use doublejit_vm::backend::EbpfWasmCompiler;
    use doublejit_vm::backend::X86EbpfCompiler;
    use doublejit_vm::X86Mode;

    fn roundtrip(mode: X86Mode, input: &[u8], expected: u64) {
        let bpf = X86EbpfCompiler::new(mode).compile(input).unwrap();
        let artifact = EbpfX86Compiler::new().compile(bpf.instructions()).unwrap();
        let runtime = artifact.prepare().unwrap();
        // The executable mapping owns its code independently of the artifact.
        drop(artifact);
        for _ in 0..3 {
            assert_eq!(runtime.execute().unwrap(), expected);
        }
    }

    #[test]
    #[cfg(feature = "wasm")]
    fn both_source_modes_return_42_and_match_wasm() {
        for (mode, input) in [
            (X86Mode::X86, vec![0xb8, 40, 0, 0, 0, 0x83, 0xc0, 2, 0xc3]),
            (
                X86Mode::X86_64,
                vec![0x48, 0xc7, 0xc0, 40, 0, 0, 0, 0x48, 0x83, 0xc0, 2, 0xc3],
            ),
        ] {
            roundtrip(mode, &input, 42);
            let bpf = X86EbpfCompiler::new(mode).compile(&input).unwrap();
            let wasm = EbpfWasmCompiler::new().compile(bpf.instructions()).unwrap();
            assert_eq!(wasm.execute().unwrap(), 42);
        }
    }

    #[test]
    fn preserves_width_overflow_and_sign_extension() {
        let cases: &[(&[u8], u64)] = &[
            (&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3], 0xffff_ffff),
            (&[0xb8, 0xff, 0xff, 0xff, 0xff, 0x83, 0xc0, 2, 0xc3], 1),
            (&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xc3], u64::MAX),
            (
                &[
                    0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 2, 0xc3,
                ],
                1,
            ),
            (
                &[0x48, 0xc7, 0xc0, 0, 0, 0, 0x80, 0xc3],
                0xffff_ffff_8000_0000,
            ),
            (
                &[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x89, 0xc0, 0xc3],
                0xffff_ffff,
            ),
            (&[0xb8, 0, 0, 0, 0, 0x48, 0x83, 0xc0, 0xff, 0xc3], u64::MAX),
            (
                &[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x31, 0xc0, 0xc3],
                0,
            ),
        ];
        for &(input, expected) in cases {
            roundtrip(X86Mode::X86_64, input, expected);
        }
    }

    #[test]
    fn roundtrips_every_mapped_register_at_both_widths() {
        for register in [0_u8, 1, 2, 3, 6, 7, 8, 9, 10, 11] {
            for wide in [false, true] {
                let mut input = Vec::new();
                let rex = 0x40 | (u8::from(wide) << 3) | (register >> 3);
                if rex != 0x40 {
                    input.push(rex);
                }
                input.extend_from_slice(&[0xc7, 0xc0 | (register & 7), 0xfe, 0xff, 0xff, 0xff]);
                if rex != 0x40 {
                    input.push(rex);
                }
                input.extend_from_slice(&[0x83, 0xc0 | (register & 7), 44]);
                let rex = 0x40 | (u8::from(wide) << 3) | ((register >> 3) << 2);
                if rex != 0x40 {
                    input.push(rex);
                }
                input.extend_from_slice(&[0x89, 0xc0 | ((register & 7) << 3), 0xc3]);
                roundtrip(X86Mode::X86_64, &input, 42);
            }
        }
    }

    #[test]
    fn repeat_calls_reset_registers() {
        let artifact = EbpfX86Compiler::new()
            .compile(&[insn(0x07, 9, 0, 0, 1), insn(0xbf, 0, 9, 0, 0), exit()])
            .unwrap();
        let runtime = artifact.prepare().unwrap();
        for _ in 0..10 {
            assert_eq!(runtime.execute().unwrap(), 1);
        }
        assert_eq!(
            EbpfX86Compiler::new()
                .compile(&[exit()])
                .unwrap()
                .execute()
                .unwrap(),
            0
        );
    }

    #[test]
    fn all_alu_forms_and_register_pairs_match_rust_reference() {
        // Exercise both REX extension bits, all source/destination pairs, both
        // widths, and both operand forms, including aliased src/dst registers.
        let compiler = EbpfX86Compiler::new();
        for dst in 0..10 {
            for src in 0..10 {
                for wide in [false, true] {
                    for op in [0x00, 0xa0, 0xb0] {
                        for reg_source in [false, true] {
                            let lhs = 0xffff_ffff_8000_0000_u64;
                            let rhs = if src == dst && reg_source {
                                lhs
                            } else {
                                u64::MAX
                            };
                            let mut expected = match op {
                                0x00 => lhs.wrapping_add(rhs),
                                0xa0 => lhs ^ rhs,
                                0xb0 => rhs,
                                _ => unreachable!(),
                            };
                            if !wide {
                                expected = expected as u32 as u64;
                            }
                            let code =
                                op | if wide { 7 } else { 4 } | if reg_source { 8 } else { 0 };
                            let program = [
                                insn(0xb7, src, 0, 0, -1),
                                insn(0xb7, dst, 0, 0, i32::MIN),
                                insn(
                                    code,
                                    dst,
                                    if reg_source { src } else { 0 },
                                    0,
                                    if reg_source { 0 } else { -1 },
                                ),
                                insn(0xbf, 0, dst, 0, 0),
                                exit(),
                            ];
                            assert_eq!(
                                compiler.compile(&program).unwrap().execute().unwrap(),
                                expected,
                                "dst={dst} src={src} code={code:#x}"
                            );
                        }
                    }
                }
            }
        }
    }
}
