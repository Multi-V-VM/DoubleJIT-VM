#![cfg(feature = "ebpf")]

use aya_obj::generated::bpf_insn;
use doublejit_vm::backend::{EbpfX86Compiler, X86EbpfCompiler};
use doublejit_vm::X86Mode;

fn ins(code: u8, dst: u8, src: u8, imm: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
        off: 0,
        imm,
    }
}

fn rotate(width: u8, dst: u8, tmp: u8, count: i32) -> Vec<bpf_insn> {
    let class = if width == 64 { 7 } else { 4 };
    vec![
        ins(class | 0xb8, tmp, dst, 0),
        ins(class | 0x60, dst, 0, count),
        ins(class | 0x70, tmp, 0, width as i32 - count),
        ins(class | 0x48, dst, tmp, 0),
    ]
}

#[test]
fn validates_entire_program_before_fusing() {
    let compiler = EbpfX86Compiler::new().with_native_ops(true);
    let mut program = rotate(64, 0, 1, 13);
    assert!(compiler.compile(&program).is_err());
    program.push(ins(0x95, 0, 0, 0));
    assert_eq!(compiler.compile(&program).unwrap().fusions().len(), 1);
    program.push(ins(0xb7, 0, 0, 1));
    assert!(compiler.compile(&program).is_err());
    for bad in [
        ins(0x67, 0, 0, 64),
        ins(0x64, 0, 0, 32),
        ins(0x77, 0, 0, -1),
        ins(0x6f, 0, 1, 1),
    ] {
        assert!(compiler.compile(&[bad, ins(0x95, 0, 0, 0)]).is_err());
    }
    for index in 0..4 {
        let mut bad = rotate(64, 0, 1, 13);
        bad[index].off = 1;
        bad.push(ins(0x95, 0, 0, 0));
        assert!(compiler.compile(&bad).is_err());
    }
}

#[test]
fn rejects_near_matches_and_live_temporaries() {
    let compiler = EbpfX86Compiler::new().with_native_ops(true);
    let canonical = rotate(64, 0, 1, 13);
    let mut cases = vec![];
    let mut live = canonical.clone();
    live.push(ins(0xaf, 0, 1, 0)); // temporary remains observable
    cases.push(live);
    let mut wrong_count = canonical.clone();
    wrong_count[2].imm = 50;
    cases.push(wrong_count);
    let mut mixed_width = canonical.clone();
    mixed_width[1].code = 0x64;
    cases.push(mixed_width);
    let mut wrong_source = canonical.clone();
    wrong_source[3] = ins(0x4f, 0, 2, 0);
    cases.push(wrong_source);
    cases.push(rotate(64, 0, 0, 13)); // aliased scratch
    for mut program in cases {
        program.push(ins(0x95, 0, 0, 0));
        let optimized = compiler.compile(&program).unwrap();
        let plain = EbpfX86Compiler::new().compile(&program).unwrap();
        assert!(optimized.fusions().is_empty());
        assert_eq!(plain.machine_code(), optimized.machine_code());
    }
}

#[test]
fn frontend_masks_x86_shift_counts() {
    // SHL EAX, 37 -> shift 5; SHR RAX, 69 -> shift 5.
    for (mode, code) in [
        (X86Mode::X86, vec![0xc1, 0xe0, 37, 0xc3]),
        (X86Mode::X86_64, vec![0x48, 0xc1, 0xe8, 69, 0xc3]),
    ] {
        let bpf = X86EbpfCompiler::new(mode).compile(&code).unwrap();
        assert_eq!(bpf.instructions()[0].imm, 5);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod native {
    use super::*;
    #[cfg(feature = "wasm")]
    use doublejit_vm::backend::EbpfWasmCompiler;

    #[test]
    fn all_rotate_counts_and_register_mappings_match_rust() {
        for width in [32_u8, 64] {
            for dst in 0..10 {
                let tmp = (dst + 1) % 10;
                for count in 1..width {
                    let mut program = vec![ins(0xbf, dst, 0, 0)];
                    program.extend(rotate(width, dst, tmp, count as i32));
                    program.extend([ins(0xbf, 0, dst, 0), ins(0x95, 0, 0, 0)]);
                    let optimized = EbpfX86Compiler::new()
                        .with_native_ops(true)
                        .compile(&program)
                        .unwrap();
                    let plain = EbpfX86Compiler::new().compile(&program).unwrap();
                    let fusions = optimized.fusions();
                    assert_eq!(fusions.len(), 1);
                    assert_eq!(fusions[0].ebpf_index, 1);
                    assert_eq!(fusions[0].proof_sequence.len(), 4);
                    assert_eq!(fusions[0].width, width);
                    assert_eq!(fusions[0].count, count);
                    assert!(optimized.machine_code().len() < plain.machine_code().len());
                    let optimized = optimized.prepare().unwrap();
                    let plain = plain.prepare().unwrap();
                    let mut random = 0x0123_4567_89ab_cdef_u64;
                    for i in 0..68 {
                        random ^= random << 13;
                        random ^= random >> 7;
                        random ^= random << 17;
                        let input = match i {
                            0 => 0,
                            1 => 1,
                            2 => u64::MAX,
                            3 => 1 << 63,
                            _ => random,
                        };
                        let expected = if width == 64 {
                            input.rotate_left(count as u32)
                        } else {
                            (input as u32).rotate_left(count as u32) as u64
                        };
                        assert_eq!(plain.execute_with_input(input).unwrap(), expected);
                        assert_eq!(
                            optimized.execute_with_input(input).unwrap(),
                            expected,
                            "width={width} dst={dst} count={count} input={input:#x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn live_temporary_falls_back_and_preserves_result() {
        let mut program = rotate(64, 0, 1, 13);
        program.extend([ins(0xaf, 0, 1, 0), ins(0x95, 0, 0, 0)]);
        let artifact = EbpfX86Compiler::new()
            .with_native_ops(true)
            .compile(&program)
            .unwrap();
        assert!(artifact.fusions().is_empty());
        let runtime = artifact.prepare().unwrap();
        for value in [0, 1, u64::MAX, 0x1234_5678_9abc_def0_u64] {
            assert_eq!(
                runtime.execute_with_input(value).unwrap(),
                value.rotate_left(13) ^ (value >> 51)
            );
        }
    }

    #[test]
    #[cfg(feature = "wasm")]
    fn x86_to_bpf_to_native_and_wasm_agree() {
        for width in [32, 64] {
            let mut input = vec![0xb8, 0xef, 0xcd, 0xab, 0x89];
            for bytes in [
                vec![0x89, 0xc1],
                vec![0xc1, 0xe0, 13],
                vec![0xc1, 0xe9, width - 13],
                vec![0x09, 0xc8],
            ] {
                if width == 64 {
                    input.push(0x48);
                }
                input.extend(bytes);
            }
            input.push(0xc3);
            let program = X86EbpfCompiler::new(X86Mode::X86_64)
                .compile(&input)
                .unwrap();
            let native = EbpfX86Compiler::new()
                .with_native_ops(true)
                .compile(program.instructions())
                .unwrap();
            let wasm = EbpfWasmCompiler::new()
                .compile(program.instructions())
                .unwrap();
            assert_eq!(native.fusions().len(), 1);
            assert_eq!(native.execute().unwrap(), wasm.execute().unwrap() as u64);
        }
    }
}
