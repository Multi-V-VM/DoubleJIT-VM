#![cfg(all(feature = "ebpf", target_arch = "x86_64", target_os = "linux"))]
#[path = "../examples/support/ebpf_reference.rs"]
mod reference;
use doublejit_vm::backend::{
    EbpfX86Compiler, EbpfX86Error, NativeOpKind as Kind, NativeOpPolicy, X86EbpfCompiler,
};
use doublejit_vm::X86Mode;
use reference::{ins, run};
fn end() -> aya_obj::generated::bpf_insn {
    ins(0x95, 0, 0, 0, 0)
}
fn check(program: &[aya_obj::generated::bpf_insn], kind: Option<Kind>) {
    let mut random = 0x5bfe_ba98_7654_3210_u64;
    for compiler in [
        EbpfX86Compiler::new(),
        EbpfX86Compiler::new().with_policy(NativeOpPolicy::all()),
        EbpfX86Compiler::new()
            .with_policy(NativeOpPolicy::all())
            .without_optional_isa(),
    ] {
        let a = compiler.compile(program).unwrap();
        let rt = a.prepare().unwrap();
        for i in 0..40 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let input = match i {
                0 => 0,
                1 => u64::MAX,
                2 => 1 << 63,
                3 => u32::MAX as u64,
                _ => random,
            };
            let mut memory: Vec<u8> = (0..256)
                .map(|j| (random.wrapping_add(j * 37) & 255) as u8)
                .collect();
            let mut expected_memory = memory.clone();
            let expected = run(program, input, &mut expected_memory);
            assert_eq!(
                rt.execute_with_memory(input, &mut memory).unwrap(),
                expected,
                "input={input:x}, ops={:?}",
                a.optimizations()
            );
            assert_eq!(memory, expected_memory);
        }
    }
    if let Some(kind) = kind {
        assert!(
            EbpfX86Compiler::new()
                .with_policy(NativeOpPolicy::all())
                .compile(program)
                .unwrap()
                .optimizations()
                .iter()
                .any(|x| x.kind == kind),
            "missing {kind:?}"
        );
    }
}
#[test]
fn extracts_all_widths_registers_and_cpu_fallback() {
    for class in [4, 7] {
        for dst in 0..10 {
            for start in [0, 1, 13, 31] {
                for mask in [1, 255, 0x7fff_ffff, -1] {
                    let p = [
                        ins(0xbf, dst, 0, 0, 0),
                        ins(class | 0x70, dst, 0, 0, start),
                        ins(class | 0x50, dst, 0, 0, mask),
                        ins(0xbf, 0, dst, 0, 0),
                        end(),
                    ];
                    check(
                        &p,
                        if std::is_x86_feature_detected!("bmi1") {
                            Some(Kind::BitExtract)
                        } else {
                            None
                        },
                    );
                    let fallback = EbpfX86Compiler::new()
                        .with_policy(NativeOpPolicy::all())
                        .without_optional_isa()
                        .compile(&p)
                        .unwrap();
                    assert!(!fallback
                        .optimizations()
                        .iter()
                        .any(|x| x.kind == Kind::BitExtract));
                }
            }
        }
    }
}
#[test]
fn lea_all_registers_scales_and_alias_fallback() {
    for class in [4, 7] {
        for dst in 0..10 {
            for base in 0..10 {
                for shift in 0..4 {
                    let p = [
                        ins(0xbf, dst, 0, 0, 0),
                        ins(0xb7, base, 0, 0, -15),
                        ins(class | 0x60, dst, 0, 0, shift),
                        ins(class | 8, dst, base, 0, 0),
                        ins(class, dst, 0, 0, -123),
                        ins(0xbf, 0, dst, 0, 0),
                        end(),
                    ];
                    check(&p, if dst != base { Some(Kind::Lea) } else { None });
                    if dst == base {
                        assert!(!EbpfX86Compiler::new()
                            .with_policy(NativeOpPolicy::all())
                            .compile(&p)
                            .unwrap()
                            .optimizations()
                            .iter()
                            .any(|x| x.kind == Kind::Lea));
                    }
                }
            }
        }
    }
}
#[test]
fn select_all_conditions_widths_and_source_aliases() {
    for class in [5, 6] {
        for op in [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0, 0xd0,
        ] {
            for mov in [0xb4, 0xb7, 0xbc, 0xbf] {
                for dst in [0, 1, 6, 9] {
                    for reg_cmp in [false, true] {
                        let p = [
                            ins(0xb7, 1, 0, 0, -1),
                            ins(0xbf, dst, 0, 0, 0),
                            ins(
                                class | op | if reg_cmp { 8 } else { 0 },
                                0,
                                if reg_cmp { 1 } else { 0 },
                                1,
                                if reg_cmp { 0 } else { -1 },
                            ),
                            ins(
                                mov,
                                dst,
                                if mov & 8 != 0 { 1 } else { 0 },
                                0,
                                if mov & 8 != 0 { 0 } else { -17 },
                            ),
                            ins(0xbf, 0, dst, 0, 0),
                            end(),
                        ];
                        check(&p, Some(Kind::Select));
                    }
                }
            }
        }
    }
}
#[test]
fn memory_width_endian_and_bounds() {
    for dst in 0..10 {
        for (ld, st, bits) in [
            (0x71, 0x73, 16),
            (0x69, 0x6b, 16),
            (0x61, 0x63, 32),
            (0x79, 0x7b, 64),
        ] {
            let p = [
                ins(ld, dst, 10, 1, 0),
                ins(0xdc, dst, 0, 0, bits),
                ins(st, 10, dst, 33, 0),
                ins(0xbf, 0, dst, 0, 0),
                end(),
            ];
            check(
                &p,
                if bits >= 32 && std::is_x86_feature_detected!("movbe") {
                    Some(Kind::EndianLoad)
                } else {
                    None
                },
            );
            let a = EbpfX86Compiler::new()
                .with_policy(NativeOpPolicy::all())
                .compile(&p)
                .unwrap();
            let required = a.required_memory();
            let rt = a.prepare().unwrap();
            assert!(matches!(
                rt.execute_with_input(1),
                Err(EbpfX86Error::BufferTooSmall { .. })
            ));
            assert!(rt
                .execute_with_memory(1, &mut vec![0; required - 1])
                .is_err());
            assert!(rt.execute_with_memory(1, &mut vec![0; required]).is_ok());
        }
    }
    for p in [
        vec![ins(0x79, 0, 0, 0, 0), end()],
        vec![ins(0x79, 0, 10, -1, 0), end()],
        vec![ins(0xb7, 10, 0, 0, 0), end()],
        vec![ins(0xbf, 0, 10, 0, 0), end()],
    ] {
        assert!(EbpfX86Compiler::new().compile(&p).is_err());
    }
}
#[test]
fn bulk_copy_rejects_overlap_and_live_scratch() {
    for offset in [0, 1, 8, 16, 64, 65] {
        for live in [false, true] {
            for tmp in [1, 6, 9] {
                let mut p = vec![];
                for i in 0..8 {
                    p.extend([
                        ins(0x79, tmp, 10, i * 8, 0),
                        ins(0x7b, 10, tmp, offset + i * 8, 0),
                    ]);
                }
                if live {
                    p.push(ins(0xbf, 0, tmp, 0, 0));
                }
                p.push(end());
                check(
                    &p,
                    if offset >= 64 && !live {
                        Some(Kind::BulkCopy)
                    } else {
                        None
                    },
                );
                if offset < 64 || live {
                    assert!(!EbpfX86Compiler::new()
                        .with_policy(NativeOpPolicy::all())
                        .compile(&p)
                        .unwrap()
                        .optimizations()
                        .iter()
                        .any(|x| x.kind == Kind::BulkCopy));
                }
            }
        }
    }
}
#[test]
fn explicit_prefetch_checks_and_policy() {
    let p = [ins(5, 0, 0, 0, 0), end()];
    let c = EbpfX86Compiler::new().with_policy(NativeOpPolicy::all());
    let a = c.compile_with_prefetch_hints(&p, &[(0, 127)]).unwrap();
    assert_eq!(a.optimizations()[0].kind, Kind::Prefetch);
    let rt = a.prepare().unwrap();
    let mut m = vec![123; 128];
    assert_eq!(rt.execute_with_memory(42, &mut m).unwrap(), 42);
    assert_eq!(m, vec![123; 128]);
    assert!(rt.execute_with_memory(42, &mut [0; 127]).is_err());
    for hints in [vec![(1, 0)], vec![(2, 0)], vec![(0, 0), (0, 1)]] {
        assert!(c.compile_with_prefetch_hints(&p, &hints).is_err());
    }
    let disabled = c
        .with_policy(NativeOpPolicy {
            prefetch: false,
            ..Default::default()
        })
        .compile_with_prefetch_hints(&p, &[(0, 127)])
        .unwrap();
    assert!(disabled.optimizations().is_empty());
    assert_eq!(disabled.required_memory(), 128);
}
#[test]
fn alu_folding_and_variable_shifts() {
    for class in [4, 7] {
        for op in [0, 0x40, 0x50, 0xa0] {
            let p = [
                ins(class | op, 0, 0, 0, i32::MAX),
                ins(class | op, 0, 0, 0, i32::MAX),
                ins(class | op, 0, 0, 0, -12),
                end(),
            ];
            check(&p, Some(Kind::AluFold));
        }
    }
    for class in [4, 7] {
        for op in [0x60, 0x70] {
            for dst in 0..10 {
                for src in 0..10 {
                    let p = [
                        ins(0xbf, dst, 0, 0, 0),
                        ins(0xb7, src, 0, 0, 67),
                        ins(class | op | 8, dst, src, 0, 0),
                        ins(0xbf, 0, dst, 0, 0),
                        end(),
                    ];
                    check(&p, None);
                }
            }
        }
    }
}
#[test]
fn right_rotate_and_branch_liveness() {
    for class in [4, 7] {
        let w = if class == 7 { 64 } else { 32 };
        let p = [
            ins(class | 0xb8, 1, 0, 0, 0),
            ins(class | 0x70, 0, 0, 0, 7),
            ins(class | 0x60, 1, 0, 0, w - 7),
            ins(class | 0x48, 0, 1, 0, 0),
            end(),
        ];
        check(&p, Some(Kind::RotateRight));
        let mut p = p[..4].to_vec();
        p.extend([
            ins(0x15, 0, 0, 1, 0),
            ins(0xb7, 1, 0, 0, 0),
            ins(0xaf, 0, 1, 0, 0),
            end(),
        ]);
        check(&p, Some(Kind::Select));
        assert!(!EbpfX86Compiler::new()
            .with_policy(NativeOpPolicy::all())
            .compile(&p)
            .unwrap()
            .optimizations()
            .iter()
            .any(|o| o.kind == Kind::RotateRight));
    }
    for p in [
        vec![ins(0x15, 0, 0, -1, 0), end()],
        vec![ins(0x15, 0, 0, 2, 0), ins(0xb7, 0, 0, 0, 0), end()],
        vec![ins(0x15, 0, 0, 1, 0), ins(0x79, 0, 10, 0, 0), end()],
    ] {
        assert!(EbpfX86Compiler::new().compile(&p).is_err());
    }
}
#[test]
fn x86_frontend_reaches_all_new_families() {
    let fixtures: Vec<(Vec<u8>, Kind)> = vec![
        (
            vec![
                0x48, 0xc1, 0xe8, 5, 0x48, 0x81, 0xe0, 0xff, 0x03, 0, 0, 0xc3,
            ],
            Kind::BitExtract,
        ),
        (
            vec![
                0x48, 0xc1, 0xe0, 2, 0x48, 0x01, 0xc8, 0x48, 0x83, 0xc0, 17, 0xc3,
            ],
            Kind::Lea,
        ),
        (
            vec![
                0x48, 0x83, 0xf8, 0, 0x74, 7, 0x48, 0xc7, 0xc0, 42, 0, 0, 0, 0xc3,
            ],
            Kind::Select,
        ),
        (
            vec![0x48, 0x8b, 0x45, 0, 0x48, 0x0f, 0xc8, 0xc3],
            Kind::EndianLoad,
        ),
        (
            vec![
                0x48, 0x8b, 0x4d, 0, 0x48, 0x89, 0x4d, 32, 0x48, 0x8b, 0x4d, 8, 0x48, 0x89, 0x4d,
                40, 0xc3,
            ],
            Kind::BulkCopy,
        ),
        (vec![0x0f, 0x18, 0x4d, 64, 0xc3], Kind::Prefetch),
    ];
    for (bytes, kind) in fixtures {
        let bpf = X86EbpfCompiler::new(X86Mode::X86_64)
            .compile(&bytes)
            .unwrap();
        let artifact = EbpfX86Compiler::new()
            .with_policy(NativeOpPolicy::all())
            .compile_program(&bpf)
            .unwrap();
        let isa = match kind {
            Kind::BitExtract => std::is_x86_feature_detected!("bmi1"),
            Kind::EndianLoad => std::is_x86_feature_detected!("movbe"),
            _ => true,
        };
        if isa {
            assert!(
                artifact.optimizations().iter().any(|o| o.kind == kind),
                "{kind:?}"
            );
        }
        let mut m = vec![0x97; 128];
        let mut expected_m = m.clone();
        let expected = run(bpf.instructions(), 0xdeadbeef, &mut expected_m);
        assert_eq!(
            artifact
                .prepare()
                .unwrap()
                .execute_with_memory(0xdeadbeef, &mut m)
                .unwrap(),
            expected
        );
        assert_eq!(m, expected_m);
    }
}
#[test]
fn policy_off_produces_plain_bytes() {
    let p = [
        ins(0x67, 0, 0, 0, 2),
        ins(0x0f, 0, 1, 0, 0),
        ins(0x07, 0, 0, 0, 12),
        ins(0x07, 0, 0, 0, 31),
        end(),
    ];
    let policy = NativeOpPolicy {
        rotate: false,
        select: false,
        extract: false,
        lea: false,
        endian: false,
        bulk_copy: false,
        prefetch: false,
        alu: false,
    };
    let plain = EbpfX86Compiler::new().compile(&p).unwrap();
    let off = EbpfX86Compiler::new()
        .with_policy(policy)
        .compile(&p)
        .unwrap();
    assert_eq!(plain.machine_code(), off.machine_code());
}

#[test]
fn extract_control_cache_survives_only_non_scratch_operations() {
    let mut p = vec![];
    for middle in 0..4 {
        p.extend([
            ins(0x77, 0, 0, 0, 5),
            ins(0x57, 0, 0, 0, 1023),
            ins(0x07, 0, 0, 0, 0x7fffffff),
        ]);
        match middle {
            0 => p.extend([ins(0x15, 0, 0, 1, 1), ins(0xb7, 0, 0, 0, -1)]),
            1 => p.extend([ins(0xb7, 1, 0, 0, 13), ins(0x6f, 0, 1, 0, 0)]),
            2 => p.push(ins(0x07, 0, 0, 0, 10)),
            _ => p.extend([ins(0x77, 0, 0, 0, 3), ins(0x57, 0, 0, 0, 255)]),
        }
    }
    p.extend([ins(0x77, 0, 0, 0, 5), ins(0x57, 0, 0, 0, 1023), end()]);
    check(&p, None);
}

#[test]
fn default_policy_leaves_select_and_prefetch_opt_in() {
    let policy = NativeOpPolicy::default();
    assert!(!policy.select);
    assert!(!policy.prefetch);
    let p = [
        ins(5, 0, 0, 0, 0),
        ins(0x15, 0, 0, 1, 0),
        ins(0xb7, 0, 0, 0, 42),
        end(),
    ];
    let a = EbpfX86Compiler::new()
        .with_native_ops(true)
        .compile_with_prefetch_hints(&p, &[(0, 0)])
        .unwrap();
    assert!(a.optimizations().is_empty());
    let plain = EbpfX86Compiler::new()
        .compile_with_prefetch_hints(&p, &[(0, 0)])
        .unwrap();
    assert_eq!(a.machine_code(), plain.machine_code());
}
