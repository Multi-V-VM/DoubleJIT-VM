#![cfg(feature = "ebpf")]
#[path = "../examples/support/ebpf_reference.rs"]
mod reference;
use doublejit_vm::backend::{
    Arm64EbpfCompiler, EbpfNativeCompiler, EbpfX86Error, NativeOpKind, NativeOpPolicy,
    NativeTarget, RiscV64EbpfCompiler,
};
use reference::{ins, run};
fn end() -> aya_obj::generated::bpf_insn {
    ins(0x95, 0, 0, 0, 0)
}
fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}
fn compare(p: &[aya_obj::generated::bpf_insn]) {
    for target in [NativeTarget::Arm64, NativeTarget::RiscV64] {
        for optimized in [false, true] {
            let c = EbpfNativeCompiler::new(target);
            let c = if optimized {
                c.with_policy(NativeOpPolicy::all())
            } else {
                c
            };
            let a = c.compile(p).unwrap();
            assert_eq!(a.machine_code().len() % 4, 0);
            if NativeTarget::host() != Some(target) {
                assert!(matches!(
                    a.prepare(),
                    Err(EbpfX86Error::UnsupportedTarget(_))
                ));
                continue;
            }
            let rt = a.prepare().unwrap();
            for x in [
                0,
                1,
                31,
                32,
                63,
                64,
                65,
                u64::MAX,
                0x8000000000000000,
                0xffffffff,
                0x123456789abcdef0,
            ] {
                let mut memory: Vec<u8> = (0..256).map(|i| (i * 37 + 11) as u8).collect();
                let mut expected_memory = memory.clone();
                let expected = run(p, x, &mut expected_memory);
                assert_eq!(
                    rt.execute_with_memory(x, &mut memory).unwrap(),
                    expected,
                    "{target:?}, optimized={optimized}, input={x:x}, p={p:?}"
                );
                assert_eq!(memory, expected_memory);
            }
        }
    }
}
#[test]
fn arithmetic_all_registers_widths_sources() {
    for class in [4, 7] {
        for op in [0, 0x10, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0] {
            for dst in 0..10 {
                for src in 0..10 {
                    for reg in [false, true] {
                        let value = if matches!(op, 0x60 | 0x70 | 0xc0) {
                            13
                        } else {
                            i32::MIN
                        };
                        let p = [
                            ins(0xbf, dst, 0, 0, 0),
                            ins(0xb7, src, 0, 0, -17),
                            ins(
                                class | op | if reg { 8 } else { 0 },
                                dst,
                                if reg { src } else { 0 },
                                0,
                                if reg { 0 } else { value },
                            ),
                            ins(0xbf, 0, dst, 0, 0),
                            end(),
                        ];
                        compare(&p);
                    }
                }
            }
        }
    }
}
#[test]
fn conditional_assignment_all_comparisons() {
    for class in [5, 6] {
        for op in [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0, 0xd0,
        ] {
            for mov in [0xb4, 0xb7, 0xbc, 0xbf] {
                for reg in [false, true] {
                    let p = [
                        ins(0xb7, 1, 0, 0, -1),
                        ins(
                            class | op | if reg { 8 } else { 0 },
                            0,
                            if reg { 1 } else { 0 },
                            1,
                            if reg { 0 } else { -1 },
                        ),
                        ins(
                            mov,
                            0,
                            if mov & 8 != 0 { 1 } else { 0 },
                            0,
                            if mov & 8 != 0 { 0 } else { i32::MIN },
                        ),
                        end(),
                    ];
                    compare(&p);
                }
            }
        }
    }
}
#[test]
fn memory_endian_unaligned_and_bounds() {
    for (load, store) in [(0x71, 0x73), (0x69, 0x6b), (0x61, 0x63), (0x79, 0x7b)] {
        for width in [16, 32, 64] {
            for reg in [0, 5, 9] {
                let p = [
                    ins(load, reg, 10, 1, 0),
                    ins(0xdc, reg, 0, 0, width),
                    ins(store, 10, reg, 65, 0),
                    ins(0xbf, 0, reg, 0, 0),
                    end(),
                ];
                compare(&p);
                if let Some(target) = NativeTarget::host() {
                    let a = EbpfNativeCompiler::new(target).compile(&p).unwrap();
                    let rt = a.prepare().unwrap();
                    assert!(rt.execute_with_input(0).is_err());
                    assert!(rt
                        .execute_with_memory(0, &mut vec![0; a.required_memory() - 1])
                        .is_err());
                    let mut buffer = vec![0; a.required_memory() + 1];
                    assert!(rt.execute_with_memory(0, &mut buffer[1..]).is_ok());
                }
            }
        }
    }
}
#[test]
fn rotate_extract_lea_fold_and_copy() {
    for class in [4, 7] {
        let width = if class == 7 { 64 } else { 32 };
        for k in 1..width {
            for left in [false, true] {
                let p = [
                    ins(class | 0xb8, 1, 0, 0, 0),
                    ins(class | if left { 0x60 } else { 0x70 }, 0, 0, 0, k),
                    ins(class | if left { 0x70 } else { 0x60 }, 1, 0, 0, width - k),
                    ins(class | 0x48, 0, 1, 0, 0),
                    end(),
                ];
                compare(&p);
                for t in [NativeTarget::Arm64, NativeTarget::RiscV64] {
                    let a = EbpfNativeCompiler::new(t)
                        .with_native_ops(true)
                        .compile(&p)
                        .unwrap();
                    assert_eq!(a.optimizations().len(), 1);
                }
            }
        }
        for start in [0, 1, 13, 31] {
            for mask in [255, 0x7fffffff, -1] {
                compare(&[
                    ins(class | 0x70, 0, 0, 0, start),
                    ins(class | 0x50, 0, 0, 0, mask),
                    end(),
                ]);
            }
        }
        for shift in 0..4 {
            compare(&[
                ins(0xb7, 1, 0, 0, -17),
                ins(class | 0x60, 0, 0, 0, shift),
                ins(class | 8, 0, 1, 0, 0),
                end(),
            ]);
        }
        compare(&[
            ins(class, 0, 0, 0, 1000),
            ins(class, 0, 0, 0, 1000),
            ins(class, 0, 0, 0, 1000),
            end(),
        ]);
    }
    for offset in [0, 8, 16, 64, 65] {
        let mut p = vec![];
        for i in 0..8 {
            p.extend([
                ins(0x79, 1, 10, i * 8, 0),
                ins(0x7b, 10, 1, offset + i * 8, 0),
            ]);
        }
        p.push(end());
        compare(&p);
    }
}
#[test]
fn invalid_bpf_and_prefetch_fallback() {
    for target in [NativeTarget::Arm64, NativeTarget::RiscV64] {
        let c = EbpfNativeCompiler::new(target).with_policy(NativeOpPolicy::all());
        for p in [
            vec![],
            vec![ins(0x85, 0, 0, 0, 0), end()],
            vec![ins(0x79, 0, 0, 0, 0), end()],
            vec![ins(0xbf, 0, 10, 0, 0), end()],
            vec![ins(0xc7, 0, 0, 0, 64), end()],
            vec![ins(0x15, 0, 0, -1, 0), end()],
            vec![end(), end()],
        ] {
            assert!(c.compile(&p).is_err());
        }
        let a = c
            .compile_with_prefetch_hints(&[ins(5, 0, 0, 0, 0), end()], &[(0, 127)])
            .unwrap();
        assert_eq!(a.required_memory(), 128);
        assert_eq!(
            a.optimizations()
                .iter()
                .any(|o| o.kind == NativeOpKind::Prefetch),
            target == NativeTarget::Arm64
        );
        if NativeTarget::host() == Some(target) {
            assert_eq!(
                a.prepare()
                    .unwrap()
                    .execute_with_memory(42, &mut [0; 128])
                    .unwrap(),
                42
            );
        }
    }
}

// Execute the actual input machine code with the documented guest-register ABI.
// All source bytes passed here are fixed test fixtures, never untrusted inputs.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn original(source: &[u8], input: u64, memory: &mut [u8]) -> u64 {
    let mut w = vec![];
    #[cfg(target_arch = "aarch64")]
    {
        w.extend([0xd503245f, 0xa9bf7bf4, 0xaa0103f4]); // save x20/LR; buffer x1 -> x20
        for r in 1..9 {
            w.push(0xaa1f03e0 | r);
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        w.extend([0xff010113, 0x00813023, 0x00058413]); // save s0; buffer a1 -> s0
        for r in (11..18).chain([5]) {
            w.push(r << 7 | 0x13);
        }
    }
    let mut code = bytes(&w);
    code.extend_from_slice(&source[..source.len() - 4]);
    #[cfg(target_arch = "aarch64")]
    code.extend(bytes(&[0xa8c17bf4, 0xd65f03c0]));
    #[cfg(target_arch = "riscv64")]
    code.extend(bytes(&[0x00013403, 0x01010113, 0x00008067]));
    let mut map = memmap2::MmapMut::map_anon(code.len()).unwrap();
    map.copy_from_slice(&code);
    let map = map.make_exec().unwrap();
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            unsafe extern "C" {
                fn __clear_cache(a: *mut u8, b: *mut u8);
            }
            __clear_cache(
                map.as_ptr() as *mut u8,
                map.as_ptr().add(map.len()) as *mut u8,
            );
        }
        #[cfg(target_arch = "riscv64")]
        assert_eq!(
            libc::syscall(
                259 as libc::c_long,
                map.as_ptr(),
                map.as_ptr().add(map.len()),
                0
            ),
            0
        );
        let f: unsafe extern "C" fn(u64, *mut u8) -> u64 = std::mem::transmute(map.as_ptr());
        f(input, memory.as_mut_ptr())
    }
}
fn frontend_case(target: NativeTarget, words: &[u32]) {
    let source = bytes(words);
    let p = match target {
        NativeTarget::Arm64 => Arm64EbpfCompiler::new().compile(&source).unwrap(),
        NativeTarget::RiscV64 => RiscV64EbpfCompiler::new().compile(&source).unwrap(),
    };
    assert_eq!(p.instructions().len(), p.source_offsets().len());
    compare(p.instructions());
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    if NativeTarget::host() == Some(target) {
        for x in [0, 1, u64::MAX, 0x80000000, 0x123456789abcdef0] {
            let mut m: Vec<u8> = (0..256).map(|i| (i * 37 + 11) as u8).collect();
            let mut expected_m = m.clone();
            let expected = run(p.instructions(), x, &mut expected_m);
            let actual = original(&source, x, &mut m);
            assert_eq!(
                actual, expected,
                "original {target:?}, source={words:x?}, input={x:x}"
            );
            assert_eq!(m, expected_m);
        }
    }
}
#[test]
fn arm_frontend_original_machine_code() {
    let t = NativeTarget::Arm64;
    frontend_case(t, &[0xd2800500, 0x91000800, 0xd65f03c0]);
    // MOVZ/MOVK/MOVN at both widths, including the sign bit and upper chunks.
    frontend_case(
        t,
        &[0xd2f12340, 0xf2b579a0, 0x92800001, 0xcb000020, 0xd65f03c0],
    );
    frontend_case(t, &[0x52bffff0 - 16, 0x12800001, 0x4b000020, 0xd65f03c0]);
    // True 3-address noncommutative alias: sub x0,x1,x0.
    frontend_case(t, &[0xd28000e1, 0xcb000020, 0xd65f03c0]);
    for wide in [false, true] {
        let sf = if wide { 1 << 31 } else { 0 };
        let ub = if wide { 0xd3400000 } else { 0x53000000 };
        let width = if wide { 64 } else { 32 };
        for shift in [1, 13, 31] {
            frontend_case(
                t,
                &[
                    sf | 0x2a0003e1,
                    ub | ((width - shift) << 16) | ((width - 1 - shift) << 10),
                    ub | ((width - shift) << 16) | ((width - 1) << 10) | 1 << 5 | 1,
                    sf | 0x2a010000,
                    0xd65f03c0,
                ],
            );
        }
    }
    frontend_case(
        t,
        &[0xf9400280, 0xf9002680, 0x39400681, 0x8b010000, 0xd65f03c0],
    );
}
fn rv_i(op: u32, f: u32, d: u32, s: u32, value: i32) -> u32 {
    ((value as u32 & 4095) << 20) | s << 15 | f << 12 | d << 7 | op
}
fn rv_r(op: u32, f7: u32, f: u32, d: u32, a: u32, b: u32) -> u32 {
    f7 << 25 | b << 20 | a << 15 | f << 12 | d << 7 | op
}
#[test]
fn riscv_frontend_original_machine_code() {
    let t = NativeTarget::RiscV64;
    let ret = 0x00008067;
    frontend_case(t, &[0x02800513, 0x00250513, ret]);
    for op in [0x13, 0x1b] {
        for val in [-2048, -1, 0, 2047] {
            frontend_case(t, &[rv_i(op, 0, 10, 10, val), ret]);
        }
    }
    for opcode in [0x33, 0x3b] {
        for (f7, f3) in [(0, 0), (0x20, 0), (0, 1), (0, 5), (0x20, 5)] {
            frontend_case(
                t,
                &[
                    rv_i(0x13, 0, 11, 0, 13),
                    rv_r(opcode, f7, f3, 10, 11, 10),
                    ret,
                ],
            );
            frontend_case(
                t,
                &[
                    rv_i(0x13, 0, 0, 10, 17),
                    rv_r(opcode, f7, f3, 10, 0, 10),
                    ret,
                ],
            );
        }
    }
    for top in [0x7ffff, 0x80000, 0xfffff] {
        frontend_case(t, &[top << 12 | 10 << 7 | 0x37, ret]);
    }
    for f in 0..7 {
        frontend_case(t, &[rv_i(3, f, 10, 8, 1), ret]);
    }
    frontend_case(
        t,
        &[
            rv_i(3, 3, 10, 8, 0),
            10 << 20 | 8 << 15 | 3 << 12 | 16 << 7 | 0x23,
            ret,
        ],
    );
    frontend_case(
        t,
        &[
            rv_i(0x13, 0, 11, 10, 0),
            rv_i(0x13, 1, 10, 10, 13),
            rv_i(0x13, 5, 11, 11, 51),
            rv_r(0x33, 0, 6, 10, 10, 11),
            ret,
        ],
    );
}
#[test]
fn frontends_reject_unsupported_and_truncated_code() {
    for code in [
        vec![],
        vec![1],
        bytes(&[0xd65f03c0, 0xd65f03c0]),
        bytes(&[0xd2800510, 0xd65f03c0]),
        bytes(&[0x910003e0, 0xd65f03c0]),
    ] {
        assert!(Arm64EbpfCompiler::new().compile(&code).is_err());
    }
    for code in [
        vec![],
        vec![1, 0],
        bytes(&[0x00008067, 0x00008067]),
        bytes(&[0x00110113, 0x00008067]),
        bytes(&[0x00000073, 0x00008067]),
    ] {
        assert!(RiscV64EbpfCompiler::new().compile(&code).is_err());
    }
}

#[test]
fn word_sign_extension_fusions() {
    for op in [0, 0x10, 0x40, 0x50, 0x60, 0x70, 0xa0, 0xb0, 0xc0] {
        for reg in [false, true] {
            for dst in [0, 5, 9] {
                let p = [
                    ins(0xbf, dst, 0, 0, 0),
                    ins(0xb7, 1, 0, 0, 13),
                    ins(
                        4 | op | if reg { 8 } else { 0 },
                        dst,
                        if reg { 1 } else { 0 },
                        0,
                        if reg { 0 } else { 17 },
                    ),
                    ins(0x67, dst, 0, 0, 32),
                    ins(0xc7, dst, 0, 0, 32),
                    ins(0xbf, 0, dst, 0, 0),
                    end(),
                ];
                compare(&p);
                let a = EbpfNativeCompiler::new(NativeTarget::RiscV64)
                    .with_native_ops(true)
                    .compile(&p)
                    .unwrap();
                assert!(a
                    .optimizations()
                    .iter()
                    .any(|x| x.kind == NativeOpKind::SignExtend));
            }
        }
    }
}
