#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::{
        Arm64EbpfCompiler, EbpfNativeCompiler, NativeTarget, RiscV64EbpfCompiler,
    };
    use std::{hint::black_box, time::Instant};
    let mut args = std::env::args().skip(1);
    let target =
        match args.next().as_deref() {
            Some("arm64") => NativeTarget::Arm64,
            Some("riscv64") => NativeTarget::RiscV64,
            _ => return Err(
                "usage: risc-native-bench arm64|riscv64 [directory] [timed-iterations, default 0]"
                    .into(),
            ),
        };
    let directory = args
        .next()
        .unwrap_or_else(|| "target/risc-native-bench".into());
    let n: usize = args.next().map(|s| s.parse()).transpose()?.unwrap_or(0);
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    if n > 0 && NativeTarget::host() != Some(target) {
        return Err("timing requires a matching target host".into());
    }
    std::fs::create_dir_all(&directory)?;
    let directory = std::path::Path::new(&directory);
    let mut csv=String::from("target,workload,source_bytes,bpf_instructions,plain_bytes,optimized_bytes,sites,execution_verified,plain_ns,optimized_ns\n");
    let mut raw = String::from("workload,sample,path,ns,checksum\n");
    for name in ["rotate64", "add64", "word32"] {
        let mut words = vec![];
        for _ in 0..128 {
            match (target, name) {
                (NativeTarget::Arm64, "rotate64") => {
                    words.extend([0xaa0003e1, 0xd373c800, 0xd373fc21, 0xaa010000, 0x91004400])
                }
                (NativeTarget::Arm64, "add64") => words.push(0x91004400),
                (NativeTarget::Arm64, _) => words.push(0x11004400), // ADD W0,W0,17: zero extension
                (NativeTarget::RiscV64, "rotate64") => {
                    words.extend([0x00050593, 0x00d51513, 0x0335d593, 0x00b56533, 0x01150513])
                }
                (NativeTarget::RiscV64, "add64") => words.push(0x01150513),
                (NativeTarget::RiscV64, _) => words.push(0x0115051b), // ADDIW a0,a0,17: sign extension
            }
        }
        words.push(if target == NativeTarget::Arm64 {
            0xd65f03c0
        } else {
            0x00008067
        });
        let source: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let bpf = match target {
            NativeTarget::Arm64 => Arm64EbpfCompiler::new().compile(&source)?,
            NativeTarget::RiscV64 => RiscV64EbpfCompiler::new().compile(&source)?,
        };
        let plain = EbpfNativeCompiler::new(target).compile(bpf.instructions())?;
        let optimized = EbpfNativeCompiler::new(target)
            .with_native_ops(true)
            .compile(bpf.instructions())?;
        let mut timings = [String::new(), String::new()];
        let verified = NativeTarget::host() == Some(target);
        if verified {
            let a = plain.prepare()?;
            let b = optimized.prepare()?;
            for input in [0, 1, u64::MAX, 0x80000000, 0x123456789abcdef0] {
                let mut expected = input;
                for _ in 0..128 {
                    expected = match name {
                        "rotate64" => expected.rotate_left(13).wrapping_add(17),
                        "add64" => expected.wrapping_add(17),
                        _ => {
                            let v = (expected as u32).wrapping_add(17);
                            if target == NativeTarget::Arm64 {
                                v as u64
                            } else {
                                v as i32 as i64 as u64
                            }
                        }
                    };
                }
                assert_eq!(a.execute_with_input(input)?, expected);
                assert_eq!(b.execute_with_input(input)?, expected);
            }
            if n > 0 {
                println!("Timing enabled: report as hardware performance only when run on physical {target:?}, not QEMU.");
                let measure = |rt: &doublejit_vm::backend::EbpfNativeRuntime, count: usize| {
                    let mut input = 0x123456789abcdef0_u64;
                    let start = Instant::now();
                    for i in 0..count {
                        input = black_box(
                            rt.execute_with_input(black_box(input.wrapping_add(i as u64)))
                                .unwrap(),
                        );
                    }
                    (start.elapsed().as_nanos() as f64 / count as f64, input)
                };
                for rt in [&a, &b] {
                    black_box(measure(rt, 2000));
                }
                let mut data = [vec![], vec![]];
                for sample in 0..9 {
                    let mut sums = [0, 0];
                    for step in 0..2 {
                        let index = (sample + step) % 2;
                        let (ns, sum) = measure([&a, &b][index], n);
                        data[index].push(ns);
                        sums[index] = sum;
                        raw.push_str(&format!("{name},{sample},{index},{ns:.4},{sum:016x}\n"));
                    }
                    assert_eq!(sums[0], sums[1]);
                }
                for i in 0..2 {
                    data[i].sort_by(f64::total_cmp);
                    timings[i] = format!("{:.4}", data[i][4]);
                }
            }
        }
        println!(
            "{target:?} {name}: native {} -> {} bytes, {} rewrites, executed={verified}",
            plain.machine_code().len(),
            optimized.machine_code().len(),
            optimized.optimizations().len()
        );
        csv.push_str(&format!(
            "{target:?},{name},{},{},{},{},{},{verified},{},{}\n",
            source.len(),
            bpf.instructions().len(),
            plain.machine_code().len(),
            optimized.machine_code().len(),
            optimized.optimizations().len(),
            timings[0],
            timings[1]
        ));
        for (suffix, code) in [
            ("source", source.as_slice()),
            ("ebpf", bpf.to_bytes().as_slice()),
            ("plain", plain.machine_code()),
            ("optimized", optimized.machine_code()),
        ] {
            std::fs::write(directory.join(format!("{name}.{suffix}.bin")), code)?;
        }
    }
    std::fs::write(directory.join("summary.csv"), csv)?;
    std::fs::write(directory.join("samples.csv"), raw)?;
    Ok(())
}
#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!("Enable --features ebpf");
    std::process::exit(1);
}
