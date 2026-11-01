#[cfg(all(feature = "ebpf", target_arch = "x86_64", target_os = "linux"))]
#[path = "support/ebpf_reference.rs"]
mod reference;
#[cfg(all(feature = "ebpf", target_arch = "x86_64", target_os = "linux"))]
mod bench {
    use super::reference;
    use doublejit_vm::backend::{EbpfX86Compiler, EbpfX86Runtime, NativeOpPolicy, X86EbpfCompiler};
    use doublejit_vm::X86Mode;
    use std::{hint::black_box, time::Instant};
    fn memory(code: &mut Vec<u8>, op: u8, reg: u8, offset: i32) {
        code.extend_from_slice(&[0x48, op, 0x85 | (reg << 3)]);
        code.extend_from_slice(&offset.to_le_bytes());
    }
    fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
        let mut result = vec![];
        for name in [
            "rotate-right",
            "extract",
            "lea",
            "select",
            "select-random",
            "endian-load",
            "bulk-copy",
            "prefetch",
            "alu-fold",
        ] {
            let mut c = vec![0x48, 0x89, 0xc6]; // RSI = original scalar input
            for round in 0..128 {
                match name {
                    "rotate-right" => c.extend_from_slice(&[
                        0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe8, 13, 0x48, 0xc1, 0xe1, 51, 0x48, 0x09,
                        0xc8, 0x48, 0x83, 0xc0, 17,
                    ]),
                    "extract" => c.extend_from_slice(&[
                        0x48, 0xc1, 0xe8, 5, 0x48, 0x81, 0xe0, 0xff, 0x03, 0, 0, 0x48, 0x01, 0xf0,
                    ]),
                    "lea" => c.extend_from_slice(&[
                        0x48, 0xc1, 0xe0, 2, 0x48, 0x01, 0xf0, 0x48, 0x83, 0xc0, 17,
                    ]),
                    "select" => c.extend_from_slice(&[
                        0x48, 0x39, 0xf0, 0x76, 3, 0x48, 0x89, 0xf0, 0x48, 0x83, 0xc0, 17,
                    ]),
                    "select-random" => c.extend_from_slice(&[
                        0x48, 0x89, 0xc1, 0x48, 0xc1, 0xe1, 13, 0x48, 0x31, 0xc8, 0x48, 0x89, 0xc1,
                        0x48, 0xc1, 0xe9, 7, 0x48, 0x31, 0xc8, 0x48, 0x83, 0xf8, 0, 0x7d, 3, 0x48,
                        0x89, 0xc1, 0x48, 0x31, 0xca,
                    ]),
                    "endian-load" => {
                        memory(&mut c, 0x8b, 1, (round % 8) * 8);
                        c.extend_from_slice(&[0x48, 0x0f, 0xc9, 0x48, 0x01, 0xc8]);
                    }
                    "bulk-copy" => {
                        // One 64-byte region per round; fixed, disjoint intervals.
                        for i in 0..8 {
                            memory(&mut c, 0x8b, 1, i * 8);
                            memory(&mut c, 0x89, 1, 256 + i * 8);
                        }
                    }
                    "prefetch" => {
                        c.extend_from_slice(&[0x0f, 0x18, 0x8d]);
                        c.extend_from_slice(&(((round + 8) % 64) * 8_i32).to_le_bytes());
                        memory(&mut c, 0x8b, 1, (round % 64) * 8);
                        c.extend_from_slice(&[0x48, 0x01, 0xc8]);
                    }
                    "alu-fold" => c.extend_from_slice(&[0x48, 0x83, 0xc0, 17]),
                    _ => unreachable!(),
                }
            }
            if name == "bulk-copy" {
                memory(&mut c, 0x8b, 0, 256);
            }
            if name == "select-random" {
                c.extend_from_slice(&[0x48, 0x89, 0xd0]);
            }
            c.push(0xc3);
            result.push((name, c));
        }
        result
    }
    fn initial_memory() -> Vec<u8> {
        (0..1024).map(|i| ((i * 37 + 11) & 255) as u8).collect()
    }
    fn measure(rt: &EbpfX86Runtime, n: usize) -> (f64, u64, Vec<u8>) {
        let mut m = initial_memory();
        let mut x = 0x1234_5678_9abc_def0_u64;
        let mut checksum = 0_u64;
        let start = Instant::now();
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            checksum = checksum.wrapping_add(black_box(
                rt.execute_with_memory(black_box(x), &mut m).unwrap(),
            ));
        }
        (start.elapsed().as_nanos() as f64 / n as f64, checksum, m)
    }
    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = std::env::args().skip(1);
        let n: usize = args
            .next()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(100000);
        let samples: usize = args.next().map(|s| s.parse()).transpose()?.unwrap_or(9);
        let output = args
            .next()
            .unwrap_or_else(|| "target/all-native-ops".into());
        if n == 0 || !(3..=101).contains(&samples) || samples % 2 == 0 || args.next().is_some() {
            return Err(
                "usage: x86-native-ops-bench [iterations>0] [odd samples 3..101] [directory]"
                    .into(),
            );
        }
        let directory = std::path::Path::new(&output);
        std::fs::create_dir_all(directory)?;
        println!(
            "128 rounds/call; {n} calls/sample; {samples} samples; release={}; BMI1={}; MOVBE={}",
            !cfg!(debug_assertions),
            std::is_x86_feature_detected!("bmi1"),
            std::is_x86_feature_detected!("movbe")
        );
        let mut summary=String::from("workload,plain_ns,optimized_ns,speedup,plain_bytes,optimized_bytes,sites,frontend_us,plain_setup_us,optimized_setup_us,default_ns,default_speedup,default_setup_us,checksum\n");
        let mut raw = String::from("workload,sample,path,ns,checksum\n");
        for (name, source) in fixtures() {
            let t = Instant::now();
            let bpf = X86EbpfCompiler::new(X86Mode::X86_64).compile(&source)?;
            let frontend = t.elapsed().as_secs_f64() * 1e6;
            let t = Instant::now();
            let plain = EbpfX86Compiler::new().compile_program(&bpf)?;
            let plain_rt = plain.prepare()?;
            let plain_setup = t.elapsed().as_secs_f64() * 1e6;
            let t = Instant::now();
            let optimized = EbpfX86Compiler::new()
                .with_policy(NativeOpPolicy::all())
                .compile_program(&bpf)?;
            let opt_rt = optimized.prepare()?;
            let opt_setup = t.elapsed().as_secs_f64() * 1e6;
            let t = Instant::now();
            let recommended = EbpfX86Compiler::new()
                .with_native_ops(true)
                .compile_program(&bpf)?;
            let recommended_rt = recommended.prepare()?;
            let recommended_setup = t.elapsed().as_secs_f64() * 1e6;
            for x in [0, 1, u64::MAX, 1 << 63, 0x123456789abcdef0] {
                let mut expected_m = initial_memory();
                let expected = reference::run(bpf.instructions(), x, &mut expected_m);
                for rt in [&plain_rt, &opt_rt, &recommended_rt] {
                    let mut m = initial_memory();
                    assert_eq!(rt.execute_with_memory(x, &mut m)?, expected, "{name}");
                    assert_eq!(m, expected_m);
                }
            }
            for rt in [&plain_rt, &opt_rt, &recommended_rt] {
                black_box(measure(rt, 2000));
            }
            let mut times = [vec![], vec![], vec![]];
            let mut checksum = 0;
            for sample in 0..samples {
                let mut outcomes = [None, None, None];
                for step in 0..3 {
                    let index = (sample + step) % 3;
                    let (ns, sum, m) = measure([&plain_rt, &opt_rt, &recommended_rt][index], n);
                    times[index].push(ns);
                    raw.push_str(&format!("{name},{sample},{index},{ns:.4},{sum:016x}\n"));
                    outcomes[index] = Some((sum, m));
                    checksum = sum;
                }
                assert_eq!(outcomes[0], outcomes[1], "{name}: timed outputs differ");
                assert_eq!(outcomes[0], outcomes[2], "{name}: default policy differs");
            }
            for v in &mut times {
                v.sort_by(f64::total_cmp);
            }
            let base = times[0][samples / 2];
            let opt = times[1][samples / 2];
            let speedup = base / opt;
            let recommended_ns = times[2][samples / 2];
            let recommended_speedup = base / recommended_ns;
            println!(
                "{name:14} {base:9.2} -> {opt:9.2} ns  {speedup:6.3}x all; {recommended_speedup:6.3}x default; sites={}",
                optimized.optimizations().len()
            );
            summary.push_str(&format!("{name},{base:.4},{opt:.4},{speedup:.4},{},{},{},{frontend:.3},{plain_setup:.3},{opt_setup:.3},{recommended_ns:.4},{recommended_speedup:.4},{recommended_setup:.3},{checksum:016x}\n",plain.machine_code().len(),optimized.machine_code().len(),optimized.optimizations().len()));
            std::fs::write(directory.join(format!("{name}.input.bin")), source)?;
            std::fs::write(directory.join(format!("{name}.ebpf")), bpf.to_bytes())?;
            std::fs::write(
                directory.join(format!("{name}.plain.bin")),
                plain.machine_code(),
            )?;
            std::fs::write(
                directory.join(format!("{name}.optimized.bin")),
                optimized.machine_code(),
            )?;
            std::fs::write(
                directory.join(format!("{name}.default.bin")),
                recommended.machine_code(),
            )?;
            std::fs::write(
                directory.join(format!("{name}.sites.txt")),
                format!("{:#?}\n", optimized.optimizations()),
            )?;
        }
        std::fs::write(directory.join("summary.csv"), summary)?;
        std::fs::write(directory.join("samples.csv"), raw)?;
        println!("Artifacts: {}", directory.display());
        Ok(())
    }
}
#[cfg(all(feature = "ebpf", target_arch = "x86_64", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    bench::main()
}
#[cfg(not(all(feature = "ebpf", target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("Requires --features ebpf on x86-64 Linux");
    std::process::exit(1);
}
