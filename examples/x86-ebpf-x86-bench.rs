//! Kops-inspired immediate-rotate recovery, measured against unchanged emitters.
#[cfg(all(feature = "ebpf", target_arch = "x86_64", target_os = "linux"))]
mod bench {
    use doublejit_vm::backend::{EbpfX86Compiler, X86EbpfCompiler};
    use doublejit_vm::X86Mode;
    use std::hint::black_box;
    use std::time::Instant;

    const ROUNDS: usize = 128;
    const ADD: u32 = 0x1357_9bdf;

    fn source(width: u32, rotate: bool) -> Vec<u8> {
        let mut code = Vec::new();
        for round in 0..ROUNDS {
            let count = [5, 13, 17, 23][round % 4];
            if rotate {
                for bytes in [
                    vec![0x89, 0xc1], // mov ecx/eax or rcx/rax
                    vec![0xc1, 0xe0, count],
                    vec![0xc1, 0xe9, width as u8 - count],
                    vec![0x09, 0xc8],
                ] {
                    if width == 64 {
                        code.push(0x48);
                    }
                    code.extend(bytes);
                }
            }
            if width == 64 {
                code.push(0x48);
            }
            code.extend_from_slice(&[0x81, 0xc0]);
            code.extend_from_slice(&ADD.to_le_bytes());
        }
        code.push(0xc3);
        code
    }

    #[inline(never)]
    fn reference64(mut value: u64) -> u64 {
        for _ in 0..ROUNDS / 4 {
            value = value.rotate_left(5).wrapping_add(ADD as u64);
            value = value.rotate_left(13).wrapping_add(ADD as u64);
            value = value.rotate_left(17).wrapping_add(ADD as u64);
            value = value.rotate_left(23).wrapping_add(ADD as u64);
        }
        value
    }

    #[inline(never)]
    fn reference32(value: u64) -> u64 {
        let mut value = value as u32;
        for _ in 0..ROUNDS / 4 {
            value = value.rotate_left(5).wrapping_add(ADD);
            value = value.rotate_left(13).wrapping_add(ADD);
            value = value.rotate_left(17).wrapping_add(ADD);
            value = value.rotate_left(23).wrapping_add(ADD);
        }
        value as u64
    }

    #[inline(never)]
    fn reference_add(value: u64) -> u64 {
        value.wrapping_add((ADD as u64) * ROUNDS as u64)
    }

    fn measure(run: &dyn Fn(u64) -> u64, iterations: usize) -> (f64, u64) {
        let mut value = 0x0123_4567_89ab_cdef_u64;
        let start = Instant::now();
        for i in 0..iterations {
            value = black_box(run(black_box(value.wrapping_add(i as u64))));
        }
        (start.elapsed().as_nanos() as f64 / iterations as f64, value)
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = std::env::args().skip(1);
        let iterations: usize = args
            .next()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(200_000);
        let samples: usize = args.next().map(|s| s.parse()).transpose()?.unwrap_or(9);
        let directory = args.next().unwrap_or_else(|| "target/kops-poc".into());
        if iterations == 0
            || !(3..=101).contains(&samples)
            || samples % 2 == 0
            || args.next().is_some()
        {
            return Err(
                "usage: x86-ebpf-x86-bench [iterations>0] [odd samples:3..101] [output-directory]"
                    .into(),
            );
        }
        std::fs::create_dir_all(&directory)?;
        let directory = std::path::Path::new(&directory);
        println!("Userspace Kops-inspired PoC; {ROUNDS} rounds/call, {iterations} calls/sample, {samples} samples");
        println!(
            "Runtime inputs; warmup; interleaved paths; median hot ns/call; compilation excluded."
        );
        let mut csv = String::from("workload,path,median_ns,min_ns,max_ns,code_bytes,fusions,compile_prepare_us,frontend_us,speedup_vs_plain,speedup_vs_original,checksum\n");
        let mut raw = String::from("workload,sample,path,ns_per_call,checksum\n");
        for (name, width, rotate, reference) in [
            ("rotate64", 64, true, reference64 as fn(u64) -> u64),
            ("rotate32", 32, true, reference32 as fn(u64) -> u64),
            ("add64-control", 64, false, reference_add as fn(u64) -> u64),
        ] {
            let input = source(width, rotate);
            let start = Instant::now();
            let bpf = X86EbpfCompiler::new(if width == 64 {
                X86Mode::X86_64
            } else {
                X86Mode::X86
            })
            .compile(&input)?;
            let frontend_us = start.elapsed().as_secs_f64() * 1e6;
            let start = Instant::now();
            let plain = EbpfX86Compiler::new().compile(bpf.instructions())?;
            let plain_runtime = plain.prepare()?;
            let plain_us = start.elapsed().as_secs_f64() * 1e6;
            let start = Instant::now();
            let optimized = EbpfX86Compiler::new()
                .with_native_ops(true)
                .compile(bpf.instructions())?;
            let optimized_runtime = optimized.prepare()?;
            let optimized_us = start.elapsed().as_secs_f64() * 1e6;
            assert_eq!(optimized.fusions().len(), if rotate { ROUNDS } else { 0 });

            // Original *expanded* x86 source, executed directly with the same
            // r0=argument convention. This private fixture only touches RAX/RCX.
            let start = Instant::now();
            let mut original_code = vec![0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x89, 0xf8];
            original_code.extend_from_slice(&input);
            let mut original = memmap2::MmapMut::map_anon(original_code.len())?;
            original.copy_from_slice(&original_code);
            let original = original.make_exec()?;
            let original_us = start.elapsed().as_secs_f64() * 1e6;
            // SAFETY: source() emits only fixed register arithmetic and RET;
            // our wrapper initializes RAX, preserves SysV callee-saved registers,
            // and the immutable executable mapping outlives every call below.
            let original_fn: unsafe extern "C" fn(u64) -> u64 =
                unsafe { std::mem::transmute(original.as_ptr()) };
            let original_run = |value| unsafe { original_fn(value) };
            let plain_run = |value| plain_runtime.execute_with_input(value).unwrap();
            let optimized_run = |value| optimized_runtime.execute_with_input(value).unwrap();
            let paths: [(&str, &dyn Fn(u64) -> u64); 4] = [
                ("original-x86", &original_run),
                ("plain-jit", &plain_run),
                ("native-ops", &optimized_run),
                ("rust-reference", &reference),
            ];
            for value in [0, 1, u64::MAX, 0x8000_0000_8000_0000, 0x1234_5678_90ab_cdef] {
                for (path, run) in paths {
                    assert_eq!(run(value), reference(value), "{name}: {path}");
                }
            }
            for (_, run) in paths {
                black_box(measure(run, 2000));
            }
            let mut times: [Vec<f64>; 4] = std::array::from_fn(|_| Vec::new());
            let mut expected_checksum = None;
            for sample in 0..samples {
                for step in 0..4 {
                    let index = (sample + step) % 4;
                    let (path, run) = paths[index];
                    let (ns, checksum) = measure(run, iterations);
                    assert_eq!(
                        *expected_checksum.get_or_insert(checksum),
                        checksum,
                        "{name}: {path}"
                    );
                    times[index].push(ns);
                    raw.push_str(&format!("{name},{sample},{path},{ns:.4},{checksum:016x}\n"));
                }
            }
            for values in &mut times {
                values.sort_by(f64::total_cmp);
            }
            let medians: Vec<f64> = times.iter().map(|v| v[samples / 2]).collect();
            let sizes = [
                original_code.len(),
                plain.machine_code().len(),
                optimized.machine_code().len(),
                0,
            ];
            let costs = [original_us, plain_us, optimized_us, 0.0];
            for (index, (path, _)) in paths.iter().enumerate() {
                let ns = medians[index];
                let speedup = medians[1] / ns;
                let vs_original = medians[0] / ns;
                println!("{name:14} {path:15} {ns:9.2} ns/call  plain/{path}: {speedup:.3}x  original/{path}: {vs_original:.3}x");
                csv.push_str(&format!("{name},{path},{ns:.4},{:.4},{:.4},{},{},{:.3},{frontend_us:.3},{speedup:.4},{vs_original:.4},{:016x}\n",
                    times[index][0], times[index][samples-1], sizes[index],
                    if index == 2 { optimized.fusions().len() } else { 0 }, costs[index], expected_checksum.unwrap()));
            }
            std::fs::write(directory.join(format!("{name}.input.bin")), &input)?;
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
                directory.join(format!("{name}.fusions.txt")),
                format!("{:#?}\n", optimized.fusions()),
            )?;
        }
        std::fs::write(directory.join("summary.csv"), csv)?;
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
    eprintln!(
        "Requires x86-64 Linux: cargo run --release --features ebpf --example x86-ebpf-x86-bench"
    );
    std::process::exit(1);
}
