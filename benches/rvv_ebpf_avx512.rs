#![allow(clippy::needless_range_loop)]

#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    bench::main()
}

#[cfg(not(feature = "ebpf"))]
fn main() {
    println!(
        "Enable the eBPF benchmark path with: cargo bench --features ebpf --bench rvv_ebpf_avx512"
    );
}

#[cfg(feature = "ebpf")]
mod bench {
    use doublejit_vm::frontend::instruction::{
        Imm32, Instr, Instruction, RV32Instr, RV64Instr, Rd, Reg, Rs1, Rs2, Rs3, Xx, RV32I, RVV, VM,
    };
    use doublejit_vm::middleend::{EbpfCompiler, WasmEmitter};
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use wasmer::sys::EngineBuilder;
    use wasmer::{imports, Engine, Instance, Module, Store, Value};
    use wasmer_compiler_singlepass::Singlepass;

    const RVV_LANES_PER_CHUNK: usize = 64;

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let lanes = round_up(env_usize("BENCH_LANES", 1 << 20), RVV_LANES_PER_CHUNK);
        let reps = env_usize("BENCH_REPS", 64);
        let runs = env_usize("BENCH_RUNS", 5).max(1);
        let ebpf_insns = env_usize("BENCH_EBPF_INSNS", 262_144);
        let out_dir = PathBuf::from(
            std::env::var("BENCH_OUT_DIR").unwrap_or_else(|_| "bench-results".to_string()),
        );

        fs::create_dir_all(&out_dir)?;

        let avx512 = cfg!(target_arch = "x86_64") && std::is_x86_feature_detected!("avx512f");
        println!("RVV/eBPF/AVX512 cargo bench");
        println!("  lanes: {lanes}");
        println!("  reps: {reps}");
        println!("  runs: {runs}");
        println!("  ebpf source instructions: {ebpf_insns}");
        println!("  x86 avx512f detected: {avx512}");

        let (input_a, input_b) = make_inputs(lanes);
        let mut rows = Vec::new();

        rows.push(bench_rvv_decode(lanes, reps, runs)?);
        rows.push(bench_rvv_wasm(lanes, reps, runs, &input_a, &input_b)?);
        rows.push(bench_ebpf_compile_verify(ebpf_insns, runs)?);
        rows.push(check_rvv_to_ebpf_status());

        if avx512 {
            rows.push(bench_avx512(lanes, reps, runs, &input_a, &input_b)?);
        } else {
            rows.push(BenchRow::skipped(
                "x64_avx512_execute",
                "host does not report avx512f",
            ));
        }

        write_results(&out_dir, lanes, reps, runs, ebpf_insns, avx512, &rows)?;
        print_results(&rows);

        Ok(())
    }

    fn bench_rvv_decode(
        lanes: usize,
        reps: usize,
        runs: usize,
    ) -> Result<BenchRow, Box<dyn std::error::Error>> {
        let opcodes: [[u8; 4]; 5] = [
            0x0d0170d7u32.to_le_bytes(), // vsetvli x1, x2, e32, m1, ta, ma
            0x02016087u32.to_le_bytes(), // vle32.v v1, (x2)
            0x02026187u32.to_le_bytes(), // vle32.v v3, (x4)
            0x022180d7u32.to_le_bytes(), // vadd.vv v1, v2, v3
            0x020261a7u32.to_le_bytes(), // vse32.v v3, (x4)
        ];
        let iterations = (lanes / RVV_LANES_PER_CHUNK).saturating_mul(reps);
        let mut decoded = 0usize;
        let samples = time_runs(runs, || {
            let mut local = 0usize;
            for _ in 0..iterations {
                for opcode in &opcodes {
                    let instr = Instruction::parse(opcode);
                    std::hint::black_box(instr);
                    local += 1;
                }
            }
            decoded = local;
        });
        let median = median_duration(&samples);
        Ok(BenchRow {
            name: "rvv_frontend_decode".to_string(),
            kind: "compile_frontend".to_string(),
            status: "ok".to_string(),
            lanes,
            reps,
            work_items: decoded,
            median_ns: median.as_nanos(),
            ns_per_item: ns_per(median, decoded),
            giga_items_per_s: giga_per_s(median, decoded),
            checksum: None,
            note: "decodes vsetvli/vle32/vadd/vse32 instruction words".to_string(),
        })
    }

    fn bench_rvv_wasm(
        lanes: usize,
        reps: usize,
        runs: usize,
        input_a: &[i32],
        input_b: &[i32],
    ) -> Result<BenchRow, Box<dyn std::error::Error>> {
        let chunks = lanes / RVV_LANES_PER_CHUNK;
        let array_bytes = lanes * std::mem::size_of::<i32>();
        let base_a = 0usize;
        let base_b = base_a + array_bytes;
        let base_c = base_b + array_bytes;
        let vreg_base = round_up(base_c + array_bytes, 65_536);
        let memory_bytes = vreg_base + 32 * 256 + 65_536;
        let memory_pages = round_up(memory_bytes, 65_536) / 65_536;
        let wat = rvv_wasm_module(memory_pages, base_b, base_c, vreg_base)?;

        let compiler = Singlepass::new();
        let engine: Engine = EngineBuilder::new(compiler).into();
        let mut store = Store::new(engine);
        let wasm = wasmer::wat2wasm(wat.as_bytes())?;
        let module = Module::new(&store, wasm)?;
        let instance = Instance::new(&mut store, &module, &imports! {})?;
        let memory = instance.exports.get_memory("memory")?.clone();
        let bench = instance.exports.get_function("bench")?.clone();

        let mut checksum = 0i64;
        let samples = time_runs(runs, || {
            {
                let view = memory.view(&mut store);
                unsafe {
                    let ptr = view.data_ptr();
                    std::ptr::copy_nonoverlapping(
                        input_a.as_ptr().cast::<u8>(),
                        ptr.add(base_a),
                        array_bytes,
                    );
                    std::ptr::copy_nonoverlapping(
                        input_b.as_ptr().cast::<u8>(),
                        ptr.add(base_b),
                        array_bytes,
                    );
                    std::ptr::write_bytes(ptr.add(base_c), 0, array_bytes);
                }
            }
            bench
                .call(
                    &mut store,
                    &[Value::I32(chunks as i32), Value::I32(reps as i32)],
                )
                .expect("RVV/WASM bench call failed");
            let mut out = vec![0i32; lanes];
            {
                let view = memory.view(&store);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        view.data_ptr().add(base_c).cast::<i32>(),
                        out.as_mut_ptr(),
                        lanes,
                    );
                }
            }
            checksum = checksum_i32(&out);
            std::hint::black_box(checksum);
        });

        let median = median_duration(&samples);
        let items = lanes.saturating_mul(reps);
        Ok(BenchRow {
            name: "rvv_wasm_execute".to_string(),
            kind: "runtime".to_string(),
            status: "ok".to_string(),
            lanes,
            reps,
            work_items: items,
            median_ns: median.as_nanos(),
            ns_per_item: ns_per(median, items),
            giga_items_per_s: giga_per_s(median, items),
            checksum: Some(checksum),
            note: "actual WasmEmitter RVV backend via Wasmer Singlepass; current backend lowers to lane loops".to_string(),
        })
    }

    fn bench_ebpf_compile_verify(
        source_instructions: usize,
        runs: usize,
    ) -> Result<BenchRow, Box<dyn std::error::Error>> {
        let entries = scalar_ebpf_entries(source_instructions);
        let compiler = EbpfCompiler::new();
        let mut target_instructions = 0usize;
        let samples = time_runs(runs, || {
            let program = compiler
                .compile_entries(&entries)
                .expect("scalar eBPF compile failed");
            let report = program
                .verify_compile_time()
                .expect("scalar eBPF verification failed");
            target_instructions = report.compilation.target_instructions;
            std::hint::black_box(target_instructions);
        });
        let median = median_duration(&samples);
        Ok(BenchRow {
            name: "ebpf_compile_verify_scalar".to_string(),
            kind: "compile_verify".to_string(),
            status: "ok".to_string(),
            lanes: 0,
            reps: 0,
            work_items: source_instructions,
            median_ns: median.as_nanos(),
            ns_per_item: ns_per(median, source_instructions),
            giga_items_per_s: giga_per_s(median, source_instructions),
            checksum: None,
            note: format!(
                "one-to-one scalar RISC-V->eBPF compile+verification; target_insns={target_instructions}"
            ),
        })
    }

    fn check_rvv_to_ebpf_status() -> BenchRow {
        let entries = [(
            0x1000,
            Instr::RV64(RV64Instr::RV64V(RVV::VADD_VV(
                Rd(vreg(1)),
                Rs1(vreg(1)),
                Rs2(vreg(2)),
                VM(true),
            ))),
        )];
        let status = match EbpfCompiler::new().compile_entries(&entries) {
            Ok(program) => {
                let report = program
                    .verify_compile_time()
                    .expect("RVV helper-call eBPF verification failed");
                let proof = &program.proof_obligations()[0];
                format!(
                    "ok: one_to_one={} proof_target_len={} target_insns={} kernel_jumps={} kernel_exits={} proof_rule={}",
                    report.compilation.one_to_one,
                    proof.target_len,
                    report.compilation.target_instructions,
                    report.kernel.jump_instructions,
                    report.kernel.exit_instructions,
                    proof.rule
                )
            }
            Err(err) => format!("unsupported: {err}"),
        };
        BenchRow {
            name: "rvv_to_ebpf_status".to_string(),
            kind: "capability".to_string(),
            status,
            lanes: 0,
            reps: 0,
            work_items: 1,
            median_ns: 0,
            ns_per_item: 0.0,
            giga_items_per_s: 0.0,
            checksum: None,
            note: "supported RVV eBPF path uses one helper-call descriptor per RVV instruction plus proof obligation".to_string(),
        }
    }

    fn bench_avx512(
        lanes: usize,
        reps: usize,
        runs: usize,
        input_a: &[i32],
        input_b: &[i32],
    ) -> Result<BenchRow, Box<dyn std::error::Error>> {
        let mut out = vec![0i32; lanes];
        let mut checksum = 0i64;
        let samples = time_runs(runs, || {
            out.fill(0);
            unsafe {
                avx512_add_i32(input_a, input_b, &mut out, reps);
            }
            checksum = checksum_i32(&out);
            std::hint::black_box(checksum);
        });
        let median = median_duration(&samples);
        let items = lanes.saturating_mul(reps);
        Ok(BenchRow {
            name: "x64_avx512_execute".to_string(),
            kind: "runtime".to_string(),
            status: "ok".to_string(),
            lanes,
            reps,
            work_items: items,
            median_ns: median.as_nanos(),
            ns_per_item: ns_per(median, items),
            giga_items_per_s: giga_per_s(median, items),
            checksum: Some(checksum),
            note: "native x86_64 AVX512F i32 vector add baseline".to_string(),
        })
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn avx512_add_i32(a: &[i32], b: &[i32], out: &mut [i32], reps: usize) {
        use std::arch::x86_64::{_mm512_add_epi32, _mm512_loadu_si512, _mm512_storeu_si512};

        let vector_lanes = 16;
        let chunks = a.len() / vector_lanes;
        for _ in 0..reps {
            for chunk in 0..chunks {
                let offset = chunk * vector_lanes;
                let lhs = _mm512_loadu_si512(a.as_ptr().add(offset).cast());
                let rhs = _mm512_loadu_si512(b.as_ptr().add(offset).cast());
                let sum = _mm512_add_epi32(lhs, rhs);
                _mm512_storeu_si512(out.as_mut_ptr().add(offset).cast(), sum);
            }

            for i in chunks * vector_lanes..a.len() {
                *out.get_unchecked_mut(i) = *a.get_unchecked(i) + *b.get_unchecked(i);
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn avx512_add_i32(_a: &[i32], _b: &[i32], _out: &mut [i32], _reps: usize) {
        unreachable!("AVX512 benchmark is only available on x86_64");
    }

    fn rvv_wasm_module(
        memory_pages: usize,
        base_b: usize,
        base_c: usize,
        vreg_base: usize,
    ) -> Result<String, String> {
        let rvv_chunk = rvv_chunk_function_wat()?;
        Ok(format!(
            r#"(module
  (memory (export "memory") {memory_pages})
  (global $x1 (mut i64) (i64.const 0))
  (global $x2 (mut i64) (i64.const 0))
  (global $x3 (mut i64) (i64.const 0))
  (global $x10 (mut i64) (i64.const 64))
  (global $vl (mut i64) (i64.const 64))
  (global $vtype (mut i64) (i64.const 0))
  (global $vreg_base (mut i32) (i32.const {vreg_base}))

  (func $vaddr_to_offset (param $vaddr i64) (result i32)
    local.get $vaddr
    i32.wrap_i64
  )

{rvv_chunk}

  (func $bench (export "bench") (param $chunks i32) (param $reps i32)
    (local $rep i32)
    (local $chunk i32)
    (local $base_a i32)
    (local $base_b i32)
    (local $base_c i32)

    i32.const 0
    local.set $rep
    block $done_reps
      loop $reps_loop
        local.get $rep
        local.get $reps
        i32.ge_u
        br_if $done_reps

        i32.const 0
        local.set $chunk
        block $done_chunks
          loop $chunks_loop
            local.get $chunk
            local.get $chunks
            i32.ge_u
            br_if $done_chunks

            local.get $chunk
            i32.const 8
            i32.shl
            local.tee $base_a
            i32.const {base_b}
            i32.add
            local.set $base_b

            local.get $base_a
            i32.const {base_c}
            i32.add
            local.set $base_c

            local.get $base_a
            i64.extend_i32_u
            global.set $x1
            local.get $base_b
            i64.extend_i32_u
            global.set $x2
            local.get $base_c
            i64.extend_i32_u
            global.set $x3
            i64.const 64
            global.set $x10
            call $rvv_chunk

            local.get $chunk
            i32.const 1
            i32.add
            local.set $chunk
            br $chunks_loop
          end
        end

        local.get $rep
        i32.const 1
        i32.add
        local.set $rep
        br $reps_loop
      end
    end
  )
)"#
        ))
    }

    fn rvv_chunk_function_wat() -> Result<String, String> {
        let mut emitter = WasmEmitter::new();
        emitter.start_function("rvv_chunk");
        emitter.emit_rvv_instruction(&RVV::VSETVLI(
            Rd(xreg(0)),
            Rs1(xreg(10)),
            Imm32::<30, 20>::from(0x0d0),
        ))?;
        emitter.emit_rvv_instruction(&RVV::VLE32_V(Rd(vreg(1)), Rs1(xreg(1)), VM(true)))?;
        emitter.emit_rvv_instruction(&RVV::VLE32_V(Rd(vreg(2)), Rs1(xreg(2)), VM(true)))?;
        emitter.emit_rvv_instruction(&RVV::VADD_VV(
            Rd(vreg(3)),
            Rs1(vreg(1)),
            Rs2(vreg(2)),
            VM(true),
        ))?;
        emitter.emit_rvv_instruction(&RVV::VSE32_V(Rs3(vreg(3)), Rs1(xreg(3)), VM(true)))?;
        emitter.end_function();
        Ok(emitter.finalize())
    }

    fn scalar_ebpf_entries(count: usize) -> Vec<(u64, Instr)> {
        let instr = Instr::RV32(RV32Instr::RV32I(RV32I::ADD(
            Rd(xreg(1)),
            Rs1(xreg(1)),
            Rs2(xreg(2)),
        )));
        (0..count)
            .map(|i| (0x1000 + (i as u64) * 4, instr))
            .collect()
    }

    fn make_inputs(lanes: usize) -> (Vec<i32>, Vec<i32>) {
        let mut a = vec![0i32; lanes];
        let mut b = vec![0i32; lanes];
        for i in 0..lanes {
            a[i] = ((i as i32).wrapping_mul(31) ^ 0x5a5a_1234u32 as i32).wrapping_add(7);
            b[i] = ((i as i32).wrapping_mul(17) ^ 0x1234_5678).wrapping_sub(3);
        }
        (a, b)
    }

    fn xreg(n: u32) -> Reg {
        Reg::X(Xx::new(n))
    }

    fn vreg(n: u32) -> Reg {
        Reg::V(Xx::new(n))
    }

    fn time_runs<F>(runs: usize, mut f: F) -> Vec<Duration>
    where
        F: FnMut(),
    {
        f();
        let mut samples = Vec::with_capacity(runs);
        for _ in 0..runs {
            let start = Instant::now();
            f();
            samples.push(start.elapsed());
        }
        samples
    }

    fn median_duration(samples: &[Duration]) -> Duration {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    fn checksum_i32(values: &[i32]) -> i64 {
        values
            .iter()
            .fold(0i64, |acc, value| acc.wrapping_add(i64::from(*value)))
    }

    fn env_usize(name: &str, default: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    fn round_up(value: usize, multiple: usize) -> usize {
        if multiple == 0 {
            value
        } else {
            ((value + multiple - 1) / multiple) * multiple
        }
    }

    fn ns_per(duration: Duration, items: usize) -> f64 {
        if items == 0 {
            0.0
        } else {
            duration.as_nanos() as f64 / items as f64
        }
    }

    fn giga_per_s(duration: Duration, items: usize) -> f64 {
        let secs = duration.as_secs_f64();
        if secs == 0.0 {
            0.0
        } else {
            items as f64 / secs / 1_000_000_000.0
        }
    }

    fn write_results(
        out_dir: &PathBuf,
        lanes: usize,
        reps: usize,
        runs: usize,
        ebpf_insns: usize,
        avx512: bool,
        rows: &[BenchRow],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let csv_path = out_dir.join("rvv-ebpf-avx512.csv");
        let md_path = out_dir.join("rvv-ebpf-avx512.md");

        let mut csv = fs::File::create(&csv_path)?;
        writeln!(
            csv,
            "name,kind,status,lanes,reps,work_items,median_ns,ns_per_item,giga_items_per_s,checksum,note"
        )?;
        for row in rows {
            writeln!(
                csv,
                "{},{},{},{},{},{},{},{:.6},{:.6},{},{}",
                csv_escape(&row.name),
                csv_escape(&row.kind),
                csv_escape(&row.status),
                row.lanes,
                row.reps,
                row.work_items,
                row.median_ns,
                row.ns_per_item,
                row.giga_items_per_s,
                row.checksum
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "NA".to_string()),
                csv_escape(&row.note)
            )?;
        }

        let mut md = fs::File::create(&md_path)?;
        writeln!(md, "# RVV/eBPF/AVX512 Bench")?;
        writeln!(md)?;
        writeln!(md, "- lanes: `{lanes}`")?;
        writeln!(md, "- reps: `{reps}`")?;
        writeln!(md, "- runs: `{runs}`")?;
        writeln!(md, "- eBPF source instructions: `{ebpf_insns}`")?;
        writeln!(md, "- AVX512F detected: `{avx512}`")?;
        writeln!(md)?;
        writeln!(
            md,
            "| Benchmark | Kind | Status | Work Items | Median ns | ns/item | Gitems/s | Checksum | Note |"
        )?;
        writeln!(
            md,
            "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |"
        )?;
        for row in rows {
            writeln!(
                md,
                "| `{}` | {} | {} | {} | {} | {:.3} | {:.6} | {} | {} |",
                row.name,
                row.kind,
                row.status.replace('|', "\\|"),
                row.work_items,
                row.median_ns,
                row.ns_per_item,
                row.giga_items_per_s,
                row.checksum
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "NA".to_string()),
                row.note.replace('|', "\\|")
            )?;
        }
        writeln!(md)?;
        writeln!(
            md,
            "Generated by `cargo bench --features ebpf --bench rvv_ebpf_avx512`."
        )?;

        println!("  wrote {}", csv_path.display());
        println!("  wrote {}", md_path.display());
        Ok(())
    }

    fn print_results(rows: &[BenchRow]) {
        println!();
        println!(
            "{:<30} {:<16} {:>14} {:>12} {:>12}  {}",
            "benchmark", "kind", "median_ns", "ns/item", "Gitems/s", "status"
        );
        for row in rows {
            println!(
                "{:<30} {:<16} {:>14} {:>12.3} {:>12.6}  {}",
                row.name,
                row.kind,
                row.median_ns,
                row.ns_per_item,
                row.giga_items_per_s,
                row.status
            );
        }
    }

    fn csv_escape(value: &str) -> String {
        if value.contains([',', '"', '\n']) {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }

    #[derive(Clone, Debug)]
    struct BenchRow {
        name: String,
        kind: String,
        status: String,
        lanes: usize,
        reps: usize,
        work_items: usize,
        median_ns: u128,
        ns_per_item: f64,
        giga_items_per_s: f64,
        checksum: Option<i64>,
        note: String,
    }

    impl BenchRow {
        fn skipped(name: &str, reason: &str) -> Self {
            Self {
                name: name.to_string(),
                kind: "runtime".to_string(),
                status: "skipped".to_string(),
                lanes: 0,
                reps: 0,
                work_items: 0,
                median_ns: 0,
                ns_per_item: 0.0,
                giga_items_per_s: 0.0,
                checksum: None,
                note: reason.to_string(),
            }
        }
    }
}
