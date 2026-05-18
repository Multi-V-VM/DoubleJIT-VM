#![allow(clippy::needless_range_loop)]

use doublejit_vm::frontend::elf::{ElfFile, SectionHeader};
use doublejit_vm::frontend::instruction::{Instr, Instruction};
use doublejit_vm::middleend::WasmEmitter;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(feature = "ebpf")]
use doublejit_vm::middleend::EbpfCompiler;

const EXECUTABLE_SECTION_FLAG: u64 = 0x4;
const TEST_BINARY_ROOT: &str = "test_binaries";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let decode_reps = env_usize("BENCH_TRACE_DECODE_REPS", 10_000);
    let wasm_reps = env_usize("BENCH_TRACE_WASM_REPS", 25);
    let ebpf_reps = env_usize("BENCH_TRACE_EBPF_REPS", 1_000);
    let runs = env_usize("BENCH_TRACE_RUNS", 5).max(1);
    let out_dir = PathBuf::from(
        std::env::var("BENCH_OUT_DIR").unwrap_or_else(|_| "bench-results".to_string()),
    );

    fs::create_dir_all(&out_dir)?;

    let traces = load_all_assembly_traces();
    let total_instructions: usize = traces.iter().map(|trace| trace.entries.len()).sum();
    println!("Assembly trace cargo bench");
    println!("  traces: {}", traces.len());
    println!("  instructions: {total_instructions}");
    println!("  decode reps: {decode_reps}");
    println!("  wasm reps: {wasm_reps}");
    println!("  eBPF reps: {ebpf_reps}");
    println!("  runs: {runs}");
    println!("  eBPF feature enabled: {}", cfg!(feature = "ebpf"));

    let mut rows = Vec::new();
    for trace in &traces {
        rows.push(bench_decode(trace, decode_reps, runs));
        rows.push(bench_wasm_codegen(trace, wasm_reps, runs)?);
        rows.push(bench_ebpf_compile_verify(trace, ebpf_reps, runs));
    }

    write_results(
        &out_dir,
        traces.len(),
        total_instructions,
        decode_reps,
        wasm_reps,
        ebpf_reps,
        runs,
        &rows,
    )?;
    print_results(&rows);

    Ok(())
}

#[derive(Debug)]
struct AssemblyTrace {
    source_path: PathBuf,
    binary_path: PathBuf,
    entries: Vec<TraceEntry>,
    executable_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
struct TraceEntry {
    pc: u64,
    bytes: [u8; 4],
    instr: Instr,
}

#[derive(Debug)]
struct BenchRow {
    trace: String,
    stage: String,
    status: String,
    instructions: usize,
    reps: usize,
    median_ns: u128,
    ns_per_instruction: f64,
    giga_instructions_per_s: f64,
    note: String,
}

fn bench_decode(trace: &AssemblyTrace, reps: usize, runs: usize) -> BenchRow {
    let mut decoded = 0usize;
    let samples = time_runs(runs, || {
        let mut local = 0usize;
        for _ in 0..reps {
            for entry in &trace.entries {
                let instr = Instruction::parse(&entry.bytes);
                std::hint::black_box(instr);
                local += 1;
            }
        }
        decoded = local;
    });
    let median = median_duration(&samples);
    BenchRow {
        trace: trace_name(&trace.source_path),
        stage: "frontend_decode".to_string(),
        status: "ok".to_string(),
        instructions: trace.entries.len(),
        reps,
        median_ns: median.as_nanos(),
        ns_per_instruction: ns_per(median, decoded),
        giga_instructions_per_s: giga_per_s(median, decoded),
        note: format!(
            "binary={} executable_bytes={} decoded_instances={decoded}",
            display_path(&trace.binary_path),
            trace.executable_bytes
        ),
    }
}

fn bench_wasm_codegen(
    trace: &AssemblyTrace,
    reps: usize,
    runs: usize,
) -> Result<BenchRow, Box<dyn std::error::Error>> {
    let mut total_wasm_bytes = 0usize;
    let mut total_wat_bytes = 0usize;
    let samples = time_runs(runs, || {
        let mut local_wasm_bytes = 0usize;
        let mut local_wat_bytes = 0usize;
        for _ in 0..reps {
            let wat = wasm_module_for_trace(trace);
            local_wat_bytes += wat.len();
            let wasm = wasmer::wat2wasm(wat.as_bytes()).expect("trace WAT should validate");
            local_wasm_bytes += wasm.len();
            std::hint::black_box(&wasm);
        }
        total_wat_bytes = local_wat_bytes;
        total_wasm_bytes = local_wasm_bytes;
    });
    let median = median_duration(&samples);
    let work = trace.entries.len() * reps;
    Ok(BenchRow {
        trace: trace_name(&trace.source_path),
        stage: "wasm_emit_validate".to_string(),
        status: "ok".to_string(),
        instructions: trace.entries.len(),
        reps,
        median_ns: median.as_nanos(),
        ns_per_instruction: ns_per(median, work),
        giga_instructions_per_s: giga_per_s(median, work),
        note: format!("wat_bytes={total_wat_bytes} wasm_bytes={total_wasm_bytes}"),
    })
}

#[cfg(feature = "ebpf")]
fn bench_ebpf_compile_verify(trace: &AssemblyTrace, reps: usize, runs: usize) -> BenchRow {
    let entries = trace
        .entries
        .iter()
        .map(|entry| (entry.pc, entry.instr))
        .collect::<Vec<_>>();
    let compiler = EbpfCompiler::new();
    let first_status = ebpf_status(&compiler, &entries);

    let samples = time_runs(runs, || {
        for _ in 0..reps {
            let status = ebpf_status(&compiler, &entries);
            std::hint::black_box(status);
        }
    });
    let median = median_duration(&samples);
    let work = trace.entries.len() * reps;
    BenchRow {
        trace: trace_name(&trace.source_path),
        stage: "ebpf_compile_verify".to_string(),
        status: first_status,
        instructions: trace.entries.len(),
        reps,
        median_ns: median.as_nanos(),
        ns_per_instruction: ns_per(median, work),
        giga_instructions_per_s: giga_per_s(median, work),
        note: "compile entries and run compile-time/kernel preflight when lowering succeeds"
            .to_string(),
    }
}

#[cfg(feature = "ebpf")]
fn ebpf_status(compiler: &EbpfCompiler, entries: &[(u64, Instr)]) -> String {
    match compiler.compile_entries(entries) {
        Ok(program) => match program.verify_compile_time() {
            Ok(report) => format!(
                "ok: one_to_one={} target_insns={} kernel_jumps={} kernel_exits={}",
                report.compilation.one_to_one,
                report.compilation.target_instructions,
                report.kernel.jump_instructions,
                report.kernel.exit_instructions
            ),
            Err(err) => format!("verification_failed: {err}"),
        },
        Err(err) => format!("unsupported: {err}"),
    }
}

#[cfg(not(feature = "ebpf"))]
fn bench_ebpf_compile_verify(trace: &AssemblyTrace, _reps: usize, _runs: usize) -> BenchRow {
    BenchRow {
        trace: trace_name(&trace.source_path),
        stage: "ebpf_compile_verify".to_string(),
        status: "skipped: enable with cargo bench --features ebpf --bench assembly_traces"
            .to_string(),
        instructions: trace.entries.len(),
        reps: 0,
        median_ns: 0,
        ns_per_instruction: 0.0,
        giga_instructions_per_s: 0.0,
        note: "eBPF feature is disabled".to_string(),
    }
}

fn load_all_assembly_traces() -> Vec<AssemblyTrace> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(TEST_BINARY_ROOT);
    let mut sources = Vec::new();
    collect_assembly_sources(&root, &mut sources);
    sources.sort();
    sources
        .into_iter()
        .map(|source_path| load_trace(&source_path))
        .collect()
}

fn collect_assembly_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .map(|entry| entry.expect("directory entry should be readable").path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            collect_assembly_sources(&path, out);
        } else if is_assembly_source(&path) {
            out.push(path);
        }
    }
}

fn is_assembly_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("S" | "s" | "asm")
    )
}

fn load_trace(source_path: &Path) -> AssemblyTrace {
    let binary_path = source_path.with_extension("");
    let bytes = fs::read(&binary_path).unwrap_or_else(|err| {
        panic!(
            "failed to read sibling ELF for {} at {}: {err}",
            display_path(source_path),
            display_path(&binary_path)
        )
    });
    let elf = ElfFile::new(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse {} as ELF: {err:?}", binary_path.display()));

    let mut entries = Vec::new();
    let mut executable_bytes = 0usize;
    for section in elf.section_iter() {
        let (flags, offset, size, vaddr) = section_metadata(section);
        if flags & EXECUTABLE_SECTION_FLAG == 0 {
            continue;
        }
        assert_eq!(
            size % 4,
            0,
            "{} has executable section length {size}, not divisible by 4",
            display_path(&binary_path)
        );

        executable_bytes += size;
        let section_data = &elf.input[offset..offset + size];
        for (index, chunk) in section_data.chunks_exact(4).enumerate() {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(chunk);
            let instr = Instruction::parse(chunk).instr;
            entries.push(TraceEntry {
                pc: vaddr + (index as u64) * 4,
                bytes: raw,
                instr,
            });
        }
    }

    entries.sort_by_key(|entry| entry.pc);
    AssemblyTrace {
        source_path: source_path.to_path_buf(),
        binary_path,
        entries,
        executable_bytes,
    }
}

fn section_metadata(section: SectionHeader<'_>) -> (u64, usize, usize, u64) {
    match section {
        SectionHeader::SectionHeader32(header) => (
            u64::from(header.flags),
            header.offset as usize,
            header.size as usize,
            u64::from(header.address),
        ),
        SectionHeader::SectionHeader64(header) => (
            header.flags,
            header.offset as usize,
            header.size as usize,
            header.address,
        ),
    }
}

fn wasm_module_for_trace(trace: &AssemblyTrace) -> String {
    let mut emitter = WasmEmitter::new();
    emitter.start_function("trace");
    emitter.start_loop();
    for entry in &trace.entries {
        emitter
            .emit_instruction(entry.pc, &Instruction { instr: entry.instr })
            .unwrap();
    }
    emitter.end_loop_with_exit_check();
    emitter.end_function();

    format!(
        r#"(module
  (memory (export "memory") 1)
  (global $pc (mut i64) (i64.const {entry_pc}))
  (global $entry_pc (mut i64) (i64.const {entry_pc}))
  (global $exit_flag (mut i32) (i32.const 0))
  (global $instr_count (mut i64) (i64.const 0))
  (global $vl (mut i64) (i64.const 0))
  (global $vtype (mut i64) (i64.const 0))
  (global $vreg_base (mut i32) (i32.const 0))
{x_globals}
  (func $vaddr_to_offset (param $vaddr i64) (result i32)
    local.get $vaddr
    i32.wrap_i64)
  (func $wasi_write (param $fd i64) (param $buf i64) (param $len i64) (result i64)
    i64.const 0)
  (func $syscall
    (param $nr i64) (param $a0 i64) (param $a1 i64) (param $a2 i64)
    (param $a3 i64) (param $a4 i64) (param $a5 i64)
    (result i64)
    i64.const 0)
{function}
)"#,
        entry_pc = trace.entries.first().map(|entry| entry.pc).unwrap_or(0),
        x_globals = x_globals(),
        function = emitter.finalize()
    )
}

fn x_globals() -> String {
    (0..32)
        .map(|reg| format!("  (global $x{reg} (mut i64) (i64.const 0))\n"))
        .collect()
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

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
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
    out_dir: &Path,
    trace_count: usize,
    total_instructions: usize,
    decode_reps: usize,
    wasm_reps: usize,
    ebpf_reps: usize,
    runs: usize,
    rows: &[BenchRow],
) -> Result<(), Box<dyn std::error::Error>> {
    let csv_path = out_dir.join("assembly-traces.csv");
    let md_path = out_dir.join("assembly-traces.md");

    let mut csv = fs::File::create(&csv_path)?;
    writeln!(
        csv,
        "trace,stage,status,instructions,reps,median_ns,ns_per_instruction,giga_instructions_per_s,note"
    )?;
    for row in rows {
        writeln!(
            csv,
            "{},{},{},{},{},{},{:.6},{:.6},{}",
            csv_escape(&row.trace),
            csv_escape(&row.stage),
            csv_escape(&row.status),
            row.instructions,
            row.reps,
            row.median_ns,
            row.ns_per_instruction,
            row.giga_instructions_per_s,
            csv_escape(&row.note)
        )?;
    }

    let mut md = fs::File::create(&md_path)?;
    writeln!(md, "# Assembly Trace Bench")?;
    writeln!(md)?;
    writeln!(md, "- traces: `{trace_count}`")?;
    writeln!(md, "- instructions: `{total_instructions}`")?;
    writeln!(md, "- decode reps: `{decode_reps}`")?;
    writeln!(md, "- wasm reps: `{wasm_reps}`")?;
    writeln!(md, "- eBPF reps: `{ebpf_reps}`")?;
    writeln!(md, "- runs: `{runs}`")?;
    writeln!(md, "- eBPF feature enabled: `{}`", cfg!(feature = "ebpf"))?;
    writeln!(md)?;
    writeln!(
        md,
        "| Trace | Stage | Status | Instructions | Reps | Median ns | ns/instruction | Ginstr/s | Note |"
    )?;
    writeln!(
        md,
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |"
    )?;
    for row in rows {
        writeln!(
            md,
            "| `{}` | {} | {} | {} | {} | {} | {:.3} | {:.6} | {} |",
            row.trace,
            row.stage,
            row.status.replace('|', "\\|"),
            row.instructions,
            row.reps,
            row.median_ns,
            row.ns_per_instruction,
            row.giga_instructions_per_s,
            row.note.replace('|', "\\|")
        )?;
    }
    writeln!(md)?;
    writeln!(md, "Generated by `cargo bench --bench assembly_traces`.")?;

    println!("  wrote {}", csv_path.display());
    println!("  wrote {}", md_path.display());
    Ok(())
}

fn print_results(rows: &[BenchRow]) {
    println!();
    println!(
        "{:<38} {:<20} {:>12} {:>12} {:>12}  {}",
        "trace", "stage", "median_ns", "ns/instr", "Ginstr/s", "status"
    );
    for row in rows {
        println!(
            "{:<38} {:<20} {:>12} {:>12.3} {:>12.6}  {}",
            row.trace,
            row.stage,
            row.median_ns,
            row.ns_per_instruction,
            row.giga_instructions_per_s,
            row.status
        );
    }
}

fn trace_name(path: &Path) -> String {
    display_path(path)
}

fn display_path(path: &Path) -> String {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .display()
        .to_string()
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
