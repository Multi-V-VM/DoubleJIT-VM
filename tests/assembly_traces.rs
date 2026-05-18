use doublejit_vm::frontend::elf::{ElfFile, SectionHeader};
use doublejit_vm::frontend::instruction::{Instr, Instruction};
use doublejit_vm::middleend::WasmEmitter;
use std::fs;
use std::path::{Path, PathBuf};

const EXECUTABLE_SECTION_FLAG: u64 = 0x4;
const TEST_BINARY_ROOT: &str = "test_binaries";

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

#[test]
fn all_assembly_sources_have_decodable_instruction_traces() {
    let traces = load_all_assembly_traces();
    assert_eq!(
        traces.len(),
        4,
        "expected every checked-in .S file under {TEST_BINARY_ROOT} to be covered"
    );

    let total_instructions: usize = traces.iter().map(|trace| trace.entries.len()).sum();
    assert_eq!(total_instructions, 37);

    for trace in &traces {
        assert!(
            trace.binary_path.is_file(),
            "{} has no sibling compiled ELF at {}",
            display_path(&trace.source_path),
            display_path(&trace.binary_path)
        );
        assert!(
            !trace.entries.is_empty(),
            "{} produced an empty executable trace",
            display_path(&trace.source_path)
        );
        assert_eq!(
            trace.executable_bytes,
            trace.entries.len() * 4,
            "{} executable trace is not fully decoded as 4-byte instructions",
            display_path(&trace.source_path)
        );

        for window in trace.entries.windows(2) {
            assert_eq!(
                window[0].pc + 4,
                window[1].pc,
                "{} trace is not a contiguous 4-byte instruction stream",
                display_path(&trace.source_path)
            );
        }

        for entry in &trace.entries {
            assert_eq!(
                Instruction::parse(&entry.bytes).instr,
                entry.instr,
                "{} trace decode is not stable at pc=0x{:x}",
                display_path(&trace.source_path),
                entry.pc
            );
        }
    }
}

#[test]
fn all_assembly_instruction_traces_emit_valid_wasm() {
    for trace in load_all_assembly_traces() {
        let wat = wasm_module_for_trace(&trace);
        let wasm = wasmer::wat2wasm(wat.as_bytes()).unwrap_or_else(|err| {
            panic!(
                "WAT validation failed for {}: {err}",
                display_path(&trace.source_path)
            )
        });
        assert!(
            !wasm.is_empty(),
            "{} emitted empty WASM",
            display_path(&trace.source_path)
        );
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

fn display_path(path: &Path) -> String {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .display()
        .to_string()
}
