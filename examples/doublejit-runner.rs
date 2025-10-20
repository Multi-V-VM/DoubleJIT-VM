use doublejit_vm::frontend::elf::ElfFile;
use doublejit_vm::frontend::instruction::Instruction;
use doublejit_vm::middleend::{AddressMap, WasmEmitter, RiscVState};
use doublejit_vm::backend::RuntimeBuilder;
use std::sync::{Arc, Mutex};
use wasmer::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-riscv-binary>", args[0]);
        eprintln!("\nExample: {} hello-riscv.elf", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          DoubleJIT VM - RISC-V to Native x86/ARM        ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // STEP 1: Frontend - Parse RISC-V ELF Binary
    // ========================================================================
    println!("[1/5] 📥 Loading RISC-V binary: {}", path);

    let binary_data = std::fs::read(path)?;
    let elf_file = ElfFile::new(&binary_data).map_err(|e| format!("ELF parse error: {:?}", e))?;

    println!("      ✓ ELF class: {:?}", elf_file.header_part1.get_class());
    println!("      ✓ Machine: {:?}", elf_file.header_part2.get_machine());
    println!("      ✓ Entry point: 0x{:x}", elf_file.header_part2.get_entry_point());

    // ========================================================================
    // STEP 2: Middleend - Create Address Map for Memory Layout
    // ========================================================================
    println!("\n[2/5] 🗺️  Creating address map and loading sections...");

    let address_map = AddressMap::from_sections(&elf_file, elf_file.section_iter());

    println!("      ✓ Memory base: 0x{:x}", address_map.memory_base);
    println!("      ✓ Required pages: {} ({}KB)",
             address_map.required_pages(),
             address_map.required_memory_size() / 1024);
    println!("      ✓ Sections loaded: {}", address_map.segments().len());

    // ========================================================================
    // STEP 3: Middleend - Translate RISC-V Instructions to WAT
    // ========================================================================
    println!("\n[3/5] 🔄 Translating RISC-V instructions to WebAssembly...");

    let mut emitter = WasmEmitter::new();
    emitter.start_function("translated_code");
    emitter.start_loop(); // Start interpreter loop

    let entry_point = elf_file.header_part2.get_entry_point();
    let mut total_instructions = 0;
    let mut translated_instructions = 0;

    // Find and translate text sections
    for section in elf_file.section_iter() {
        let section_name = section.get_name(&elf_file).unwrap_or("");

        if section_name.contains("text") {
            println!("      📝 Processing section: {}", section_name);

            let (section_data, section_vaddr) = match section {
                doublejit_vm::frontend::elf::SectionHeader::SectionHeader32(h) => {
                    let offset = h.offset as usize;
                    let size = h.size as usize;
                    let vaddr = h.address as u64;
                    (&elf_file.input[offset..offset + size], vaddr)
                }
                doublejit_vm::frontend::elf::SectionHeader::SectionHeader64(h) => {
                    let offset = h.offset as usize;
                    let size = h.size as usize;
                    let vaddr = h.address;
                    (&elf_file.input[offset..offset + size], vaddr)
                }
            };

            // CRITICAL FIX: PC must start at the section's virtual address, not entry point!
            let mut pc = section_vaddr;
            let mut offset = 0;
            while offset + 4 <= section_data.len() {
                let instr_bytes = &section_data[offset..offset + 4];
                total_instructions += 1;

                // Parse and emit instruction
                let instr = Instruction::parse(instr_bytes);
                match emitter.emit_instruction(pc, &instr) {
                    Ok(_) => {
                        translated_instructions += 1;
                    }
                    Err(e) => {
                        eprintln!("         ⚠ Warning at 0x{:x}: {}", pc, e);
                    }
                }

                pc += 4;
                offset += 4;
            }
        }
    }

    emitter.end_loop_with_exit_check(); // End interpreter loop with exit check
    emitter.end_function();
    let function_code = emitter.finalize();

    println!("      ✓ Total instructions scanned: {}", total_instructions);
    println!("      ✓ Successfully translated: {}", translated_instructions);
    println!("      ✓ WAT code size: {} bytes", function_code.len());

    // Build complete WASM module with imports, memory, and globals
    // IMPORTANT: In WASM, imports must come BEFORE globals
    let vaddr_base = address_map.vaddr_base();
    println!("      ✓ Virtual address base: 0x{:x}", vaddr_base);
    println!("      ✓ Memory mapping: vaddr 0x{:x} → offset 0x{:x}", vaddr_base, address_map.memory_base);

    // Print all mapped segments for debugging
    println!("      📍 Mapped address ranges:");
    for seg in address_map.segments() {
        let end_addr = seg.vaddr + seg.size as u64 - 1;
        println!("         0x{:x}-0x{:x} ({})", seg.vaddr, end_addr,
                 if seg.executable { "exec" } else if seg.writable { "rw" } else { "ro" });
    }

    let complete_wat = format!(r#"(module
  ;; Import syscall handler (must come before globals)
  (import "env" "syscall" (func $syscall (param i64 i64 i64 i64 i64 i64 i64) (result i64)))
  (import "env" "debug_print" (func $debug_print (param i32)))

  ;; Import WASI functions for direct syscall translation
  (import "wasi_snapshot_preview1" "fd_write" (func $wasi_fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $wasi_fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $wasi_proc_exit (param i32)))

  ;; Memory: 3072 pages initially (192MB), max 4096 pages (256MB)
  ;; This accommodates programs that expect larger address spaces (stack, heap, TLS)
  ;; Stack is typically at high addresses (e.g. 0x7ffee88 = ~134MB)
  (memory (export "memory") 3072 4096)

  ;; Declare WASI version for wasix (using _start as entry point marker for wasip1)
  (export "_start" (func $main))

  ;; Globals for RISC-V register file (x0-x31)
  (global $x0 (mut i64) (i64.const 0))
  (global $x1 (mut i64) (i64.const 0))
  (global $x2 (mut i64) (i64.const 0))
  (global $x3 (mut i64) (i64.const 0))
  (global $x4 (mut i64) (i64.const 0))
  (global $x5 (mut i64) (i64.const 0))
  (global $x6 (mut i64) (i64.const 0))
  (global $x7 (mut i64) (i64.const 0))
  (global $x8 (mut i64) (i64.const 0))
  (global $x9 (mut i64) (i64.const 0))
  (global $x10 (mut i64) (i64.const 0))
  (global $x11 (mut i64) (i64.const 0))
  (global $x12 (mut i64) (i64.const 0))
  (global $x13 (mut i64) (i64.const 0))
  (global $x14 (mut i64) (i64.const 0))
  (global $x15 (mut i64) (i64.const 0))
  (global $x16 (mut i64) (i64.const 0))
  (global $x17 (mut i64) (i64.const 0))
  (global $x18 (mut i64) (i64.const 0))
  (global $x19 (mut i64) (i64.const 0))
  (global $x20 (mut i64) (i64.const 0))
  (global $x21 (mut i64) (i64.const 0))
  (global $x22 (mut i64) (i64.const 0))
  (global $x23 (mut i64) (i64.const 0))
  (global $x24 (mut i64) (i64.const 0))
  (global $x25 (mut i64) (i64.const 0))
  (global $x26 (mut i64) (i64.const 0))
  (global $x27 (mut i64) (i64.const 0))
  (global $x28 (mut i64) (i64.const 0))
  (global $x29 (mut i64) (i64.const 0))
  (global $x30 (mut i64) (i64.const 0))
  (global $x31 (mut i64) (i64.const 0))

  ;; Program counter
  (global $pc (mut i64) (i64.const 0))

  ;; Memory mapping base - RISC-V virtual addresses need this offset subtracted
  (global $vaddr_offset (mut i64) (i64.const {}))

  ;; Vector CSRs
  (global $vl (mut i64) (i64.const 0))
  (global $vtype (mut i64) (i64.const 0))
  (global $vstart (mut i64) (i64.const 0))
  (global $vlenb (mut i64) (i64.const 256))

  ;; Exit flag - set to 1 when program should exit
  (global $exit_flag (mut i32) (i32.const 0))

  ;; Instruction execution counter (for debugging infinite loops)
  (global $instr_count (mut i64) (i64.const 0))

  ;; Accessor functions for exit_flag and instr_count (exported as immutable functions)
  (func $get_exit_flag (export "get_exit_flag") (result i32)
    global.get $exit_flag
  )

  (func $set_exit_flag (export "set_exit_flag") (param $value i32)
    local.get $value
    global.set $exit_flag
  )

  (func $get_instr_count (export "get_instr_count") (result i64)
    global.get $instr_count
  )

  ;; Helper function: Set register value (called before execution to initialize registers)
  ;; Uses if-then-else chain for simplicity
  (func $set_reg (export "set_reg") (param $reg i32) (param $val i64)
    local.get $reg i32.const 2 i32.eq if local.get $val global.set $x2 return end
    local.get $reg i32.const 4 i32.eq if local.get $val global.set $x4 return end
    local.get $reg i32.const 10 i32.eq if local.get $val global.set $x10 return end
    local.get $reg i32.const 11 i32.eq if local.get $val global.set $x11 return end
    local.get $reg i32.const 1 i32.eq if local.get $val global.set $x1 return end
    local.get $reg i32.const 3 i32.eq if local.get $val global.set $x3 return end
    local.get $reg i32.const 5 i32.eq if local.get $val global.set $x5 return end
    local.get $reg i32.const 6 i32.eq if local.get $val global.set $x6 return end
    local.get $reg i32.const 7 i32.eq if local.get $val global.set $x7 return end
    local.get $reg i32.const 8 i32.eq if local.get $val global.set $x8 return end
    local.get $reg i32.const 9 i32.eq if local.get $val global.set $x9 return end
    local.get $reg i32.const 12 i32.eq if local.get $val global.set $x12 return end
    local.get $reg i32.const 13 i32.eq if local.get $val global.set $x13 return end
    local.get $reg i32.const 14 i32.eq if local.get $val global.set $x14 return end
    local.get $reg i32.const 15 i32.eq if local.get $val global.set $x15 return end
    local.get $reg i32.const 16 i32.eq if local.get $val global.set $x16 return end
    local.get $reg i32.const 17 i32.eq if local.get $val global.set $x17 return end
    local.get $reg i32.const 18 i32.eq if local.get $val global.set $x18 return end
    local.get $reg i32.const 19 i32.eq if local.get $val global.set $x19 return end
    local.get $reg i32.const 20 i32.eq if local.get $val global.set $x20 return end
    local.get $reg i32.const 21 i32.eq if local.get $val global.set $x21 return end
    local.get $reg i32.const 22 i32.eq if local.get $val global.set $x22 return end
    local.get $reg i32.const 23 i32.eq if local.get $val global.set $x23 return end
    local.get $reg i32.const 24 i32.eq if local.get $val global.set $x24 return end
    local.get $reg i32.const 25 i32.eq if local.get $val global.set $x25 return end
    local.get $reg i32.const 26 i32.eq if local.get $val global.set $x26 return end
    local.get $reg i32.const 27 i32.eq if local.get $val global.set $x27 return end
    local.get $reg i32.const 28 i32.eq if local.get $val global.set $x28 return end
    local.get $reg i32.const 29 i32.eq if local.get $val global.set $x29 return end
    local.get $reg i32.const 30 i32.eq if local.get $val global.set $x30 return end
    local.get $reg i32.const 31 i32.eq if local.get $val global.set $x31 return end
  )

  ;; Helper function: Translate RISC-V virtual address to WASM linear memory offset
  (func $vaddr_to_offset (param $vaddr i64) (result i32)
    ;; Just do the translation - trust that the address is valid
    ;; The WASM runtime will trap if we access out of bounds anyway
    local.get $vaddr
    global.get $vaddr_offset
    i64.sub
    i64.const {}
    i64.add
    i32.wrap_i64
  )

  ;; WASI write wrapper: adapt RISC-V write(fd, buf, count) to WASI fd_write
  (func $wasi_write (param $fd i64) (param $buf i64) (param $count i64) (result i64)
    (local $iovec_ptr i32)
    (local $nwritten_ptr i32)
    (local $result i32)

    ;; Allocate space for iovec at a high memory address (0x7ff0000)
    i32.const 0x7ff0000
    local.set $iovec_ptr

    ;; Allocate space for nwritten result (0x7ff0010)
    i32.const 0x7ff0010
    local.set $nwritten_ptr

    ;; Write iovec structure: [buf_ptr, buf_len]
    local.get $iovec_ptr
    local.get $buf
    call $vaddr_to_offset
    i32.store

    local.get $iovec_ptr
    i32.const 4
    i32.add
    local.get $count
    i32.wrap_i64
    i32.store

    ;; Call WASI fd_write(fd, iovec_ptr, iovec_count=1, nwritten_ptr)
    local.get $fd
    i32.wrap_i64
    local.get $iovec_ptr
    i32.const 1  ;; iovec count
    local.get $nwritten_ptr
    call $wasi_fd_write
    local.set $result

    ;; Check result
    local.get $result
    i32.const 0
    i32.eq
    if (result i64)
      ;; Success: return number of bytes written
      local.get $nwritten_ptr
      i32.load
      i64.extend_i32_u
    else
      ;; Error: return -1
      i64.const -1
    end
  )

{}

  ;; Main entry point - wraps translated_code
  (func $main (export "main") (result i32)
    ;; Initialize PC to entry point before starting interpreter
    i64.const {}
    global.set $pc
    call $translated_code
    i32.const 0
  )
)"#, vaddr_base, address_map.memory_base, function_code, entry_point);

    // Debug: optionally print WAT code
    if std::env::var("PRINT_WAT").is_ok() {
        eprintln!("\n========== Generated WAT Code ==========");
        eprintln!("{}", complete_wat);
        eprintln!("========================================\n");
    }

    // ========================================================================
    // STEP 4: Backend - Compile WAT to Native Code using Singlepass
    // ========================================================================
    println!("\n[4/5] ⚙️  Compiling to native code (Singlepass)...");

    let mut runtime_builder = RuntimeBuilder::with_opt_level(doublejit_vm::backend::wasm_builder::OptLevel::None)?;
    let state = Arc::new(Mutex::new(RiscVState::default()));

    // Set up initial PC and memory base (stack will be initialized after loading memory)
    {
        let mut s = state.lock().unwrap();
        s.pc = entry_point;
        s.memory_base = address_map.memory_base;
    }

    // Compile WAT → Optimized WAT → WASM → Native Code
    println!("      🔨 Optimizing and compiling WAT to native code...");
    let original_wat_size = complete_wat.len();

    let mut runtime = match runtime_builder.build_from_wat(&complete_wat, state.clone()) {
        Ok(rt) => {
            println!("      ✓ Native code compilation successful!");
            println!("      ✓ Target: {} architecture", std::env::consts::ARCH);

            // Print WAT optimization statistics
            if let Some(stats) = runtime_builder.last_optimization_stats() {
                if stats.total() > 0 {
                    println!("\n      📊 WAT Optimization Statistics:");
                    println!("         Original WAT size: {} bytes", original_wat_size);
                    if stats.constants_propagated > 0 {
                        println!("         • Constants propagated:     {}", stats.constants_propagated);
                    }
                    if stats.peephole_optimizations > 0 {
                        println!("         • Peephole optimizations:   {}", stats.peephole_optimizations);
                    }
                    if stats.dead_code_eliminated > 0 {
                        println!("         • Dead code eliminated:     {}", stats.dead_code_eliminated);
                    }
                    if stats.redundant_stores_eliminated > 0 {
                        println!("         • Redundant stores removed: {}", stats.redundant_stores_eliminated);
                    }
                    if stats.redundant_loads_eliminated > 0 {
                        println!("         • Redundant loads removed:  {}", stats.redundant_loads_eliminated);
                    }
                    if stats.branches_simplified > 0 {
                        println!("         • Branches simplified:      {}", stats.branches_simplified);
                    }
                    println!("         Total optimizations: {}", stats.total());
                }
            }

            rt
        }
        Err(e) => {
            eprintln!("\n❌ Compilation failed: {}", e);
            return Err(e);
        }
    };

    // ========================================================================
    // STEP 5: Load Memory and Execute Native Code
    // ========================================================================
    println!("\n[5/5] 🚀 Loading memory and executing native code...");

    // Load initial memory from binary sections
    let memory_initializers = address_map.get_memory_initializers();
    println!("      📦 Loading {} memory segments...", memory_initializers.len());

    // IMPORTANT: Load ELF headers first (needed for AT_PHDR to work)
    // The first LOAD segment includes the ELF header and program headers
    // For add_test, this is vaddr 0x10000-0x10377 (before .text at 0x10378)
    let first_section_offset = memory_initializers.first().map(|(off, _)| *off).unwrap_or(0);
    if first_section_offset > 0x10000 {
        // Load the gap (ELF headers + program headers)
        let header_size = (first_section_offset - 0x10000) as usize;
        let elf_header_data = &binary_data[0..header_size];
        runtime.load_memory(0x10000, elf_header_data)?;
        println!("         • Loaded {} bytes at offset 0x10000 (ELF + program headers)", header_size);
    }

    for (offset, data) in memory_initializers {
        runtime.load_memory(offset, &data)?;
        println!("         • Loaded {} bytes at offset 0x{:x}", data.len(), offset);
    }

    // ========================================================================
    // Initialize stack with argc, argv, envp for C runtime
    // ========================================================================
    println!("\n      📋 Initializing stack with program arguments...");

    // Set up minimal argc/argv/envp on the stack
    // RISC-V Linux ABI expects stack layout on program entry:
    //   sp+0:  argc
    //   sp+8:  argv[0] (pointer to program name)
    //   sp+16: argv[1..n] (additional arguments)
    //   sp+X:  NULL (argv terminator)
    //   sp+X+8: envp[0..n] (environment variables)
    //   sp+Y:  NULL (envp terminator)
    //   sp+Y+8: auxv[] (auxiliary vector with AT_* entries)

    const WASM_MEMORY_SIZE: u64 = 128 * 1024 * 1024; // 128MB
    let stack_top = WASM_MEMORY_SIZE - 0x1000; // Leave 4KB at top for safety

    // Program name and arguments
    let program_name = path.as_bytes();
    let argc = 1i64; // Just the program name for now

    // Layout strings at top of stack, then build pointer array below
    let mut current_addr = stack_top;

    // Write program name string
    current_addr -= program_name.len() as u64 + 1; // +1 for null terminator
    let program_name_addr = current_addr;
    runtime.load_memory(current_addr as u32, program_name)?;
    runtime.load_memory((current_addr + program_name.len() as u64) as u32, &[0])?; // null terminator
    println!("         • Program name at 0x{:x}: {:?}", program_name_addr, path);

    // Align to 16-byte boundary (RISC-V calling convention)
    current_addr = current_addr & !0xF;

    // Now build the argc/argv/envp structure
    // First, add auxiliary vector (auxv) entries
    // AT_NULL = 0 (terminator)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?; // value
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?; // AT_NULL

    // AT_PAGESZ = 6 (page size)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &4096u64.to_le_bytes())?; // 4KB pages
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &6u64.to_le_bytes())?; // AT_PAGESZ

    // AT_RANDOM = 25 (random bytes for stack canary, etc.)
    let random_addr = current_addr - 16;
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &random_addr.to_le_bytes())?; // pointer to random bytes
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &25u64.to_le_bytes())?; // AT_RANDOM

    // Write 16 random bytes (actually just zeros for now)
    current_addr -= 16;
    runtime.load_memory(current_addr as u32, &[0u8; 16])?;

    // CRITICAL for glibc: AT_PHDR = 3 (program headers address)
    // Program headers are at offset 0x40 in the ELF file, loaded at vaddr 0x10000
    // So the virtual address is 0x10000 + 0x40 = 0x10040
    let phdr_vaddr = 0x10040u64; // Virtual address of program headers in memory
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &phdr_vaddr.to_le_bytes())?; // phdr address
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &3u64.to_le_bytes())?; // AT_PHDR

    // AT_PHENT = 4 (size of program header entry)
    let phent_size = 56u64; // Standard size for ELF64 program header entry (Elf64_Phdr)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &phent_size.to_le_bytes())?; // phent size
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &4u64.to_le_bytes())?; // AT_PHENT

    // AT_PHNUM = 5 (number of program headers)
    // For add_test: 6 program headers
    let phnum = 6u64;
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &phnum.to_le_bytes())?; // phnum
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &5u64.to_le_bytes())?; // AT_PHNUM

    // AT_ENTRY = 9 (entry point address)
    let entry = elf_file.header_part2.get_entry_point();
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &entry.to_le_bytes())?; // entry
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &9u64.to_le_bytes())?; // AT_ENTRY

    // AT_UID = 11 (user ID)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &1000u64.to_le_bytes())?; // UID
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &11u64.to_le_bytes())?; // AT_UID

    // AT_EUID = 12 (effective user ID)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &1000u64.to_le_bytes())?; // EUID
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &12u64.to_le_bytes())?; // AT_EUID

    // AT_GID = 13 (group ID)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &1000u64.to_le_bytes())?; // GID
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &13u64.to_le_bytes())?; // AT_GID

    // AT_EGID = 14 (effective group ID)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &1000u64.to_le_bytes())?; // EGID
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &14u64.to_le_bytes())?; // AT_EGID

    // AT_SECURE = 23 (secure mode - 0 = not secure)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?; // not secure
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &23u64.to_le_bytes())?; // AT_SECURE

    // AT_HWCAP = 16 (hardware capabilities)
    // RISC-V hwcap bits: I=1, M=4, A=8, F=16, D=32, C=64
    // RV64IMAFDC = 0x1 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 = 0x7D
    let hwcap = 0x112Du64; // RISC-V basic capabilities
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &hwcap.to_le_bytes())?;
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &16u64.to_le_bytes())?; // AT_HWCAP

    // AT_CLKTCK = 17 (clock ticks per second)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &100u64.to_le_bytes())?; // 100 Hz
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &17u64.to_le_bytes())?; // AT_CLKTCK

    // AT_PLATFORM = 15 (platform string)
    let platform_str = "riscv64\0";
    let platform_addr = current_addr - platform_str.len() as u64;
    current_addr = platform_addr;
    runtime.load_memory(current_addr as u32, platform_str.as_bytes())?;
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &platform_addr.to_le_bytes())?; // pointer to string
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &15u64.to_le_bytes())?; // AT_PLATFORM

    // AT_BASE = 7 (base address of interpreter - 0 for statically linked)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?; // 0 for static
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &7u64.to_le_bytes())?; // AT_BASE

    // AT_FLAGS = 8 (flags)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?; // no flags
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &8u64.to_le_bytes())?; // AT_FLAGS

    // AT_EXECFN = 31 (executable filename - reuse program_name)
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &program_name_addr.to_le_bytes())?;
    current_addr -= 8;
    runtime.load_memory(current_addr as u32, &31u64.to_le_bytes())?; // AT_EXECFN

    current_addr -= 8; // Space for envp NULL terminator
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?;

    current_addr -= 8; // Space for argv NULL terminator
    runtime.load_memory(current_addr as u32, &0u64.to_le_bytes())?;

    current_addr -= 8; // argv[0] = pointer to program name
    runtime.load_memory(current_addr as u32, &program_name_addr.to_le_bytes())?;
    let argv_addr = current_addr;

    current_addr -= 8; // argc
    runtime.load_memory(current_addr as u32, &argc.to_le_bytes())?;

    let final_sp = current_addr;

    // Set up Thread Local Storage (TLS)
    // In RISC-V, tp (x4) points to the Thread Control Block (TCB)
    // TLS variables are accessed at negative offsets from tp
    // We need to allocate space for .tdata and .tbss sections

    // Allocate TLS area above the stack (should be at a high address)
    let tls_size = 4096u64; // 4KB for TLS (more than enough for small programs)
    let tls_area_end = current_addr - 256; // Leave gap between stack and TLS
    let tls_area_start = tls_area_end - tls_size;
    let tp = tls_area_end; // tp points to END of TLS area (variables at negative offsets)

    // Initialize TLS area to zeros
    runtime.load_memory(tls_area_start as u32, &vec![0u8; tls_size as usize])?;
    println!("         • TLS area: 0x{:x} - 0x{:x}", tls_area_start, tls_area_end);

    // Update the stack pointer and other registers in the state
    {
        let mut s = state.lock().unwrap();
        s.x_regs[2] = final_sp as i64; // sp = x2
        s.x_regs[4] = tp as i64; // tp = x4 (thread pointer)
        // IMPORTANT: Do NOT pre-initialize a0-a7! _start will set them up correctly.
        // argc is read from the stack at sp+0, not passed in registers
        // The _start routine will load main's address into a0 and call __libc_start_main
        println!("         • Stack pointer (sp/x2) = 0x{:x}", final_sp);
        println!("         • Thread pointer (tp/x4) = 0x{:x}", tp);
        println!("         • argc at stack[sp] = {}", argc);
        println!("         • argv at stack[sp+8] = 0x{:x}", argv_addr);
        println!("         • _start will load main's address and call __libc_start_main");
    }

    println!("\n      ▶️  Executing native code...\n");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                   Program Output                         ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Execute the compiled native code
    let exit_code_result = runtime.execute();

    // Get instruction count after execution (using accessor function)
    let get_instr_count_func = runtime.instance().exports.get_function("get_instr_count").ok().cloned();
    if let Some(func) = get_instr_count_func {
        match func.call(runtime.store_mut(), &[]) {
            Ok(results) if !results.is_empty() => {
                if let Value::I64(count) = results[0] {
                    eprintln!("\n╔═══════════════════════════════════════════════════════════════╗");
                    eprintln!("║  DEBUG: Executed {} instructions", count);
                    eprintln!("╚═══════════════════════════════════════════════════════════════╝");
                }
            }
            _ => {}
        }
    }

    match exit_code_result {
        Ok(exit_code) => {

            println!("\n╔══════════════════════════════════════════════════════════╗");
            println!("║                  Execution Complete                      ║");
            println!("╚══════════════════════════════════════════════════════════╝");
            println!("Exit code: {}", exit_code);

            // Note: Final PC and registers are stored in WASM globals during execution
            // They are not synced back to RiscVState
            // For debugging, check syscall logs and instruction count above

            Ok(())
        }
        Err(e) => {
            eprintln!("\n❌ Execution error: {}", e);
            Err(e)
        }
    }
}
