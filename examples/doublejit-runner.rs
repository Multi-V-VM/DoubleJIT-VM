use doublejit_vm::frontend::elf::ElfFile;
use doublejit_vm::frontend::instruction::Instruction;
use doublejit_vm::middleend::{AddressMap, WasmEmitter, RiscVState};
use doublejit_vm::backend::RuntimeBuilder;
use std::sync::{Arc, Mutex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let entry_point = elf_file.header_part2.get_entry_point();
    let mut pc = entry_point;
    let mut total_instructions = 0;
    let mut translated_instructions = 0;

    // Find and translate text sections
    for section in elf_file.section_iter() {
        let section_name = section.get_name(&elf_file).unwrap_or("");

        if section_name.contains("text") {
            println!("      📝 Processing section: {}", section_name);

            let section_data = match section {
                doublejit_vm::frontend::elf::SectionHeader::SectionHeader32(h) => {
                    let offset = h.offset as usize;
                    let size = h.size as usize;
                    &elf_file.input[offset..offset + size]
                }
                doublejit_vm::frontend::elf::SectionHeader::SectionHeader64(h) => {
                    let offset = h.offset as usize;
                    let size = h.size as usize;
                    &elf_file.input[offset..offset + size]
                }
            };

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

                // Limit for demo (remove in production)
                if translated_instructions >= 1000 {
                    println!("         ℹ Demo limit reached (1000 instructions)");
                    break;
                }
            }
        }
    }

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

  ;; Memory: 256 pages initially (16MB), max 4096 pages (256MB)
  (memory (export "memory") 256 4096)

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

  ;; Helper function: Translate RISC-V virtual address to WASM linear memory offset
  (func $vaddr_to_offset (param $vaddr i64) (result i32)
    local.get $vaddr
    global.get $vaddr_offset
    i64.sub
    i64.const {}
    i64.add
    i32.wrap_i64
  )

{}

  ;; Main entry point - wraps translated_code
  (func $main (export "main") (result i32)
    call $translated_code
    i32.const 0
  )
)"#, vaddr_base, address_map.memory_base, function_code);

    // ========================================================================
    // STEP 4: Backend - Compile WAT to Native Code using Cranelift
    // ========================================================================
    println!("\n[4/5] ⚙️  Compiling to native code (Cranelift)...");

    let runtime_builder = RuntimeBuilder::new()?;
    let state = Arc::new(Mutex::new(RiscVState::default()));

    // Set up initial PC and stack pointer
    {
        let mut s = state.lock().unwrap();
        s.pc = entry_point;
        s.memory_base = address_map.memory_base;

        // Initialize stack pointer (x2/sp) to top of available memory
        // RISC-V stacks grow downward, so we set sp to a high address
        // We'll use the end of our allocated memory region
        let stack_top = (address_map.required_memory_size() - 16) as i64;
        s.x_regs[2] = stack_top; // sp = x2
        println!("      ✓ Stack pointer initialized to: 0x{:x}", stack_top);
    }

    // Compile WAT to native code
    println!("      🔨 Compiling WASM bytecode to native x86-64/ARM...");
    let mut runtime = match runtime_builder.build_from_wat(&complete_wat, state.clone()) {
        Ok(rt) => {
            println!("      ✓ Native code compilation successful!");
            println!("      ✓ Target: {} architecture", std::env::consts::ARCH);
            rt
        }
        Err(e) => {
            eprintln!("\n❌ Compilation failed: {}", e);
            eprintln!("\nGenerated WAT code:");
            eprintln!("{}", complete_wat);
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

    for (offset, data) in memory_initializers {
        runtime.load_memory(offset, &data)?;
        println!("         • Loaded {} bytes at offset 0x{:x}", data.len(), offset);
    }

    println!("\n      ▶️  Executing native code...\n");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                   Program Output                         ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Execute the compiled native code
    match runtime.execute() {
        Ok(exit_code) => {
            println!("\n╔══════════════════════════════════════════════════════════╗");
            println!("║                  Execution Complete                      ║");
            println!("╚══════════════════════════════════════════════════════════╝");
            println!("Exit code: {}", exit_code);

            // Print final state
            let final_state = state.lock().unwrap();
            println!("\nFinal state:");
            println!("  PC: 0x{:x}", final_state.pc);
            println!("  Registers:");
            for i in 0..32 {
                if final_state.x_regs[i] != 0 {
                    println!("    x{}: 0x{:x} ({})", i, final_state.x_regs[i], final_state.x_regs[i]);
                }
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("\n❌ Execution error: {}", e);
            Err(e)
        }
    }
}
