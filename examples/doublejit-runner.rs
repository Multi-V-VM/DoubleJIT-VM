use doublejit_vm::frontend::binary::Binary;
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
    let elf_file = ElfFile::new(&binary_data)?;

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
                if let Some(instr) = Instruction::parse(instr_bytes) {
                    match emitter.emit_instruction(pc, &instr) {
                        Ok(_) => {
                            translated_instructions += 1;
                        }
                        Err(e) => {
                            eprintln!("         ⚠ Warning at 0x{:x}: {}", pc, e);
                        }
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
    let wat_code = emitter.finalize();

    println!("      ✓ Total instructions scanned: {}", total_instructions);
    println!("      ✓ Successfully translated: {}", translated_instructions);
    println!("      ✓ WAT code size: {} bytes", wat_code.len());

    // ========================================================================
    // STEP 4: Backend - Compile WAT to Native Code using Cranelift
    // ========================================================================
    println!("\n[4/5] ⚙️  Compiling to native code (Cranelift)...");

    let runtime_builder = RuntimeBuilder::new()?;
    let state = Arc::new(Mutex::new(RiscVState::default()));

    // Set up initial PC
    {
        let mut s = state.lock().unwrap();
        s.pc = entry_point;
        s.memory_base = address_map.memory_base;
    }

    // Compile WAT to native code
    println!("      🔨 Compiling WASM bytecode to native x86-64/ARM...");
    let mut runtime = match runtime_builder.build_from_wat(&wat_code, state.clone()) {
        Ok(rt) => {
            println!("      ✓ Native code compilation successful!");
            println!("      ✓ Target: {} architecture", std::env::consts::ARCH);
            rt
        }
        Err(e) => {
            eprintln!("\n❌ Compilation failed: {}", e);
            eprintln!("\nGenerated WAT code:");
            eprintln!("{}", wat_code);
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
