use doublejit_vm::frontend::binary::Binary;
use doublejit_vm::frontend::instruction::Instruction;

fn main() {
    // Parse command line arguments
    let path = std::env::args().nth(1).expect("Usage: doublejit-runner <path-to-binary>");

    println!("Loading binary from: {}", path);

    // Load and parse the binary from file
    let binary_data = std::fs::read(&path)
        .expect(&format!("Failed to read binary file: {}", path));

    let bin = Binary::parse(&binary_data)
        .expect("Failed to parse binary");

    println!("Binary loaded successfully");
    println!("Entry point: 0x{:x}", bin.entry_point);

    // Create WASM module for execution
    let mut wasm_module = doublejit_vm::middleend::WasmModule::new()
        .expect("Failed to create WASM module");

    println!("WASM module initialized");

    // Create WASM emitter for instruction translation
    let mut emitter = doublejit_vm::middleend::WasmEmitter::new();

    // Start the main function
    emitter.start_function("translated_code");

    // Translate RISC-V instructions to WASM
    println!("\nTranslating RISC-V instructions to WASM...");
    let mut pc = bin.entry_point;
    let mut instr_count = 0;

    // For demonstration, let's parse a few instructions from the text section
    // In a real implementation, you would iterate through all executable sections
    for section in &bin.sections {
        if section.name.contains("text") {
            println!("Processing .text section at 0x{:x}", section.addr);

            let mut offset = 0;
            while offset + 4 <= section.data.len() {
                let instr_bytes = &section.data[offset..offset + 4];

                // Try to parse the instruction
                if let Some(instr) = Instruction::parse(instr_bytes) {
                    match emitter.emit_instruction(pc, &instr) {
                        Ok(_) => {
                            instr_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to emit instruction at 0x{:x}: {}", pc, e);
                        }
                    }
                } else {
                    // Unknown instruction, skip
                    println!("Unknown instruction at 0x{:x}: {:02x} {:02x} {:02x} {:02x}",
                             pc, instr_bytes[0], instr_bytes[1], instr_bytes[2], instr_bytes[3]);
                }

                pc += 4;
                offset += 4;

                // Limit translation for demo purposes
                if instr_count >= 100 {
                    println!("Translated first {} instructions (demo limit)", instr_count);
                    break;
                }
            }
        }
    }

    // End the function
    emitter.end_function();

    // Get the generated WAT code
    let wat_code = emitter.finalize();

    println!("\n=== Generated WASM (WAT) Code ===");
    println!("{}", wat_code);

    println!("\n=== Translation Summary ===");
    println!("Total instructions translated: {}", instr_count);
    println!("Entry point: 0x{:x}", bin.entry_point);

    // In a full implementation, you would:
    // 1. Complete the WASM module with the translated code
    // 2. Load initial memory state from binary sections
    // 3. Execute the WASM module
    // 4. Handle syscalls and I/O

    println!("\nNote: Full execution not yet implemented.");
    println!("This demo shows RISC-V to WASM translation only.");
}