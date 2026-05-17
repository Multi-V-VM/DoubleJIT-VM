#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::{collect_executable_instructions, AyaEbpfBuilder};
    use doublejit_vm::frontend::elf::ElfFile;

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path-to-riscv-elf> [output-ebpf.bin]", args[0]);
        std::process::exit(1);
    }

    let input = std::fs::read(&args[1])?;
    let elf_file = ElfFile::new(&input).map_err(|err| format!("ELF parse error: {err:?}"))?;
    let entries = collect_executable_instructions(&elf_file);

    println!("RISC-V executable instructions: {}", entries.len());
    println!("Compiling with one-to-one eBPF verifier...");

    let program = AyaEbpfBuilder::new().compile_entries(&entries)?;
    let report = program.verification_report();

    println!("eBPF instructions: {}", report.target_instructions);
    println!("Mapped instructions: {}", report.mapped_instructions);
    println!("Trailer instructions: {}", report.trailer_instructions);
    println!("One-to-one verified: {}", report.one_to_one);

    if std::env::var("PRINT_EBPF").is_ok() {
        for (idx, ins) in program.instructions().iter().enumerate() {
            println!(
                "{idx:04}: code=0x{:02x} dst=r{} src=r{} off={} imm={}",
                ins.code,
                ins.dst_reg(),
                ins.src_reg(),
                ins.off,
                ins.imm
            );
        }
    }

    if let Some(output_path) = args.get(2) {
        std::fs::write(output_path, program.to_bytes())?;
        println!("Wrote raw eBPF bytecode: {output_path}");
    }

    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!("Enable the eBPF compiler with: cargo run --features ebpf --example riscv-ebpf-compiler -- <path-to-riscv-elf>");
    std::process::exit(1);
}
