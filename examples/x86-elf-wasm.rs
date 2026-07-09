#[cfg(feature = "x86_elf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::X86ElfWasmCompiler;

    let path = std::env::args().nth(1).ok_or("usage: x86-elf-wasm <x86_64-elf> [--wat]")?;
    let bytes = std::fs::read(&path)?;
    let artifact = X86ElfWasmCompiler::new().compile_bytes(&bytes)?;
    if std::env::args().nth(2).as_deref() == Some("--wat") {
        print!("{}", artifact.wat());
        return Ok(());
    }
    println!("translated ELF: {path}");
    println!("reachable x86 instructions: {}", artifact.instruction_count());
    println!("result: {}", artifact.execute()?);
    Ok(())
}

#[cfg(not(feature = "x86_elf"))]
fn main() {
    eprintln!("Enable the ELF path with: cargo run --features x86_elf --example x86-elf-wasm -- <x86_64-elf>");
    std::process::exit(1);
}
