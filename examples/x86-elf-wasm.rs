#[cfg(feature = "x86_elf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::X86ElfWasmCompiler;

    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: x86-elf-wasm <x86_64-elf> [--wat] [guest-args...]")?;
    let bytes = std::fs::read(&path)?;
    let artifact = X86ElfWasmCompiler::new().compile_bytes(&bytes)?;
    let guest_args = args.collect::<Vec<_>>();
    if guest_args.first().map(String::as_str) == Some("--wat") {
        print!("{}", artifact.wat());
        return Ok(());
    }
    println!("translated ELF: {path}");
    println!("reachable x86 instructions: {}", artifact.instruction_count());
    let mut runtime = artifact.prepare()?;
    let mut argv = Vec::with_capacity(guest_args.len() + 1);
    argv.push(path.clone());
    argv.extend(guest_args);
    println!("result: {}", runtime.execute_with_args(&argv)?);
    Ok(())
}

#[cfg(not(feature = "x86_elf"))]
fn main() {
    eprintln!("Enable the ELF path with: cargo run --features x86_elf --example x86-elf-wasm -- <x86_64-elf>");
    std::process::exit(1);
}
