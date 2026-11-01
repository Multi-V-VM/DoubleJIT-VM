#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::{EbpfX86Compiler, X86EbpfCompiler};
    use doublejit_vm::X86Mode;

    let mut args = std::env::args().skip(1);
    let mode = match args.next().as_deref() {
        None | Some("x86_64") | Some("x64") => X86Mode::X86_64,
        Some("x86") => X86Mode::X86,
        Some(other) => {
            return Err(
                format!("usage: x86-ebpf-x86 [x86|x86_64] [output-directory], got {other}").into(),
            )
        }
    };
    let output = args.next();
    if args.next().is_some() {
        return Err("usage: x86-ebpf-x86 [x86|x86_64] [output-directory]".into());
    }

    // mov accumulator, 40; add accumulator, 2; ret
    let input = match mode {
        X86Mode::X86 => vec![0xb8, 40, 0, 0, 0, 0x83, 0xc0, 2, 0xc3],
        X86Mode::X86_64 => vec![0x48, 0xc7, 0xc0, 40, 0, 0, 0, 0x48, 0x83, 0xc0, 2, 0xc3],
    };
    let ebpf = X86EbpfCompiler::new(mode).compile(&input)?;
    let native = EbpfX86Compiler::new().compile(ebpf.instructions())?;
    println!("pipeline: {mode:?} -> eBPF -> x86_64 (direct userspace JIT)");
    println!("input x86 bytes: {:02x?}", input);
    println!("eBPF instructions: {}", ebpf.instructions().len());
    println!("eBPF bytes: {:02x?}", ebpf.to_bytes());
    println!("native x86_64 bytes: {:02x?}", native.machine_code());

    if let Some(directory) = output {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory)?;
        std::fs::write(directory.join("input-x86.bin"), &input)?;
        std::fs::write(directory.join("program.ebpf"), ebpf.to_bytes())?;
        std::fs::write(directory.join("output-x86_64.bin"), native.machine_code())?;
        println!("artifacts: {}", directory.display());
    }

    let runtime = native.prepare()?;
    let result = runtime.execute()?;
    if result != 42 {
        return Err(format!("expected 42, got {result}").into());
    }
    println!("result: {result}");
    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!(
        "Enable the pipeline with: cargo run --features ebpf --example x86-ebpf-x86 -- x86_64"
    );
    std::process::exit(1);
}
