#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::{EbpfWasmCompiler, X86EbpfCompiler};
    use doublejit_vm::X86Mode;

    let mode = match std::env::args().nth(1).as_deref() {
        None | Some("x86_64") | Some("x64") => X86Mode::X86_64,
        Some("x86") => X86Mode::X86,
        Some(other) => return Err(format!("usage: x86-ebpf-wasm [x86|x86_64], got {other}").into()),
    };

    // Leaf function: mov accumulator, 40; add accumulator, 2; ret.
    let bytes: Vec<u8> = match mode {
        X86Mode::X86 => vec![0xb8, 40, 0, 0, 0, 0x83, 0xc0, 2, 0xc3],
        X86Mode::X86_64 => vec![
            0x48, 0xc7, 0xc0, 40, 0, 0, 0, // mov rax, 40
            0x48, 0x83, 0xc0, 2, // add rax, 2
            0xc3,
        ],
    };

    let ebpf = X86EbpfCompiler::new(mode).compile(&bytes)?;
    let wasm = EbpfWasmCompiler::new().compile(ebpf.instructions())?;
    let result = wasm.execute()?;

    println!("frontend: {mode:?}");
    println!("eBPF instructions: {}", ebpf.instructions().len());
    println!("WASM bytes: {}", wasm.wasm_bytes()?.len());
    println!("result: {result}");
    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!(
        "Enable the pipeline with: cargo run --features ebpf --example x86-ebpf-wasm -- x86_64"
    );
    std::process::exit(1);
}
