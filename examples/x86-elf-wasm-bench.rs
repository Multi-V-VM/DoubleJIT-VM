#[cfg(feature = "x86_elf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::X86ElfWasmCompiler;
    use std::hint::black_box;
    use std::time::Instant;

    let path = std::env::args()
        .nth(1)
        .ok_or("usage: x86-elf-wasm-bench <x86_64-elf> [compile-iters] [hot-iters]")?;
    let compile_iterations = std::env::args()
        .nth(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(20_u64);
    let hot_iterations = std::env::args()
        .nth(3)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1_000_u64);
    let bytes = std::fs::read(&path)?;
    let compiler = X86ElfWasmCompiler::new();

    let start = Instant::now();
    for _ in 0..compile_iterations {
        black_box(compiler.compile_bytes(black_box(&bytes))?);
    }
    let translate_ns = start.elapsed().as_nanos() / u128::from(compile_iterations);

    let artifact = compiler.compile_bytes(&bytes)?;
    let start = Instant::now();
    for _ in 0..compile_iterations {
        black_box(artifact.prepare()?);
    }
    let prepare_ns = start.elapsed().as_nanos() / u128::from(compile_iterations);

    let mut runtime = artifact.prepare()?;
    for _ in 0..10 {
        black_box(runtime.execute()?);
    }
    let start = Instant::now();
    let mut checksum = 0_i64;
    for _ in 0..hot_iterations {
        checksum ^= black_box(runtime.execute()?);
    }
    let hot_ns = start.elapsed().as_nanos() / u128::from(hot_iterations);

    println!("artifact: {path}");
    println!("reachable_x86_instructions: {}", artifact.instruction_count());
    println!("translate_ns_per_iteration: {translate_ns}");
    println!("prepare_ns_per_iteration: {prepare_ns}");
    println!("hot_execute_ns_per_iteration: {hot_ns}");
    println!("checksum: {checksum}");
    Ok(())
}

#[cfg(not(feature = "x86_elf"))]
fn main() {
    eprintln!("Enable the benchmark with: cargo run --features x86_elf --example x86-elf-wasm-bench -- <x86_64-elf>");
    std::process::exit(1);
}
