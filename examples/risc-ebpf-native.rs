#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::{
        Arm64EbpfCompiler, EbpfNativeCompiler, NativeTarget, RiscV64EbpfCompiler,
    };
    let mut args = std::env::args().skip(1);
    let target = match args.next().as_deref() {
        Some("arm64") | Some("aarch64") => NativeTarget::Arm64,
        Some("riscv64") => NativeTarget::RiscV64,
        None => NativeTarget::host().unwrap_or(NativeTarget::Arm64),
        _ => return Err("usage: risc-ebpf-native [arm64|riscv64] [directory]".into()),
    };
    let dir = args.next();
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let words: Vec<u32> = match target {
        NativeTarget::Arm64 => vec![0xd2800500, 0x91000800, 0xd65f03c0],
        NativeTarget::RiscV64 => vec![0x02800513, 0x00250513, 0x00008067],
    };
    let source: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let bpf = match target {
        NativeTarget::Arm64 => Arm64EbpfCompiler::new().compile(&source)?,
        NativeTarget::RiscV64 => RiscV64EbpfCompiler::new().compile(&source)?,
    };
    let plain = EbpfNativeCompiler::new(target).compile(bpf.instructions())?;
    let optimized = EbpfNativeCompiler::new(target)
        .with_native_ops(true)
        .compile(bpf.instructions())?;
    println!(
        "{target:?} -> eBPF -> {target:?}: {} BPF instructions, {} -> {} native bytes",
        bpf.instructions().len(),
        plain.machine_code().len(),
        optimized.machine_code().len()
    );
    if let Some(dir) = dir {
        std::fs::create_dir_all(&dir)?;
        let dir = std::path::Path::new(&dir);
        std::fs::write(dir.join("source.bin"), source)?;
        std::fs::write(dir.join("program.ebpf"), bpf.to_bytes())?;
        std::fs::write(dir.join("plain.bin"), plain.machine_code())?;
        std::fs::write(dir.join("optimized.bin"), optimized.machine_code())?;
    }
    if NativeTarget::host() == Some(target) {
        for artifact in [plain, optimized] {
            let runtime = artifact.prepare()?;
            for value in [0, 1, u64::MAX] {
                let result = runtime.execute_with_input(value)?;
                assert_eq!(result, 42);
            }
        }
        println!("result: 42 (plain and optimized, 3 runtime inputs)");
    } else {
        println!("Generated only: execution requires a matching Linux host or a target binary under QEMU.");
    }
    Ok(())
}
#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!("Enable --features ebpf");
    std::process::exit(1);
}
