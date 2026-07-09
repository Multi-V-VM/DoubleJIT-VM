#[cfg(feature = "x86_elf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::X86ElfWasmCompiler;
    use std::time::Instant;

    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(
        "usage: llama-kv-live-migration <x86_64-actor-elf> [source-epochs] [target-epochs]",
    )?;
    let source_epochs = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(8_u64);
    let target_epochs = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(8_u64);
    if source_epochs == 0 {
        return Err("source-epochs must be non-zero so the control-state delta is measurable".into());
    }

    let bytes = std::fs::read(&path)?;
    let artifact = X86ElfWasmCompiler::new().compile_bytes(&bytes)?;
    let control = artifact
        .symbol_region("actor_state")
        .ok_or("actor_state must be a sized ELF symbol")?;

    let mut source = artifact.prepare()?;
    for _ in 0..source_epochs {
        if source.execute()? != 0 {
            return Err("source actor returned a failed page-copy status".into());
        }
    }
    let snapshot_started = Instant::now();
    let checkpoint = source.snapshot_region(control)?;
    let snapshot_ns = snapshot_started.elapsed().as_nanos();
    let source_sequence = read_u64(&checkpoint, 0)?;
    let sequence_per_epoch = source_sequence / source_epochs;
    if sequence_per_epoch == 0 || source_sequence % source_epochs != 0 {
        return Err("source actor control state did not advance by a fixed epoch delta".into());
    }

    let target_prepare_started = Instant::now();
    let mut target = artifact.prepare()?;
    let target_prepare_ns = target_prepare_started.elapsed().as_nanos();
    let restore_started = Instant::now();
    target.restore_region(control, &checkpoint)?;
    let restore_ns = restore_started.elapsed().as_nanos();
    if target.snapshot_region(control)? != checkpoint {
        return Err("target control state differs from the source checkpoint".into());
    }

    for _ in 0..target_epochs {
        if target.execute()? != 0 {
            return Err("target actor returned a failed page-copy status".into());
        }
    }
    let final_state = target.snapshot_region(control)?;
    let final_sequence = read_u64(&final_state, 0)?;
    let expected_sequence = source_sequence + sequence_per_epoch * target_epochs;
    if final_sequence != expected_sequence {
        return Err(format!(
            "migration lost or duplicated actor work: expected sequence {expected_sequence}, got {final_sequence}"
        )
        .into());
    }

    println!("actor: {path}");
    println!("reachable_x86_instructions: {}", artifact.instruction_count());
    println!("source_epochs: {source_epochs}");
    println!("target_epochs: {target_epochs}");
    println!("control_state_bytes: {}", checkpoint.len());
    println!("source_sequence: {source_sequence}");
    println!("final_sequence: {final_sequence}");
    println!("checkpoint_snapshot_ns: {snapshot_ns}");
    println!("target_prepare_ns: {target_prepare_ns}");
    println!("checkpoint_restore_ns: {restore_ns}");
    println!("migration_total_ns: {}", snapshot_ns + target_prepare_ns + restore_ns);
    println!("migration_status: passed");
    Ok(())
}

#[cfg(feature = "x86_elf")]
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn std::error::Error>> {
    let end = offset.checked_add(8).ok_or("control-state offset overflow")?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or("control-state checkpoint is truncated")?
        .try_into()?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(not(feature = "x86_elf"))]
fn main() {
    eprintln!("Enable the migration experiment with: cargo run --features x86_elf --example llama-kv-live-migration -- <x86_64-actor-elf>");
    std::process::exit(1);
}
