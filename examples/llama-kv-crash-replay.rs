#[cfg(feature = "x86_elf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use doublejit_vm::backend::{
        ActorCrashPoint, ActorOwner, X86ActorReplayMigration, X86ElfWasmCompiler,
    };

    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(
        "usage: llama-kv-crash-replay <x86_64-actor-elf> [source-epochs] [queued-requests]",
    )?;
    let source_epochs = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(8_u64);
    let queued_requests = args
        .next()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(8_u64);
    if source_epochs == 0 {
        return Err("source-epochs must be non-zero".into());
    }

    let bytes = std::fs::read(&path)?;
    let artifact = X86ElfWasmCompiler::new().compile_bytes(&bytes)?;
    let control = artifact
        .symbol_region("actor_state")
        .ok_or("actor_state must be a sized ELF symbol")?;

    for crash in [
        ActorCrashPoint::BeforeReady,
        ActorCrashPoint::BetweenReadyAndActive,
        ActorCrashPoint::AfterActive,
    ] {
        let mut migration = X86ActorReplayMigration::new(artifact.clone(), control)?;
        for _ in 0..source_epochs {
            migration.execute_source_epoch()?;
        }
        let source_state = migration.snapshot_control_state()?;
        let source_sequence = read_u64(&source_state)?;
        let sequence_per_epoch = source_sequence / source_epochs;
        if sequence_per_epoch == 0 || source_sequence % source_epochs != 0 {
            return Err("source actor does not advance by a fixed epoch delta".into());
        }

        for request_id in 0..queued_requests {
            migration.enqueue_request(request_id)?;
        }

        match crash {
            ActorCrashPoint::BeforeReady => {
                migration.recover_after_crash(crash)?;
            }
            ActorCrashPoint::BetweenReadyAndActive => {
                migration.publish_ready()?;
                migration.reconstruct_destination()?;
                migration.recover_after_crash(crash)?;
            }
            ActorCrashPoint::AfterActive => {
                migration.publish_ready()?;
                migration.reconstruct_destination()?;
                migration.publish_active()?;
                migration.recover_after_crash(crash)?;
            }
        }

        let owner = migration.owner();
        migration.execute_resolved_requests()?;
        let final_state = migration.snapshot_control_state()?;
        let final_sequence = read_u64(&final_state)?;
        let expected_sequence = source_sequence + sequence_per_epoch * queued_requests;
        if final_sequence != expected_sequence {
            return Err(format!(
                "{crash:?}: expected final sequence {expected_sequence}, got {final_sequence}"
            )
            .into());
        }
        if migration.completed_request_count() != queued_requests as usize
            || migration.pending_request_count() != 0
        {
            return Err(format!("{crash:?}: PMR submission replay was incomplete").into());
        }
        let expected_owner = match crash {
            ActorCrashPoint::AfterActive => ActorOwner::Destination,
            ActorCrashPoint::BeforeReady | ActorCrashPoint::BetweenReadyAndActive => {
                ActorOwner::Source
            }
        };
        if owner != expected_owner {
            return Err(format!("{crash:?}: recovered the wrong owner {owner:?}").into());
        }

        let checkpoint_bytes = migration
            .durable_checkpoint()
            .map(|checkpoint| checkpoint.bytes.len())
            .unwrap_or(0);
        println!("scenario: {crash:?}");
        println!("recovered_owner: {owner:?}");
        println!("checkpoint_bytes: {checkpoint_bytes}");
        println!("queued_requests: {queued_requests}");
        println!("completed_requests: {}", migration.completed_request_count());
        println!("source_sequence: {source_sequence}");
        println!("final_sequence: {final_sequence}");
        println!("replay_status: passed");
    }
    Ok(())
}

#[cfg(feature = "x86_elf")]
fn read_u64(bytes: &[u8]) -> Result<u64, Box<dyn std::error::Error>> {
    let raw: [u8; 8] = bytes
        .get(..8)
        .ok_or("actor control checkpoint is truncated")?
        .try_into()?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(not(feature = "x86_elf"))]
fn main() {
    eprintln!("Enable crash replay with: cargo run --features x86_elf --example llama-kv-crash-replay -- <x86_64-actor-elf>");
    std::process::exit(1);
}
