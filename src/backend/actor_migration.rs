//! Crash-consistent, drain-and-switch actor migration for x86 ELF/WASM actors.
//!
//! The protocol keeps a single committed owner: source before `active`, and
//! destination after `active`. The in-memory journal models a PLP-protected
//! PMR record; callers can inject the three recovery points used by ReFlux.

use super::{
    X86ElfWasmArtifact, X86ElfWasmError, X86ElfWasmMemoryRegion, X86ElfWasmRuntime,
};
use std::collections::{BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorOwner {
    Source,
    Destination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorMigrationPhase {
    Source,
    Ready,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorCrashPoint {
    BeforeReady,
    BetweenReadyAndActive,
    AfterActive,
}

#[derive(Debug, Clone)]
pub struct PmrActorCheckpoint {
    pub actor_epoch: u64,
    pub bytes: Vec<u8>,
    pub checksum: u64,
}

/// A single-actor migration coordinator with a PMR-backed submission queue.
///
/// Requests are accepted into `pending_requests`, but the coordinator invokes
/// the translated actor only after recovery resolves ownership. The completed
/// request set rejects duplicate execution by construction.
pub struct X86ActorReplayMigration {
    artifact: X86ElfWasmArtifact,
    control_region: X86ElfWasmMemoryRegion,
    source: X86ElfWasmRuntime,
    destination: Option<X86ElfWasmRuntime>,
    owner: ActorOwner,
    phase: ActorMigrationPhase,
    actor_epoch: u64,
    checkpoint: Option<PmrActorCheckpoint>,
    pending_requests: VecDeque<u64>,
    completed_requests: BTreeSet<u64>,
}

impl X86ActorReplayMigration {
    pub fn new(
        artifact: X86ElfWasmArtifact,
        control_region: X86ElfWasmMemoryRegion,
    ) -> Result<Self, X86ElfWasmError> {
        if control_region.size == 0 {
            return Err(migration_error("actor control region must not be empty"));
        }
        let source = artifact.prepare()?;
        Ok(Self {
            artifact,
            control_region,
            source,
            destination: None,
            owner: ActorOwner::Source,
            phase: ActorMigrationPhase::Source,
            actor_epoch: 0,
            checkpoint: None,
            pending_requests: VecDeque::new(),
            completed_requests: BTreeSet::new(),
        })
    }

    pub fn owner(&self) -> ActorOwner {
        self.owner
    }

    pub fn phase(&self) -> ActorMigrationPhase {
        self.phase
    }

    pub fn actor_epoch(&self) -> u64 {
        self.actor_epoch
    }

    pub fn durable_checkpoint(&self) -> Option<&PmrActorCheckpoint> {
        self.checkpoint.as_ref()
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn completed_request_count(&self) -> usize {
        self.completed_requests.len()
    }

    /// Run work already admitted to the source before it starts draining.
    pub fn execute_source_epoch(&mut self) -> Result<(), X86ElfWasmError> {
        self.require(ActorOwner::Source, ActorMigrationPhase::Source)?;
        self.execute_owner_epoch()
    }

    /// Append a new request to the PMR-backed submission path.
    pub fn enqueue_request(&mut self, request_id: u64) -> Result<(), X86ElfWasmError> {
        if self.completed_requests.contains(&request_id)
            || self.pending_requests.iter().any(|pending| *pending == request_id)
        {
            return Err(migration_error(format!(
                "request {request_id} is already admitted"
            )));
        }
        self.pending_requests.push_back(request_id);
        Ok(())
    }

    /// Drain source work and durably publish a `ready` checkpoint.
    pub fn publish_ready(&mut self) -> Result<(), X86ElfWasmError> {
        self.require(ActorOwner::Source, ActorMigrationPhase::Source)?;
        self.checkpoint = Some(self.checkpoint_source()?);
        self.phase = ActorMigrationPhase::Ready;
        Ok(())
    }

    /// Construct the destination from the ready checkpoint without ownership.
    pub fn reconstruct_destination(&mut self) -> Result<(), X86ElfWasmError> {
        if self.phase != ActorMigrationPhase::Ready {
            return Err(migration_error("destination reconstruction requires ready"));
        }
        let checkpoint = self.require_checkpoint()?.clone();
        self.verify_checkpoint(&checkpoint)?;
        let mut destination = self.artifact.prepare()?;
        destination.restore_region(self.control_region, &checkpoint.bytes)?;
        if destination.snapshot_region(self.control_region)? != checkpoint.bytes {
            return Err(migration_error("destination reconstruction changed checkpoint bytes"));
        }
        self.destination = Some(destination);
        Ok(())
    }

    /// Atomically transfer the committed owner after destination reconstruction.
    pub fn publish_active(&mut self) -> Result<(), X86ElfWasmError> {
        if self.phase != ActorMigrationPhase::Ready || self.destination.is_none() {
            return Err(migration_error("active publication requires a reconstructed destination"));
        }
        self.owner = ActorOwner::Destination;
        self.phase = ActorMigrationPhase::Active;
        Ok(())
    }

    /// Inject a control-plane crash and recover the single committed owner.
    pub fn recover_after_crash(&mut self, point: ActorCrashPoint) -> Result<(), X86ElfWasmError> {
        match point {
            ActorCrashPoint::BeforeReady => {
                if self.phase != ActorMigrationPhase::Source {
                    return Err(migration_error("before-ready crash requires source ownership"));
                }
                self.owner = ActorOwner::Source;
            }
            ActorCrashPoint::BetweenReadyAndActive => {
                if self.phase != ActorMigrationPhase::Ready {
                    return Err(migration_error("ready-to-active crash requires a ready checkpoint"));
                }
                let checkpoint = self.require_checkpoint()?.clone();
                self.verify_checkpoint(&checkpoint)?;
                self.source
                    .restore_region(self.control_region, &checkpoint.bytes)?;
                self.checkpoint = Some(self.checkpoint_source()?);
                self.destination = None;
                self.owner = ActorOwner::Source;
                self.phase = ActorMigrationPhase::Source;
            }
            ActorCrashPoint::AfterActive => {
                if self.phase != ActorMigrationPhase::Active {
                    return Err(migration_error("after-active crash requires destination ownership"));
                }
                let checkpoint = self.require_checkpoint()?.clone();
                self.verify_checkpoint(&checkpoint)?;
                let mut recovered_destination = self.artifact.prepare()?;
                recovered_destination.restore_region(self.control_region, &checkpoint.bytes)?;
                self.destination = Some(recovered_destination);
                self.owner = ActorOwner::Destination;
            }
        }
        Ok(())
    }

    /// Run all pending submissions only after ownership has been resolved.
    pub fn execute_resolved_requests(&mut self) -> Result<(), X86ElfWasmError> {
        if self.phase == ActorMigrationPhase::Ready {
            return Err(migration_error("cannot execute requests while ownership is unresolved"));
        }
        while let Some(request_id) = self.pending_requests.pop_front() {
            self.execute_owner_epoch()?;
            if !self.completed_requests.insert(request_id) {
                return Err(migration_error(format!(
                    "request {request_id} would execute twice"
                )));
            }
        }
        Ok(())
    }

    pub fn snapshot_control_state(&self) -> Result<Vec<u8>, X86ElfWasmError> {
        match self.owner {
            ActorOwner::Source => self.source.snapshot_region(self.control_region),
            ActorOwner::Destination => self.destination()?.snapshot_region(self.control_region),
        }
    }

    fn execute_owner_epoch(&mut self) -> Result<(), X86ElfWasmError> {
        let result = match self.owner {
            ActorOwner::Source => self.source.execute()?,
            ActorOwner::Destination => self.destination_mut()?.execute()?,
        };
        if result != 0 {
            return Err(migration_error(format!(
                "actor epoch {next_epoch} returned {result}",
                next_epoch = self.actor_epoch + 1
            )));
        }
        self.actor_epoch += 1;
        if self.phase == ActorMigrationPhase::Active {
            self.checkpoint = Some(self.checkpoint_destination()?);
        }
        Ok(())
    }

    fn checkpoint_source(&self) -> Result<PmrActorCheckpoint, X86ElfWasmError> {
        self.new_checkpoint(self.source.snapshot_region(self.control_region)?)
    }

    fn checkpoint_destination(&self) -> Result<PmrActorCheckpoint, X86ElfWasmError> {
        self.new_checkpoint(self.destination()?.snapshot_region(self.control_region)?)
    }

    fn new_checkpoint(&self, bytes: Vec<u8>) -> Result<PmrActorCheckpoint, X86ElfWasmError> {
        if bytes.len() as u64 != self.control_region.size {
            return Err(migration_error("snapshot does not cover the full control region"));
        }
        Ok(PmrActorCheckpoint {
            actor_epoch: self.actor_epoch,
            checksum: checkpoint_checksum(&bytes),
            bytes,
        })
    }

    fn verify_checkpoint(&self, checkpoint: &PmrActorCheckpoint) -> Result<(), X86ElfWasmError> {
        if checkpoint.checksum != checkpoint_checksum(&checkpoint.bytes) {
            return Err(migration_error("durable checkpoint checksum does not match its bytes"));
        }
        Ok(())
    }

    fn require(
        &self,
        owner: ActorOwner,
        phase: ActorMigrationPhase,
    ) -> Result<(), X86ElfWasmError> {
        if self.owner != owner || self.phase != phase {
            return Err(migration_error(format!(
                "expected owner {owner:?} in phase {phase:?}, found {:?}/{:?}",
                self.owner, self.phase
            )));
        }
        Ok(())
    }

    fn require_checkpoint(&self) -> Result<&PmrActorCheckpoint, X86ElfWasmError> {
        self.checkpoint
            .as_ref()
            .ok_or_else(|| migration_error("no durable ready checkpoint is available"))
    }

    fn destination(&self) -> Result<&X86ElfWasmRuntime, X86ElfWasmError> {
        self.destination
            .as_ref()
            .ok_or_else(|| migration_error("destination runtime is not reconstructed"))
    }

    fn destination_mut(&mut self) -> Result<&mut X86ElfWasmRuntime, X86ElfWasmError> {
        self.destination
            .as_mut()
            .ok_or_else(|| migration_error("destination runtime is not reconstructed"))
    }
}

fn checkpoint_checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn migration_error(message: impl Into<String>) -> X86ElfWasmError {
    X86ElfWasmError::Runtime(message.into())
}

#[cfg(test)]
mod tests {
    use super::checkpoint_checksum;

    #[test]
    fn checkpoint_checksum_changes_with_the_durable_bytes() {
        assert_ne!(checkpoint_checksum(&[1, 2]), checkpoint_checksum(&[1, 3]));
    }
}
