# llama.cpp KV Actor: x86 Native and DoubleJIT AArch64

## Scope

This is a ReFlux-style I/O-path actor experiment, not an end-to-end language
model inference result. The actor models a single llama.cpp KV-cache page
movement: it copies a 4 KiB cache page, updates 8 KiB of persistent actor
control state, and validates cache-line sentinels. The source workload is the
KV defragmentation/copy path in the checked-out llama.cpp revision `29b9ae9`:
`llama.cpp:9584-9638` obtains KV tensors and moves contiguous ranges with
`memcpy` at lines 9622 and 9631.

This split follows the paper's actor policy. The paper treats I/O-path actors
as migratable and excludes dense transformer kernels from reversible placement.
The full llama.cpp CLI is not part of this artifact: no GGUF model is installed,
and its C++ runtime, packed SIMD kernels, threading, and POSIX surface exceed
the current freestanding x86 ELF translator ABI.

## Actor

`actors/llama_kv_copy_actor.c` copies one 4 KiB page for 2,048 actor epochs.
Each invocation therefore moves 8 MiB, retains an 8 KiB control state, and
returns zero only after verifying the copied KV-page sentinels. The x86 build
uses `rep movsq`; the AArch64 native comparison compiles the equivalent C loop.

Build on the AArch64 machine:

```bash
bash scripts/build_llama_kv_actor.sh
./target/llama-kv-actor/llama-kv-copy-actor.aarch64

cargo run --features x86_elf --example x86-elf-wasm -- \
  target/llama-kv-actor/llama-kv-copy-actor.x86_64
```

For the real x86 host, copy the generated `llama-kv-copy-actor.x86_64` and run:

```bash
python3 scripts/benchmark_actor.py --warmup 5 --runs 30 \
  --output x86-native.json -- taskset -c 0 ./llama-kv-copy-actor.x86_64
```

On the AArch64 DoubleJIT host, separate translation, Wasmer preparation, and
steady-state actor execution:

```bash
cargo run --features x86_elf --example x86-elf-wasm-bench -- \
  target/llama-kv-actor/llama-kv-copy-actor.x86_64 10 100
```

## Results

All measurements use five warmups and thirty native process trials where
applicable. The DoubleJIT result uses ten translation/preparation samples and
one hundred executions of a single prepared runtime. The x86 and AArch64 rows
are different physical machines, so cross-machine throughput ratios are not a
CPU architecture comparison.

| Path | Machine | Median time | 8 MiB effective throughput | Status |
| --- | --- | ---: | ---: | --- |
| x86 native | Intel Xeon 6740P, Linux 5.15, one pinned core | 2.271 ms | 3.440 GiB/s | `0` |
| AArch64 native | Parallels Ubuntu 24.04, Linux 6.8, one pinned vCPU | 0.717 ms | 10.901 GiB/s | `0` |
| x86 to DoubleJIT to AArch64, hot | Same Parallels AArch64 VM | 2.244 ms | 3.481 GiB/s | checksum `0` |

DoubleJIT cold costs for the same 78 reachable x86 instructions were 1.331 ms
for x86 ELF translation and 9.927 ms for Wasmer preparation. These are paid
once per prepared actor runtime; the hot result above reuses the translated
runtime and preserves the actor control state between epochs.

The DoubleJIT hot path is 3.13x slower than the native AArch64 version of this
actor on the same VM. It is within 1.2% of the native x86 wall-clock result,
but that latter comparison is informational only because the Xeon and the
Parallels VM are not comparable hardware.

## Interpretation

The result supports the paper's narrow claim for an I/O-style, memory-moving
actor: the same x86 actor ELF executes correctly after DoubleJIT on AArch64,
and its preparation cost can be amortized across repeated page movements. It
does not establish LLaMA token/s, model quality, KV-cache pressure behavior,
thermal migration, CXL coherence, or packed-SIMD support. Those require a
GGUF-backed llama.cpp integration and the remaining x86 C++/SIMD/runtime work.

## Drain-and-Switch Live Migration

`examples/llama-kv-live-migration.rs` adds an epoch-boundary live-migration
experiment. The source runtime executes eight actor epochs, then stops taking
new epochs. The migration code discovers the sized `actor_state` ELF symbol,
snapshots its 8,208-byte control state, creates a fresh AArch64 Wasmer runtime,
restores the checkpoint, and lets the destination execute eight more epochs.
The experiment rejects the run unless the destination memory exactly matches
the checkpoint before resuming and the final actor sequence is exactly the sum
of source and destination work.

```bash
cargo run --features x86_elf --example llama-kv-live-migration -- \
  target/llama-kv-actor/llama-kv-copy-actor.x86_64 8 8
```

Five runs on the Parallels AArch64 VM all passed. The source sequence was
`16,384` after eight epochs and the destination reached `32,768` after the
next eight; no work was lost or duplicated.

| Migration phase | Median | Notes |
| --- | ---: | --- |
| Control-state snapshot | 16.625 us | Copies 8,208 B from the source runtime's linear memory. |
| Target runtime preparation | 9.815 ms | Cold Wasmer module instantiation. |
| Control-state restore | 16.250 us | Writes and byte-compares the target control state before resume. |
| End-to-end prepare plus checkpoint | 9.848 ms | Snapshot + target preparation + restore. |

This is a real drain-and-switch transfer between two running DoubleJIT/Wasmer
instances, but it is a software migration experiment: the checkpoint is copied
through host memory and no physical CXL shared-PMR hardware is present. The KV
page is deterministic shared input for this actor, so only control state moves;
a full ReFlux hardware experiment would map the KV data and queue state into
coherent CXL.mem instead of relying on the actor's idempotent page copy.

## Crash-Consistent Replay

`src/backend/actor_migration.rs` implements the crash-replay state machine.
Its `PmrActorCheckpoint` is the software stand-in for a PLP-protected PMR
record: it contains the checkpointed control bytes, actor epoch, and an FNV-1a
integrity checksum. The coordinator has exactly one committed owner in every
phase:

| Durable phase | Committed owner | Crash recovery |
| --- | --- | --- |
| `Source` | Source | Before `ready`, source remains owner. |
| `Ready` | Source | Restore source from the durable checkpoint, discard the uncommitted destination, and re-checkpoint source. |
| `Active` | Destination | Construct a fresh destination runtime, restore its durable checkpoint, and continue there. |

The PMR submission model accepts incoming request IDs into a durable pending
queue. It refuses to execute while the state is `Ready`, and after ownership
is resolved it inserts each completed ID into a set; a duplicate ID is a hard
error. Active destination epochs re-checkpoint private control state, so a
post-`active` recovery resumes from the most recently committed owner epoch.

Run the deterministic crash injection experiment with:

```bash
cargo run --features x86_elf --example llama-kv-crash-replay -- \
  target/llama-kv-actor/llama-kv-copy-actor.x86_64 8 8
```

The run covered all three crash points. For each case, source had drained eight
epochs (`sequence = 16,384`) before migration, eight requests stayed pending,
and exactly those eight requests completed after recovery (`sequence = 32,768`):

| Injected crash | Recovered owner | Durable checkpoint | Completed requests | Result |
| --- | --- | ---: | ---: | --- |
| Before `ready` | Source | 0 B | 8 / 8 | passed |
| Between `ready` and `active` | Source | 8,208 B | 8 / 8 | passed |
| After `active` | Destination | 8,208 B | 8 / 8 | passed |

This validates the protocol logic and replay invariants inside a single
process. It does not yet survive a power cut or use actual PLP/CXL hardware;
the next hardware step is to replace the in-memory journal and pending queue
with a PMR mapping plus an ordered persistence barrier.
