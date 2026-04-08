# Zyli Implementation Plan

## Goal

Zyli is a clean Zig implementation of the Hyli protocol.

The long-term target is full wire, cryptographic, and state compatibility with Hyli, including the ability to connect to Hyli testnet and behave as a valid peer. The short-term target is narrower: build an observer and then follower-grade node that can connect to the network, decode and validate protocol traffic, replay state correctly, and only later move into active protocol participation.

In parallel, `zolt-arith` should become the reusable Zig arithmetic and cryptography package that Zyli depends on. For this project, BLS12-381 belongs there directly, not as a temporary one-off inside Zyli.

## What This Plan Optimizes For

- Exact compatibility over architectural similarity.
- Durable module boundaries over Rust-crate mirroring.
- Pure protocol code before services and operators.
- Deterministic test artifacts before ambitious implementation breadth.
- Narrow, proven abstractions instead of framework-building.

## Core Principles

- Compatibility first. Zyli must match Hyli's byte formats, hashes, signatures, signable payloads, quorum rules, and replay semantics before it tries to "feel native".
- Semantic boundaries, not Rust boundaries. Hyli's workspace split is useful for discovery, but Zyli should be organized around durable responsibilities: model, crypto, wire, replay, storage, runtime, and node logic.
- Fixture-first development. Every consensus-critical encoding or hash should have a Rust-produced golden corpus before it gets a Zig implementation.
- Runtime minimalism. Zyli does not need a Tokio clone. It needs sockets, timers, bounded queues, cancellation, supervised subprocesses, and a small amount of structured concurrency.
- Reuse with discipline. `zolt-arith` should be the home for reusable arithmetic and cryptography, but its public surface should still be driven by real Hyli requirements, not by speculative library design.
- External proof systems stay external. SP1, RISC0, Jolt, and similar verifiers should remain in their native implementation languages behind narrow process boundaries.
- Use Zig capabilities. Zig source code is in ../zig if needed

## What Hyli Actually Looks Like

Hyli is not one monolith. The Rust codebase already separates several durable responsibilities:

- `hyli-model`: protocol and state types, Borsh layouts, hashes, transaction and block structures.
- `hyli-crypto`: validator BLS signing and aggregate verification.
- `hyli-net`: length-delimited TCP framing, pings, handshakes, peer connection state.
- `mempool`: lane-local `DataProposal` chains, PoDA voting, sync replies, proof preprocessing.
- `consensus`: prepare / vote / confirm / commit / timeout / sync logic.
- `data_availability`: signed block storage and historical streaming.
- `node_state`: replay of signed blocks into contracts, unsettled transactions, native verifiers, and settlement outcomes.
- `verifier_workers`: a small IPC boundary for external proof verification.

That split is helpful because it shows where Zyli should have stable seams. It also shows what should not be coupled together early.

## Protocol Surfaces That Matter First

These are the compatibility-critical surfaces Zyli needs first:

- Borsh encoding and decoding of Hyli protocol and storage types.
- Hash definitions for transactions, data proposals, consensus proposals, Hyli outputs, and certificates.
- BLS12-381 `min_pk` semantics used for validator signatures and aggregate signatures.
- TCP length-delimited framing and `PING` handling.
- P2P handshake semantics, including canal names and signed connection data.
- Signed message header validation, including exact "what gets signed" rules per network message.
- Mempool network messages:
  - `DataProposal`
  - `DataVote`
  - `SyncRequest`
  - `SyncReply`
- Consensus network messages:
  - `Prepare`
  - `PrepareVote`
  - `Confirm`
  - `ConfirmAck`
  - `Commit`
  - `Timeout`
  - `TimeoutCertificate`
  - `ValidatorCandidacy`
  - `SyncRequest`
  - `SyncReply`
- Data availability request / reply streaming.
- Node-state replay rules for unsettled blob transactions, verified proofs, contract updates, and native verifiers.
- Verifier-worker IPC messages and supervision rules.

## Program Structure

The work should be split into three tracks, not two:

1. `zyli`
   The Hyli-compatible node implementation: protocol model, wire layer, storage, consensus, mempool, DA sync, replay, runtime, and operations.

2. `compat`
   A compatibility corpus and differential harness: golden fixtures, trace captures, replay vectors, and cross-implementation checks against Rust Hyli. This is not optional. It is the executable spec.

3. `zolt-arith`
   A reusable Zig arithmetic and cryptography package that Zyli depends on directly. Its first concrete milestone is BLS12-381 support sufficient for Hyli validator verification.

## Durable Module Boundaries

### `zyli/model`

- Borsh codec
- Hyli protocol types
- Hash functions and signable payload builders
- Genesis and chain-identity artifacts
- No networking, storage, timers, or subprocess logic

### `zyli/crypto`

- BLS12-381 public key, signature, aggregate verification
- Hash-to-curve / domain separation required by Hyli
- Native verifier helpers needed by replay (`blst`, `sha3_256`, `secp256k1`)
- No proof-system-specific code

### `zyli/wire`

- TCP framing
- `PING` compatibility
- P2P handshake
- Message header signing / verification
- Peer state and per-canal connection management

### `zyli/storage`

- DA block storage
- Lane storage
- Buffered prepare / replay persistence
- Append-oriented formats and integrity checks

### `zyli/runtime`

- Event loop and scheduler
- Timers and cancellation
- Bounded work queues
- External worker supervision
- Logging and metrics hooks

### `zyli/node`

- Observer mode
- Mempool
- Consensus follower
- State replay
- Lane-manager mode
- Validator mode

### `zolt-arith`

Initial scope:

- Big integer limb arithmetic
- Montgomery field machinery
- BLS12-381 fields and groups
- Pairing and multi-pairing required for Hyli validator verification
- MSM only where needed by BLS implementation
- A small arithmetic-oriented thread pool if benchmarks justify it

Deferred scope:

- Becoming the "arkworks of Zig"
- Broad curve catalog
- Generic polynomial / zkVM-driven abstractions unrelated to Hyli

## `zolt-arith` Rule

Make `zolt-arith` the direct path for Hyli cryptography.

That means:

- extract the reusable arithmetic substrate from `../zolt`
- add BLS12-381 there directly
- make Zyli consume BLS verification through `zolt-arith` from the start

The durability constraint is not "delay `zolt-arith`". The durability constraint is:

- keep `zolt-arith` focused on arithmetic and cryptography
- design its modules from concrete Hyli and Zolt needs
- avoid expanding it into unrelated zkVM or protocol code

So the right failure mode to avoid is not extraction itself. It is over-broad extraction.

## Compatibility Artifacts

Before major implementation work, create and version a compatibility corpus:

- Borsh golden vectors for all protocol-critical structs and enums.
- Hash golden vectors for every custom hash in Hyli.
- Signed-header vectors showing the exact bytes signed for each network message variant.
- BLS signature verification vectors.
- Aggregate-signature verification vectors.
- Handshake captures.
- Mempool traffic captures.
- Consensus traffic captures.
- Signed block and replay fixtures.
- Verifier-worker IPC request / response fixtures.
- Genesis and chain-configuration snapshots.

This corpus should be produced from Rust Hyli and consumed by Zig tests.

## Roadmap

### Phase 0: Extract the Executable Spec

Objective: turn Hyli's Rust implementation into a compatibility oracle.

Deliverables:

- A written compatibility matrix of protocol surfaces.
- Rust-generated fixture corpus for encoding, hashing, signing, replay, and IPC.
- A small differential harness that can compare Zig outputs against Rust fixture expectations.
- A trace format for captured live traffic and replay sessions.

Exit criteria:

- Zyli has a reproducible corpus for byte-level, hash-level, and signature-level equivalence tests.

### Phase 1: Create `zolt-arith` as a Reusable Package

Objective: extract the reusable arithmetic substrate from `../zolt` into a package Zyli can depend on directly.

Deliverables:

- Extract generic arithmetic pieces from `../zolt`.
- Establish stable initial modules for:
  - `bigint`
  - `field`
  - `ec`
  - `msm`
  - `pairing`
  - `thread_pool`
- Keep zkVM-specific code out of the public surface.
- Ensure Zyli can import `zolt-arith` without pulling prover-specific modules.

Exit criteria:

- Zyli can depend on `zolt-arith` as its arithmetic and cryptography foundation.

### Phase 2: Add BLS12-381 to `zolt-arith`

Objective: make `zolt-arith` useful for Hyli validator compatibility.

Deliverables:

- BLS12-381 fields.
- G1 and G2 with serialization compatible with Hyli validator keys and signatures.
- Pairing and multi-pairing.
- Aggregate signature verification compatible with Hyli.
- Tests against Rust Hyli and `blst` vectors.
- A small Zyli-facing crypto adapter layer built on top of `zolt-arith`.

Notes:

- This phase is consensus-critical.
- BLS12-381 belongs in `zolt-arith`, not as a temporary Zyli-local implementation.
- The public API should still stay narrow and driven by real consumers.

Exit criteria:

- Zyli can verify Hyli validator signatures and aggregate signatures through `zolt-arith`.

### Phase 3: Build the Pure Protocol Kernel

Objective: implement the protocol model pieces that should remain stable even if runtime and storage change later.

Deliverables:

- Borsh codec in Zig.
- Core Hyli model types.
- Exact hash functions and signable-payload builders.
- Roundtrip tests against the compatibility corpus.

Exit criteria:

- Zig can encode, decode, and hash protocol-critical Hyli types exactly like Rust.

### Phase 4: Passive Wire-Compatible Observer

Objective: connect safely to the network and validate incoming traffic.

Deliverables:

- TCP framing and ping compatibility.
- P2P handshake.
- Signed message header validation.
- Decoding of mempool, consensus, and DA messages.
- Persistent capture of validated traffic for offline replay.

Exit criteria:

- Zyli can connect to peers, stay online, decode traffic, and reject malformed or invalid messages.

### Phase 5: DA Sync and Consensus Follower

Objective: follow chain progress deterministically without producing protocol actions yet.

Deliverables:

- DA historical sync and live streaming.
- Consensus prepare / vote / confirm / commit / timeout validation.
- Missing-parent and sync-request handling.
- Local follower state machine.

Exit criteria:

- Zyli can follow real network progress as a deterministic consensus follower.

### Phase 6: State Replay and Native Settlement

Objective: move from wire compatibility to semantic compatibility.

Deliverables:

- Signed block replay.
- Contract state tracking.
- Unsettled transaction handling.
- Settlement outcome tracking.
- Native verifier support for:
  - BLS / `blst`
  - SHA3-256
  - secp256k1
- External verifier-worker IPC for SP1, RISC0, Jolt, and others.

Exit criteria:

- Zyli can replay real signed blocks and converge on expected state transitions.

### Phase 7: Lane Manager and Mempool Participation

Objective: participate in lane-local protocol flow before full validation duties.

Deliverables:

- Own-lane transaction intake.
- `DataProposal` construction.
- `DataVote` production and validation.
- Sync request / reply behavior.
- PoDA threshold logic.
- Proof routing to external verifier workers.

Exit criteria:

- Zyli can operate a lane correctly and interoperate with Rust nodes at the mempool layer.

### Phase 8: Active Validator

Objective: support full validator participation only after the previous phases are stable.

Deliverables:

- Vote production.
- Leader behavior.
- Validator candidacy flow.
- Restart and recovery semantics.
- Catchup behavior and operational recovery.

Exit criteria:

- Zyli can interoperate as a validator in a controlled mixed Rust/Zig environment.

### Phase 9: Operational Surface

Objective: add only the operator-facing pieces needed after core correctness is proven.

Deliverables:

- Minimal admin API
- Observability
- Storage tooling
- Soak and recovery testing
- Optional REST compatibility where it helps interoperability

Exit criteria:

- Zyli is operable for long-running testnet or pre-testnet deployments.

## Immediate Priorities

The first concrete sequence should be:

1. Build the compatibility corpus from Rust Hyli.
2. Create `zolt-arith` from reusable pieces in `../zolt`.
3. Add BLS12-381 support there.
4. Implement Zig Borsh and exact model/hashing/signable-payload tests.
5. Implement Zyli's TCP framing, handshake, and signed-header validation.
6. Build a passive observer that can connect to testnet and validate traffic.

This is the fastest path to real evidence that the rewrite is working.

## Non-Goals For The First Milestones

- Rebuilding Hyli's full operational surface on day one.
- Recreating Rust crate boundaries in Zig.
- Designing a general-purpose Zig async framework before protocol work demands it.
- Turning `zolt-arith` into a broad ecosystem package unrelated to Hyli and Zolt needs.
- Implementing every proof verifier in Zig.
- Building explorer or indexer equivalents before core protocol compatibility.

## Main Risks

- BLS12-381 correctness is consensus-critical. A small arithmetic or serialization bug invalidates the entire effort.
- Wire compatibility depends on exact byte layouts and exact signable payload definitions, not on equivalent-looking structs.
- State replay is harder than networking because semantic mismatches appear late and are expensive to diagnose.
- Over-expanding `zolt-arith` beyond arithmetic and cryptography can still delay interoperability.
- A zero-dependency Zig strategy is viable, but only if the testing discipline is much stricter than in an ordinary application codebase.

## Success Criteria

Zyli is on the right path when:

- it can prove byte-for-byte equivalence on the compatibility corpus
- it can verify Hyli validator signatures and aggregate signatures through `zolt-arith`
- it can parse and validate real Hyli network traffic
- it can replay signed blocks into a compatible local state model
- it can follow consensus safely before attempting leader behavior
- its reusable crypto substrate lives in `zolt-arith` and remains shaped by proven needs instead of speculative design
