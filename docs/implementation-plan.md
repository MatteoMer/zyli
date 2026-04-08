# Zyli Implementation Plan

## Goal

Zyli is a clean Zig implementation of the Hyli protocol.

The long-term target is full wire and state compatibility with Hyli, including the ability to connect to Hyli testnet and behave as a valid peer. The short-term target is narrower: build a passive and then follower-grade node that can connect to the network, decode and validate protocol traffic, and replay state correctly.

In parallel, `zolt-arith` should become a reusable Zig cryptography and arithmetic package, with the long-term ambition of being the "arkworks of Zig". That means BLS12-381 belongs there, not as a one-off inside Zyli.

## Principles

- Compatibility first. Zyli should match Hyli's byte formats, hashes, signatures, quorum rules, and replay semantics before chasing architecture parity.
- Protocol first. Reimplement protocol-critical surfaces before REST, admin, indexer, explorer, or operational tooling.
- Zig-first, dependency-light. Prefer Zig stdlib and local packages. External proof systems can remain in their native implementation languages behind narrow IPC boundaries.
- Reusable crypto. Generic field, curve, MSM, pairing, and serialization logic should live in `zolt-arith`, not inside Zyli.
- Separate runtime from protocol. Zyli does not need a Tokio clone. It needs correct networking, scheduling, timeouts, and bounded concurrency.

## Program Structure

The work should split into two tracks:

1. `zyli`
   The Hyli-compatible node implementation: transport, protocol types, consensus, mempool, DA sync, state replay, verifier-worker IPC, and eventually validator behavior.

2. `zolt-arith`
   A reusable Zig arithmetic and cryptography package extracted from and evolved alongside `../zolt`. This should host finite fields, elliptic curves, MSM, pairings, hashes where appropriate, and serialization helpers for cryptographic data types.

## What Lives Where

### Zyli

- Borsh codec and protocol type definitions
- Hyli transaction, block, consensus, mempool, and DA message layouts
- TCP framing and peer handshake
- Signed message header validation
- Consensus state machine
- Mempool lane logic
- DA sync and block assembly
- Node-state replay and settlement logic
- Verifier-worker IPC and process supervision
- Config, storage, logging, and operational interfaces

### zolt-arith

- Big integer limb arithmetic
- Montgomery field machinery
- Reusable field implementations
- Curve group implementations
- MSM
- Pairings
- Hash-to-curve helpers if needed
- Signature primitives and aggregation support for supported schemes
- Parallel compute primitives useful for arithmetic-heavy workloads

## Roadmap

### Phase 0: Spec Extraction and Test Corpus

Objective: turn Hyli's Rust implementation into an executable compatibility target.

Deliverables:

- Document the exact protocol-critical types Zyli must support first.
- Collect golden fixtures for:
  - transaction encoding
  - message header encoding/signing
  - consensus messages
  - mempool messages
  - BLS signatures and aggregate signatures
  - DA requests and replies
  - verifier-worker IPC payloads
- Identify which Hyli tests should become cross-implementation fixture sources.

Exit criteria:

- Zyli has a written compatibility matrix and a fixture set for byte-level and hash-level equivalence tests.

### Phase 1: Create `zolt-arith` as a Reusable Package

Objective: extract the reusable arithmetic and parallelism substrate from `../zolt`.

Deliverables:

- Split generic pieces out of `../zolt` into `zolt-arith`.
- Keep the current worker pool as an arithmetic-oriented compute runtime.
- Keep BN254 support if it is already useful, but remove zkVM-specific assumptions from the public surface.
- Design stable modules for:
  - `bigint`
  - `field`
  - `ec`
  - `msm`
  - `pairing`
  - `thread_pool`

Exit criteria:

- Zyli can import `zolt-arith` without pulling in zkVM-specific modules.
- `zolt` can depend on `zolt-arith` rather than duplicating the arithmetic core.

### Phase 2: Add BLS12-381 to `zolt-arith`

Objective: make `zolt-arith` useful for Hyli's consensus cryptography.

Deliverables:

- Implement BLS12-381 scalar and base fields.
- Implement G1 and G2 with serialization compatible with Hyli's expected public key and signature formats.
- Implement pairing and multi-pairing.
- Implement the signature mode Hyli uses for consensus compatibility.
- Implement aggregate signature verification and public-key aggregation semantics compatible with Hyli.
- Add test vectors against known-good Rust implementations.

Notes:

- This is not optional if Zyli aims to validate or produce real Hyli consensus traffic.
- This is the most important `zolt-arith` milestone for Hyli.
- If `zolt-arith` is meant to become the Zig equivalent of arkworks, BLS12-381 should be treated as a foundational curve, not an add-on.

Exit criteria:

- Zyli can verify Hyli validator signatures and aggregate signatures using `zolt-arith`.

### Phase 3: Zyli Passive Observer

Objective: join the network safely before attempting validator actions.

Deliverables:

- Implement TCP framing and peer handshake.
- Implement Borsh decoding for Hyli protocol messages.
- Verify signed message headers.
- Decode and verify consensus and mempool traffic.
- Connect to DA sources and ingest signed blocks.
- Persist enough local state to replay chain progress.

Exit criteria:

- Zyli can connect to testnet peers, stay synchronized as an observer, and reject malformed or invalid messages.

### Phase 4: Consensus Follower

Objective: implement the follower-grade consensus engine before leader behavior.

Deliverables:

- Track validator set, voting power, slot, and view.
- Validate leader proposals, quorum certificates, timeout certificates, and sync replies.
- Request missing data when required.
- Maintain the canonical local consensus state machine without producing blocks yet.

Exit criteria:

- Zyli can follow network progress deterministically and detect consensus-invalid traffic.

### Phase 5: State Replay and Native Verification

Objective: make Zyli semantically compatible, not just wire-compatible.

Deliverables:

- Replay signed blocks into local node state.
- Track contracts, unsettled transactions, and settlement outcomes.
- Implement or integrate the native verifier paths needed by Hyli semantics:
  - BLS verification
  - SHA3-256
  - secp256k1
- Preserve the external verifier-worker boundary for proof systems such as SP1.

Exit criteria:

- Zyli can replay real network blocks and converge on expected state transitions.

### Phase 6: Mempool and Own-Lane Operation

Objective: move from passive participation to protocol participation.

Deliverables:

- Implement lane-local transaction intake.
- Batch transactions into `DataProposal`s.
- Validate and produce `DataVote`s.
- Implement PoDA-related logic compatible with Hyli.
- Implement mempool sync request and reply behavior.
- Route proof-bearing transactions to external verifier workers.

Exit criteria:

- Zyli can operate its own lane correctly and participate in mempool dissemination.

### Phase 7: Active Validator

Objective: support full participation in the validator protocol.

Deliverables:

- Enable voting once follower behavior is stable.
- Implement leader behavior.
- Handle validator candidacy and validator-set transitions.
- Implement restart and recovery semantics required for practical operation.
- Add fast catchup or equivalent recovery only after correctness is established.

Exit criteria:

- Zyli can run as a real validator in a controlled environment and interoperate with Rust Hyli nodes.

### Phase 8: Operational Surface

Objective: round out the implementation after protocol correctness.

Deliverables:

- Minimal admin and observability interfaces
- Optional REST compatibility where useful
- Storage maintenance tools
- Testnet deployment and soak testing

Exit criteria:

- Zyli is operable in long-running environments.

## Immediate Priorities

The first concrete sequence should be:

1. Create `zolt-arith` from reusable pieces in `../zolt`.
2. Add BLS12-381 support there.
3. Build Zyli's Borsh codec and protocol type layer.
4. Build the Hyli TCP and signed-header stack.
5. Build a passive observer that can connect to testnet and validate traffic.

This sequence is the fastest path to meaningful interoperability.

## Non-Goals for the First Milestones

- Rebuilding Hyli's full operational surface on day one
- Recreating Rust crate boundaries in Zig
- Implementing every proof verifier inside Zig
- Building indexer or explorer functionality before core protocol compatibility

## Main Risks

- BLS12-381 correctness is consensus-critical. A small arithmetic or serialization bug will invalidate the entire effort.
- Wire compatibility depends on exact byte layouts and exact signable payload definitions, not just equivalent structs.
- State replay is more difficult than basic networking because semantic mismatches appear late and are expensive to debug.
- A zero-dependency strategy is viable, but it shifts complexity into Zyli and `zolt-arith`, so testing discipline has to be much stricter than normal application code.

## Success Criteria

Zyli is on the right path when:

- it can parse and validate real Hyli traffic
- it can verify Hyli BLS signatures and aggregate signatures through `zolt-arith`
- it can replay blocks into a compatible local state model
- it can participate as a follower before it attempts leader behavior
- the reusable crypto substrate is general enough to outlive this one project
