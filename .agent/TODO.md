# Zyli TODO

## Status

**Phases 0–5 complete. Phase 6 in progress.**

`zolt-arith` (485 tests) provides the arithmetic and cryptography substrate:
- Field tower: Fp / Fp2 / Fp6 / Fp12 / Fr
- Curves: BLS12-381 (G1/G2 affine + projective), BN254, curve-generic infrastructure
- Compressed point encode/decode for both G1 and G2
- Optimal Ate Miller loop with sparse line evaluation
- Final exponentiation (easy + hard parts via arkworks/Gurvy chain)
- Hash-to-curve for G2 (RFC 9380 SSWU + 3-isogeny + h_eff cofactor clearing)
- BLS verify, aggregate verify, sign, derive public key
- Pairing bilinearity validated against e(2P,Q) = e(P,Q)^2 etc.
- MSM with GLV optimization
- Polynomial commitments (Dory)
- GPU backends (CUDA/Metal)

> **Note:** zolt-arith has grown beyond the original BLS12-381 scope into multi-curve
> and polynomial commitment territory. The implementation plan flags this as deferred
> scope ("broad curve catalog, generic polynomial/zkVM-driven abstractions"). The core
> BLS12-381 surface Zyli depends on remains solid and well-tested.

Zyli (326 tests, 166 fixtures) has:
- Borsh codec, protocol model types, exact hash functions
- Wire layer: framing, TCP message parsing, handshake types, DA wire protocol
- Message encoding: `encodeP2PTcpMessage`, `encodeConsensusData` (sending side)
- Structural message validation (QC markers, slot/view cross-checks)
- Consensus follower state machine with gap detection + SyncRequest trigger
- BLS signature verification for all message types (QCs, TCs, SignedBlocks)
- Hello handshake builder with BLS signing
- DA sync client with ChainValidator, Follower, block store persistence + resume
- Storage subsystem: append-only block store with slot→offset index + allSlots
- State subsystem: ReplayState tracks contract registry, tx counts, staking actions
- Integration tests: full pipeline through validator/follower/store + replay
- Subcommands: `observe`, `record`, `replay`, `da-sync`, `replay-store`
- `observe` sends SyncRequests when follower detects gaps
- Cross-implementation BLS test vectors verified against Rust blst
- 153 borsh/wire/hash/crypto fixtures from `compat/fixture-gen`

**811 tests total (326 zyli + 485 zolt-arith).**

## Phase 6: State Replay and Native Settlement (in progress)

Per the implementation plan, Phase 6 deliverables are:

### Done
- [x] ReplayState foundation (contract registry, tx counting, staking actions)
- [x] Blob transaction and verified proof processing with OnchainEffect
- [x] ReplayState wired into both da-sync and replay-store subcommands
- [x] Integration tests for replay pipeline

### Not started
- [ ] **Unsettled blob transaction tracking** — match blobs to proofs, track which blobs are waiting for settlement. Current code only counts; no data structure for pending blobs or matching logic.
- [ ] **State commitment tracking per contract** — track initial_state → next_state transitions. Currently state_commitment is set once at registration and never updated from verified proofs.
- [ ] **Settlement outcome tracking** — track which proofs have been verified, which contracts settled, history of settlement attempts.
- [ ] **Native verifier support** — BLS exists via zolt-arith. Still need: SHA3-256 verifier abstraction, secp256k1 implementation/verifier.
- [ ] **External verifier-worker IPC** — types defined (VerifyRequest/VerifyResponse) but no IPC implementation, process spawning, or supervision. Needed for SP1, RISC0, Jolt.
- [ ] **Cross-validate replay against Hyli golden vectors** — no replay fixture suite yet.

### Phase 6 exit criteria (from plan)
> Zyli can replay real signed blocks and converge on expected state transitions.

## Completed Phases

### Phase 0: Compatibility Corpus ✅
- 153 fixtures from Rust Hyli (borsh, wire, hash, crypto)
- Differential harness in `compat/fixture-gen`

### Phase 1: zolt-arith Package ✅
- Extracted from `../zolt`, stable modules for bigint, field, ec, msm, pairing

### Phase 2: BLS12-381 in zolt-arith ✅
- Full BLS12-381 surface, verified against Rust blst vectors

### Phase 3: Pure Protocol Kernel ✅
- Borsh codec, model types, exact hashes, signable payloads

### Phase 4: Passive Wire-Compatible Observer ✅
- TCP framing, handshake, signed header validation, message decoding
- `observe` and `record` subcommands

### Phase 5: DA Sync and Consensus Follower ✅
- DA historical sync + block store persistence + resume
- Consensus follower with gap detection + SyncRequest
- `da-sync` and `replay-store` subcommands
- Missing-parent handling and sync-request sending

## Phase 7+ (future)

- Lane manager and mempool participation (DataProposal, DataVote, PoDA)
- Active validator behavior (vote production, leader rotation)
- Operational surface: admin API, observability, soak testing

## Performance hardening (after correctness)

- Combined Miller loop for multi-pairing
- Cyclotomic squaring in final exponentiation
- Faster G2 cofactor clearing via ψ-endomorphism
- Faster Fr exponent walks via NAF / sliding window
