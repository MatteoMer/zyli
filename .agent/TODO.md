# Zyli TODO

## Status

**Phases 0–4 complete. Phase 5 substantially complete. Phase 6 started.**

`zolt-arith` (219 tests) provides the full BLS12-381 surface:
- Field tower: Fp / Fp2 / Fp6 / Fp12 / Fr
- Curves: G1Affine / G2Affine / G1Projective / G2Projective / G2HomProjective
- Compressed point encode/decode for both G1 and G2
- Optimal Ate Miller loop with sparse line evaluation (`fp12MulBy014`)
- Final exponentiation (easy + hard parts via arkworks/Gurvy chain)
- Hash-to-curve for G2 (RFC 9380 SSWU + 3-isogeny + h_eff cofactor clearing)
- BLS verify with multi-pairing optimization (single final exponentiation)
- BLS aggregate verify (`verifyAggregate`)
- BLS sign (`signWithScalar`, `signBytes`, `derivePublicKeyFromScalar`)
- Pairing bilinearity validated against e(2P,Q) = e(P,Q)^2 etc.

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

**545 tests total (326 zyli + 219 zolt-arith).**

## This Session's Deliverables

1. ✅ handleSignedBlock in Follower for DA block ingestion (4 tests)
2. ✅ ChainValidator: height monotonicity + parent hash chain continuity (7 tests)
3. ✅ Follower + ChainValidator wired into syncAndReport
4. ✅ BlockStore: append-only signed block persistence with index rebuild (8 tests)
5. ✅ Block store integrated into DA sync with resume support (`--store`)
6. ✅ encodeP2PTcpMessage + encodeConsensusData for sending messages (3 tests)
7. ✅ Gap detection in Follower with gap_detected event (2 tests)
8. ✅ SyncRequest sending on consensus channel when gaps detected
9. ✅ replay-store subcommand for offline block chain verification
10. ✅ Integration tests: full pipeline through chain/follower/store (5 tests)
11. ✅ State replay engine (ReplayState) with contract registration (6 tests)
12. ✅ ReplayState wired into both da-sync and replay-store subcommands

## Remaining Phase 5

- DA stream live mode after historical catchup (reconnection logic)
- SyncReply processing end-to-end with a real peer
- DA envelope fixtures against real testnet captures

## Phase 6 (in progress)

- ✓ ReplayState foundation (contract registry, tx counting, staking)
- ✓ Blob transaction and verified proof processing with OnchainEffect
- Proper unsettled blob transaction tracking (match blobs to proofs)
- State commitment tracking per contract (initial_state → next_state)
- Native verifier support for BLS, SHA3-256, secp256k1
- External verifier-worker IPC for SP1, RISC0, Jolt
- Settlement outcome tracking
- Cross-validate replay results against Hyli golden vectors

## Phase 7+

- Lane manager and mempool participation
- Active validator behavior (vote production, leader rotation)
- Operational surface: admin API, observability, soak testing

## Performance hardening (after correctness)

- Combined Miller loop for multi-pairing
- Cyclotomic squaring in final exponentiation
- Faster G2 cofactor clearing via ψ-endomorphism
- Faster Fr exponent walks via NAF / sliding window
