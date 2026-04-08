# Zyli TODO

## Status

**Phases 0–4 complete. Phase 5 substantially complete. Phase 6 groundwork started.**

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

Zyli (314 tests, 166 fixtures) has:
- Borsh codec, protocol model types, exact hash functions
- Wire layer: framing, TCP message parsing, handshake types, DA wire protocol
- **Message encoding**: `encodeP2PTcpMessage`, `encodeConsensusData` (sending side)
- Structural message validation (QC markers, slot/view cross-checks)
- Consensus follower state machine (`node/follower.zig`)
  - `handleSignedBlock` for DA block ingestion
  - Gap detection with `gap_detected` event for SyncRequest trigger
- BLS signature verification for all message types
- Same-message aggregate signature verification for QCs
- TimeoutCertificate / SignedBlock certificate verification
- Hello handshake builder with BLS signing
- DA sync client with:
  - ChainValidator (height monotonicity + parent hash chain continuity)
  - Follower integration (blocks advance follower state)
  - Block store persistence (`--store <path>`) with resume
- Storage subsystem (`storage/block_store.zig`) — append-only
  signed block file with slot→offset index, rebuild-on-open, allSlots iterator
- Subcommands: `observe`, `record`, `replay`, `da-sync`, `replay-store`
- `observe` sends SyncRequests when follower detects gaps
- Cross-implementation BLS test vectors verified against Rust blst
- 153 borsh/wire/hash/crypto fixtures from `compat/fixture-gen`

**533 tests total (314 zyli + 219 zolt-arith).**

## Immediate

- ✅ Persistent BLS identity (`--identity <path>` flag)
- ✅ SignedBlock certificate verification wired into DA sync reporting
- ✅ Verack BLS signature verification after handshake
- ✅ PING echo on consensus connection (observe/record)
- ✅ Structural validation in DA sync (height monotonicity, parent hash chain)
- ✅ Feed DA-synced blocks through the follower to advance chain state
- ✅ Block store persistence with resume support
- ✅ Gap detection in follower + SyncRequest sending
- ✅ Message encoding (encodeP2PTcpMessage, encodeConsensusData)
- ✅ replay-store subcommand for offline block chain verification
- Add fixtures for DA envelopes against real testnet captures

## Phase 5 (substantially complete)

- ✓ DA wire protocol module (encode/decode requests and events)
- ✓ DA sync client connecting to a DA server
- ✓ ChainValidator for structural block chain validation
- ✓ Block persistence via append-only store with resume
- ✓ Follower state machine with handleSignedBlock + gap detection
- ✓ SyncRequest sending on consensus channel when gaps detected
- ✓ Message encoding for sending protocol messages
- ✓ Offline block chain replay (replay-store subcommand)
- DA stream live mode after historical catchup
- SyncReply processing for gap filling (follower already handles it,
  but end-to-end flow with a real peer needs testing)

## Phase 6 (next)

- State replay of signed blocks into contract state transitions
- Native verifier support for BLS, SHA3-256, secp256k1
- External verifier-worker IPC for SP1, RISC0, Jolt
- Unsettled transaction handling
- Settlement outcome tracking

## Phase 7+

- Lane manager and mempool participation
- Active validator behavior (vote production, leader rotation)
- Operational surface: admin API, observability, soak testing

## Performance hardening (after correctness)

- Combined Miller loop for multi-pairing
- Cyclotomic squaring in final exponentiation
- Faster G2 cofactor clearing via ψ-endomorphism
- Faster Fr exponent walks via NAF / sliding window
