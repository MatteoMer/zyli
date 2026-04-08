# Zyli TODO

## Status

**Phases 0–4 complete. Phase 2 BLS substrate complete and cross-validated against Rust blst. Phase 5 in progress.**

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

Zyli (290 tests, 166 fixtures) has:
- Borsh codec, protocol model types, exact hash functions
- Wire layer: framing, TCP message parsing, handshake types, DA wire protocol
- Structural message validation (QC markers, slot/view cross-checks)
- Consensus follower state machine (`node/follower.zig`)
- BLS signature verification adapter wired into consensus messages
  (`crypto/bls.zig`, `crypto/consensus_verify.zig`)
- Same-message aggregate signature verification for QCs
- TimeoutCertificate verification with cph plumbed from embedded proposal
- SignedBlock certificate verification (DA-side BLS check)
- Hello handshake builder (`node/handshake.zig`) — generates ephemeral
  BLS key, signs NodeConnectionData, frames the envelope
- DA sync client (`node/da_sync.zig`) — connects to a DA server,
  sends StreamFromHeight, receives signed blocks
- `observe`, `record`, `replay`, `da-sync` subcommands
- `observe`/`record` issue real BLS-signed Hello handshakes on connect
- Cross-implementation BLS test vectors verified against Rust blst:
  - basic verify, alt-message verify, sig/msg swap rejection
  - empty-message edge case
  - 256-byte long-message edge case
  - 3-signer aggregate (the QC verification path)
- 153 borsh/wire/hash/crypto fixtures from `compat/fixture-gen`

**509 tests total (290 zyli + 219 zolt-arith).**

## Immediate

- ✅ Persistent BLS identity (`--identity <path>` flag, `node/identity.zig`)
- ✅ SignedBlock certificate verification wired into DA sync reporting
- ✅ Verack BLS signature verification after handshake
- ✅ PING echo on consensus connection (observe/record)
- Add structural validation to the DA sync client (block height
  monotonicity, parent hash chain continuity).
- Feed DA-synced blocks through the follower to advance chain state.
- Add fixtures for DA envelopes against real testnet captures.

## Phase 5 (in progress)

- ✓ DA wire protocol module (encode/decode requests and events)
- ✓ DA sync client connecting to a DA server
- DA stream live mode after historical catchup
- Persistence layer for received signed blocks (so the follower can
  resume across restarts)
- Sync request handling on the consensus side (when WE need to fetch
  missing blocks from a peer)
- Promote the follower from "structurally validated and BLS verified"
  to "applied to a local state model"

## Phase 6+

- State replay and native verifier support for BLS, SHA3-256, secp256k1
- External verifier-worker IPC for SP1, RISC0, Jolt
- Lane manager and mempool participation
- Active validator behavior (vote production, leader rotation)
- Operational surface: admin API, observability, soak testing

## Performance hardening (after correctness)

- Combined Miller loop for multi-pairing (one bit walk over |x|
  evaluating both line pairs at each step instead of two separate
  Miller loops). Would roughly halve the verify cost again.
- Cyclotomic squaring in the hard part of the final exponentiation
  (currently uses plain Fp12.square which is ~4x slower).
- Faster G2 cofactor clearing via the ψ-endomorphism shortcut from
  the IETF draft instead of a 636-bit naive scalar multiplication.
- Faster Fr exponent walks via NAF / sliding window.
