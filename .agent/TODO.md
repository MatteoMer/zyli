# Zyli TODO

## Status

**Phases 0–4 complete. Phase 2 BLS substrate complete. Real BLS-signed P2P handshake working.**

`zolt-arith` (219 tests) provides the full BLS12-381 surface:
- Field tower: Fp / Fp2 / Fp6 / Fp12 / Fr
- Curves: G1Affine / G2Affine / G1Projective / G2Projective / G2HomProjective
- Compressed point encode/decode for both G1 and G2
- Optimal Ate Miller loop with sparse line evaluation (`fp12MulBy014`)
- Final exponentiation (easy + hard parts)
- Hash-to-curve for G2 (RFC 9380 SSWU + 3-isogeny + cofactor clearing)
- BLS verify (`verify`, `verifyCompressed`, `verifyAggregate`)
- BLS sign (`signWithScalar`, `signBytes`, `derivePublicKeyFromScalar`)
- Pairing bilinearity validated against e(2P,Q) = e(P,Q)^2 etc.

Zyli (266 tests, 153 fixtures) has:
- Borsh codec, protocol model types, exact hash functions
- Wire layer: framing, TCP message parsing, handshake types
- Structural message validation (QC markers, slot/view cross-checks)
- Consensus follower state machine (`node/follower.zig`)
- BLS signature verification adapter wired into consensus messages
  (`crypto/bls.zig`, `crypto/consensus_verify.zig`)
- Same-message aggregate signature verification for QCs
- Hello handshake builder (`node/handshake.zig`) — generates ephemeral
  BLS key, signs NodeConnectionData, frames the envelope
- `observe` issues a real BLS-signed Hello on connect, reads Verack,
  then enters the frame-decoding loop with cryptographic verification
  on every consensus message
- `record` and `replay` subcommands for offline analysis
- Staking, indexer, DA stream, and verifier-worker IPC types

**485 tests total (266 zyli + 219 zolt-arith).**

## Immediate

The BLS substrate is done. The handshake initiator is wired into the
observer. The remaining short-term work is hardening and corpus growth:

- Add cross-implementation BLS vectors (Rust blst-produced signatures
  verified by Zig) to the compatibility corpus. Currently we only test
  against self-generated (sk, pk, sig) triples — those validate the
  algebraic identities but not byte-level wire compatibility.
- Add fixtures for the DA historical-stream `DataAvailabilityRequest` /
  `DataAvailabilityReply` envelopes once the follower-side code that
  consumes them is closer to landing.
- Plumb the embedded-cph through `verifyConsensusMessage` so that the
  TimeoutCertificate's PrepareQC inner can also be verified, not just
  the outer TimeoutQC.
- Persist the observer's BLS key across runs so it can build a stable
  validator identity for testnet observation. Today every connect
  generates a fresh key.

## Phase 5+

- DA historical sync: request signed blocks from a peer after
  handshake, persist locally, feed to follower.
- State replay and native verifier support for BLS, SHA3-256, secp256k1.
- Lane manager and mempool participation.
- Active validator behavior (vote production, leader rotation).
- Operational surface: admin API, observability, soak testing.

## Performance hardening (after correctness)

- Faster cofactor clearing on G2 via the ψ-endomorphism shortcut
  instead of naive 8-limb scalar mul.
- Faster Fr exponent walks via NAF / sliding window.
- Cyclotomic squaring for the hard part of the final exponentiation
  (currently uses plain Fp12.square).
- Multi-pairing for verifyAggregate (single Miller loop product
  instead of two separate pairings).
