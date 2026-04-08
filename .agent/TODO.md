# Zyli TODO

## Status

**Phases 0–3 complete. Phase 4 nearly complete. BLS substrate done.**

`zolt-arith` (213 tests) provides the full BLS12-381 surface:
- Field tower: Fp / Fp2 / Fp6 / Fp12 / Fr
- Curves: G1Affine / G2Affine / G1Projective / G2Projective / G2HomProjective
- Compressed point encode/decode for both G1 and G2
- Optimal Ate Miller loop with sparse line evaluation (`fp12MulBy014`)
- Final exponentiation (easy + hard parts)
- Hash-to-curve for G2 (RFC 9380 SSWU + 3-isogeny + cofactor clearing)
- BLS verify (`verify`, `verifyCompressed`, `verifyAggregate`)
- BLS sign (`signWithScalar`, `signBytes`, `derivePublicKeyFromScalar`)

Zyli (256 tests, 153 fixtures) has:
- Borsh codec, protocol model types, exact hash functions
- Wire layer: framing, TCP message parsing, handshake types
- Structural message validation (QC markers, slot/view cross-checks)
- Consensus follower state machine (`node/follower.zig`)
- BLS signature verification adapter wired into consensus messages
  (`crypto/bls.zig`, `crypto/consensus_verify.zig`)
- `observe`, `record`, `replay` subcommands
- Staking, indexer, DA stream, and verifier-worker IPC types

**469 tests total (256 zyli + 213 zolt-arith).**

## Immediate — BLS Handshake for Observer

The observer connects to peers and decodes traffic, but does NOT
perform the P2P handshake. Without it, Hyli peers close the
connection immediately. The handshake requires:

1. Generate an ephemeral BLS keypair (or accept one via config)
2. Build `NodeConnectionData` for this Zyli node
3. Borsh-encode → BLS-sign → wrap in `Signed<NCD, ValidatorSignature>`
4. Frame as `P2PTcpMessage::Handshake(Hello(canal, signed_ncd, ts))`
5. Send the length-delimited frame over TCP
6. Read the `Verack` response and verify its BLS signature
7. After handshake succeeds, enter the existing frame-reading loop

Files to create/modify:
- `src/wire/handshake_client.zig` — handshake initiator logic
- `src/main.zig` — wire handshake into `observe`/`record`

## Next

- Add cross-implementation BLS vectors (Rust blst-produced signatures
  verified by Zig) to the compatibility corpus.
- Build DA historical sync — request signed blocks from a peer after
  handshake, persist locally, feed to follower.
- Harden subgroup membership checks in the zyli adapter for
  adversarially-supplied pubkeys.
- Add G1/G2 point compression encoder round-trip tests against corpus.

## Later

- Phase 5: Full consensus follower with DA ingestion and storage
- Phase 6: State replay, contract tracking, native verifier support
- Phase 7: Lane manager and mempool participation
- Phase 8: Active validator
- Phase 9: Operational surface
