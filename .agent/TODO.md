# Zyli TODO

## Immediate

- Collect Hyli compatibility fixtures for Borsh encoding, hashes, signatures, and aggregate signatures.
- Use `zolt-arith` as the shared arithmetic and cryptography library path for both Zyli and Zolt.
- Extract reusable arithmetic and parallelism components from `../zolt` into `zolt-arith` without pulling prover-specific modules into its public surface.
- Define the first stable `zolt-arith` modules: `bigint`, `field`, `ec`, `msm`, `pairing`, `thread_pool`.
- Add BLS12-381 field, curve, pairing, and aggregation support to `zolt-arith`.
- Keep `zolt-arith` narrow at first and expand it only when Hyli or Zolt needs more arithmetic or crypto surface.
- Implement Zyli's Borsh codec and protocol type layer.
- Implement Hyli TCP framing and handshake.
- Implement signed message header verification.

## Next

- Build a passive Zyli observer that can connect to testnet peers and validate incoming traffic.
- Implement DA ingestion and local persistence for replay.
- Implement consensus follower validation for proposals, QCs, TCs, and sync messages.
- Implement state replay and native verifier support for BLS, SHA3-256, and secp256k1.

## Later

- Implement own-lane mempool operation and PoDA-related behavior.
- Integrate external verifier workers for SP1 and other non-native verifiers.
- Enable active validator behavior only after passive and follower modes are stable.
- Add operational tooling after protocol correctness is established.
