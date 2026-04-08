# Zyli TODO

## Immediate

- Extract reusable arithmetic and parallelism components from `../zolt` into a dedicated `zolt-arith` package.
- Define the first stable `zolt-arith` modules: `bigint`, `field`, `ec`, `msm`, `pairing`, `thread_pool`.
- Add BLS12-381 field, curve, pairing, and aggregation support to `zolt-arith`.
- Collect Hyli compatibility fixtures for Borsh encoding, hashes, signatures, and aggregate signatures.
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
