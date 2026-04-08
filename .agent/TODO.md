# Zyli TODO

## Status

Project bootstrapped: `build.zig`, `build.zig.zon`, `src/root.zig`,
`src/main.zig`, and the first durable subsystem `zyli/model` exist. The Zig
Borsh codec lives in `src/model/borsh.zig` and is exercised by ~20 unit tests
covering primitives, options, slices, fixed arrays, structs, payload-less
enums, tagged unions, and the main rejection cases (invalid bool, invalid
option tag, invalid enum tag, truncated buffers, NaN floats). `zig build` and
`zig build test` are both green.

## Immediate

- Inventory protocol-critical Hyli types in `crates/hyli-model` and write a
  list of which structs/enums need golden Borsh + hash vectors first
  (transactions, data proposals, consensus messages, signed blocks).
- Set up `compat/` directory with a Rust fixture-generator binary that links
  `hyli-model` and emits binary + JSON golden vectors into a versioned
  on-disk corpus.
- Wire a Zig-side fixture loader in `model/` so unit tests can re-decode the
  corpus and assert byte equivalence.
- Begin extracting reusable arithmetic from `../zolt` into `zolt-arith`
  (`bigint`, `field`, `ec`, `msm`, `pairing`, `thread_pool`).
- Add BLS12-381 field, curve, pairing, and aggregation support to
  `zolt-arith`, with vectors borrowed from Rust Hyli / `blst`.
- Once Borsh fixtures pass, implement Hyli's hash + signable-payload helpers
  in `zyli/model` against the same corpus.
- Implement Hyli TCP framing and handshake under `zyli/wire` (depends on
  `zyli/model` Borsh + `zyli/crypto` BLS).
- Implement signed message header verification.

## Next

- Build a passive Zyli observer that can connect to testnet peers and
  validate incoming traffic.
- Implement DA ingestion and local persistence for replay.
- Implement consensus follower validation for proposals, QCs, TCs, and sync
  messages.
- Implement state replay and native verifier support for BLS, SHA3-256, and
  secp256k1.

## Later

- Implement own-lane mempool operation and PoDA-related behavior.
- Integrate external verifier workers for SP1 and other non-native verifiers.
- Enable active validator behavior only after passive and follower modes are
  stable.
- Add operational tooling after protocol correctness is established.
