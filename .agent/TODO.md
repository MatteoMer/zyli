# Zyli TODO

## Status

Phase 0 + early Phase 3 underway.

- `build.zig` / `build.zig.zon` set up; library + executable build cleanly.
- Borsh codec lives in `src/model/borsh.zig` with ~20 self-contained unit
  tests covering primitives, options, slices, fixed arrays, structs,
  payload-less enums, tagged unions, and the main rejection cases.
- Zig-side mirror types for the first round of Hyli protocol newtypes and
  composites live in `src/model/types.zig` (`Identity`, `ContractName`,
  `ProgramId`, `Verifier`, `StateCommitment`, `BlockHeight`, `BlobIndex`,
  `BlobData`, `Blob`, `TimestampMs`, `DataProposalHash`,
  `ValidatorPublicKey`, `LaneId`, `DataProposalParent`).
- Compat harness scaffolded under `compat/`:
  - `compat/fixture-gen/` is a Rust binary pinned to `rustc 1.94` via
    `rust-toolchain.toml` and depends on `hyli-model` as a path dep
    (`features = ["std", "full"]`). Workspace inheritance is broken on
    purpose with an empty `[workspace]` table.
  - Running `cargo run` writes 32 fixtures into `compat/corpus/` and emits
    a Zig manifest at `compat/corpus.zig` that re-exports each fixture as
    an `@embedFile` constant.
  - `build.zig` exposes the manifest as a `corpus` import to the test
    module so `src/model/compat_test.zig` can reach the bytes without
    bumping into Zig's package-path restriction.
- `src/model/compat_test.zig` runs the round-trip checks for every
  current fixture: 11 primitive vectors, 11 newtype/leaf vectors, the
  composite `Blob`, and both variants of `DataProposalParent`. The
  `BlobIndex` test pins down that Borsh emits `usize` as 8 bytes.
- Inventory of protocol-critical Hyli types lives in
  `.agent/hyli-model-inventory.md` and drives the next batch of fixtures.

## Immediate

- Add a `zyli/model/hash.zig` module that wraps `std.crypto.hash.sha3.Sha3_256`
  and replays Hyli's custom hash construction order. First targets:
  `Blob::hashed`, `RegisterContractAction::hashed`,
  `DataProposal::hashed`. Verify each against the existing
  `corpus.hash.model.*` fixtures.
- Extend `compat/fixture-gen` to cover the rest of T1: `Transaction`,
  `BlobTransaction`, `ProofTransaction`, `VerifiedProofTransaction`,
  `Calldata`, `HyliOutput`, `ConsensusProposal`, plus their hashes.
  Mirror the Zig types in `src/model/types.zig` as fixtures land.
- Decide how to encode `BTreeMap`-backed types (`BlobsHashes`) on the Zig
  side — Borsh requires sorted-by-key bytes. Either provide a wrapper
  type or assert callers pre-sort.
- Add fixtures for `Signed<T, V>` envelopes and the exact `Borsh(msg)`
  bytes used as the BLS signing input.
- Begin extracting reusable arithmetic from `../zolt` into `zolt-arith`
  (`bigint`, `field`, `ec`, `msm`, `pairing`, `thread_pool`).
- Add BLS12-381 field, curve, pairing, and aggregation support to
  `zolt-arith`, with vectors borrowed from Rust Hyli / `blst`.
- Implement Hyli TCP framing and handshake under `zyli/wire`.
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
