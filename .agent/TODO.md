# Zyli TODO

## Status

Phase 0 + early Phase 3 underway. **66 tests passing.**

- `build.zig` / `build.zig.zon` set up; library + executable build cleanly.
- Borsh codec in `src/model/borsh.zig` covers primitives, options, slices,
  fixed arrays, structs, payload-less enums, tagged unions, and the main
  rejection cases.
- Compat harness scaffolded under `compat/`:
  - `compat/fixture-gen/` is a Rust binary pinned to `rustc 1.94` via
    `rust-toolchain.toml` and depends on `hyli-model` as a path dep with
    `features = ["std", "full"]`. Workspace inheritance is broken on
    purpose with an empty `[workspace]` table so the hyli MSRV doesn't
    leak.
  - Running `cargo run` writes 47 fixtures into `compat/corpus/` and
    emits a Zig manifest at `compat/corpus.zig` that re-exports each
    fixture as an `@embedFile` constant.
  - `build.zig` exposes the manifest as a `corpus` import so test files
    in `src/` can reach the bytes without bumping into Zig's
    package-path restriction.
- `src/model/types.zig` mirrors the Hyli protocol surface needed for the
  current corpus: leaf newtypes, `Blob`, `BlobTransaction`,
  `ProofTransaction`, `VerifiedProofTransaction`, `Transaction` (wraps
  the `TransactionData` enum), `Signed<Msg, Sig>`, `ValidatorSignature`,
  `ValidatorCandidacy`, `AggregateSignature`, `DataProposalParent`.
- `src/model/compat_test.zig` round-trips every fixture through the Zig
  Borsh codec. The `BlobIndex` test pins down that Borsh emits `usize`
  as 8 bytes; the `Signed<>` test pins down generic envelope ordering.
- `src/model/hash.zig` mirrors all Hyli SHA3-256 custom hashes that have
  fixtures: `Blob`, `RegisterContractAction`, `DataProposal`,
  `ProofData`, `BlobTransaction`, `ProofTransaction`, and
  `VerifiedProofTransaction`. The latter two share a digest construction
  and the test asserts they agree.
- Inventory of protocol-critical Hyli types lives in
  `.agent/hyli-model-inventory.md` and drives the next batch of
  fixtures.

## Immediate

- Add fixtures + Zig mirror for `Calldata`, `HyliOutput`, and
  `OnchainEffect` (along with their hashes where they exist). Each is
  consensus-critical for the replay path.
- Add `ConsensusProposal` and its custom-hash construction (different
  field selection from any of the existing T1 hashes — see
  `node/consensus.rs`). This is the most subtle hash and should land
  before any consensus follower work.
- Decide how to encode `BTreeMap`-backed types (`BlobsHashes`) on the
  Zig side — Borsh requires sorted-by-key bytes. Either provide a
  wrapper type or assert callers pre-sort.
- Add fixtures for the exact bytes that get BLS-signed for each network
  message variant — this is the "signable payload" surface called out in
  the plan and is what the wire layer will need to verify against.
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
