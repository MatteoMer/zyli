# Zyli TODO

## Status

Phase 0 corpus is broad; Phase 3 model + Phase 4 wire layer have closed
the handshake/replay-path gap.
**117 tests passing. 91 fixtures.**

- `build.zig` / `build.zig.zon` set up; library + executable build cleanly.
- Borsh codec in `src/model/borsh.zig` covers primitives, options, slices,
  fixed arrays, structs, payload-less enums, tagged unions, and the main
  rejection cases. `BlobsHashes` (BTreeMap-backed) is encoded via a
  pre-sorted slice — the encoder relies on the caller having ordered
  entries by key, mirroring the BTreeMap iteration contract on the Rust
  side.
- Compat harness scaffolded under `compat/`:
  - `compat/fixture-gen/` is a Rust binary pinned to `rustc 1.94` via
    `rust-toolchain.toml` and depends on `hyli-model` as a path dep with
    `features = ["std", "full"]`. Workspace inheritance is broken on
    purpose with an empty `[workspace]` table so the hyli MSRV doesn't
    leak.
  - Running `cargo run` writes 91 fixtures into `compat/corpus/` and
    emits a Zig manifest at `compat/corpus.zig` that re-exports each
    fixture as an `@embedFile` constant.
  - `build.zig` exposes the manifest as a `corpus` import so test files
    in `src/` can reach the bytes without bumping into Zig's
    package-path restriction.
- `src/model/types.zig` mirrors the Hyli protocol surface needed for the
  current corpus: leaf newtypes, `Blob`, `BlobTransaction`,
  `ProofTransaction`, `VerifiedProofTransaction`, `Transaction` (wraps
  the `TransactionData` enum), `Signed<Msg, Sig>`, `ValidatorSignature`,
  `ValidatorCandidacy`, `AggregateSignature`, `DataProposalParent`,
  `BlobsHashes`, `IndexedBlobs`, `TxContext`, `Calldata`,
  `RegisterContractEffect`, `OnchainEffect`, `HyliOutput`, plus the
  wire-layer `Canal`, `NodeConnectionData`, `HandshakePayload`,
  `Handshake`, and `P2PTcpMessage<Data>`.
- `src/model/compat_test.zig` round-trips every fixture through the Zig
  Borsh codec. The `BlobIndex` test pins down that Borsh emits `usize`
  as 8 bytes; the `Signed<>` test pins down generic envelope ordering;
  the `BlobsHashes` test pins down BTreeMap encoding.
- `src/model/hash.zig` mirrors all Hyli SHA3-256 custom hashes that have
  fixtures: `Blob`, `RegisterContractAction`, `DataProposal`,
  `ProofData`, `BlobTransaction`, `ProofTransaction`,
  `VerifiedProofTransaction`, `ConsensusProposal`,
  `RegisterContractEffect`, all `OnchainEffect` variants, and
  `HyliOutput` (the field-by-field replay-path digest from
  `data_availability.rs`, with `usize` always emitted as 8 bytes).
- `Box<T>` transparency on the wire is asserted at fixture-generation
  time so a borsh regression in the Bond variant would fail the build
  before any Zig test runs.
- Inventory of protocol-critical Hyli types lives in
  `.agent/hyli-model-inventory.md` and drives the next batch of
  fixtures.
- `src/wire/` exists with `framing.zig` (4-byte BE length-delimited
  frames matching `tokio_util::LengthDelimitedCodec` defaults),
  `tcp_message.zig` (the `TcpMessage::Ping`/`Data` shape from
  `hyli_net::tcp`, including the `b"PING"` magic that bypasses borsh),
  and `handshake.zig` (the `P2PTcpMessage<Data>` envelope plus
  `Handshake::{Hello,Verack}` variants). The framing decoder is
  pull-based with explicit `need_more`/`frame` results so it can be
  dropped over an `std.net.Stream` later without re-design.
- `src/crypto/signable.zig` pins the BLS DST string used by
  `hyli-crypto::sign_msg` and exposes `signableBytesAlloc(Msg, msg)` —
  the "what bytes get BLS-signed" rule (`borsh::to_vec(&msg)` for any
  `Signed<T, V>`). The fixture-gen asserts at build time that the
  signable payload equals the standalone borsh fixture, so a future
  refactor that breaks the invariant fails the build immediately.

## Immediate

- Begin extracting reusable arithmetic from `../zolt` into `zolt-arith`
  (`bigint`, `field`, `ec`, `msm`, `pairing`, `thread_pool`). This is
  Phase 1 of the implementation plan and unblocks BLS12-381.
- Add BLS12-381 field, curve, pairing, and aggregation support to
  `zolt-arith`, with vectors borrowed from Rust Hyli / `blst`. Phase 2.
- Implement signed message header verification (BLS12-381 verify on
  `signable.zig`'s output) once `zolt-arith` BLS lands.
- Wire `framing.FrameDecoder` over a real `std.net.Stream` to make the
  observer attempt a live testnet connection.
- Add fixtures for the rest of the consensus message family
  (`Prepare`, `PrepareVote`, `Confirm`, `ConfirmAck`, `Commit`,
  `Timeout`, `TimeoutCertificate`, `SyncRequest`, `SyncReply`) and the
  matching mempool messages — all behind `Signed<...>` envelopes.
- Add fixtures for `SignedBlock` and the DA stream messages so the
  follower path has its own corpus before any code lands.

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
