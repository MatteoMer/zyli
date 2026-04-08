# Zyli TODO

## Status

Phase 0 corpus is broad; Phase 3 model + Phase 4 wire layer cover the
handshake, the replay path, the full consensus message family
(including Timeout / TimeoutCertificate), the mempool message family,
the SignedBlock shape, a stream-driven frame reader, and a typed
P2PTcpMessage decoder. The executable's `observe HOST:PORT` subcommand
prints actual ConsensusNetMessage variant labels for Data frames.
Phase 1 of the implementation plan is in progress: `zolt-arith` exists
as a sibling package at `../zolt-arith` with `bigint` already in place,
and Zyli depends on it via `build.zig.zon`.
**171 tests passing in zyli, 14 in zolt-arith (185 total). 127 fixtures.**

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
  `Handshake::{Hello,Verack}` variants). `framing.zig` also exposes
  `StreamFrameReader(Reader)` — a comptime-generic pull loop over any
  `read([]u8) !usize`-shaped reader that buffers, decodes, and compacts
  frame bytes. It is exercised against a slice fake (single-shot,
  back-to-back, 1-byte chunked, truncated, oversized) so it can be
  dropped over a real `std.net.Stream` without redesign.
- The consensus message family from `hyli/src/consensus/network.rs` is
  pinned in the corpus: `ConsensusMarker` enum, `QuorumCertificate`,
  `PrepareQC`/`CommitQC`/`TimeoutQC`/`NilQC` aliases, `PrepareVote`,
  `ConfirmAck`, `Ticket::{Genesis,CommitQC,...}`, `TimeoutKind`,
  `TCKind`, `ConsensusTimeout`, and every `ConsensusNetMessage` variant
  (`Prepare`, `PrepareVote`, `Confirm`, `ConfirmAck`, `Commit`,
  `Timeout`, `TimeoutCertificate`, `ValidatorCandidacy`, `SyncRequest`,
  `SyncReply`). The Prepare/Commit QC marker-distinctness invariant is
  asserted both in the fixture-gen and in the Zig tests.
- The mempool network family from `hyli/src/mempool.rs` is pinned in
  the corpus: `ValidatorDAG`, `MempoolNetMessage::DataProposal`,
  `DataVote`, `SyncRequest` (with both `Some/Some` and `None/None`
  bound combinations), and `SyncReply`. `DataProposal` itself now
  exists as a Zig type and is round-tripped against the existing
  `data_proposal_empty` fixture.
- `SignedBlock` from `crates/hyli-model/src/block.rs` has its own
  fixture and Zig mirror — the entry point for state-replay work.
  `src/model/block.zig` exposes the `parentHash`/`height`/`totalTxCount`
  accessors that mirror `SignedBlock::parent_hash()` /
  `SignedBlock::height()` from upstream and decodes the fixture
  end-to-end through the borsh codec.
- `src/main.zig` is now a small executable with an `observe` subcommand
  that connects to a TCP peer, drives `StreamFrameReader` over a real
  `std.net.Stream`, and prints either `PING` or the decoded
  `ConsensusNetMessage` variant label (`Prepare`, `PrepareVote`, …) for
  each frame. It does NOT speak the BLS handshake yet — that lands once
  `zolt-arith` provides BLS12-381 verification.
- `src/wire/protocol.zig` exposes a `decodeP2PTcpMessage(allocator,
  Data, frame_bytes)` helper that returns a `Decoded(Data)` value
  backed by an internal arena allocator. The arena shape exists
  precisely because the borsh decoder leaks intermediate allocations on
  its error path; routing per-message decodes through an arena means a
  truncated frame deallocates everything together. `messageLabel(Data,
  value)` mirrors the upstream `IntoStaticStr` projection on
  `ConsensusNetMessage` and `MempoolNetMessage`.
- `../zolt-arith` exists as a standalone Zig package with its own
  `build.zig`, `build.zig.zon`, and a `bigint` module covering
  fixed-width little-endian limb arithmetic over `[N]u64` (add, sub,
  cmp, isZero/isOne, bitLen, fromBytesLe/Be, toBytesLe/Be) for both
  4-limb (BN254-width) and 6-limb (BLS12-381-width) operands. Zyli
  imports it via path dependency in `build.zig.zon` and re-exports it
  through `src/crypto/zolt_arith.zig`. `src/crypto/zolt_arith_adapter.zig`
  is the seam where Hyli wire bytes (compressed BLS12-381 G1 / G2 byte
  strings) get converted into the limb representation `zolt_arith`
  consumes — kept in zyli so the substrate stays Hyli-agnostic. Each
  package owns its own test step: `zig build test` in zyli runs 171
  tests, in `../zolt-arith` runs 14, and the test runner does NOT
  propagate across module boundaries on Zig 0.15.
- `src/crypto/signable.zig` pins the BLS DST string used by
  `hyli-crypto::sign_msg` and exposes `signableBytesAlloc(Msg, msg)` —
  the "what bytes get BLS-signed" rule (`borsh::to_vec(&msg)` for any
  `Signed<T, V>`). The fixture-gen asserts at build time that the
  signable payload equals the standalone borsh fixture, so a future
  refactor that breaks the invariant fails the build immediately.

## Immediate

- Add `field.zig` to `zolt-arith`: comptime-generic Montgomery field
  parameterised by limb count, with multiplication via CIOS and
  inversion via Fermat. The 6-limb case is the BLS12-381 base field
  (Fp); the 4-limb case can later host BN254 if `../zolt` ever
  consumes the new package.
- Add the BLS12-381 Fp constants (modulus, R, R^2, -p^-1 mod 2^64) to
  `zolt-arith` and instantiate `Fp` over them.
- Add `Fp2` (quadratic extension) on top of `Fp`.
- Add G1 / G2 short Weierstrass curve arithmetic (affine + projective).
- Add the optimal Ate pairing for BLS12-381.
- Add hash-to-curve (RFC 9380, suite
  `BLS12381G2_XMD:SHA-256_SSWU_RO_`) so we can verify signatures.
- Wire BLS verification into `src/crypto/zolt_arith_adapter.zig` and
  hook it into a verifier in `src/crypto/`.
- Teach the observer to issue a real `Handshake::Hello` once BLS
  signing exists — the message shapes and signable bytes are already
  pinned, only the BLS surface is missing.
- Add fixtures for the DA historical-stream messages
  (`DataAvailabilityRequest`/`Reply`) once the follower-side code that
  consumes them is closer to landing — these belong to a separate crate
  and have their own envelope types.

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
