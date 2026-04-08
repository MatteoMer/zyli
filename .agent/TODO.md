# Zyli TODO

## Status

Phase 0 corpus is broad; Phase 3 model + Phase 4 wire layer cover the
handshake, the replay path, the full consensus message family
(including Timeout / TimeoutCertificate), the mempool message family,
the SignedBlock shape, a stream-driven frame reader, and a typed
P2PTcpMessage decoder. The executable's `observe HOST:PORT` subcommand
prints actual ConsensusNetMessage variant labels for Data frames.
Phases 1 and 2 of the implementation plan are **well underway**:
`zolt-arith` exists as a sibling package at `../zolt-arith` with the
**full BLS12-381 field tower** in place: Fp (with sqrt), Fp2 (with
sqrt), Fp6, and Fp12. Plus the BLS12-381 scalar field Fr. G1 and G2
affine short-Weierstrass arithmetic (add / double / neg / scalar mul)
and **compressed point decoding for both G1 and G2** — the wire
format Hyli puts validator pubkeys and signatures in. Both decoders
are wired into Zyli's `crypto/zolt_arith_adapter.zig`.

Still missing for full BLS verification:
- Optimal Ate pairing (Miller loop + final exponentiation in Fp12)
- Hash-to-curve for G2 (RFC 9380 SSWU)
- BLS verify entry point
- Subgroup membership checks for hostile inputs

**210 tests passing in zyli, 171 in zolt-arith (381 total). 139 fixtures.**

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
  `std.net.Stream`, decodes each frame as a `P2PTcpMessage<ConsensusNetMessage>`,
  prints a detailed one-line summary (slot/view/cph for consensus,
  canal/name for handshake) plus a structural validation verdict
  (`[ok]` / `[INVALID]`). It does NOT speak the BLS handshake yet —
  that lands once `zolt-arith` provides BLS12-381 verification.
- `src/wire/protocol.zig` exposes:
  - `decodeP2PTcpMessage(allocator, Data, frame_bytes)` returning a
    `Decoded(Data)` value backed by an internal arena allocator.
  - `messageLabel(Data, value)` mirroring upstream `IntoStaticStr`.
  - `validateMessage(Data, value)` running the structural validator
    on the inner payload.
  - `formatMessage(Data, value, writer)` printing a detailed one-line
    description (slot/view, hashes, validator counts).
- `src/wire/validate.zig` enforces the QC marker / variant
  cross-check from
  hyli/src/consensus/network.rs::quorum_certificate_cannot_be_reused_across_steps:
  Confirm carries a PrepareQC, Commit carries a CommitQC, the inner
  Signed marker matches the outer ConsensusNetMessage variant,
  TimeoutCertificate's TCKind uses the matching markers, and
  Ticket::ForcedCommitQC is rejected when received from a peer
  (it's an internal-only variant).
- The DA stream and mempool dissemination event types are pinned in
  the corpus: `TxId`, `TransactionKind`, `TransactionMetadata`,
  `MempoolStatusEvent::{WaitingDissemination, DataProposalCreated}`,
  `DataAvailabilityRequest::{StreamFromHeight, BlockRequest}`, and
  `DataAvailabilityEvent::{SignedBlock, MempoolStatusEvent, BlockNotFound}`.
  All have Zig mirrors and round-trip tests.
- `src/wire/protocol.zig` exposes a `decodeP2PTcpMessage(allocator,
  Data, frame_bytes)` helper that returns a `Decoded(Data)` value
  backed by an internal arena allocator. The arena shape exists
  precisely because the borsh decoder leaks intermediate allocations on
  its error path; routing per-message decodes through an arena means a
  truncated frame deallocates everything together. `messageLabel(Data,
  value)` mirrors the upstream `IntoStaticStr` projection on
  `ConsensusNetMessage` and `MempoolNetMessage`.
- `../zolt-arith` exists as a standalone Zig package with its own
  `build.zig`, `build.zig.zon`, and three modules: `bigint`, `field`,
  and `bls12_381`.
  - `bigint`: fixed-width little-endian limb arithmetic over `[N]u64`
    (add, sub, cmp, isZero/isOne, bitLen, fromBytesLe/Be, toBytesLe/Be)
    for both 4-limb (BN254-width) and 6-limb (BLS12-381-width) operands.
  - `field.MontgomeryField(N, modulus, r2, n_prime)`: comptime-generic
    finite field stored in Montgomery form, with add/sub/neg, CIOS
    Montgomery multiplication, square, square-and-multiply pow, and
    Fermat inversion. Tested over Curve25519's base field (4 limbs,
    p = 2^255 - 19) so a hand-checkable instantiation validates the
    algorithm before BLS12-381 is involved.
  - `bls12_381.Fp`: BLS12-381 base field instantiation. Pins the
    standard `blst` constants (modulus, R^2, -p^-1) and exercises
    identity laws, distributive multiplication, associativity, near-
    modulus round-trips, the (p-1)^2 = 1 mod p identity, and the
    6-limb Fermat inversion (~381 squarings + ~190 multiplies).
  - `bls12_381.Fp2`: quadratic extension `Fp[u]/(u² + 1)`. Add, sub,
    neg, mul (schoolbook), specialized square via `(a+b)(a-b) + 2ab·u`,
    and norm-based inversion. Tested with the `u² = -1` invariant,
    distributive multiplication, hand-computed values, and inversion
    round-trips.
  - `bls12_381.Fr`: BLS12-381 scalar field instantiation (4 limbs, 255
    bits). Validators sign with scalars from this field; the curve
    point group order is exactly `r`. Tested with identity laws,
    distributive multiplication, the (r-1)+1 = 0 wraparound, and the
    4-limb Fermat inversion round-trip.
  - `bls12_381.Fp6`: cubic extension `Fp2[v]/(v³ - (1+u))`. add, sub,
    neg, mul (schoolbook, 9 Fp2 mults), square, mulByV, inv (via the
    standard adjugate/norm formula). Tested with the v³ = 1+u tower
    relation, distributive multiplication, associativity, mulByV
    against manual mul, and inversion round-trips.
  - `bls12_381.Fp12`: quadratic extension `Fp6[w]/(w² - v)` — the
    target group of the BLS12-381 optimal Ate pairing. mul uses
    Karatsuba (3 Fp6 mults), inv is norm-based (one Fp6 inversion).
    Tested with the w² = v tower relation, distributive
    multiplication, and inversion round-trips.
  - `bls12_381.G1Affine` / `bls12_381.G2Affine`: short-Weierstrass
    curves `y² = x³ + 4` (G1, over Fp) and `y² = x³ + 4(1+u)` (G2,
    over Fp2). `identity`, `fromRaw`, `isOnCurve`, `eql`, `neg`,
    `double`, `add`, and double-and-add `mul` parametric over scalar
    limb count. Generator coordinates pinned from the standard hex
    encodings and validated against the curve equation. Tested with
    neutrality, P + (-P) = id, the 2P/3P/4P consistency checks,
    commutativity, associativity, and scalar-multiplication identities.
  - `bls12_381.G1Projective` / `bls12_381.G2Projective`: Jacobian
    projective coordinates `(X, Y, Z)` representing the affine point
    `(X/Z², Y/Z³)`. Doubling (`dbl-2009-l`) and addition
    (`add-2007-bl`) are inversion-free; only the final affine
    projection needs an inverse. The Miller loop will hold its G2
    accumulator in this representation. Tested by cross-checking
    against the affine arithmetic for every operation.
  - `bls12_381.isInG1Subgroup` / `bls12_381.isInG2Subgroup`: subgroup
    membership predicates that verify `r·P == identity`. Slow but
    correct; the standard fast checks (Bowe's endomorphism trick)
    can land later as drop-in replacements.
  - `bls12_381.BLS_X_ABS` / `BLS_X_IS_NEGATIVE` / `BLS_X_LOOP_BITS`:
    the BLS12-381 trace parameter the Miller loop walks, plus a
    detailed roadmap comment for the optimal Ate pairing
    (Miller loop + final exponentiation) that's still to come.
  - `bls12_381.fp2Frobenius` / `Fp12.conjugate`: the smallest
    pairing primitives. The Fp2 Frobenius is just conjugation
    (because BLS12-381's prime is `p ≡ 3 mod 4`); the Fp12
    conjugation is what the easy part of the final exponentiation
    uses to avoid a full `p^6` powering.
  - `bls12_381.fp2Pow` / `bls12_381.Fp6.pow` / `bls12_381.Fp12.pow`:
    square-and-multiply over a generic-width limb exponent. Slow
    fallback paths for the optimized Frobenius-based versions to
    validate against, plus a way to compute Frobenius coefficients
    at runtime without hand-typed tables.
  - `bls12_381.fp6Frobenius` / `bls12_381.fp12Frobenius` /
    `bls12_381.fp12FrobeniusSquared`: full BLS12-381 Frobenius
    chain on Fp6 and Fp12 using comptime-derived (p-1)/3 and (p-1)/6
    exponents. Cross-checked against the slow `Fp6.pow(a, p)` and
    `Fp12.pow(a, p)` baselines.
  - `bls12_381.fp12FinalExpEasy`: the easy part of the BLS12-381
    final exponentiation, `f^((p^6 - 1)(p^2 + 1))`. Validated by
    checking that the result lives in the cyclotomic subgroup
    (`conjugate(g) · g = 1`).
  - `bls12_381.fpFromBytes64Be` / `bls12_381.FP_2_TO_256`: reduce a
    64-byte big-endian integer modulo `p`. Both halves are < 2^256
    < p, so the reduction collapses to one Fp mul + one Fp add.
- `../zolt-arith/src/hash_to_field.zig` is the start of the RFC 9380
  hash-to-curve pipeline. `expand_message_xmd(out, msg, dst)`
  implements RFC 9380 §5.3.1 with SHA-256. `hash_to_field_fp` /
  `hash_to_field_fp2` use it to produce BLS12-381 Fp / Fp2 elements
  with `L = 64` and `k = 128`. Tests are self-consistency rather
  than cross-implementation vectors — a separate cross-check pass
  against RFC 9380 Appendix K vectors lands once an external test
  harness is in place.
  - `bls12_381.fpSqrt` / `bls12_381.fp2Sqrt`: square roots in Fp and
    Fp2. The Fp version uses `a^((p+1)/4)` (BLS12-381's prime is
    `p ≡ 3 mod 4`); the Fp2 version uses the standard "norm trick"
    that reduces to two Fp sqrts plus a halve.
  - `bls12_381.decodeG1Compressed` / `bls12_381.decodeG2Compressed`:
    parsers for the 48-byte (G1) and 96-byte (G2) compressed wire
    forms from the IETF pairing-friendly-curves draft §C.2. Validate
    the compression / infinity / y-sign flags, reconstruct y from the
    curve equation, verify x < p, and pick the correct y root via
    lexicographic comparison. Tested end-to-end against the canonical
    G1 and G2 generator hex encodings.
  Zyli imports the package via path dependency in `build.zig.zon` and
  re-exports it through `src/crypto/zolt_arith.zig`.
  `src/crypto/zolt_arith_adapter.zig` is the seam where Hyli wire bytes
  (compressed BLS12-381 G1 / G2 byte strings) get converted into curve
  points. `validatorPublicKeyToG1` and `signatureToG2` complete the
  end-to-end "Hyli wire → BLS12-381 point" path; the substrate stays
  Hyli-agnostic. Each package owns its own test step: `zig build test`
  in zyli runs 176 tests, in `../zolt-arith` runs 111, and the test
  runner does NOT propagate across module boundaries on Zig 0.15.
- `src/crypto/signable.zig` pins the BLS DST string used by
  `hyli-crypto::sign_msg` and exposes `signableBytesAlloc(Msg, msg)` —
  the "what bytes get BLS-signed" rule (`borsh::to_vec(&msg)` for any
  `Signed<T, V>`). The fixture-gen asserts at build time that the
  signable payload equals the standalone borsh fixture, so a future
  refactor that breaks the invariant fails the build immediately.

## Immediate

- Add the optimal Ate Miller loop for BLS12-381. The doubling and
  addition steps run on `G2Projective` and produce both the new
  G2 point and a sparse `Fp12` line value evaluated at the G1
  point. The line has at most 3 non-zero `Fp2` coefficients (the
  M-twist embedding fits in three positions of `Fp12`); a
  specialized "mul by sparse line" can replace full `Fp12.mul` once
  the simple version is correct.
- Add the hard part of the final exponentiation:
  `f^((p^4 - p^2 + 1) / r)`, expressed via an addition chain over
  the BLS x parameter and cyclotomic squarings.
- Add the SSWU map for Fp2 → an isogenous curve E', then the
  11-isogeny push from E' to BLS12-381 G2. This is the third stage
  of hash-to-curve.
- Add G2 cofactor clearing (multiply by `h_eff` from the IETF
  pairing-friendly-curves draft). The new `G2Projective.mul` is now
  fast enough to handle the ~636-bit cofactor.
- Add a `bls.verify(pk, msg, sig)` entry point that ties everything
  together: hash msg → G2, then check `e(pk, H(msg)) == e(g1, sig)`.
- Wire that verifier into a `crypto/bls.zig` module in zyli.
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
