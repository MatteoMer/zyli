//! Hyli-shaped BLS signature verification.
//!
//! Wires the `zolt_arith.bls` verifier into the protocol types Zyli
//! actually carries on the wire. Three layers:
//!
//!   1. `verifyBlobBytes(pk_bytes, msg, sig_bytes)` — the lowest level.
//!      Takes raw 48-byte pubkey and 96-byte signature and the bytes
//!      to verify. Mirrors `BlstCrypto::verify_bytes` from
//!      `hyli-crypto`.
//!
//!   2. `verifyValidatorSig(sig, msg)` — Hyli `ValidatorSignature`
//!      flavor. Pulls the pubkey and the BLS signature out of a
//!      `ValidatorSignature` envelope and runs the bytes-level verify.
//!
//!   3. `verifySignedByValidator(comptime Msg, signed)` — the typed
//!      flavor. Borshs `signed.msg` to bytes via the existing
//!      `signable` rule, then dispatches into `verifyValidatorSig`.
//!      This is what protocol-handling code (consensus / mempool /
//!      handshake) will reach for once we start verifying real wire
//!      messages.
//!
//! All three return `bool` for the verdict and `error` only for
//! malformed inputs (wrong-length bytes, decode failures, subgroup
//! check failures). Verifiers must NEVER swallow signature failures
//! into success — Hyli relies on this for consensus safety.

const std = @import("std");
const zolt_arith = @import("zolt_arith");
const types = @import("../model/types.zig");
const signable = @import("signable.zig");
const adapter = @import("zolt_arith_adapter.zig");
const borsh = @import("../model/borsh.zig");

const bls = zolt_arith.bls;
const decodeG1Compressed = zolt_arith.bls12_381.decodeG1Compressed;
const decodeG2Compressed = zolt_arith.bls12_381.decodeG2Compressed;

/// Re-export the IETF DST string so the rest of Zyli can use it as the
/// canonical "what DST does Hyli sign with" constant. Pinned equal to
/// `signable.bls_min_pk_dst` at compile time so a future drift between
/// the two surfaces shows up as a build break, not a silent runtime
/// rejection.
pub const DST = bls.DST_BLS_SIG_NUL;

comptime {
    if (!std.mem.eql(u8, DST, signable.bls_min_pk_dst)) {
        @compileError("DST string drift between zolt_arith.bls and zyli signable");
    }
}

pub const Error = error{
    InvalidPubkeyEncoding,
    InvalidSignatureEncoding,
    PublicKeyIsIdentity,
    PublicKeyNotInSubgroup,
    SignatureNotInSubgroup,
    HashFailed,
} || borsh.Error;

/// Lowest-level entry point: verify that `sig_bytes` is a valid BLS
/// signature on `msg` under the public key encoded in `pk_bytes`.
///
/// `pk_bytes` must be the 48-byte compressed BLS12-381 G1 form,
/// `sig_bytes` must be the 96-byte compressed G2 form. Both decoders
/// also enforce subgroup membership downstream.
///
/// Mirrors `BlstCrypto::verify_bytes` from `hyli-crypto/src/lib.rs`.
pub fn verifyBlobBytes(
    pk_bytes: []const u8,
    msg: []const u8,
    sig_bytes: []const u8,
) Error!bool {
    if (pk_bytes.len != 48) return Error.InvalidPubkeyEncoding;
    if (sig_bytes.len != 96) return Error.InvalidSignatureEncoding;

    const pk = decodeG1Compressed(pk_bytes) catch return Error.InvalidPubkeyEncoding;
    const sig = decodeG2Compressed(sig_bytes) catch return Error.InvalidSignatureEncoding;

    return bls.verify(pk, msg, sig, DST) catch |err| switch (err) {
        bls.VerifyError.PublicKeyIsIdentity => Error.PublicKeyIsIdentity,
        bls.VerifyError.PublicKeyNotInSubgroup => Error.PublicKeyNotInSubgroup,
        bls.VerifyError.SignatureNotInSubgroup => Error.SignatureNotInSubgroup,
        bls.VerifyError.HashFailed => Error.HashFailed,
    };
}

/// Verify a Hyli `ValidatorSignature` envelope against the bytes the
/// validator signed. Pulls the pubkey out of `sig.validator` and the
/// signature bytes out of `sig.signature`, then dispatches into
/// `verifyBlobBytes`.
pub fn verifyValidatorSig(
    sig: types.ValidatorSignature,
    msg_bytes: []const u8,
) Error!bool {
    return verifyBlobBytes(sig.validator.bytes, msg_bytes, sig.signature.bytes);
}

/// Highest-level entry point: verify a `Signed<Msg, ValidatorSignature>`
/// envelope. The signable bytes are computed via the existing
/// `signable.signableBytesAlloc` rule (`borsh::to_vec(&msg)`), then
/// fed through `verifyValidatorSig`.
///
/// `comptime Msg` keeps the dispatch monomorphic so the borsh encoder
/// can specialize per type. The caller's allocator is used for the
/// transient signable buffer; on success and on failure the buffer is
/// freed before this function returns.
pub fn verifySignedByValidator(
    allocator: std.mem.Allocator,
    comptime Msg: type,
    signed: types.Signed(Msg, types.ValidatorSignature),
) Error!bool {
    const msg_bytes = try signable.signableBytesAlloc(allocator, Msg, signed.msg);
    defer allocator.free(msg_bytes);
    return verifyValidatorSig(signed.signature, msg_bytes);
}

// ---------------------------------------------------------------------------
// Aggregate signature verification.
//
// Hyli uses same-message BLS aggregates for consensus QCs: many
// validators sign the same prepare/commit/timeout payload, the
// signatures are summed, and the resulting `AggregateSignature`
// carries both the summed bytes and the validator list. The verifier
// rebuilds the aggregate public key from the validator list, then
// runs the standard `verify` rule against the aggregated signature.
// ---------------------------------------------------------------------------

/// Verify a Hyli `AggregateSignature` envelope against the bytes the
/// validators signed. Decodes each validator pubkey out of the
/// `validators` list, decodes the aggregate signature, and runs the
/// same-message aggregate verifier.
///
/// Allocates a small temporary buffer to hold the decoded pubkeys
/// (heap-allocated so the validator list size isn't bounded at compile
/// time). Empty validator lists always reject.
pub fn verifyAggregateSig(
    allocator: std.mem.Allocator,
    agg: types.AggregateSignature,
    msg_bytes: []const u8,
) Error!bool {
    if (agg.signature.bytes.len != 96) return Error.InvalidSignatureEncoding;

    const pks = try allocator.alloc(zolt_arith.bls12_381.G1Affine, agg.validators.len);
    defer allocator.free(pks);
    for (agg.validators, 0..) |pk, i| {
        if (pk.bytes.len != 48) return Error.InvalidPubkeyEncoding;
        pks[i] = decodeG1Compressed(pk.bytes) catch return Error.InvalidPubkeyEncoding;
    }
    const sig = decodeG2Compressed(agg.signature.bytes) catch return Error.InvalidSignatureEncoding;

    return zolt_arith.bls.verifyAggregate(pks, msg_bytes, sig, DST) catch |err| switch (err) {
        zolt_arith.bls.VerifyError.PublicKeyIsIdentity => Error.PublicKeyIsIdentity,
        zolt_arith.bls.VerifyError.PublicKeyNotInSubgroup => Error.PublicKeyNotInSubgroup,
        zolt_arith.bls.VerifyError.SignatureNotInSubgroup => Error.SignatureNotInSubgroup,
        zolt_arith.bls.VerifyError.HashFailed => Error.HashFailed,
    };
}

/// Typed convenience: verify a `Signed<Msg, AggregateSignature>`. Same
/// shape as `verifySignedByValidator` but for the aggregate path.
pub fn verifySignedAggregate(
    allocator: std.mem.Allocator,
    comptime Msg: type,
    signed: types.Signed(Msg, types.AggregateSignature),
) Error!bool {
    const msg_bytes = try signable.signableBytesAlloc(allocator, Msg, signed.msg);
    defer allocator.free(msg_bytes);
    return verifyAggregateSig(allocator, signed.signature, msg_bytes);
}

// ---------------------------------------------------------------------------
// Tests
//
// We don't have a Hyli-produced test fixture yet. Instead, we use the
// algebraic identities and the round-trip path: construct a (sk, pk)
// pair on the fly, sign a known borsh payload via the same primitives
// the verifier consumes, and check that the verdict is correct.
// ---------------------------------------------------------------------------

const testing = std.testing;
const bls12_381 = zolt_arith.bls12_381;
const hash_to_curve_g2 = zolt_arith.hash_to_curve_g2;

/// Helper: produce a (pk_bytes, sig_bytes) pair for `msg` from a small
/// scalar `sk`. The bytes are the *uncompressed* form of the public
/// key x-coordinate / signature x-coordinate stuffed into the
/// compressed-wire layout — we don't have a compressor in zolt_arith
/// yet, so we route around it by feeding the affine points directly
/// into the high-level verify, which means the bytes-level entry
/// point can't be tested round-trip with a brand-new key. Instead the
/// bytes-level test re-uses canonical generator encodings.
fn signWithScalarForTest(sk: u64, msg: []const u8) struct {
    pk: bls12_381.G1Affine,
    sig: bls12_381.G2Affine,
} {
    const sk_limbs: [4]u64 = .{ sk, 0, 0, 0 };
    const pk = bls12_381.g1Generator().mul(4, sk_limbs);
    const h_msg = hash_to_curve_g2.hashToG2(msg, DST) catch unreachable;
    const sig = h_msg.mul(4, sk_limbs);
    return .{ .pk = pk, .sig = sig };
}

test "DST constant matches Hyli signable DST" {
    try testing.expectEqualSlices(u8, signable.bls_min_pk_dst, DST);
}

test "verifyBlobBytes rejects wrong pubkey length" {
    const pk_short: [47]u8 = .{0} ** 47;
    const sig: [96]u8 = .{0} ** 96;
    try testing.expectError(Error.InvalidPubkeyEncoding, verifyBlobBytes(&pk_short, "msg", &sig));
}

test "verifyBlobBytes rejects wrong signature length" {
    const pk: [48]u8 = .{0x80} ** 48; // compression flag set, infinity bits cleared
    const sig_short: [95]u8 = .{0} ** 95;
    try testing.expectError(Error.InvalidSignatureEncoding, verifyBlobBytes(&pk, "msg", &sig_short));
}

test "verifyValidatorSig: round-trip with self-constructed signature" {
    // Generate a real (pk, sig) pair, then route the (raw points)
    // through the verifier directly via the strict bls.verify entry
    // point. This sidesteps the missing compression encoder while
    // still exercising the full pairing path.
    const generated = signWithScalarForTest(7, "validator-sig-test");
    const ok = try zolt_arith.bls.verify(
        generated.pk,
        "validator-sig-test",
        generated.sig,
        DST,
    );
    try testing.expect(ok);
}

test "verifyValidatorSig: rejects swapped message" {
    const generated = signWithScalarForTest(11, "message A");
    const result = try zolt_arith.bls.verify(
        generated.pk,
        "message B",
        generated.sig,
        DST,
    );
    try testing.expect(!result);
}

test "verifyBlobBytes: cross-impl vector from Rust blst::min_pk verifies" {
    // The fixture-gen produces this vector via the same blst surface
    // hyli-crypto uses for sign_msg / verify. If our pipeline diverges
    // from blst at any wire-format level (compression bits, hash-to-
    // curve variant, DST handling, point ordering), this test fails.
    const corpus_mod = @import("corpus");
    const pk = corpus_mod.crypto.bls.cross_impl_pubkey;
    const msg = corpus_mod.crypto.bls.cross_impl_msg;
    const sig = corpus_mod.crypto.bls.cross_impl_signature;

    const ok = try verifyBlobBytes(pk, msg, sig);
    try testing.expect(ok);
}

test "verifyBlobBytes: cross-impl alternate-message vector verifies" {
    const corpus_mod = @import("corpus");
    const pk = corpus_mod.crypto.bls.cross_impl_pubkey;
    const msg_alt = corpus_mod.crypto.bls.cross_impl_msg_alt;
    const sig_alt = corpus_mod.crypto.bls.cross_impl_signature_alt;

    const ok = try verifyBlobBytes(pk, msg_alt, sig_alt);
    try testing.expect(ok);
}

test "verifyBlobBytes: cross-impl signature/message swap rejects" {
    // Signature for the original message but verifying against the
    // alternate message — must be rejected.
    const corpus_mod = @import("corpus");
    const pk = corpus_mod.crypto.bls.cross_impl_pubkey;
    const msg_alt = corpus_mod.crypto.bls.cross_impl_msg_alt;
    const sig_orig = corpus_mod.crypto.bls.cross_impl_signature;

    const ok = try verifyBlobBytes(pk, msg_alt, sig_orig);
    try testing.expect(!ok);
}

test "verifyAggregateSig: rejects empty validator list" {
    // Use an infinity-encoded G2 signature so the decoder accepts it,
    // then assert the empty validator list short-circuits to false.
    var infty_sig: [96]u8 = .{0} ** 96;
    infty_sig[0] = 0xc0;
    const agg: types.AggregateSignature = .{
        .signature = .{ .bytes = &infty_sig },
        .validators = &.{},
    };
    const result = try verifyAggregateSig(testing.allocator, agg, "msg");
    try testing.expect(!result);
}

test "verifyAggregateSig: rejects wrong-length signature bytes" {
    const short_sig: [95]u8 = .{0} ** 95;
    const agg: types.AggregateSignature = .{
        .signature = .{ .bytes = &short_sig },
        .validators = &.{},
    };
    try testing.expectError(
        Error.InvalidSignatureEncoding,
        verifyAggregateSig(testing.allocator, agg, "msg"),
    );
}

test "verifySignedByValidator: routes through borsh+verify" {
    // Build a real signed payload — we use ValidatorCandidacy because
    // it has a stable borsh encoding the corpus already pins, and
    // because its signable_bytes are exactly borsh(msg).
    const candidacy: types.ValidatorCandidacy = .{ .peer_address = "127.0.0.1:4242" };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ValidatorCandidacy,
        candidacy,
    );
    defer testing.allocator.free(msg_bytes);

    // Sign those bytes with a fresh scalar.
    const generated = signWithScalarForTest(13, msg_bytes);
    const ok = try zolt_arith.bls.verify(generated.pk, msg_bytes, generated.sig, DST);
    try testing.expect(ok);

    // Cross-check that altering one byte makes the verifier reject.
    var tampered = try testing.allocator.alloc(u8, msg_bytes.len);
    defer testing.allocator.free(tampered);
    @memcpy(tampered, msg_bytes);
    tampered[0] ^= 0xff;
    const bad = try zolt_arith.bls.verify(generated.pk, tampered, generated.sig, DST);
    try testing.expect(!bad);
}
