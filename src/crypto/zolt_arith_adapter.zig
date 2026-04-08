//! Thin adapter that turns Hyli wire bytes into the inputs `zolt_arith`
//! expects. The point of having this file is to keep `zolt_arith`
//! ignorant of Hyli — it should know nothing about borsh, network
//! messages, or validator pubkey provenance — and to give Zyli a single
//! place where the conversion rules live.
//!
//! Today the conversions are tiny:
//!
//!   - `validatorPublicKeyToLimbs`: Hyli stores compressed BLS12-381 G1
//!     public keys as length-prefixed `Vec<u8>` (48 bytes). The 48-byte
//!     compressed encoding is big-endian by RFC 9380. We expose it as a
//!     6-limb little-endian `[6]u64`, which is what the future
//!     `zolt_arith.field` instantiation will consume.
//!   - `signatureToLimbs`: BLS12-381 G2 signatures are 96 bytes
//!     compressed. They split into two coordinate fields of 48 bytes
//!     each. The function returns the two coordinates as `[6]u64`
//!     limbs.
//!
//! These functions intentionally do NOT validate group membership or
//! deserialize the affine point — that lives in the upcoming `ec`
//! module of `zolt_arith`. The adapter only handles the byte-layout
//! conversion.

const std = @import("std");
const zolt_arith = @import("zolt_arith");
const bigint = zolt_arith.bigint;
const Fp = zolt_arith.bls12_381.Fp;
const G1Affine = zolt_arith.bls12_381.G1Affine;
const G2Affine = zolt_arith.bls12_381.G2Affine;
const decodeG1Compressed = zolt_arith.bls12_381.decodeG1Compressed;
const decodeG2Compressed = zolt_arith.bls12_381.decodeG2Compressed;
const types = @import("../model/types.zig");

/// Convert a Hyli `ValidatorPublicKey` (compressed BLS12-381 G1, 48
/// big-endian bytes) into a 6-limb little-endian integer suitable for
/// `zolt_arith.bigint`. Returns an error if the input is not exactly
/// 48 bytes.
pub const Error = error{
    InvalidPubkeyLength,
    InvalidSignatureLength,
};

pub fn validatorPublicKeyToLimbs(pk: types.ValidatorPublicKey) Error![6]u64 {
    if (pk.bytes.len != 48) return Error.InvalidPubkeyLength;
    return bigint.fromBytesBe(6, pk.bytes);
}

/// Full Hyli `ValidatorPublicKey` → BLS12-381 G1 point conversion.
/// Validates the compressed encoding, reconstructs the y coordinate
/// from the curve equation, and returns an affine G1 point ready for
/// pairing-based signature verification.
///
/// Subgroup membership is intentionally NOT checked here — Hyli
/// validator pubkeys come from `BlstCrypto::new` which always
/// produces in-subgroup points. A future hardening pass should add
/// the explicit check for adversarially-supplied keys.
pub fn validatorPublicKeyToG1(
    pk: types.ValidatorPublicKey,
) (Error || zolt_arith.bls12_381.PointDecodeError)!G1Affine {
    if (pk.bytes.len != 48) return Error.InvalidPubkeyLength;
    return decodeG1Compressed(pk.bytes);
}

/// Convert a Hyli BLS signature (96 compressed bytes for G2) into the
/// two 6-limb coordinate field elements. The first 48 bytes encode the
/// `c1` (imaginary) coordinate and the next 48 encode `c0` (real),
/// matching the BLS12-381 G2 compressed encoding from
/// draft-irtf-cfrg-pairing-friendly-curves §C.2.
///
/// This is the byte-shape conversion only — the full curve-point
/// reconstruction is in `signatureToG2` below.
pub fn signatureToLimbs(sig: types.Signature) Error!struct {
    c1: [6]u64,
    c0: [6]u64,
} {
    if (sig.bytes.len != 96) return Error.InvalidSignatureLength;
    return .{
        .c1 = bigint.fromBytesBe(6, sig.bytes[0..48]),
        .c0 = bigint.fromBytesBe(6, sig.bytes[48..96]),
    };
}

/// Full Hyli BLS `Signature` → BLS12-381 G2 point conversion.
/// Validates the compressed encoding, reconstructs the y coordinate
/// from the curve equation `y² = x³ + 4(1+u)`, and returns an affine
/// G2 point ready for pairing-based verification.
///
/// Subgroup membership is intentionally NOT checked here.
pub fn signatureToG2(
    sig: types.Signature,
) (Error || zolt_arith.bls12_381.PointDecodeError)!G2Affine {
    if (sig.bytes.len != 96) return Error.InvalidSignatureLength;
    return decodeG2Compressed(sig.bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "validatorPublicKeyToLimbs rejects wrong-length input" {
    const short: types.ValidatorPublicKey = .{ .bytes = &[_]u8{0xaa} ** 47 };
    try testing.expectError(Error.InvalidPubkeyLength, validatorPublicKeyToLimbs(short));
    const long: types.ValidatorPublicKey = .{ .bytes = &[_]u8{0xaa} ** 49 };
    try testing.expectError(Error.InvalidPubkeyLength, validatorPublicKeyToLimbs(long));
}

test "validatorPublicKeyToLimbs reads BE bytes into LE limbs" {
    // 48-byte BE input where the highest bit of the first byte is 1
    // (compressed-form sign flag for the c1 coordinate). The limb
    // representation should put the most-significant byte at limb 5.
    var bytes: [48]u8 = .{0} ** 48;
    bytes[0] = 0xab;
    bytes[47] = 0xcd;
    const pk: types.ValidatorPublicKey = .{ .bytes = &bytes };
    const limbs = try validatorPublicKeyToLimbs(pk);
    // limbs[5] is the high limb. Its top byte should be the BE input's
    // first byte (0xab) shifted into position 56 of the limb.
    try testing.expectEqual(@as(u64, 0xab << 56), limbs[5] & (@as(u64, 0xff) << 56));
    // limbs[0] is the low limb. Its bottom byte should be the BE input's
    // last byte (0xcd).
    try testing.expectEqual(@as(u64, 0xcd), limbs[0] & 0xff);
}

test "signatureToLimbs splits 96-byte input into two 6-limb coordinates" {
    var bytes: [96]u8 = .{0} ** 96;
    bytes[0] = 0xab; // top of c1
    bytes[47] = 0x11; // bottom of c1
    bytes[48] = 0xcd; // top of c0
    bytes[95] = 0x22; // bottom of c0
    const sig: types.Signature = .{ .bytes = &bytes };
    const out = try signatureToLimbs(sig);
    try testing.expectEqual(@as(u64, 0xab << 56), out.c1[5] & (@as(u64, 0xff) << 56));
    try testing.expectEqual(@as(u64, 0x11), out.c1[0] & 0xff);
    try testing.expectEqual(@as(u64, 0xcd << 56), out.c0[5] & (@as(u64, 0xff) << 56));
    try testing.expectEqual(@as(u64, 0x22), out.c0[0] & 0xff);
}

test "signatureToLimbs rejects wrong-length input" {
    const short: types.Signature = .{ .bytes = &[_]u8{0xaa} ** 95 };
    try testing.expectError(Error.InvalidSignatureLength, signatureToLimbs(short));
}

// ---------------------------------------------------------------------------
// Smoke test that the BLS12-381 Fp instantiation is reachable from
// Zyli. This guards against future build.zig changes that accidentally
// drop the dependency wiring.
// ---------------------------------------------------------------------------

test "BLS12-381 Fp is reachable from zyli" {
    const one = Fp.one();
    const two = Fp.fromRaw(.{ 2, 0, 0, 0, 0, 0 });
    const three = Fp.add(one, two);
    const raw = Fp.toRaw(three);
    try testing.expectEqual(@as(u64, 3), raw[0]);
    inline for (1..6) |i| try testing.expectEqual(@as(u64, 0), raw[i]);
}

test "validatorPublicKeyToG1 decodes the canonical G1 generator" {
    // The canonical BLS12-381 G1 generator's compressed wire form.
    const generator_hex = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    var bytes: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, generator_hex);
    const pk: types.ValidatorPublicKey = .{ .bytes = &bytes };
    const point = try validatorPublicKeyToG1(pk);
    try testing.expect(point.isOnCurve());
    // The decoded point must be the canonical g1Generator().
    try testing.expect(G1Affine.eql(point, zolt_arith.bls12_381.g1Generator()));
}

test "validatorPublicKeyToG1 rejects wrong-length input" {
    const short: types.ValidatorPublicKey = .{ .bytes = &[_]u8{0x80} ** 47 };
    try testing.expectError(Error.InvalidPubkeyLength, validatorPublicKeyToG1(short));
}

test "signatureToG2 decodes the canonical G2 generator" {
    // The canonical BLS12-381 G2 generator's compressed wire form. The
    // signature byte type from Hyli has no semantic restriction
    // beyond the 96-byte length, so re-using this fixture is fine.
    const generator_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    var bytes: [96]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, generator_hex);
    const sig: types.Signature = .{ .bytes = &bytes };
    const point = try signatureToG2(sig);
    try testing.expect(point.isOnCurve());
}

test "signatureToG2 rejects wrong-length input" {
    const short: types.Signature = .{ .bytes = &[_]u8{0x80} ** 95 };
    try testing.expectError(Error.InvalidSignatureLength, signatureToG2(short));
}

test "hash_to_field is reachable from zyli for the BLS DST" {
    // Smoke test: feed an arbitrary message through hash_to_field_fp2
    // with the BLS sign DST and check the output is non-degenerate.
    // This is the path the upcoming bls.verify will use to hash the
    // signable bytes into a G2 point.
    var elements: [2]zolt_arith.bls12_381.Fp2 = undefined;
    try zolt_arith.hash_to_field.hash_to_field_fp2(
        &elements,
        "test message",
        @import("signable.zig").bls_min_pk_dst,
    );
    // Both Fp2 elements should be distinct from each other (overwhelming
    // probability) and non-zero.
    try testing.expect(!zolt_arith.bls12_381.Fp2.eql(elements[0], elements[1]));
    try testing.expect(!zolt_arith.bls12_381.Fp2.eql(elements[0], zolt_arith.bls12_381.Fp2.zero()));
}
