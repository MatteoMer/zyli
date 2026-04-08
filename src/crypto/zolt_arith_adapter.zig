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

/// Convert a Hyli BLS signature (96 compressed bytes for G2) into the
/// two 6-limb coordinate field elements. The first 48 bytes encode the
/// `c1` (imaginary) coordinate and the next 48 encode `c0` (real),
/// matching the BLS12-381 G2 compressed encoding from
/// draft-irtf-cfrg-pairing-friendly-curves §C.2.
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
