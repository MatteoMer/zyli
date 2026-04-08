//! Signable-payload extraction for `Signed<T, V>` envelopes.
//!
//! Hyli's BLS verifier (`crates/hyli-crypto/src/lib.rs::verify`) computes
//! the message digest from `borsh::to_vec(&signed.msg)`. There is no domain
//! separation, no length prefix, no envelope — just the borsh bytes of the
//! inner message. The DST string is provided to `blst::min_pk` separately
//! and lives in `bls_min_pk_dst` below.
//!
//! This module exists so the rest of Zyli can ask "what bytes would Hyli
//! BLS-sign for this message?" without re-implementing the rule at every
//! call site, and so the invariant has a single test surface against the
//! `borsh/crypto/signable_*` corpus fixtures.

const std = @import("std");
const borsh = @import("../model/borsh.zig");

/// Domain separation tag used by `hyli-crypto` for `blst::min_pk` signing.
/// Pinned as a compile-time constant; the future BLS verifier in
/// `zolt-arith` must use this exact byte string.
pub const bls_min_pk_dst: []const u8 = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Encode the inner message of any value into the byte string that BLS
/// signs. Generic over the message type so it works for every Hyli network
/// message. The caller owns the returned buffer.
pub fn signableBytesAlloc(
    allocator: std.mem.Allocator,
    comptime Msg: type,
    msg: Msg,
) ![]u8 {
    var list = try borsh.encodeAlloc(allocator, Msg, msg);
    return list.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const corpus = @import("corpus");
const types = @import("../model/types.zig");

test "BLS DST constant matches the upstream hyli-crypto value" {
    try testing.expectEqualSlices(u8, corpus.borsh.crypto.bls_min_pk_dst, bls_min_pk_dst);
}

test "signable bytes for ValidatorCandidacy = borsh(msg)" {
    const candidacy: types.ValidatorCandidacy = .{
        .peer_address = "127.0.0.1:4242",
    };
    const out = try signableBytesAlloc(testing.allocator, types.ValidatorCandidacy, candidacy);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(
        u8,
        corpus.borsh.crypto.signable_validator_candidacy,
        out,
    );
    // The signable payload must match the standalone borsh fixture too —
    // that is the whole "signable == borsh(msg)" invariant.
    try testing.expectEqualSlices(
        u8,
        corpus.borsh.model.validator_candidacy,
        out,
    );
}

test "signable bytes for NodeConnectionData = borsh(msg)" {
    const node: types.NodeConnectionData = .{
        .version = 1,
        .name = "validator-a",
        .current_height = 42,
        .p2p_public_address = "127.0.0.1:4242",
        .da_public_address = "127.0.0.1:4243",
        .start_timestamp = .{ .millis = 1_700_000_000_000 },
    };
    const out = try signableBytesAlloc(testing.allocator, types.NodeConnectionData, node);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(
        u8,
        corpus.borsh.crypto.signable_node_connection_data,
        out,
    );
    try testing.expectEqualSlices(
        u8,
        corpus.borsh.model.node_connection_data,
        out,
    );
}
