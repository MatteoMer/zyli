//! Build and serialize a real Hyli `Handshake::Hello` for the
//! observer.
//!
//! The flow is:
//!
//!   1. Pick a BLS secret key (caller-supplied — typically a fresh
//!      ephemeral scalar; the observer never reuses one across runs).
//!   2. Build a `NodeConnectionData` describing this node's identity
//!      and peer-routing info.
//!   3. Borsh-encode the `NodeConnectionData` and BLS-sign the bytes
//!      with the canonical Hyli `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`
//!      DST. The signature pairs with the derived public key to form a
//!      `ValidatorSignature` envelope.
//!   4. Wrap the signed connection data in a `HandshakePayload` along
//!      with the canal name (`"p2p"` for the consensus channel) and
//!      the current wall-clock timestamp.
//!   5. Wrap that in `Handshake::Hello` and again in
//!      `P2PTcpMessage<Data>::Handshake`.
//!   6. Borsh-encode and prepend the 4-byte BE length prefix.
//!
//! The output is exactly the bytes Hyli's `hyli-net::tcp` reader
//! expects to see for an inbound connection — it can be written
//! verbatim to a TCP stream.
//!
//! Subgroup membership of the derived public key is implicit:
//! `derivePublicKeyFromScalar(sk)` always lands in the prime-order
//! G1 subgroup because the generator does and `r·sk·G = O`.

const std = @import("std");
const types = @import("../model/types.zig");
const borsh = @import("../model/borsh.zig");
const framing = @import("../wire/framing.zig");
const handshake_wire = @import("../wire/handshake.zig");
const bls = @import("../crypto/bls.zig");
const zolt_arith = @import("zolt_arith");

/// What the observer needs to provide so the Hello can be filled in.
pub const HelloConfig = struct {
    /// 4-limb BLS secret key (Fr canonical form, little-endian limbs).
    sk: [4]u64,
    /// Validator name advertised in `NodeConnectionData.name`.
    name: []const u8,
    /// Public p2p socket address (`host:port`) advertised to the peer.
    p2p_public_address: []const u8,
    /// Public DA socket address (`host:port`) advertised to the peer.
    da_public_address: []const u8,
    /// Start timestamp the observer claims as its launch time.
    start_timestamp: types.TimestampMs,
    /// Wall-clock timestamp written into the outer `HandshakePayload.timestamp`.
    handshake_timestamp: types.TimestampMs,
    /// Canal name. Hyli uses `"p2p"` for the consensus channel.
    canal: []const u8 = "p2p",
    /// Current local block height the observer claims to know about.
    current_height: u64 = 0,
    /// Hyli protocol version. Pinned at 1 in upstream `hyli-net`.
    version: u16 = 1,
};

/// What the caller gets back from `buildHelloFrame`. The bytes slices
/// are heap-allocated and must be freed with `Bundle.deinit`.
pub const Bundle = struct {
    /// The signed `NodeConnectionData` bytes used as the BLS signing
    /// payload. Kept around because the public key + signature alone
    /// don't tell you what was signed.
    signed_payload: []const u8,
    /// The compressed BLS public key bytes (48 bytes).
    pubkey_bytes: []const u8,
    /// The compressed BLS signature bytes (96 bytes).
    signature_bytes: []const u8,
    /// The full Borsh-encoded `P2PTcpMessage::Handshake(Hello(..))` payload.
    /// This is what would go into the framed envelope.
    inner: []const u8,
    /// The framed bytes — `inner` prefixed with its 4-byte BE length.
    /// This is what gets written to the TCP stream.
    framed: []const u8,

    pub fn deinit(self: *Bundle, allocator: std.mem.Allocator) void {
        allocator.free(self.signed_payload);
        allocator.free(self.pubkey_bytes);
        allocator.free(self.signature_bytes);
        allocator.free(self.inner);
        allocator.free(self.framed);
    }
};

pub const Error = error{
    /// `HelloConfig.sk` is the zero scalar.
    SecretKeyIsZero,
    /// Hash-to-curve over the signing payload failed.
    HashFailed,
} || std.mem.Allocator.Error || borsh.Error || framing.Error;

/// Build a fully-signed `Handshake::Hello` ready to write to a TCP
/// stream. The returned `Bundle` owns five heap allocations; release
/// them all with `bundle.deinit(allocator)`.
///
/// The `Inner` type parameter is the inner-data type of the
/// `P2PTcpMessage<Inner>` envelope. For the consensus channel this is
/// `ConsensusNetMessage`; for the DA channel it's a different type.
/// The choice doesn't affect the Hello bytes themselves — Hello is
/// the `Handshake` variant of the envelope, which carries no `Inner`
/// payload — but the Borsh encoder needs the comptime parameter to
/// monomorphise.
pub fn buildHelloFrame(
    allocator: std.mem.Allocator,
    comptime Inner: type,
    config: HelloConfig,
) Error!Bundle {
    if (config.sk[0] == 0 and config.sk[1] == 0 and config.sk[2] == 0 and config.sk[3] == 0) {
        return Error.SecretKeyIsZero;
    }

    // 1. Borsh-encode NodeConnectionData (this is what gets signed).
    const ncd: types.NodeConnectionData = .{
        .version = config.version,
        .name = config.name,
        .current_height = config.current_height,
        .p2p_public_address = config.p2p_public_address,
        .da_public_address = config.da_public_address,
        .start_timestamp = config.start_timestamp,
    };
    var signed_payload_list = try borsh.encodeAlloc(
        allocator,
        types.NodeConnectionData,
        ncd,
    );
    const signed_payload = try signed_payload_list.toOwnedSlice(allocator);
    errdefer allocator.free(signed_payload);

    // 2. BLS-sign over the borsh-encoded NCD.
    const sig_point = zolt_arith.bls.signWithScalar(
        config.sk,
        signed_payload,
        bls.DST,
    ) catch |err| switch (err) {
        zolt_arith.bls.SignError.HashFailed => return Error.HashFailed,
        zolt_arith.bls.SignError.InvalidSecretKeyLength,
        zolt_arith.bls.SignError.SecretKeyIsZero,
        => unreachable, // signWithScalar with raw [4]u64 doesn't surface these
    };
    const sig_bytes_arr = zolt_arith.bls12_381.encodeG2Compressed(sig_point);
    const sig_bytes = try allocator.dupe(u8, &sig_bytes_arr);
    errdefer allocator.free(sig_bytes);

    // 3. Derive the corresponding public key.
    const pk_point = zolt_arith.bls.derivePublicKeyFromScalar(config.sk);
    const pk_bytes_arr = zolt_arith.bls12_381.encodeG1Compressed(pk_point);
    const pk_bytes = try allocator.dupe(u8, &pk_bytes_arr);
    errdefer allocator.free(pk_bytes);

    // 4. Wrap into the typed envelope: Signed<NCD, ValidatorSignature>.
    const signed_ncd: types.Signed(types.NodeConnectionData, types.ValidatorSignature) = .{
        .msg = ncd,
        .signature = .{
            .signature = .{ .bytes = sig_bytes },
            .validator = .{ .bytes = pk_bytes },
        },
    };

    // 5. Wrap in HandshakePayload + Handshake::Hello + P2PTcpMessage.
    const hp: types.HandshakePayload = .{
        .canal = .{ .name = config.canal },
        .signed_node_connection_data = signed_ncd,
        .timestamp = config.handshake_timestamp,
    };
    const M = types.P2PTcpMessage(Inner);
    const envelope: M = handshake_wire.handshakeEnvelope(Inner, handshake_wire.hello(hp));

    // 6. Borsh-encode the envelope.
    var inner_list = try borsh.encodeAlloc(allocator, M, envelope);
    const inner = try inner_list.toOwnedSlice(allocator);
    errdefer allocator.free(inner);

    // 7. Frame it: 4-byte BE length prefix.
    const framed = try framing.encodeFrameAlloc(allocator, inner);
    errdefer allocator.free(framed);

    return .{
        .signed_payload = signed_payload,
        .pubkey_bytes = pk_bytes,
        .signature_bytes = sig_bytes,
        .inner = inner,
        .framed = framed,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "buildHelloFrame: produces a verifiable signature on the NodeConnectionData" {
    var bundle = try buildHelloFrame(testing.allocator, []const u8, .{
        .sk = .{ 0xdeadbeef, 0, 0, 0 },
        .name = "zyli-observer",
        .p2p_public_address = "0.0.0.0:4242",
        .da_public_address = "0.0.0.0:4243",
        .start_timestamp = .{ .millis = 1_700_000_000_000 },
        .handshake_timestamp = .{ .millis = 1_700_000_000_001 },
    });
    defer bundle.deinit(testing.allocator);

    // The signature must verify against the bundle's pubkey + payload.
    const ok = try bls.verifyBlobBytes(
        bundle.pubkey_bytes,
        bundle.signed_payload,
        bundle.signature_bytes,
    );
    try testing.expect(ok);
}

test "buildHelloFrame: framed bytes round-trip through the frame reader" {
    var bundle = try buildHelloFrame(testing.allocator, []const u8, .{
        .sk = .{ 0x12345, 0, 0, 0 },
        .name = "zyli-observer",
        .p2p_public_address = "127.0.0.1:4242",
        .da_public_address = "127.0.0.1:4243",
        .start_timestamp = .{ .millis = 1_000_000 },
        .handshake_timestamp = .{ .millis = 1_000_001 },
    });
    defer bundle.deinit(testing.allocator);

    // Decode the inner P2PTcpMessage out of the Borsh bytes and check
    // it round-trips back to a Handshake::Hello. Use an arena so we
    // don't have to walk the decoded value tree to free every slice.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const Inner = []const u8;
    const M = types.P2PTcpMessage(Inner);
    var reader = borsh.Reader.init(bundle.inner);
    const decoded = try borsh.decode(M, &reader, arena.allocator());

    try testing.expect(decoded == .handshake);
    try testing.expect(decoded.handshake == .hello);
    try testing.expectEqualStrings("p2p", decoded.handshake.hello.canal.name);
    try testing.expectEqualStrings(
        "zyli-observer",
        decoded.handshake.hello.signed_node_connection_data.msg.name,
    );
}

test "buildHelloFrame: rejects zero secret key" {
    try testing.expectError(Error.SecretKeyIsZero, buildHelloFrame(
        testing.allocator,
        []const u8,
        .{
            .sk = .{ 0, 0, 0, 0 },
            .name = "x",
            .p2p_public_address = "0.0.0.0:0",
            .da_public_address = "0.0.0.0:0",
            .start_timestamp = .{ .millis = 0 },
            .handshake_timestamp = .{ .millis = 0 },
        },
    ));
}

test "buildHelloFrame: framed prefix matches the inner length" {
    var bundle = try buildHelloFrame(testing.allocator, []const u8, .{
        .sk = .{ 7, 0, 0, 0 },
        .name = "z",
        .p2p_public_address = "1.2.3.4:5",
        .da_public_address = "1.2.3.4:6",
        .start_timestamp = .{ .millis = 1 },
        .handshake_timestamp = .{ .millis = 2 },
    });
    defer bundle.deinit(testing.allocator);

    // Frame layout: 4 bytes BE length || inner bytes.
    try testing.expectEqual(bundle.inner.len + 4, bundle.framed.len);
    const len_prefix = std.mem.readInt(u32, bundle.framed[0..4], .big);
    try testing.expectEqual(@as(u32, @intCast(bundle.inner.len)), len_prefix);
    try testing.expectEqualSlices(u8, bundle.inner, bundle.framed[4..]);
}
