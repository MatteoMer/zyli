//! `TcpMessage` codec — Hyli's per-frame inner envelope.
//!
//! A frame on the wire is one of:
//!   - The literal 4-byte sequence `b"PING"`. Hyli does NOT borsh-encode
//!     pings as an enum variant; the receiver detects the magic bytes by
//!     direct comparison before even attempting borsh deserialization.
//!     Mirror that behavior here exactly.
//!   - A borsh-encoded `TcpWireData = { headers: Vec<(String,String)>,
//!     payload: Vec<u8> }`. The Rust definition is `pub(crate)` and lives
//!     in `crates/hyli-net/src/tcp.rs`; the field order and types are the
//!     contract.
//!
//! Decoders that ignore the headers can also fall back to decoding the
//! frame payload directly as `Data` — Hyli does this in
//! `decode_tcp_payload` for backwards compatibility — but encoders should
//! always emit the `TcpWireData` shape so that future header propagation
//! does not require a wire-format break.

const std = @import("std");
const borsh = @import("../model/borsh.zig");

/// 4-byte magic prefix that identifies a ping frame.
pub const ping_magic: []const u8 = "PING";

/// One header pair `(name, value)` carried alongside a TCP payload. Hyli
/// uses this for opentelemetry context propagation; an observer-grade
/// node treats them as opaque strings.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Mirror of `hyli_net::tcp::TcpWireData`. The Rust struct is private to
/// the `hyli_net` crate but the wire layout is part of the public
/// protocol. Field order MUST match the Rust definition exactly: headers
/// first, then payload.
pub const TcpWireData = struct {
    headers: []const Header,
    payload: []const u8,
};

/// Outer enum of what a Hyli TCP frame can carry. Note that this enum is
/// NOT borsh-encoded as an enum on the wire — the discriminant is implicit
/// in whether the frame bytes equal `ping_magic` or not.
pub const TcpMessage = union(enum) {
    ping,
    data: TcpWireData,
};

/// Encode a `TcpMessage` to the inner frame bytes (the bytes that go
/// inside the length-delimited frame, not the framed bytes themselves).
///
/// For pings this is just a borrow of `ping_magic`; for data messages it
/// is a freshly-allocated buffer the caller must free.
pub fn encodeInnerAlloc(allocator: std.mem.Allocator, message: TcpMessage) ![]u8 {
    switch (message) {
        .ping => {
            const buf = try allocator.alloc(u8, ping_magic.len);
            @memcpy(buf, ping_magic);
            return buf;
        },
        .data => |wire| {
            var list = try borsh.encodeAlloc(allocator, TcpWireData, wire);
            return list.toOwnedSlice(allocator);
        },
    }
}

/// Inspect a frame and classify it as ping or data without decoding any
/// borsh bytes. Useful for the read loop where the next thing to do
/// depends entirely on the discriminant.
pub fn classifyFrame(frame: []const u8) TcpMessageKind {
    if (std.mem.eql(u8, frame, ping_magic)) return .ping;
    return .data;
}

pub const TcpMessageKind = enum { ping, data };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const corpus = @import("corpus");

test "encodeInnerAlloc emits raw PING bytes for the ping variant" {
    const out = try encodeInnerAlloc(testing.allocator, .ping);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, corpus.wire.messages.tcp_message_ping_inner, out);
    try testing.expectEqualSlices(u8, "PING", out);
}

test "encodeInnerAlloc matches the corpus simple-data inner bytes" {
    const message: TcpMessage = .{ .data = .{
        .headers = &[_]Header{},
        .payload = &[_]u8{ 1, 2, 3 },
    } };
    const out = try encodeInnerAlloc(testing.allocator, message);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(
        u8,
        corpus.wire.messages.tcp_message_data_simple_inner,
        out,
    );
}

test "encodeInnerAlloc matches the corpus header-bearing inner bytes" {
    const message: TcpMessage = .{ .data = .{
        .headers = &[_]Header{
            .{ .name = "k", .value = "v" },
        },
        .payload = &[_]u8{ 0xaa, 0xbb },
    } };
    const out = try encodeInnerAlloc(testing.allocator, message);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(
        u8,
        corpus.wire.messages.tcp_message_data_header_inner,
        out,
    );
}

test "classifyFrame distinguishes PING from data frames" {
    try testing.expectEqual(TcpMessageKind.ping, classifyFrame("PING"));
    try testing.expectEqual(
        TcpMessageKind.data,
        classifyFrame(corpus.wire.messages.tcp_message_data_simple_inner),
    );
    // Anything that isn't exactly "PING" — even a byte-aligned suffix — is data.
    try testing.expectEqual(TcpMessageKind.data, classifyFrame("PINGX"));
    try testing.expectEqual(TcpMessageKind.data, classifyFrame("PIN"));
}
