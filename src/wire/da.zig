//! DA (Data Availability) wire protocol.
//!
//! The DA stream uses a simpler wire format than the P2P consensus
//! channel:
//!
//!   - No handshake (no Hello/Verack, no canal names).
//!   - Same 4-byte BE length-delimited framing as P2P.
//!   - Same PING detection (literal `b"PING"` bytes).
//!   - Data frames are `borsh(TcpWireData { headers, payload })` where
//!     the payload is `borsh(DataAvailabilityRequest)` (client → server)
//!     or `borsh(DataAvailabilityEvent)` (server → client).
//!   - Hyli's `decode_tcp_payload` falls back to raw borsh if the
//!     TcpWireData decode fails, so sending raw borsh without the
//!     TcpWireData wrapper also works.
//!
//! This module provides encode/decode helpers for both directions.

const std = @import("std");
const borsh = @import("../model/borsh.zig");
const types = @import("../model/types.zig");
const framing = @import("framing.zig");
const tcp_message = @import("tcp_message.zig");

pub const Error = error{
    PingFrameNotDecodable,
    InvalidEncoding,
    TrailingBytes,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Encoding (client → server)
// ---------------------------------------------------------------------------

/// Build a framed DA request ready for TCP. The request is wrapped in a
/// `TcpWireData` envelope with empty headers. Returns heap-allocated
/// bytes: 4-byte BE length + borsh(TcpWireData { [], borsh(req) }).
pub fn encodeRequestFrameAlloc(
    allocator: std.mem.Allocator,
    request: types.DataAvailabilityRequest,
) ![]u8 {
    // 1. Borsh-encode the inner request.
    var inner_list = try borsh.encodeAlloc(allocator, types.DataAvailabilityRequest, request);
    const inner_payload = try inner_list.toOwnedSlice(allocator);
    defer allocator.free(inner_payload);

    // 2. Wrap in TcpWireData { headers: [], payload: inner_payload }.
    const wire_data: tcp_message.TcpWireData = .{
        .headers = &[_]tcp_message.Header{},
        .payload = inner_payload,
    };
    var wire_list = try borsh.encodeAlloc(allocator, tcp_message.TcpWireData, wire_data);
    const wire_bytes = try wire_list.toOwnedSlice(allocator);
    defer allocator.free(wire_bytes);

    // 3. Frame it: 4-byte BE length prefix.
    return framing.encodeFrameAlloc(allocator, wire_bytes);
}

// ---------------------------------------------------------------------------
// Decoding (server → client)
// ---------------------------------------------------------------------------

/// A decoded DA event with its backing arena. Drop via `deinit`.
pub const DecodedEvent = struct {
    value: types.DataAvailabilityEvent,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *DecodedEvent) void {
        const child = self.arena.child_allocator;
        self.arena.deinit();
        child.destroy(self.arena);
    }
};

/// Decode a DA event frame. The frame bytes are the payload after the
/// 4-byte length prefix has been stripped (as returned by
/// `StreamFrameReader.nextFrame`).
///
/// Tries `TcpWireData` decoding first, falls back to raw borsh — same
/// two-pass strategy as Hyli's `decode_tcp_payload`.
pub fn decodeEventFrame(
    parent_allocator: std.mem.Allocator,
    frame_bytes: []const u8,
) Error!DecodedEvent {
    if (tcp_message.classifyFrame(frame_bytes) == .ping) return Error.PingFrameNotDecodable;

    const arena = try parent_allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer {
        arena.deinit();
        parent_allocator.destroy(arena);
    }

    // Try TcpWireData first.
    if (decodeTcpWirePayload(arena.allocator(), frame_bytes)) |payload| {
        var reader = borsh.Reader.init(payload);
        const value = borsh.decode(types.DataAvailabilityEvent, &reader, arena.allocator()) catch
            return Error.InvalidEncoding;
        if (!reader.isEmpty()) return Error.TrailingBytes;
        return .{ .value = value, .arena = arena };
    } else |_| {
        // Fallback: decode raw bytes as DataAvailabilityEvent.
        var reader = borsh.Reader.init(frame_bytes);
        const value = borsh.decode(types.DataAvailabilityEvent, &reader, arena.allocator()) catch
            return Error.InvalidEncoding;
        if (!reader.isEmpty()) return Error.TrailingBytes;
        return .{ .value = value, .arena = arena };
    }
}

/// Decode a TcpWireData envelope and return the inner payload bytes.
fn decodeTcpWirePayload(
    allocator: std.mem.Allocator,
    frame_bytes: []const u8,
) ![]const u8 {
    var reader = borsh.Reader.init(frame_bytes);
    const wire = try borsh.decode(tcp_message.TcpWireData, &reader, allocator);
    return wire.payload;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "encodeRequestFrameAlloc round-trips through decoding" {
    const request: types.DataAvailabilityRequest = .{
        .stream_from_height = .{ .height = 42 },
    };
    const framed = try encodeRequestFrameAlloc(testing.allocator, request);
    defer testing.allocator.free(framed);

    // The framed bytes start with a 4-byte BE length prefix.
    try testing.expect(framed.len > 4);
    const len = std.mem.readInt(u32, framed[0..4], .big);
    try testing.expectEqual(@as(u32, @intCast(framed.len - 4)), len);

    // Decode the inner TcpWireData.
    const inner = framed[4..];
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const payload = try decodeTcpWirePayload(arena.allocator(), inner);

    // Decode the DA request from the payload.
    var reader = borsh.Reader.init(payload);
    const decoded = try borsh.decode(types.DataAvailabilityRequest, &reader, arena.allocator());
    try testing.expect(decoded == .stream_from_height);
    try testing.expectEqual(@as(u64, 42), decoded.stream_from_height.height);
}

test "encodeRequestFrameAlloc: block_request variant" {
    const request: types.DataAvailabilityRequest = .{
        .block_request = .{ .height = 100 },
    };
    const framed = try encodeRequestFrameAlloc(testing.allocator, request);
    defer testing.allocator.free(framed);

    const inner = framed[4..];
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const payload = try decodeTcpWirePayload(arena.allocator(), inner);

    var reader = borsh.Reader.init(payload);
    const decoded = try borsh.decode(types.DataAvailabilityRequest, &reader, arena.allocator());
    try testing.expect(decoded == .block_request);
    try testing.expectEqual(@as(u64, 100), decoded.block_request.height);
}

test "decodeEventFrame: decodes a TcpWireData-wrapped BlockNotFound" {
    // Manually build a TcpWireData frame containing a DataAvailabilityEvent.
    const event: types.DataAvailabilityEvent = .{
        .block_not_found = .{ .height = 99 },
    };
    var inner_list = try borsh.encodeAlloc(testing.allocator, types.DataAvailabilityEvent, event);
    const inner_payload = try inner_list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(inner_payload);

    const wire_data: tcp_message.TcpWireData = .{
        .headers = &[_]tcp_message.Header{},
        .payload = inner_payload,
    };
    var wire_list = try borsh.encodeAlloc(testing.allocator, tcp_message.TcpWireData, wire_data);
    const frame_bytes = try wire_list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(frame_bytes);

    var decoded = try decodeEventFrame(testing.allocator, frame_bytes);
    defer decoded.deinit();

    try testing.expect(decoded.value == .block_not_found);
    try testing.expectEqual(@as(u64, 99), decoded.value.block_not_found.height);
}

test "decodeEventFrame: fallback decodes raw borsh DataAvailabilityEvent" {
    // Send raw borsh without TcpWireData wrapping — Hyli's decode_tcp_payload
    // falls back to this and so should we.
    const event: types.DataAvailabilityEvent = .{
        .block_not_found = .{ .height = 7 },
    };
    var raw_list = try borsh.encodeAlloc(testing.allocator, types.DataAvailabilityEvent, event);
    const raw_bytes = try raw_list.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(raw_bytes);

    var decoded = try decodeEventFrame(testing.allocator, raw_bytes);
    defer decoded.deinit();

    try testing.expect(decoded.value == .block_not_found);
    try testing.expectEqual(@as(u64, 7), decoded.value.block_not_found.height);
}

test "decodeEventFrame: rejects PING" {
    try testing.expectError(Error.PingFrameNotDecodable, decodeEventFrame(testing.allocator, "PING"));
}
