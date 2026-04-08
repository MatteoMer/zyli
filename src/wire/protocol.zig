//! High-level frame → typed message decoder.
//!
//! `framing.zig` and `tcp_message.zig` produce raw frame bytes. This
//! module is the next layer up: given a frame's inner bytes plus a
//! comptime payload type, it decodes the full `P2PTcpMessage<Data>` and
//! returns it. The observer subcommand uses this to print message labels
//! beyond just `PING` / `DATA`.
//!
//! Two helpers:
//!
//!   - `decodeP2PTcpMessage(allocator, Data, frame_bytes)` decodes the
//!     borsh-encoded envelope. Returns the typed value plus a tiny
//!     bookkeeping struct so callers can free the heap allocations the
//!     borsh decoder makes for slice fields.
//!
//!   - `messageLabel(Data, value)` projects any P2PTcpMessage<Data>
//!     value into a short, stable string for logging. Mirrors the
//!     upstream `TcpMessageLabel` derive used by hyli-net.
//!
//! `Data` is intentionally comptime: it must be one of the inner protocol
//! enums (e.g. `ConsensusNetMessage`, `MempoolNetMessage`, or even
//! `[]const u8` for unconfigured canals). The Hyli wire format multiplexes
//! these by canal name on the connection level, not by an in-band tag, so
//! the caller has to know which Data type to decode against.

const std = @import("std");
const borsh = @import("../model/borsh.zig");
const types = @import("../model/types.zig");
const tcp_message = @import("tcp_message.zig");

/// Errors the protocol decoder can surface to its caller.
pub const Error = error{
    /// The frame was a `PING` magic frame, not a borsh-encoded payload.
    /// Callers should classify with `tcp_message.classifyFrame` first.
    PingFrameNotDecodable,
    /// Borsh decoding failed (truncated bytes, invalid tag, etc.).
    InvalidEncoding,
    /// The decoder consumed fewer bytes than the frame contained — a
    /// strong signal that the wire format drifted from the Zig types.
    TrailingBytes,
    OutOfMemory,
};

/// A decoded `P2PTcpMessage<Data>` plus the arena that owns its slice
/// fields. The caller frees the entire allocation in one shot via
/// `deinit`. This is the shape an observer wants: one frame in, one
/// `Decoded(...)` out, drop it when done.
///
/// Using an arena here is the right primitive because the borsh decoder
/// allocates many small slices for nested types and its current error
/// paths only clean up the immediately-failing layer — anything that
/// successfully allocated before the failure leaks through to the
/// caller. Routing every per-message decode through an arena means a
/// truncated frame deallocates everything together.
pub fn Decoded(comptime Data: type) type {
    return struct {
        const Self = @This();

        value: types.P2PTcpMessage(Data),
        arena: *std.heap.ArenaAllocator,

        pub fn deinit(self: *Self) void {
            const child_allocator = self.arena.child_allocator;
            self.arena.deinit();
            child_allocator.destroy(self.arena);
        }
    };
}

/// Decode a frame's inner bytes into a typed `P2PTcpMessage<Data>`.
///
/// `frame_bytes` should be the bytes returned by `FrameDecoder.decode`
/// (i.e. the payload, NOT the framed bytes — no length prefix).
///
/// On success the caller MUST call `Decoded.deinit` to release the
/// arena that backs the value's slice fields. On failure no allocation
/// escapes the function.
pub fn decodeP2PTcpMessage(
    parent_allocator: std.mem.Allocator,
    comptime Data: type,
    frame_bytes: []const u8,
) Error!Decoded(Data) {
    // PING is signalled by raw `b"PING"` bytes inside the frame instead
    // of a borsh enum tag, so we reject it explicitly. The caller is
    // expected to classify first.
    if (tcp_message.classifyFrame(frame_bytes) == .ping) return Error.PingFrameNotDecodable;

    const arena = try parent_allocator.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(parent_allocator);
    errdefer {
        arena.deinit();
        parent_allocator.destroy(arena);
    }

    var reader = borsh.Reader.init(frame_bytes);
    const value = borsh.decode(types.P2PTcpMessage(Data), &reader, arena.allocator()) catch
        return Error.InvalidEncoding;
    if (!reader.isEmpty()) return Error.TrailingBytes;
    return Decoded(Data){ .value = value, .arena = arena };
}

/// Stable, short label for any `P2PTcpMessage<Data>` value. Mirrors the
/// `#[derive(TcpMessageLabel)]` projection on the Rust side: the Handshake
/// envelope distinguishes `Hello` vs `Verack`, and a `Data` payload
/// projects through whatever `messageLabel` is defined for `Data`.
///
/// `Data` must be a tagged union or expose a `messageLabel` function.
/// For convenience, `[]const u8` and `void` are accepted with hardcoded
/// labels — useful when the inner type is not yet plumbed through.
pub fn messageLabel(comptime Data: type, value: types.P2PTcpMessage(Data)) []const u8 {
    return switch (value) {
        .handshake => |hs| switch (hs) {
            .hello => "Handshake::Hello",
            .verack => "Handshake::Verack",
        },
        .data => |inner| dataLabel(Data, inner),
    };
}

fn dataLabel(comptime Data: type, value: Data) []const u8 {
    if (Data == []const u8) return "Data(opaque)";
    if (Data == void) return "Data(void)";
    if (Data == types.ConsensusNetMessage) return consensusNetMessageLabel(value);
    if (Data == types.MempoolNetMessage) return mempoolNetMessageLabel(value);
    @compileError("messageLabel: unsupported inner Data type " ++ @typeName(Data));
}

/// Mirrors the `IntoStaticStr` derive on `ConsensusNetMessage` from
/// `hyli/src/consensus/network.rs`. The variant names use the Rust
/// CamelCase form so logs match what an upstream operator would expect.
pub fn consensusNetMessageLabel(msg: types.ConsensusNetMessage) []const u8 {
    return switch (msg) {
        .prepare => "Prepare",
        .prepare_vote => "PrepareVote",
        .confirm => "Confirm",
        .confirm_ack => "ConfirmAck",
        .commit => "Commit",
        .timeout => "Timeout",
        .timeout_certificate => "TimeoutCertificate",
        .validator_candidacy => "ValidatorCandidacy",
        .sync_request => "SyncRequest",
        .sync_reply => "SyncReply",
    };
}

/// Mirrors `IntoStaticStr` on `MempoolNetMessage` from
/// `hyli/src/mempool.rs`.
pub fn mempoolNetMessageLabel(msg: types.MempoolNetMessage) []const u8 {
    return switch (msg) {
        .data_proposal => "DataProposal",
        .data_vote => "DataVote",
        .sync_request => "SyncRequest",
        .sync_reply => "SyncReply",
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const corpus = @import("corpus");

test "decodeP2PTcpMessage rejects PING frames" {
    try testing.expectError(
        Error.PingFrameNotDecodable,
        decodeP2PTcpMessage(testing.allocator, []const u8, "PING"),
    );
}

test "decodeP2PTcpMessage decodes Handshake::Hello round-trip" {
    // Use the existing handshake_hello fixture as the input frame bytes.
    const frame = corpus.wire.messages.p2p_message_handshake_hello_inner;
    var decoded = try decodeP2PTcpMessage(testing.allocator, []const u8, frame);
    defer decoded.deinit();
    try testing.expect(decoded.value == .handshake);
    try testing.expect(decoded.value.handshake == .hello);
    try testing.expectEqualSlices(u8, "Handshake::Hello", messageLabel([]const u8, decoded.value));
}

test "decodeP2PTcpMessage labels every ConsensusNetMessage variant" {
    // Decode each consensus fixture wrapped as P2PTcpMessage::Data and
    // check the label matches.
    const cases = .{
        .{ corpus.borsh.consensus.net_message_prepare, "Prepare" },
        .{ corpus.borsh.consensus.net_message_prepare_vote, "PrepareVote" },
        .{ corpus.borsh.consensus.net_message_confirm, "Confirm" },
        .{ corpus.borsh.consensus.net_message_confirm_ack, "ConfirmAck" },
        .{ corpus.borsh.consensus.net_message_commit, "Commit" },
        .{ corpus.borsh.consensus.net_message_timeout, "Timeout" },
        .{ corpus.borsh.consensus.net_message_timeout_certificate, "TimeoutCertificate" },
        .{ corpus.borsh.consensus.net_message_validator_candidacy, "ValidatorCandidacy" },
        .{ corpus.borsh.consensus.net_message_sync_request, "SyncRequest" },
        .{ corpus.borsh.consensus.net_message_sync_reply, "SyncReply" },
    };
    inline for (cases) |case| {
        // Re-frame the inner consensus message as a P2PTcpMessage::Data.
        // P2PTcpMessage::Data tag is 1u8, so we just prepend a single byte
        // to get the wire form.
        const inner = case[0];
        const expected = case[1];
        const wire = try testing.allocator.alloc(u8, 1 + inner.len);
        defer testing.allocator.free(wire);
        wire[0] = 1;
        @memcpy(wire[1..], inner);
        var decoded = try decodeP2PTcpMessage(
            testing.allocator,
            types.ConsensusNetMessage,
            wire,
        );
        defer decoded.deinit();
        try testing.expect(decoded.value == .data);
        try testing.expectEqualSlices(
            u8,
            expected,
            messageLabel(types.ConsensusNetMessage, decoded.value),
        );
    }
}

test "decodeP2PTcpMessage labels every MempoolNetMessage variant" {
    const cases = .{
        .{ corpus.borsh.mempool.net_message_data_proposal, "DataProposal" },
        .{ corpus.borsh.mempool.net_message_data_vote, "DataVote" },
        .{ corpus.borsh.mempool.net_message_sync_request, "SyncRequest" },
        .{ corpus.borsh.mempool.net_message_sync_request_none, "SyncRequest" },
        .{ corpus.borsh.mempool.net_message_sync_reply, "SyncReply" },
    };
    inline for (cases) |case| {
        const inner = case[0];
        const expected = case[1];
        const wire = try testing.allocator.alloc(u8, 1 + inner.len);
        defer testing.allocator.free(wire);
        wire[0] = 1;
        @memcpy(wire[1..], inner);
        var decoded = try decodeP2PTcpMessage(
            testing.allocator,
            types.MempoolNetMessage,
            wire,
        );
        defer decoded.deinit();
        try testing.expect(decoded.value == .data);
        try testing.expectEqualSlices(
            u8,
            expected,
            messageLabel(types.MempoolNetMessage, decoded.value),
        );
    }
}

test "decodeP2PTcpMessage rejects trailing bytes" {
    const inner = corpus.wire.messages.p2p_message_handshake_hello_inner;
    const padded = try testing.allocator.alloc(u8, inner.len + 1);
    defer testing.allocator.free(padded);
    @memcpy(padded[0..inner.len], inner);
    padded[inner.len] = 0xff;
    try testing.expectError(
        Error.TrailingBytes,
        decodeP2PTcpMessage(testing.allocator, []const u8, padded),
    );
}

test "decodeP2PTcpMessage rejects truncated bytes (no leak)" {
    const inner = corpus.wire.messages.p2p_message_handshake_hello_inner;
    const truncated = inner[0 .. inner.len - 4];
    // The arena owned by the protocol decoder is dropped on error, so
    // even though the borsh decoder leaks intermediate allocations on
    // its error path, the protocol layer cleans them up. testing.allocator
    // would assert if anything escaped.
    try testing.expectError(
        Error.InvalidEncoding,
        decodeP2PTcpMessage(testing.allocator, []const u8, truncated),
    );
}
