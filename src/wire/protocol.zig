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

/// Encode a `P2PTcpMessage<Data>` into a framed byte sequence ready
/// for TCP transmission. The result includes the 4-byte BE length
/// prefix. Caller owns the returned allocation and must free it.
pub fn encodeP2PTcpMessage(
    allocator: std.mem.Allocator,
    comptime Data: type,
    value: types.P2PTcpMessage(Data),
) ![]u8 {
    const framing = @import("framing.zig");

    // Borsh-encode the message.
    var list = try borsh.encodeAlloc(allocator, types.P2PTcpMessage(Data), value);
    const payload = try list.toOwnedSlice(allocator);
    defer allocator.free(payload);

    // Frame it with a 4-byte BE length prefix.
    return framing.encodeFrameAlloc(allocator, payload);
}

/// Encode a consensus `Data` value as a framed `P2PTcpMessage::Data`
/// ready for TCP. Convenience wrapper over `encodeP2PTcpMessage`.
pub fn encodeConsensusData(
    allocator: std.mem.Allocator,
    data: types.ConsensusNetMessage,
) ![]u8 {
    const msg: types.P2PTcpMessage(types.ConsensusNetMessage) = .{ .data = data };
    return encodeP2PTcpMessage(allocator, types.ConsensusNetMessage, msg);
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

/// Run the structural validator over a decoded `P2PTcpMessage`. Returns
/// `true` if the message is well-formed at the wire level.
///
/// The validator does NOT check signatures (that needs the BLS path)
/// or consensus state (that's the follower's job). It catches the
/// invariants the borsh decoder can't enforce alone — most importantly
/// the QC marker / variant cross-checks for `ConsensusNetMessage`.
pub fn validateMessage(comptime Data: type, value: types.P2PTcpMessage(Data)) bool {
    const validate = @import("validate.zig");
    return switch (value) {
        .handshake => true, // structural shape is enforced by borsh; signing is the BLS path's job
        .data => |inner| switch (Data) {
            types.ConsensusNetMessage => validate.validateConsensusMessage(inner),
            types.MempoolNetMessage => validate.validateMempoolMessage(inner),
            else => true,
        },
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

/// Print a richer one-line description of any `P2PTcpMessage<Data>`
/// to a `std.io.Writer`-shaped sink. The output goes beyond the bare
/// variant label and includes the most relevant slot/view/hash fields.
///
/// Example outputs:
///   Handshake::Hello(canal=p2p, name=validator-a, ts=1700000000001)
///   ConsensusNetMessage::Prepare(slot=7, view=3, ticket=Genesis)
///   ConsensusNetMessage::PrepareVote(cph=...)
///
/// `Writer` is comptime so the same code paths work for stdout, a
/// fixed-buffer test sink, or any other writer-shaped value.
pub fn formatMessage(
    comptime Data: type,
    value: types.P2PTcpMessage(Data),
    writer: anytype,
) !void {
    switch (value) {
        .handshake => |hs| switch (hs) {
            .hello => |hp| try writer.print("Handshake::Hello(canal={s}, name={s}, ts={d})", .{
                hp.canal.name,
                hp.signed_node_connection_data.msg.name,
                hp.timestamp.millis,
            }),
            .verack => |hp| try writer.print("Handshake::Verack(canal={s}, name={s}, ts={d})", .{
                hp.canal.name,
                hp.signed_node_connection_data.msg.name,
                hp.timestamp.millis,
            }),
        },
        .data => |inner| try formatData(Data, inner, writer),
    }
}

fn formatData(comptime Data: type, value: Data, writer: anytype) !void {
    if (Data == []const u8) {
        try writer.print("Data({d} bytes)", .{value.len});
        return;
    }
    if (Data == types.ConsensusNetMessage) {
        return formatConsensusNetMessage(value, writer);
    }
    if (Data == types.MempoolNetMessage) {
        return formatMempoolNetMessage(value, writer);
    }
    @compileError("formatData: unsupported inner Data type " ++ @typeName(Data));
}

fn writeHashHex(bytes: []const u8, writer: anytype) !void {
    // The on-wire ConsensusProposalHash is short (≤ 32 bytes); print
    // it in full as lowercase hex. Truncate to 16 bytes if longer
    // just to keep one-line summaries readable.
    const len = @min(bytes.len, 16);
    for (bytes[0..len]) |b| try writer.print("{x:0>2}", .{b});
    if (bytes.len > 16) try writer.print("..", .{});
}

fn formatConsensusNetMessage(msg: types.ConsensusNetMessage, writer: anytype) !void {
    switch (msg) {
        .prepare => |p| {
            try writer.print("ConsensusNetMessage::Prepare(slot={d}, view={d}, ticket=", .{
                p.proposal.slot,
                p.view,
            });
            try formatTicket(p.ticket, writer);
            try writer.print(")", .{});
        },
        .prepare_vote => |pv| {
            try writer.print("ConsensusNetMessage::PrepareVote(cph=", .{});
            try writeHashHex(pv.msg.consensus_proposal_hash.bytes, writer);
            try writer.print(")", .{});
        },
        .confirm => |c| {
            try writer.print("ConsensusNetMessage::Confirm(qc_validators={d}, cph=", .{
                c.prepare_qc.aggregate.validators.len,
            });
            try writeHashHex(c.consensus_proposal_hash.bytes, writer);
            try writer.print(")", .{});
        },
        .confirm_ack => |ca| {
            try writer.print("ConsensusNetMessage::ConfirmAck(cph=", .{});
            try writeHashHex(ca.msg.consensus_proposal_hash.bytes, writer);
            try writer.print(")", .{});
        },
        .commit => |c| {
            try writer.print("ConsensusNetMessage::Commit(qc_validators={d}, cph=", .{
                c.commit_qc.aggregate.validators.len,
            });
            try writeHashHex(c.consensus_proposal_hash.bytes, writer);
            try writer.print(")", .{});
        },
        .timeout => |t| {
            try writer.print("ConsensusNetMessage::Timeout(slot={d}, view={d}, kind=", .{
                t.outer.msg.slot,
                t.outer.msg.view,
            });
            switch (t.kind) {
                .nil_proposal => try writer.print("NilProposal", .{}),
                .prepare_qc => try writer.print("PrepareQC", .{}),
            }
            try writer.print(")", .{});
        },
        .timeout_certificate => |tc| {
            try writer.print(
                "ConsensusNetMessage::TimeoutCertificate(slot={d}, view={d}, kind=",
                .{ tc.slot, tc.view },
            );
            switch (tc.tc_kind) {
                .nil_proposal => try writer.print("NilProposal", .{}),
                .prepare_qc => try writer.print("PrepareQC", .{}),
            }
            try writer.print(")", .{});
        },
        .validator_candidacy => |signed| {
            try writer.print("ConsensusNetMessage::ValidatorCandidacy(peer={s})", .{
                signed.msg.peer_address,
            });
        },
        .sync_request => |cph| {
            try writer.print("ConsensusNetMessage::SyncRequest(cph=", .{});
            try writeHashHex(cph.bytes, writer);
            try writer.print(")", .{});
        },
        .sync_reply => |sr| {
            try writer.print(
                "ConsensusNetMessage::SyncReply(slot={d}, view={d})",
                .{ sr.proposal.slot, sr.view },
            );
        },
    }
}

fn formatTicket(ticket: types.Ticket, writer: anytype) !void {
    switch (ticket) {
        .genesis => try writer.print("Genesis", .{}),
        .commit_qc => try writer.print("CommitQC", .{}),
        .timeout_qc => try writer.print("TimeoutQC", .{}),
        .forced_commit_qc => |v| try writer.print("ForcedCommitQC({d})", .{v}),
    }
}

fn formatMempoolNetMessage(msg: types.MempoolNetMessage, writer: anytype) !void {
    switch (msg) {
        .data_proposal => |dp| {
            try writer.print("MempoolNetMessage::DataProposal(lane={s}, dp=", .{dp.lane_id.suffix});
            try writeHashHex(dp.data_proposal_hash.bytes, writer);
            try writer.print(")", .{});
        },
        .data_vote => |dv| {
            try writer.print("MempoolNetMessage::DataVote(lane={s}, dp=", .{dv.lane_id.suffix});
            try writeHashHex(dv.validator_dag.msg.data_proposal_hash.bytes, writer);
            try writer.print(")", .{});
        },
        .sync_request => |sr| {
            try writer.print("MempoolNetMessage::SyncRequest(lane={s})", .{sr.lane_id.suffix});
        },
        .sync_reply => |sr| {
            try writer.print(
                "MempoolNetMessage::SyncReply(lane={s}, dags={d})",
                .{ sr.lane_id.suffix, sr.metadata.len },
            );
        },
    }
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

test "validateMessage: every consensus fixture passes the structural validator" {
    // Each net_message_* fixture is a valid encoding of a Hyli
    // consensus message. The structural validator should accept all of
    // them when they're wrapped as P2PTcpMessage::Data.
    const cases = .{
        corpus.borsh.consensus.net_message_prepare,
        corpus.borsh.consensus.net_message_prepare_vote,
        corpus.borsh.consensus.net_message_confirm,
        corpus.borsh.consensus.net_message_confirm_ack,
        corpus.borsh.consensus.net_message_commit,
        corpus.borsh.consensus.net_message_timeout,
        corpus.borsh.consensus.net_message_timeout_certificate,
        corpus.borsh.consensus.net_message_validator_candidacy,
        corpus.borsh.consensus.net_message_sync_request,
        corpus.borsh.consensus.net_message_sync_reply,
    };
    inline for (cases) |inner| {
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
        try testing.expect(validateMessage(types.ConsensusNetMessage, decoded.value));
    }
}

test "validateMessage: handshake frames pass through" {
    const frame = corpus.wire.messages.p2p_message_handshake_hello_inner;
    var decoded = try decodeP2PTcpMessage(testing.allocator, []const u8, frame);
    defer decoded.deinit();
    try testing.expect(validateMessage([]const u8, decoded.value));
}

// ---------------------------------------------------------------------------
// formatMessage tests — exercise the writer-shaped formatter against
// each major variant. We use std.ArrayList as a sink and check that
// the output contains the expected substrings.
// ---------------------------------------------------------------------------

const ArrayListSink = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn print(self: ArrayListSink, comptime fmt: []const u8, args: anytype) !void {
        var buf: [256]u8 = undefined;
        const out = try std.fmt.bufPrint(&buf, fmt, args);
        try self.list.appendSlice(self.allocator, out);
    }
};

fn formatToList(
    allocator: std.mem.Allocator,
    comptime Data: type,
    value: types.P2PTcpMessage(Data),
) !std.ArrayList(u8) {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    const sink: ArrayListSink = .{ .list = &list, .allocator = allocator };
    try formatMessage(Data, value, sink);
    return list;
}

test "formatMessage: ConsensusNetMessage::Prepare prints slot/view" {
    const inner = corpus.borsh.consensus.net_message_prepare;
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
    var out = try formatToList(testing.allocator, types.ConsensusNetMessage, decoded.value);
    defer out.deinit(testing.allocator);
    // The fixture's cp_full has slot=7, view=7, and now uses a
    // CommitQC ticket (Genesis would be invalid for slot ≠ 1).
    try testing.expect(std.mem.indexOf(u8, out.items, "Prepare") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "slot=7") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "view=7") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "CommitQC") != null);
}

test "formatMessage: PrepareVote prints cph hex" {
    const inner = corpus.borsh.consensus.net_message_prepare_vote;
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
    var out = try formatToList(testing.allocator, types.ConsensusNetMessage, decoded.value);
    defer out.deinit(testing.allocator);
    // The fixture uses cph = "cp-1" (4 ASCII bytes); the hex is
    // "63702d31".
    try testing.expect(std.mem.indexOf(u8, out.items, "PrepareVote") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "63702d31") != null);
}

test "formatMessage: Handshake::Hello prints canal/name" {
    const frame = corpus.wire.messages.p2p_message_handshake_hello_inner;
    var decoded = try decodeP2PTcpMessage(testing.allocator, []const u8, frame);
    defer decoded.deinit();
    var out = try formatToList(testing.allocator, []const u8, decoded.value);
    defer out.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, out.items, "Handshake::Hello") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "canal=p2p") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "validator-a") != null);
}

test "formatMessage: Commit prints qc validators count and cph" {
    const inner = corpus.borsh.consensus.net_message_commit;
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
    var out = try formatToList(testing.allocator, types.ConsensusNetMessage, decoded.value);
    defer out.deinit(testing.allocator);
    // The fixture's commit_qc has 2 validators.
    try testing.expect(std.mem.indexOf(u8, out.items, "Commit") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "qc_validators=2") != null);
}

// ---------------------------------------------------------------------------
// encodeP2PTcpMessage / encodeConsensusData tests
// ---------------------------------------------------------------------------

test "encodeP2PTcpMessage: round-trip decode of SyncRequest" {
    const cph: types.ConsensusProposalHash = .{ .bytes = "test-cph-hash" };
    const msg: types.P2PTcpMessage(types.ConsensusNetMessage) = .{
        .data = .{ .sync_request = cph },
    };
    const framed = try encodeP2PTcpMessage(testing.allocator, types.ConsensusNetMessage, msg);
    defer testing.allocator.free(framed);

    // Strip the 4-byte length prefix to get the inner frame bytes.
    try testing.expect(framed.len > 4);
    const frame_len = std.mem.readInt(u32, framed[0..4], .big);
    try testing.expectEqual(framed.len - 4, frame_len);
    const frame_bytes = framed[4..];

    // Decode it back.
    var decoded = try decodeP2PTcpMessage(testing.allocator, types.ConsensusNetMessage, frame_bytes);
    defer decoded.deinit();
    try testing.expect(decoded.value == .data);
    try testing.expect(decoded.value.data == .sync_request);
    try testing.expectEqualSlices(u8, "test-cph-hash", decoded.value.data.sync_request.bytes);
}

test "encodeConsensusData: round-trip SyncRequest" {
    const cph: types.ConsensusProposalHash = .{ .bytes = "my-hash" };
    const framed = try encodeConsensusData(testing.allocator, .{ .sync_request = cph });
    defer testing.allocator.free(framed);

    const frame_bytes = framed[4..];
    var decoded = try decodeP2PTcpMessage(testing.allocator, types.ConsensusNetMessage, frame_bytes);
    defer decoded.deinit();
    try testing.expect(decoded.value == .data);
    try testing.expect(decoded.value.data == .sync_request);
    try testing.expectEqualSlices(u8, "my-hash", decoded.value.data.sync_request.bytes);
}

test "encodeP2PTcpMessage: round-trip Prepare fixture" {
    // Decode a fixture, re-encode it, decode again, and compare labels.
    const inner = corpus.borsh.consensus.net_message_prepare;
    const wire = try testing.allocator.alloc(u8, 1 + inner.len);
    defer testing.allocator.free(wire);
    wire[0] = 1;
    @memcpy(wire[1..], inner);
    var original = try decodeP2PTcpMessage(testing.allocator, types.ConsensusNetMessage, wire);
    defer original.deinit();

    const re_encoded = try encodeP2PTcpMessage(testing.allocator, types.ConsensusNetMessage, original.value);
    defer testing.allocator.free(re_encoded);

    // Decode the re-encoded bytes.
    var round_tripped = try decodeP2PTcpMessage(
        testing.allocator,
        types.ConsensusNetMessage,
        re_encoded[4..],
    );
    defer round_tripped.deinit();

    try testing.expectEqualSlices(
        u8,
        messageLabel(types.ConsensusNetMessage, original.value),
        messageLabel(types.ConsensusNetMessage, round_tripped.value),
    );
    // Check slot matches.
    try testing.expectEqual(
        original.value.data.prepare.proposal.slot,
        round_tripped.value.data.prepare.proposal.slot,
    );
}
