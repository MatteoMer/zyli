//! DA (Data Availability) historical sync client.
//!
//! Connects to a Hyli DA server, requests signed blocks starting from a
//! given height, and feeds them to a caller-supplied callback. This is
//! the "catch-up" path a follower uses to fill in the block history it
//! missed while offline.
//!
//! Wire protocol (from `wire/da.zig`):
//!   - 4-byte BE length-delimited framing.
//!   - Client sends `TcpWireData { headers: [], payload: borsh(DARequest) }`.
//!   - Server responds with `TcpWireData { headers: ..., payload: borsh(DAEvent) }`.
//!   - Literal `b"PING"` frames are echoed back as keep-alive.
//!
//! This module is deliberately simple: it opens one TCP connection,
//! sends one `StreamFromHeight` request, processes events until the
//! server closes, and returns. No reconnection, no multiplexing, no
//! in-band request pipelining — those belong in a higher-level
//! supervisor.

const std = @import("std");
const types = @import("../model/types.zig");
const framing_mod = @import("../wire/framing.zig");
const da_wire = @import("../wire/da.zig");
const tcp_message = @import("../wire/tcp_message.zig");
const consensus_verify = @import("../crypto/consensus_verify.zig");

/// What the caller gets back for each successfully-decoded event.
pub const SyncEvent = union(enum) {
    /// A signed block arrived.
    signed_block: types.SignedBlock,
    /// The server reports that a requested block does not exist.
    block_not_found: types.BlockHeight,
    /// A mempool status event (informational, not block data).
    mempool_status: types.MempoolStatusEvent,
    /// The server sent a PING.
    ping,
};

/// Summary of how the sync session ended.
pub const SyncResult = struct {
    /// Number of signed blocks received.
    blocks_received: usize,
    /// Number of BlockNotFound events.
    not_found: usize,
    /// Number of PING frames.
    pings: usize,
    /// How the session terminated.
    termination: Termination,

    pub const Termination = enum {
        /// The server closed the connection cleanly (EOF).
        server_closed,
        /// The callback returned `false` to stop early.
        stopped_by_callback,
        /// A frame read error occurred.
        read_error,
        /// A decode error occurred.
        decode_error,
    };
};

/// Callback signature for block processing. Return `true` to continue
/// receiving, `false` to stop. The signed block borrows from an arena
/// that is freed after the callback returns, so the callback must copy
/// any data it wants to keep.
pub const BlockCallback = *const fn (block: types.SignedBlock, height: types.BlockHeight) bool;

/// Connect to a DA server and stream signed blocks starting from
/// `start_height`. Each received block is passed to `on_block`; return
/// `false` from the callback to stop early.
///
/// `da_address` is `"host:port"` in the same format as the observer's
/// peer address. The DA port is typically different from the consensus
/// P2P port.
pub fn syncFromHeight(
    allocator: std.mem.Allocator,
    da_address: []const u8,
    start_height: types.BlockHeight,
    on_block: BlockCallback,
) !SyncResult {
    // Parse address.
    const sep = std.mem.lastIndexOfScalar(u8, da_address, ':') orelse return error.InvalidAddress;
    const host = da_address[0..sep];
    const port_str = da_address[sep + 1 ..];
    const port = std.fmt.parseUnsigned(u16, port_str, 10) catch return error.InvalidAddress;
    const address = std.net.Address.parseIp(host, port) catch return error.InvalidAddress;

    var stream = std.net.tcpConnectToAddress(address) catch return error.ConnectionFailed;
    defer stream.close();

    // Send the StreamFromHeight request.
    const request_frame = try da_wire.encodeRequestFrameAlloc(allocator, .{
        .stream_from_height = start_height,
    });
    defer allocator.free(request_frame);
    stream.writeAll(request_frame) catch return error.SendFailed;

    // Read frames in a loop.
    const StreamReader = struct {
        inner: std.net.Stream,
        pub fn read(self: *@This(), buf: []u8) !usize {
            return self.inner.read(buf);
        }
    };
    var stream_reader: StreamReader = .{ .inner = stream };
    var frames = framing_mod.StreamFrameReader(*StreamReader).init(allocator);
    defer frames.deinit();

    var result: SyncResult = .{
        .blocks_received = 0,
        .not_found = 0,
        .pings = 0,
        .termination = .server_closed,
    };

    while (true) {
        const maybe_frame = frames.nextFrame(&stream_reader) catch {
            result.termination = .read_error;
            return result;
        };
        const frame = maybe_frame orelse {
            result.termination = .server_closed;
            return result;
        };

        // PING echo.
        if (tcp_message.classifyFrame(frame) == .ping) {
            result.pings += 1;
            // Echo the ping back.
            const ping_framed = framing_mod.encodeFrameAlloc(allocator, tcp_message.ping_magic) catch continue;
            defer allocator.free(ping_framed);
            stream.writeAll(ping_framed) catch {};
            continue;
        }

        // Decode DA event.
        var decoded = da_wire.decodeEventFrame(allocator, frame) catch {
            result.termination = .decode_error;
            return result;
        };
        defer decoded.deinit();

        switch (decoded.value) {
            .signed_block => |block| {
                result.blocks_received += 1;
                const keep_going = on_block(block, start_height);
                if (!keep_going) {
                    result.termination = .stopped_by_callback;
                    return result;
                }
            },
            .block_not_found => {
                result.not_found += 1;
            },
            .mempool_status_event => {
                // Informational — no action needed.
            },
        }
    }
}

/// Connect to a DA server, stream blocks, verify their BLS certificates,
/// and print a one-line summary per block. This is the entry point for the
/// `da-sync` subcommand.
pub fn syncAndReport(
    allocator: std.mem.Allocator,
    stdout: anytype,
    da_address: []const u8,
    start_height: u64,
) !void {
    try stdout.print("da-sync: connecting to {s}, starting from height {d}\n", .{ da_address, start_height });
    try stdout.flush();

    // Parse address.
    const sep = std.mem.lastIndexOfScalar(u8, da_address, ':') orelse {
        try stdout.print("da-sync: address must be host:port\n", .{});
        return;
    };
    const host = da_address[0..sep];
    const port_str = da_address[sep + 1 ..];
    const port = std.fmt.parseUnsigned(u16, port_str, 10) catch {
        try stdout.print("da-sync: invalid port\n", .{});
        return;
    };
    const address = std.net.Address.parseIp(host, port) catch {
        try stdout.print("da-sync: invalid address\n", .{});
        return;
    };

    var stream = std.net.tcpConnectToAddress(address) catch {
        try stdout.print("da-sync: connection failed\n", .{});
        return;
    };
    defer stream.close();

    // Send StreamFromHeight request.
    const request_frame = da_wire.encodeRequestFrameAlloc(allocator, .{
        .stream_from_height = .{ .height = start_height },
    }) catch {
        try stdout.print("da-sync: failed to encode request\n", .{});
        return;
    };
    defer allocator.free(request_frame);
    stream.writeAll(request_frame) catch {
        try stdout.print("da-sync: failed to send request\n", .{});
        return;
    };

    try stdout.print("da-sync: request sent, reading blocks…\n", .{});
    try stdout.flush();

    // Read frames.
    const StreamReader = struct {
        inner: std.net.Stream,
        pub fn read(self: *@This(), buf: []u8) !usize {
            return self.inner.read(buf);
        }
    };
    var stream_reader: StreamReader = .{ .inner = stream };
    var frames = framing_mod.StreamFrameReader(*StreamReader).init(allocator);
    defer frames.deinit();

    var blocks: usize = 0;
    var verified: usize = 0;
    var not_found: usize = 0;

    while (true) {
        const maybe_frame = frames.nextFrame(&stream_reader) catch {
            try stdout.print("da-sync: read error after {d} blocks\n", .{blocks});
            break;
        };
        const frame = maybe_frame orelse {
            try stdout.print("da-sync: server closed after {d} blocks\n", .{blocks});
            break;
        };

        // PING echo.
        if (tcp_message.classifyFrame(frame) == .ping) {
            const ping_framed = framing_mod.encodeFrameAlloc(allocator, tcp_message.ping_magic) catch continue;
            defer allocator.free(ping_framed);
            stream.writeAll(ping_framed) catch {};
            continue;
        }

        // Decode DA event.
        var decoded = da_wire.decodeEventFrame(allocator, frame) catch {
            try stdout.print("da-sync: decode error, skipping frame\n", .{});
            continue;
        };
        defer decoded.deinit();

        switch (decoded.value) {
            .signed_block => |block| {
                blocks += 1;
                const slot = block.consensus_proposal.slot;
                const n_lanes = block.data_proposals.len;
                const n_validators = block.certificate.validators.len;

                // Verify the block's CommitQC certificate.
                const bls_ok = consensus_verify.verifySignedBlockCertificate(
                    allocator,
                    block,
                ) catch false;
                if (bls_ok) verified += 1;
                const label: []const u8 = if (bls_ok) "ok" else "BAD";

                try stdout.print("block {d}: slot={d} lanes={d} validators={d} [bls={s}]\n", .{
                    blocks, slot, n_lanes, n_validators, label,
                });
                try stdout.flush();
            },
            .block_not_found => |h| {
                not_found += 1;
                try stdout.print("da-sync: block not found at height {d}\n", .{h.height});
            },
            .mempool_status_event => {},
        }
    }

    try stdout.print("da-sync: done — {d} blocks ({d} verified), {d} not-found\n", .{
        blocks, verified, not_found,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "SyncResult default state" {
    const r: SyncResult = .{
        .blocks_received = 0,
        .not_found = 0,
        .pings = 0,
        .termination = .server_closed,
    };
    try testing.expectEqual(SyncResult.Termination.server_closed, r.termination);
}
