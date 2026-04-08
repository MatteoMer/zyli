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
const hash_mod = @import("../model/hash.zig");
const follower_mod = @import("follower.zig");
const block_store = @import("../storage/block_store.zig");

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

/// Structural chain validator for DA-streamed blocks.
///
/// Tracks height monotonicity (block slots must strictly increase) and
/// parent-hash chain continuity (each block's `parent_hash` must equal
/// the hash of the previous block's proposal). These are local checks
/// that require no BLS — they only confirm the server is sending a
/// consistent, ordered chain.
pub const ChainValidator = struct {
    /// Slot of the last accepted block. 0 means no block yet.
    last_slot: types.Slot = 0,
    /// Hash of the last accepted block's consensus proposal. null until
    /// the first block is processed.
    last_hash: ?[32]u8 = null,
    /// Number of blocks that passed validation.
    accepted: usize = 0,
    /// Number of blocks that failed height monotonicity.
    height_violations: usize = 0,
    /// Number of blocks that failed parent hash continuity.
    parent_hash_violations: usize = 0,

    pub const ValidationResult = enum {
        ok,
        height_not_monotonic,
        parent_hash_mismatch,
    };

    /// Validate a signed block against the chain state. Returns `.ok`
    /// if the block is consistent, or a violation kind otherwise.
    pub fn validate(self: *ChainValidator, block: types.SignedBlock) ValidationResult {
        const proposal = block.consensus_proposal;

        // Height monotonicity: slot must be strictly greater.
        if (proposal.slot <= self.last_slot) {
            self.height_violations += 1;
            return .height_not_monotonic;
        }

        // Parent hash continuity: if we have a previous hash, the
        // block's parent_hash must match it. Skip for the first block
        // (we don't know its parent).
        if (self.last_hash) |prev_hash| {
            if (proposal.parent_hash.bytes.len != 32 or
                !std.mem.eql(u8, proposal.parent_hash.bytes, &prev_hash))
            {
                self.parent_hash_violations += 1;
                return .parent_hash_mismatch;
            }
        }

        // Accept: compute this block's hash and advance state.
        const digest = hash_mod.consensusProposalHashed(&proposal);
        self.last_hash = digest;
        self.last_slot = proposal.slot;
        self.accepted += 1;
        return .ok;
    }
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
///
/// When `store_path` is non-null, blocks are persisted to an append-only
/// file. On subsequent runs, the sync automatically resumes from the
/// last stored block.
pub fn syncAndReport(
    allocator: std.mem.Allocator,
    stdout: anytype,
    da_address: []const u8,
    start_height: u64,
    store_path: ?[]const u8,
) !void {
    // Open the block store if requested.
    var store: ?block_store.BlockStore = null;
    if (store_path) |path| {
        store = block_store.BlockStore.open(allocator, path) catch |err| {
            try stdout.print("da-sync: failed to open block store at {s}: {s}\n", .{ path, @errorName(err) });
            return;
        };
        try stdout.print("da-sync: block store at {s} — {d} blocks, latest slot {d}\n", .{
            path,
            store.?.count,
            store.?.latest_slot,
        });
    }
    defer if (store != null) store.?.close();

    // If the store has blocks, resume from after the last one.
    const effective_height = if (store != null and store.?.count > 0)
        start_height + @as(u64, @intCast(store.?.count))
    else
        start_height;

    try stdout.print("da-sync: connecting to {s}, starting from height {d}\n", .{ da_address, effective_height });
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
        .stream_from_height = .{ .height = effective_height },
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
    var stored: usize = 0;
    var chain = ChainValidator{};
    var follower = follower_mod.Follower.init();

    // If the store has blocks, seed the chain validator and follower
    // with the last stored block so continuity checks work from the
    // first new block we receive.
    if (store != null and store.?.count > 0) {
        const maybe_last = store.?.getBySlot(store.?.latest_slot) catch null;
        if (maybe_last) |last_val| {
            var last = last_val;
            defer last.deinit();
            // Seed chain validator with the last block's hash.
            const last_digest = hash_mod.consensusProposalHashed(&last.value.consensus_proposal);
            chain.last_hash = last_digest;
            chain.last_slot = last.value.consensus_proposal.slot;
            // Seed follower.
            _ = follower.handleSignedBlock(last.value);
        }
    }

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

                // Structural chain validation.
                const chain_result = chain.validate(block);
                const chain_label: []const u8 = switch (chain_result) {
                    .ok => "ok",
                    .height_not_monotonic => "HEIGHT",
                    .parent_hash_mismatch => "PARENT",
                };

                // Feed through follower state machine.
                const f_event = follower.handleSignedBlock(block);
                const f_label: []const u8 = switch (f_event) {
                    .committed => "committed",
                    .observed => "stale",
                    .rejected => "rejected",
                    else => "other",
                };

                // Verify the block's CommitQC certificate.
                const bls_ok = consensus_verify.verifySignedBlockCertificate(
                    allocator,
                    block,
                ) catch false;
                if (bls_ok) verified += 1;
                const bls_label: []const u8 = if (bls_ok) "ok" else "BAD";

                // Persist to the block store if open and chain-valid.
                var store_label: []const u8 = "-";
                if (store != null and chain_result == .ok) {
                    _ = store.?.append(block) catch |err| {
                        try stdout.print("da-sync: store write error: {s}\n", .{@errorName(err)});
                        break;
                    };
                    stored += 1;
                    store_label = "stored";
                }

                try stdout.print("block {d}: slot={d} lanes={d} validators={d} [chain={s} bls={s} follower={s} store={s}]\n", .{
                    blocks, slot, n_lanes, n_validators, chain_label, bls_label, f_label, store_label,
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

    try stdout.print("da-sync: done — {d} blocks ({d} verified, {d} chain-ok, {d} stored), {d} not-found, follower at slot {d}\n", .{
        blocks, verified, chain.accepted, stored, not_found, follower.slot,
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

// ---------------------------------------------------------------------------
// ChainValidator tests
// ---------------------------------------------------------------------------

fn testProposalAt(slot: types.Slot, ts: u128, parent_hash: []const u8) types.ConsensusProposal {
    return .{
        .slot = slot,
        .parent_hash = .{ .bytes = parent_hash },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = ts },
    };
}

fn testBlock(slot: types.Slot, ts: u128, parent_hash: []const u8) types.SignedBlock {
    return .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = testProposalAt(slot, ts, parent_hash),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{
                .{ .bytes = &[_]u8{0x01} ** 4 },
            },
        },
    };
}

test "ChainValidator: first block always accepted" {
    var cv = ChainValidator{};
    const block = testBlock(1, 100, "genesis");
    const result = cv.validate(block);
    try testing.expectEqual(ChainValidator.ValidationResult.ok, result);
    try testing.expectEqual(@as(usize, 1), cv.accepted);
    try testing.expectEqual(@as(types.Slot, 1), cv.last_slot);
    try testing.expect(cv.last_hash != null);
}

test "ChainValidator: monotonic slots accepted" {
    var cv = ChainValidator{};

    // Block 1 — genesis parent (any hash is fine for the first block).
    const b1 = testBlock(1, 100, "genesis");
    try testing.expectEqual(ChainValidator.ValidationResult.ok, cv.validate(b1));

    // Block 2 — parent hash must be hash of b1's proposal.
    const b1_hash = hash_mod.consensusProposalHashed(&b1.consensus_proposal);
    const b2 = testBlock(2, 200, &b1_hash);
    try testing.expectEqual(ChainValidator.ValidationResult.ok, cv.validate(b2));

    try testing.expectEqual(@as(usize, 2), cv.accepted);
    try testing.expectEqual(@as(types.Slot, 2), cv.last_slot);
}

test "ChainValidator: duplicate slot rejected" {
    var cv = ChainValidator{};
    const b1 = testBlock(1, 100, "genesis");
    _ = cv.validate(b1);

    // Same slot again — height not monotonic.
    const b1_dup = testBlock(1, 100, "genesis");
    const result = cv.validate(b1_dup);
    try testing.expectEqual(ChainValidator.ValidationResult.height_not_monotonic, result);
    try testing.expectEqual(@as(usize, 1), cv.height_violations);
    try testing.expectEqual(@as(usize, 1), cv.accepted); // unchanged
}

test "ChainValidator: older slot rejected" {
    var cv = ChainValidator{};
    _ = cv.validate(testBlock(5, 100, "genesis"));
    const result = cv.validate(testBlock(3, 50, "whatever"));
    try testing.expectEqual(ChainValidator.ValidationResult.height_not_monotonic, result);
    try testing.expectEqual(@as(usize, 1), cv.height_violations);
}

test "ChainValidator: parent hash mismatch rejected" {
    var cv = ChainValidator{};
    const b1 = testBlock(1, 100, "genesis");
    _ = cv.validate(b1);

    // Block 2 with a WRONG parent hash.
    const b2_bad = testBlock(2, 200, &[_]u8{0xff} ** 32);
    const result = cv.validate(b2_bad);
    try testing.expectEqual(ChainValidator.ValidationResult.parent_hash_mismatch, result);
    try testing.expectEqual(@as(usize, 1), cv.parent_hash_violations);
    // Still at block 1 — the bad block was not accepted.
    try testing.expectEqual(@as(usize, 1), cv.accepted);
    try testing.expectEqual(@as(types.Slot, 1), cv.last_slot);
}

test "ChainValidator: three-block chain with correct hashes" {
    var cv = ChainValidator{};

    const b1 = testBlock(1, 100, "genesis");
    try testing.expectEqual(ChainValidator.ValidationResult.ok, cv.validate(b1));

    const h1 = hash_mod.consensusProposalHashed(&b1.consensus_proposal);
    const b2 = testBlock(2, 200, &h1);
    try testing.expectEqual(ChainValidator.ValidationResult.ok, cv.validate(b2));

    const h2 = hash_mod.consensusProposalHashed(&b2.consensus_proposal);
    const b3 = testBlock(3, 300, &h2);
    try testing.expectEqual(ChainValidator.ValidationResult.ok, cv.validate(b3));

    try testing.expectEqual(@as(usize, 3), cv.accepted);
    try testing.expectEqual(@as(types.Slot, 3), cv.last_slot);
    try testing.expectEqual(@as(usize, 0), cv.height_violations);
    try testing.expectEqual(@as(usize, 0), cv.parent_hash_violations);
}

test "ChainValidator: chain break after valid prefix" {
    var cv = ChainValidator{};

    const b1 = testBlock(1, 100, "genesis");
    _ = cv.validate(b1);

    const h1 = hash_mod.consensusProposalHashed(&b1.consensus_proposal);
    const b2 = testBlock(2, 200, &h1);
    _ = cv.validate(b2);

    // Block 3 with wrong parent (should be hash of b2, not b1).
    const b3_bad = testBlock(3, 300, &h1); // re-using b1's hash as parent
    const result = cv.validate(b3_bad);
    try testing.expectEqual(ChainValidator.ValidationResult.parent_hash_mismatch, result);
    try testing.expectEqual(@as(usize, 2), cv.accepted);
    try testing.expectEqual(@as(usize, 1), cv.parent_hash_violations);
}
