//! Integration test: full pipeline from block creation through chain
//! validation, follower state tracking, and block store persistence.
//!
//! This test creates a realistic chain of signed blocks with correct
//! parent hashes, feeds them through the entire processing pipeline
//! (ChainValidator → Follower → BlockStore), reopens the store, and
//! verifies that the replayed chain produces identical state.

const std = @import("std");
const types = @import("../model/types.zig");
const hash_mod = @import("../model/hash.zig");
const follower_mod = @import("follower.zig");
const da_sync = @import("da_sync.zig");
const block_store = @import("../storage/block_store.zig");

const testing = std.testing;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn makeProposal(slot: types.Slot, ts: u128, parent_hash: []const u8) types.ConsensusProposal {
    return .{
        .slot = slot,
        .parent_hash = .{ .bytes = parent_hash },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = ts },
    };
}

fn makeBlock(slot: types.Slot, ts: u128, parent_hash: []const u8, n_validators: usize) types.SignedBlock {
    // Build a validator list of the requested size.
    const validators = testing.allocator.alloc(types.ValidatorPublicKey, n_validators) catch unreachable;
    for (validators, 0..) |*v, i| {
        const key_bytes = testing.allocator.alloc(u8, 4) catch unreachable;
        @memset(key_bytes, @intCast(i + 1));
        v.* = .{ .bytes = key_bytes };
    }
    return .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = makeProposal(slot, ts, parent_hash),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = validators,
        },
    };
}

fn freeBlock(block: types.SignedBlock) void {
    for (block.certificate.validators) |v| {
        testing.allocator.free(v.bytes);
    }
    testing.allocator.free(block.certificate.validators);
}

/// Build a chain of N blocks with correct parent hashes.
fn buildChain(n: usize) ![]types.SignedBlock {
    const blocks = try testing.allocator.alloc(types.SignedBlock, n);
    errdefer testing.allocator.free(blocks);

    var parent_hash: [32]u8 = [_]u8{0} ** 32; // Genesis parent.
    for (blocks, 0..) |*b, i| {
        const slot: types.Slot = @intCast(i + 1);
        const ts: u128 = @intCast((i + 1) * 1000);
        const validators: usize = if (i % 3 == 0) 3 else 2; // vary validator count
        const ph_copy = try testing.allocator.alloc(u8, 32);
        @memcpy(ph_copy, &parent_hash);
        b.* = makeBlock(slot, ts, ph_copy, validators);
        parent_hash = hash_mod.consensusProposalHashed(&b.consensus_proposal);
    }
    return blocks;
}

fn freeChain(blocks: []types.SignedBlock) void {
    for (blocks) |block| {
        testing.allocator.free(block.consensus_proposal.parent_hash.bytes);
        freeBlock(block);
    }
    testing.allocator.free(blocks);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "integration: 10-block chain through ChainValidator and Follower" {
    const blocks = try buildChain(10);
    defer freeChain(blocks);

    var chain = da_sync.ChainValidator{};
    var follower = follower_mod.Follower.init();

    for (blocks) |block| {
        // Chain validation must pass.
        const cv = chain.validate(block);
        try testing.expectEqual(da_sync.ChainValidator.ValidationResult.ok, cv);

        // Follower must commit each block.
        const fe = follower.handleSignedBlock(block);
        try testing.expect(fe == .committed);
        try testing.expectEqual(block.consensus_proposal.slot, fe.committed.slot);
    }

    try testing.expectEqual(@as(usize, 10), chain.accepted);
    try testing.expectEqual(@as(types.Slot, 10), chain.last_slot);
    try testing.expectEqual(@as(types.Slot, 10), follower.slot);
    try testing.expectEqual(@as(types.Slot, 10), follower.last_commit_slot);
    try testing.expect(follower.last_commit_hash != null);
}

test "integration: store, reopen, replay produces identical follower state" {
    const store_path = "/tmp/zyli_test_integration_store.dat";
    defer std.fs.cwd().deleteFile(store_path) catch {};

    const blocks = try buildChain(5);
    defer freeChain(blocks);

    // Phase 1: process blocks and store them.
    var chain1 = da_sync.ChainValidator{};
    var follower1 = follower_mod.Follower.init();
    {
        var store = try block_store.BlockStore.open(testing.allocator, store_path);
        defer store.close();

        for (blocks) |block| {
            _ = chain1.validate(block);
            _ = follower1.handleSignedBlock(block);
            _ = try store.append(block);
        }
    }

    // Phase 2: reopen the store and replay.
    var chain2 = da_sync.ChainValidator{};
    var follower2 = follower_mod.Follower.init();
    {
        var store = try block_store.BlockStore.open(testing.allocator, store_path);
        defer store.close();

        try testing.expectEqual(@as(usize, 5), store.count);

        const slots = try store.allSlots(testing.allocator);
        defer testing.allocator.free(slots);

        for (slots) |slot| {
            var decoded = (try store.getBySlot(slot)).?;
            defer decoded.deinit();

            const cv = chain2.validate(decoded.value);
            try testing.expectEqual(da_sync.ChainValidator.ValidationResult.ok, cv);

            const fe = follower2.handleSignedBlock(decoded.value);
            try testing.expect(fe == .committed);
        }
    }

    // Compare: both passes should produce identical state.
    try testing.expectEqual(chain1.accepted, chain2.accepted);
    try testing.expectEqual(chain1.last_slot, chain2.last_slot);
    try testing.expectEqual(follower1.slot, follower2.slot);
    try testing.expectEqual(follower1.last_commit_slot, follower2.last_commit_slot);
    // Hash comparison: both followers should agree on last commit hash.
    try testing.expect(chain1.last_hash != null);
    try testing.expect(chain2.last_hash != null);
    try testing.expectEqualSlices(u8, &chain1.last_hash.?, &chain2.last_hash.?);
}

test "integration: chain with gap is detected by ChainValidator" {
    const blocks = try buildChain(5);
    defer freeChain(blocks);

    var chain = da_sync.ChainValidator{};

    // Process blocks 0, 1, then skip to block 3 (index 3 = slot 4).
    _ = chain.validate(blocks[0]);
    _ = chain.validate(blocks[1]);

    // Block at index 3 has parent_hash pointing to block[2], but we
    // skipped block[2]. The parent hash won't match chain's last_hash.
    const result = chain.validate(blocks[3]);
    try testing.expectEqual(da_sync.ChainValidator.ValidationResult.parent_hash_mismatch, result);
}

test "integration: duplicate block detection" {
    const blocks = try buildChain(3);
    defer freeChain(blocks);

    var chain = da_sync.ChainValidator{};
    var follower = follower_mod.Follower.init();

    for (blocks) |block| {
        _ = chain.validate(block);
        _ = follower.handleSignedBlock(block);
    }

    // Replay block[1] (slot 2) — should be detected as duplicate.
    const cv = chain.validate(blocks[1]);
    try testing.expectEqual(da_sync.ChainValidator.ValidationResult.height_not_monotonic, cv);

    const fe = follower.handleSignedBlock(blocks[1]);
    try testing.expect(fe == .observed); // stale
}

test "integration: varying validator counts preserved through store" {
    const store_path = "/tmp/zyli_test_integration_validators.dat";
    defer std.fs.cwd().deleteFile(store_path) catch {};

    const blocks = try buildChain(6);
    defer freeChain(blocks);

    // Store all blocks.
    {
        var store = try block_store.BlockStore.open(testing.allocator, store_path);
        defer store.close();
        for (blocks) |block| {
            _ = try store.append(block);
        }
    }

    // Reopen and verify validator counts match.
    {
        var store = try block_store.BlockStore.open(testing.allocator, store_path);
        defer store.close();

        for (blocks, 0..) |original, i| {
            const slot: types.Slot = @intCast(i + 1);
            var decoded = (try store.getBySlot(slot)).?;
            defer decoded.deinit();

            try testing.expectEqual(
                original.certificate.validators.len,
                decoded.value.certificate.validators.len,
            );
            try testing.expectEqual(
                original.consensus_proposal.slot,
                decoded.value.consensus_proposal.slot,
            );
        }
    }
}
