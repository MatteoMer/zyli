//! `SignedBlock` accessors.
//!
//! Hyli's `SignedBlock` carries the consensus proposal that produced it,
//! and the parent hash plus block height are derived projections over
//! that inner proposal. The Zig follower path will need both, so we keep
//! the rule in one place — `parent_hash` mirrors
//! `SignedBlock::parent_hash()` and `height` mirrors `SignedBlock::height()`
//! from `crates/hyli-model/src/block.rs`.

const std = @import("std");
const types = @import("types.zig");

/// `&SignedBlock::consensus_proposal.parent_hash`. The returned slice
/// borrows from the block.
pub fn parentHash(block: *const types.SignedBlock) types.ConsensusProposalHash {
    return block.consensus_proposal.parent_hash;
}

/// `BlockHeight(SignedBlock::consensus_proposal.slot)`. Mirrors the
/// upstream `SignedBlock::height` accessor — note that block height is
/// just the slot of the inner proposal cast into the `BlockHeight`
/// newtype.
pub fn height(block: *const types.SignedBlock) types.BlockHeight {
    return .{ .height = block.consensus_proposal.slot };
}

/// Total number of transactions across every lane in the block. Useful
/// for the follower's "is the block empty?" check, mirroring the upstream
/// `SignedBlock::has_txs` shape.
pub fn totalTxCount(block: *const types.SignedBlock) usize {
    var total: usize = 0;
    for (block.data_proposals) |lane| {
        for (lane.data_proposals) |dp| total += dp.txs.len;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const corpus = @import("corpus");
const borsh = @import("borsh.zig");

test "SignedBlock accessors round-trip the corpus fixture" {
    // Decode the SignedBlock fixture and check parent_hash/height/totalTxCount.
    const fixture = corpus.borsh.model.signed_block_sample;
    var reader = borsh.Reader.init(fixture);
    const block = try borsh.decode(types.SignedBlock, &reader, testing.allocator);
    defer freeSignedBlock(testing.allocator, block);
    try testing.expect(reader.isEmpty());

    // The fixture's inner consensus proposal is `cp_full` with
    // `parent_hash = "prev-cp"` and `slot = 7`.
    try testing.expectEqualSlices(u8, "prev-cp", parentHash(&block).bytes);
    try testing.expectEqual(@as(u64, 7), height(&block).height);
    // The lone DataProposal in the fixture is empty, so the total tx
    // count is zero.
    try testing.expectEqual(@as(usize, 0), totalTxCount(&block));
}

/// Free a `SignedBlock` value produced by the borsh decoder. Walks the
/// owned slices that the codec allocates so tests don't leak.
///
/// This is intentionally local to the test rather than a public helper —
/// the long-term plan is for storage code to manage block lifetimes
/// through a real arena allocator, not per-field frees. Once that lands
/// this helper can move with it.
fn freeSignedBlock(allocator: std.mem.Allocator, block: types.SignedBlock) void {
    for (block.data_proposals) |lane| {
        allocator.free(lane.lane_id.operator.bytes);
        allocator.free(lane.lane_id.suffix);
        for (lane.data_proposals) |dp| {
            freeDataProposalParent(allocator, dp.parent_data_proposal_hash);
            for (dp.txs) |tx| freeTransaction(allocator, tx);
            allocator.free(dp.txs);
        }
        allocator.free(lane.data_proposals);
    }
    allocator.free(block.data_proposals);
    freeConsensusProposal(allocator, block.consensus_proposal);
    freeAggregateSignature(allocator, block.certificate);
}

fn freeDataProposalParent(allocator: std.mem.Allocator, parent: types.DataProposalParent) void {
    switch (parent) {
        .lane_root => |lane| {
            allocator.free(lane.operator.bytes);
            allocator.free(lane.suffix);
        },
        .dp => |hash| allocator.free(hash.bytes),
    }
}

fn freeTransaction(allocator: std.mem.Allocator, tx: types.Transaction) void {
    switch (tx.transaction_data) {
        .blob => |blob_tx| {
            allocator.free(blob_tx.identity.value);
            for (blob_tx.blobs) |b| {
                allocator.free(b.contract_name.value);
                allocator.free(b.data.bytes);
            }
            allocator.free(blob_tx.blobs);
        },
        .proof => |pt| {
            allocator.free(pt.contract_name.value);
            allocator.free(pt.program_id.bytes);
            allocator.free(pt.verifier.value);
            allocator.free(pt.proof.bytes);
        },
        .verified_proof => |vpt| {
            allocator.free(vpt.contract_name.value);
            allocator.free(vpt.program_id.bytes);
            allocator.free(vpt.verifier.value);
            if (vpt.proof) |p| allocator.free(p.bytes);
            allocator.free(vpt.proof_hash.bytes);
            for (vpt.proven_blobs) |bp| allocator.free(bp.bytes);
            allocator.free(vpt.proven_blobs);
        },
    }
}

fn freeConsensusProposal(
    allocator: std.mem.Allocator,
    cp: types.ConsensusProposal,
) void {
    allocator.free(cp.parent_hash.bytes);
    for (cp.cut) |entry| {
        allocator.free(entry.lane_id.operator.bytes);
        allocator.free(entry.lane_id.suffix);
        allocator.free(entry.dp_hash.bytes);
        freeAggregateSignature(allocator, entry.aggregate_signature);
    }
    allocator.free(cp.cut);
    for (cp.staking_actions) |action| switch (action) {
        .bond => |signed| {
            allocator.free(signed.msg.peer_address);
            allocator.free(signed.signature.signature.bytes);
            allocator.free(signed.signature.validator.bytes);
        },
        .pay_fees_for_dadi => |pay| {
            allocator.free(pay.lane_id.operator.bytes);
            allocator.free(pay.lane_id.suffix);
        },
    };
    allocator.free(cp.staking_actions);
}

fn freeAggregateSignature(
    allocator: std.mem.Allocator,
    agg: types.AggregateSignature,
) void {
    allocator.free(agg.signature.bytes);
    for (agg.validators) |v| allocator.free(v.bytes);
    allocator.free(agg.validators);
}
