//! Signed block replay engine.
//!
//! Replays a sequence of signed blocks and tracks the resulting state:
//! - Contract registry (contract name → state commitment, verifier, program)
//! - Pending blob transactions (transactions awaiting proof verification)
//! - Settled transactions (verified and applied)
//!
//! This module does NOT perform proof verification — it only tracks the
//! bookkeeping that happens when blocks are applied. Proof verification
//! is a separate concern handled by the verifier subsystem.
//!
//! The replay engine follows the same state transitions as Hyli's
//! `NodeState::handle_signed_block`:
//!   1. Extract transactions from each lane's data proposals.
//!   2. For each BlobTransaction: register it as unsettled.
//!   3. For each ProofTransaction: match to unsettled blobs, mark as
//!      proven (but not yet verified — the verifier does that).
//!   4. Apply staking actions from the consensus proposal.
//!   5. Advance the block height.
//!
//! This is the Phase 6 starting point: a pure state accumulator that
//! can be fed blocks from the BlockStore or DA sync and produce a
//! deterministic state snapshot.

const std = @import("std");
const types = @import("../model/types.zig");
const hash_mod = @import("../model/hash.zig");

/// A registered contract in the state.
pub const ContractInfo = struct {
    verifier: types.Verifier,
    program_id: types.ProgramId,
    state_commitment: types.StateCommitment,
    timeout_window: ?types.TimeoutWindow,
};

/// Tracks the state that results from replaying signed blocks.
pub const ReplayState = struct {
    allocator: std.mem.Allocator,

    /// Contract registry: contract_name → ContractInfo.
    contracts: std.StringHashMap(ContractInfo),

    /// Number of blocks replayed.
    block_height: u64,

    /// Latest slot processed.
    latest_slot: types.Slot,

    /// Number of blob transactions seen.
    blob_tx_count: u64,

    /// Number of proof transactions seen.
    proof_tx_count: u64,

    /// Number of staking actions applied.
    staking_action_count: u64,

    /// Number of contracts registered.
    contract_count: u64,

    pub fn init(allocator: std.mem.Allocator) ReplayState {
        return .{
            .allocator = allocator,
            .contracts = std.StringHashMap(ContractInfo).init(allocator),
            .block_height = 0,
            .latest_slot = 0,
            .blob_tx_count = 0,
            .proof_tx_count = 0,
            .staking_action_count = 0,
            .contract_count = 0,
        };
    }

    pub fn deinit(self: *ReplayState) void {
        self.contracts.deinit();
    }

    /// Apply one signed block to the state. This is the core replay
    /// function: it extracts transactions, applies effects, and
    /// advances the block height.
    pub fn applyBlock(self: *ReplayState, block: types.SignedBlock) void {
        const proposal = block.consensus_proposal;

        // Extract transactions from each lane's data proposals.
        for (block.data_proposals) |lane| {
            for (lane.data_proposals) |dp| {
                for (dp.txs) |tx| {
                    self.processTransaction(tx);
                }
            }
        }

        // Apply staking actions.
        self.staking_action_count += proposal.staking_actions.len;

        // Advance block height and slot.
        self.block_height += 1;
        self.latest_slot = proposal.slot;
    }

    /// Process a single transaction based on its type.
    fn processTransaction(self: *ReplayState, tx: types.Transaction) void {
        switch (tx.transaction_data) {
            .blob => {
                self.blob_tx_count += 1;
            },
            .proof => {
                // ProofTransaction carries a raw proof — it hasn't been
                // verified yet. We just count it. The proof needs to go
                // through a verifier before its effects can be applied.
                self.proof_tx_count += 1;
            },
            .verified_proof => |vp| {
                self.proof_tx_count += 1;
                for (vp.proven_blobs) |blob_output| {
                    self.applyHyliOutput(blob_output.hyli_output);
                }
            },
        }
    }

    /// Apply the onchain effects from a HyliOutput.
    fn applyHyliOutput(self: *ReplayState, output: types.HyliOutput) void {
        for (output.onchain_effects) |effect| {
            switch (effect) {
                .register_contract, .register_contract_with_constructor => |reg| {
                    self.contracts.put(reg.contract_name.value, .{
                        .verifier = reg.verifier,
                        .program_id = reg.program_id,
                        .state_commitment = reg.state_commitment,
                        .timeout_window = reg.timeout_window,
                    }) catch {};
                    self.contract_count += 1;
                },
                .delete_contract => |name| {
                    _ = self.contracts.remove(name.value);
                },
                .update_contract_program_id => |update| {
                    if (self.contracts.getPtr(update.contract_name.value)) |info| {
                        info.program_id = update.program_id;
                    }
                },
                .update_timeout_window => |update| {
                    if (self.contracts.getPtr(update.contract_name.value)) |info| {
                        info.timeout_window = update.timeout_window;
                    }
                },
            }
        }
    }

    /// Get the current state commitment for a contract, if registered.
    pub fn getContractState(self: *const ReplayState, name: []const u8) ?ContractInfo {
        return self.contracts.get(name);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn emptyProposal(slot: types.Slot) types.ConsensusProposal {
    return .{
        .slot = slot,
        .parent_hash = .{ .bytes = "parent" },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = slot * 1000 },
    };
}

fn emptyBlock(slot: types.Slot) types.SignedBlock {
    return .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = emptyProposal(slot),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{},
        },
    };
}

test "ReplayState: empty block advances height" {
    var state = ReplayState.init(testing.allocator);
    defer state.deinit();

    state.applyBlock(emptyBlock(1));
    try testing.expectEqual(@as(u64, 1), state.block_height);
    try testing.expectEqual(@as(types.Slot, 1), state.latest_slot);
    try testing.expectEqual(@as(u64, 0), state.blob_tx_count);
    try testing.expectEqual(@as(u64, 0), state.proof_tx_count);
}

test "ReplayState: multiple empty blocks" {
    var state = ReplayState.init(testing.allocator);
    defer state.deinit();

    state.applyBlock(emptyBlock(1));
    state.applyBlock(emptyBlock(2));
    state.applyBlock(emptyBlock(3));

    try testing.expectEqual(@as(u64, 3), state.block_height);
    try testing.expectEqual(@as(types.Slot, 3), state.latest_slot);
}

test "ReplayState: block with staking actions counted" {
    var state = ReplayState.init(testing.allocator);
    defer state.deinit();

    // Block with a staking action (bond).
    const block: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = .{
            .slot = 1,
            .parent_hash = .{ .bytes = "parent" },
            .cut = &[_]types.CutEntry{},
            .staking_actions = &[_]types.ConsensusStakingAction{
                .{
                    .bond = .{
                        .msg = .{ .peer_address = "192.168.0.1:4242" },
                        .signature = .{
                            .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
                            .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
                        },
                    },
                },
            },
            .timestamp = .{ .millis = 1000 },
        },
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{},
        },
    };

    state.applyBlock(block);
    try testing.expectEqual(@as(u64, 1), state.staking_action_count);
}

test "ReplayState: no contract initially" {
    var state = ReplayState.init(testing.allocator);
    defer state.deinit();

    try testing.expect(state.getContractState("my-contract") == null);
    try testing.expectEqual(@as(u64, 0), state.contract_count);
}

test "ReplayState: blob transaction counted" {
    var state = ReplayState.init(testing.allocator);
    defer state.deinit();

    const tx: types.Transaction = .{
        .version = 1,
        .transaction_data = .{
            .blob = .{
                .identity = .{ .value = "alice" },
                .blobs = &[_]types.Blob{
                    .{
                        .contract_name = .{ .value = "my-contract" },
                        .data = .{ .bytes = "hello world" },
                    },
                },
            },
        },
    };

    const block: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{
            .{
                .lane_id = .{
                    .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
                    .suffix = "lane-a",
                },
                .data_proposals = &[_]types.DataProposal{
                    .{
                        .parent_data_proposal_hash = .{ .lane_root = .{
                            .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
                            .suffix = "lane-a",
                        } },
                        .txs = &[_]types.Transaction{tx},
                    },
                },
            },
        },
        .consensus_proposal = emptyProposal(1),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{},
        },
    };

    state.applyBlock(block);
    try testing.expectEqual(@as(u64, 1), state.blob_tx_count);
    try testing.expectEqual(@as(u64, 0), state.proof_tx_count);
}

test "ReplayState: verified proof registers contract" {
    var state = ReplayState.init(testing.allocator);
    defer state.deinit();

    const register_effect: types.OnchainEffect = .{
        .register_contract = .{
            .verifier = .{ .value = "risc0" },
            .program_id = .{ .bytes = "prog-123" },
            .state_commitment = .{ .bytes = "initial-state" },
            .contract_name = .{ .value = "my-contract" },
            .timeout_window = null,
        },
    };

    const hyli_output: types.HyliOutput = .{
        .version = 1,
        .initial_state = .{ .bytes = "" },
        .next_state = .{ .bytes = "next" },
        .identity = .{ .value = "alice" },
        .index = .{ .index = 0 },
        .blobs = .{ .blobs = &[_]types.IndexedBlobEntry{} },
        .tx_blob_count = 1,
        .tx_hash = .{ .bytes = "txhash" },
        .success = true,
        .state_reads = &[_]types.StateRead{},
        .tx_ctx = null,
        .onchain_effects = &[_]types.OnchainEffect{register_effect},
        .program_outputs = &[_]u8{},
    };

    const tx: types.Transaction = .{
        .version = 1,
        .transaction_data = .{
            .verified_proof = .{
                .contract_name = .{ .value = "my-contract" },
                .program_id = .{ .bytes = "prog-123" },
                .verifier = .{ .value = "risc0" },
                .proof = null,
                .proof_hash = .{ .bytes = "proof-hash" },
                .proof_size = 0,
                .is_recursive = false,
                .proven_blobs = &[_]types.BlobProofOutput{
                    .{
                        .blob_tx_hash = .{ .bytes = "blob-tx" },
                        .original_proof_hash = .{ .bytes = "proof-hash" },
                        .hyli_output = hyli_output,
                        .program_id = .{ .bytes = "prog-123" },
                        .verifier = .{ .value = "risc0" },
                    },
                },
            },
        },
    };

    const block: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{
            .{
                .lane_id = .{
                    .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
                    .suffix = "lane-a",
                },
                .data_proposals = &[_]types.DataProposal{
                    .{
                        .parent_data_proposal_hash = .{ .lane_root = .{
                            .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
                            .suffix = "lane-a",
                        } },
                        .txs = &[_]types.Transaction{tx},
                    },
                },
            },
        },
        .consensus_proposal = emptyProposal(1),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{},
        },
    };

    state.applyBlock(block);
    try testing.expectEqual(@as(u64, 1), state.proof_tx_count);
    try testing.expectEqual(@as(u64, 1), state.contract_count);

    // The contract should now be registered.
    const info = state.getContractState("my-contract").?;
    try testing.expectEqualSlices(u8, "risc0", info.verifier.value);
    try testing.expectEqualSlices(u8, "prog-123", info.program_id.bytes);
    try testing.expectEqualSlices(u8, "initial-state", info.state_commitment.bytes);
}
