//! Compatibility tests against the Rust-generated `compat/corpus`.
//!
//! Each test pulls a fixture from the auto-generated `corpus` module,
//! re-encodes the same value through Zyli's Borsh codec, and asserts
//! byte-for-byte equality. The corpus is the executable spec from Phase 0
//! of the implementation plan, so any divergence here is a hard failure of
//! the wire compatibility goal.
//!
//! The `corpus` module is added in `build.zig` and points at
//! `compat/corpus.zig`. Re-running `compat/fixture-gen` is what regenerates
//! both the bytes and the manifest, so a missing fixture surfaces as a
//! compile error before any test runs.

const std = @import("std");
const testing = std.testing;
const borsh = @import("borsh.zig");
const types = @import("types.zig");
const corpus = @import("corpus");

fn expectMatchesFixture(comptime T: type, value: T, fixture: []const u8) !void {
    var list = try borsh.encodeAlloc(testing.allocator, T, value);
    defer list.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, fixture, list.items);
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

test "fixture: u8 42" {
    try expectMatchesFixture(u8, 42, corpus.borsh.primitives.u8_42);
}

test "fixture: u32 0xdeadbeef" {
    try expectMatchesFixture(u32, 0xdeadbeef, corpus.borsh.primitives.u32_0xdeadbeef);
}

test "fixture: u64 1" {
    try expectMatchesFixture(u64, 1, corpus.borsh.primitives.u64_one);
}

test "fixture: u128 max" {
    try expectMatchesFixture(u128, std.math.maxInt(u128), corpus.borsh.primitives.u128_max);
}

test "fixture: i32 -1" {
    try expectMatchesFixture(i32, -1, corpus.borsh.primitives.i32_neg_one);
}

test "fixture: Option<u32> Some(7)" {
    try expectMatchesFixture(?u32, 7, corpus.borsh.primitives.option_u32_some_7);
}

test "fixture: Option<u32> None" {
    try expectMatchesFixture(?u32, null, corpus.borsh.primitives.option_u32_none);
}

test "fixture: String hello" {
    try expectMatchesFixture([]const u8, "hello", corpus.borsh.primitives.string_hello);
}

test "fixture: String unicode" {
    try expectMatchesFixture([]const u8, "héllo🦀", corpus.borsh.primitives.string_unicode);
}

test "fixture: Vec<u8> [1, 2, 3]" {
    try expectMatchesFixture([]const u8, &[_]u8{ 1, 2, 3 }, corpus.borsh.primitives.vec_u8_three);
}

test "fixture: Vec<u32> [1, 2]" {
    try expectMatchesFixture([]const u32, &[_]u32{ 1, 2 }, corpus.borsh.primitives.vec_u32_two);
}

// ---------------------------------------------------------------------------
// Hyli model newtypes — these are tuple structs around a single field, so
// the Borsh wire format is identical to the inner field's encoding.
// ---------------------------------------------------------------------------

test "fixture: Identity(\"alice@hyli\")" {
    try expectMatchesFixture(
        types.Identity,
        .{ .value = "alice@hyli" },
        corpus.borsh.model.identity_alice,
    );
}

test "fixture: ContractName(\"hyli\")" {
    try expectMatchesFixture(
        types.ContractName,
        .{ .value = "hyli" },
        corpus.borsh.model.contract_name_hyli,
    );
}

test "fixture: ProgramId([0xde,0xad,0xbe,0xef])" {
    try expectMatchesFixture(
        types.ProgramId,
        .{ .bytes = &[_]u8{ 0xde, 0xad, 0xbe, 0xef } },
        corpus.borsh.model.program_id_4_bytes,
    );
}

test "fixture: Verifier(\"risc0\")" {
    try expectMatchesFixture(
        types.Verifier,
        .{ .value = "risc0" },
        corpus.borsh.model.verifier_risc0,
    );
}

test "fixture: StateCommitment([0,1,2,3])" {
    try expectMatchesFixture(
        types.StateCommitment,
        .{ .bytes = &[_]u8{ 0, 1, 2, 3 } },
        corpus.borsh.model.state_commitment_4_bytes,
    );
}

test "fixture: BlockHeight(42)" {
    try expectMatchesFixture(
        types.BlockHeight,
        .{ .height = 42 },
        corpus.borsh.model.block_height_42,
    );
}

test "fixture: BlobIndex(3) — usize encodes as u64" {
    // The Rust struct stores `usize`, but Borsh always serializes `usize`
    // as a fixed `u64`. Asserting the fixture is exactly 8 bytes proves the
    // wire format is platform-independent.
    try testing.expectEqual(@as(usize, 8), corpus.borsh.model.blob_index_3.len);
    try expectMatchesFixture(
        types.BlobIndex,
        .{ .index = 3 },
        corpus.borsh.model.blob_index_3,
    );
}

test "fixture: TimestampMs(0)" {
    try testing.expectEqual(@as(usize, 16), corpus.borsh.model.timestamp_ms_unix_epoch.len);
    try expectMatchesFixture(
        types.TimestampMs,
        .{ .millis = 0 },
        corpus.borsh.model.timestamp_ms_unix_epoch,
    );
}

test "fixture: TimestampMs(u64::MAX as u128)" {
    try expectMatchesFixture(
        types.TimestampMs,
        .{ .millis = std.math.maxInt(u64) },
        corpus.borsh.model.timestamp_ms_max_u64,
    );
}

test "fixture: LaneId::default()" {
    try expectMatchesFixture(
        types.LaneId,
        .{
            .operator = .{ .bytes = &[_]u8{} },
            .suffix = "default",
        },
        corpus.borsh.model.lane_id_default,
    );
}

// ---------------------------------------------------------------------------
// Composite struct: Blob.
// ---------------------------------------------------------------------------

test "fixture: Blob { contract_name=\"hyli\", data=[1,2,3] }" {
    const blob: types.Blob = .{
        .contract_name = .{ .value = "hyli" },
        .data = .{ .bytes = &[_]u8{ 0x01, 0x02, 0x03 } },
    };
    try expectMatchesFixture(types.Blob, blob, corpus.borsh.model.blob_simple);
}

// ---------------------------------------------------------------------------
// Enum: DataProposalParent. Both variants are checked individually so a
// silent reordering of the Rust enum would surface immediately.
// ---------------------------------------------------------------------------

test "fixture: DataProposalParent::LaneRoot(default)" {
    const value: types.DataProposalParent = .{
        .lane_root = .{
            .operator = .{ .bytes = &[_]u8{} },
            .suffix = "default",
        },
    };
    try expectMatchesFixture(
        types.DataProposalParent,
        value,
        corpus.borsh.model.data_proposal_parent_lane_root,
    );
}

test "fixture: DataProposalParent::DP(\"parent\")" {
    const value: types.DataProposalParent = .{
        .dp = .{ .bytes = "parent" },
    };
    try expectMatchesFixture(
        types.DataProposalParent,
        value,
        corpus.borsh.model.data_proposal_parent_dp,
    );
}

// ---------------------------------------------------------------------------
// Transaction family
// ---------------------------------------------------------------------------

/// Reusable BlobTransaction sample. Mirrors the Rust fixture exactly.
fn sampleBlobTransaction() types.BlobTransaction {
    const blobs = &[_]types.Blob{
        .{
            .contract_name = .{ .value = "hyli" },
            .data = .{ .bytes = &[_]u8{ 0xaa, 0xbb } },
        },
        .{
            .contract_name = .{ .value = "counter" },
            .data = .{ .bytes = &[_]u8{ 0x01, 0x02, 0x03, 0x04 } },
        },
    };
    return .{
        .identity = .{ .value = "alice@hyli" },
        .blobs = blobs,
    };
}

fn sampleProofTransaction() types.ProofTransaction {
    return .{
        .contract_name = .{ .value = "counter" },
        .program_id = .{ .bytes = &[_]u8{ 0xde, 0xad } },
        .verifier = .{ .value = "risc0" },
        .proof = .{ .bytes = &[_]u8{0x42} ** 16 },
    };
}

test "fixture: BlobTransaction(alice@hyli, [hyli, counter])" {
    try expectMatchesFixture(
        types.BlobTransaction,
        sampleBlobTransaction(),
        corpus.borsh.model.blob_transaction,
    );
}

test "fixture: ProofTransaction(counter, risc0)" {
    try expectMatchesFixture(
        types.ProofTransaction,
        sampleProofTransaction(),
        corpus.borsh.model.proof_transaction,
    );
}

test "fixture: VerifiedProofTransaction(counter, proof=None)" {
    // The Rust fixture computes proof_hash from sha3_256(proof_data); we
    // re-derive the same digest in the test rather than embedding the
    // expected hash bytes inline.
    const proof_data_bytes = &[_]u8{0x42} ** 16;
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(proof_data_bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    const value: types.VerifiedProofTransaction = .{
        .contract_name = .{ .value = "counter" },
        .program_id = .{ .bytes = &[_]u8{ 0xde, 0xad } },
        .verifier = .{ .value = "risc0" },
        .proof = null,
        .proof_hash = .{ .bytes = &digest },
        .proof_size = 16,
        .proven_blobs = &[_]types.BlobProofOutput{},
        .is_recursive = false,
    };
    try expectMatchesFixture(
        types.VerifiedProofTransaction,
        value,
        corpus.borsh.model.verified_proof_transaction,
    );
}

test "fixture: Transaction(version=1, Blob(...))" {
    const value: types.Transaction = .{
        .version = 1,
        .transaction_data = .{ .blob = sampleBlobTransaction() },
    };
    try expectMatchesFixture(types.Transaction, value, corpus.borsh.model.transaction_blob);
}

test "fixture: Transaction(version=1, Proof(...))" {
    const value: types.Transaction = .{
        .version = 1,
        .transaction_data = .{ .proof = sampleProofTransaction() },
    };
    try expectMatchesFixture(types.Transaction, value, corpus.borsh.model.transaction_proof);
}

// ---------------------------------------------------------------------------
// Signed envelopes
// ---------------------------------------------------------------------------

test "fixture: ValidatorPublicKey([0x01;4])" {
    try expectMatchesFixture(
        types.ValidatorPublicKey,
        .{ .bytes = &[_]u8{0x01} ** 4 },
        corpus.borsh.model.validator_public_key,
    );
}

test "fixture: Signature([0xff;8])" {
    try expectMatchesFixture(
        types.Signature,
        .{ .bytes = &[_]u8{0xff} ** 8 },
        corpus.borsh.model.signature_8_bytes,
    );
}

test "fixture: ValidatorSignature" {
    try expectMatchesFixture(
        types.ValidatorSignature,
        .{
            .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
            .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
        },
        corpus.borsh.model.validator_signature,
    );
}

test "fixture: ValidatorCandidacy" {
    try expectMatchesFixture(
        types.ValidatorCandidacy,
        .{ .peer_address = "127.0.0.1:4242" },
        corpus.borsh.model.validator_candidacy,
    );
}

test "fixture: SignedByValidator<ValidatorCandidacy>" {
    const SignedT = types.Signed(types.ValidatorCandidacy, types.ValidatorSignature);
    const value: SignedT = .{
        .msg = .{ .peer_address = "127.0.0.1:4242" },
        .signature = .{
            .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
            .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
        },
    };
    try expectMatchesFixture(SignedT, value, corpus.borsh.model.signed_validator_candidacy);
}

test "fixture: AggregateSignature(2 validators)" {
    const value: types.AggregateSignature = .{
        .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
        .validators = &[_]types.ValidatorPublicKey{
            .{ .bytes = &[_]u8{0x01} ** 4 },
            .{ .bytes = &[_]u8{0x02} ** 4 },
        },
    };
    try expectMatchesFixture(
        types.AggregateSignature,
        value,
        corpus.borsh.model.aggregate_signature_2,
    );
}

// ---------------------------------------------------------------------------
// Consensus
// ---------------------------------------------------------------------------

test "fixture: LaneBytesSize(4096)" {
    try expectMatchesFixture(
        types.LaneBytesSize,
        .{ .bytes = 4096 },
        corpus.borsh.model.lane_bytes_size_4096,
    );
}

test "fixture: ConsensusStakingAction::Bond — Box<T> is wire-transparent" {
    const value: types.ConsensusStakingAction = .{
        .bond = .{
            .msg = .{ .peer_address = "127.0.0.1:4242" },
            .signature = .{
                .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
                .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
            },
        },
    };
    try expectMatchesFixture(
        types.ConsensusStakingAction,
        value,
        corpus.borsh.model.consensus_staking_action_bond,
    );
}

test "fixture: ConsensusStakingAction::PayFeesForDaDi" {
    const value: types.ConsensusStakingAction = .{
        .pay_fees_for_dadi = .{
            .lane_id = .{
                .operator = .{ .bytes = &[_]u8{} },
                .suffix = "default",
            },
            .cumul_size = .{ .bytes = 4096 },
        },
    };
    try expectMatchesFixture(
        types.ConsensusStakingAction,
        value,
        corpus.borsh.model.consensus_staking_action_pay,
    );
}

test "fixture: ConsensusProposal (empty cut and staking_actions)" {
    const value: types.ConsensusProposal = .{
        .slot = 1,
        .parent_hash = .{ .bytes = "genesis" },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = 1234 },
    };
    try expectMatchesFixture(
        types.ConsensusProposal,
        value,
        corpus.borsh.model.consensus_proposal_empty,
    );
}

// ---------------------------------------------------------------------------
// Replay-path types
// ---------------------------------------------------------------------------

test "fixture: BlobsHashes (empty)" {
    const value: types.BlobsHashes = .{
        .hashes = &[_]types.BlobsHashesEntry{},
    };
    try expectMatchesFixture(types.BlobsHashes, value, corpus.borsh.model.blobs_hashes_empty);
}

test "fixture: BlobsHashes (two entries, sorted by index)" {
    // BTreeMap iteration order is sorted by key Ord. The Zig encoder relies
    // on the caller having pre-sorted the slice — passing entries in the
    // wrong order would silently break wire compatibility.
    const value: types.BlobsHashes = .{
        .hashes = &[_]types.BlobsHashesEntry{
            .{ .index = .{ .index = 0 }, .hash = .{ .bytes = &[_]u8{0xaa} ** 4 } },
            .{ .index = .{ .index = 1 }, .hash = .{ .bytes = &[_]u8{0xbb} ** 4 } },
        },
    };
    try expectMatchesFixture(types.BlobsHashes, value, corpus.borsh.model.blobs_hashes_two);
}

test "fixture: TxContext" {
    const value: types.TxContext = .{
        .lane_id = .{
            .operator = .{ .bytes = &[_]u8{} },
            .suffix = "default",
        },
        .block_hash = .{ .bytes = &[_]u8{0x55} ** 4 },
        .block_height = .{ .height = 123 },
        .timestamp = .{ .millis = 456 },
        .chain_id = 7,
    };
    try expectMatchesFixture(types.TxContext, value, corpus.borsh.model.tx_context);
}

test "fixture: Calldata" {
    const blobs = &[_]types.IndexedBlobEntry{
        .{
            .index = .{ .index = 0 },
            .blob = .{
                .contract_name = .{ .value = "counter" },
                .data = .{ .bytes = &[_]u8{ 0x10, 0x11 } },
            },
        },
    };
    const tx_ctx: types.TxContext = .{
        .lane_id = .{
            .operator = .{ .bytes = &[_]u8{} },
            .suffix = "default",
        },
        .block_hash = .{ .bytes = &[_]u8{0x55} ** 4 },
        .block_height = .{ .height = 123 },
        .timestamp = .{ .millis = 456 },
        .chain_id = 7,
    };
    const value: types.Calldata = .{
        .tx_hash = .{ .bytes = &[_]u8{0x77} ** 4 },
        .identity = .{ .value = "alice@counter" },
        .blobs = .{ .blobs = blobs },
        .tx_blob_count = 1,
        .index = .{ .index = 0 },
        .tx_ctx = tx_ctx,
        .private_input = &[_]u8{ 0xfe, 0xed },
    };
    try expectMatchesFixture(types.Calldata, value, corpus.borsh.model.calldata);
}

test "fixture: RegisterContractEffect" {
    const value: types.RegisterContractEffect = .{
        .verifier = .{ .value = "risc0" },
        .program_id = .{ .bytes = &[_]u8{0xaa} ** 8 },
        .state_commitment = .{ .bytes = &[_]u8{0xbb} ** 8 },
        .contract_name = .{ .value = "counter" },
        .timeout_window = .{ .timeout = .{
            .hard_timeout = .{ .height = 50 },
            .soft_timeout = .{ .height = 100 },
        } },
    };
    try expectMatchesFixture(
        types.RegisterContractEffect,
        value,
        corpus.borsh.model.register_contract_effect,
    );
}

fn sampleRegisterContractEffect() types.RegisterContractEffect {
    return .{
        .verifier = .{ .value = "risc0" },
        .program_id = .{ .bytes = &[_]u8{0xaa} ** 8 },
        .state_commitment = .{ .bytes = &[_]u8{0xbb} ** 8 },
        .contract_name = .{ .value = "counter" },
        .timeout_window = .{ .timeout = .{
            .hard_timeout = .{ .height = 50 },
            .soft_timeout = .{ .height = 100 },
        } },
    };
}

test "fixture: OnchainEffect::RegisterContractWithConstructor" {
    const value: types.OnchainEffect = .{
        .register_contract_with_constructor = sampleRegisterContractEffect(),
    };
    try expectMatchesFixture(
        types.OnchainEffect,
        value,
        corpus.borsh.model.onchain_effect_register_with_ctor,
    );
}

test "fixture: OnchainEffect::RegisterContract" {
    const value: types.OnchainEffect = .{
        .register_contract = sampleRegisterContractEffect(),
    };
    try expectMatchesFixture(
        types.OnchainEffect,
        value,
        corpus.borsh.model.onchain_effect_register,
    );
}

test "fixture: OnchainEffect::DeleteContract" {
    const value: types.OnchainEffect = .{
        .delete_contract = .{ .value = "counter" },
    };
    try expectMatchesFixture(
        types.OnchainEffect,
        value,
        corpus.borsh.model.onchain_effect_delete,
    );
}

test "fixture: OnchainEffect::UpdateContractProgramId" {
    const value: types.OnchainEffect = .{
        .update_contract_program_id = .{
            .contract_name = .{ .value = "counter" },
            .program_id = .{ .bytes = &[_]u8{0xcc} ** 4 },
        },
    };
    try expectMatchesFixture(
        types.OnchainEffect,
        value,
        corpus.borsh.model.onchain_effect_update_program_id,
    );
}

test "fixture: OnchainEffect::UpdateTimeoutWindow(NoTimeout)" {
    const value: types.OnchainEffect = .{
        .update_timeout_window = .{
            .contract_name = .{ .value = "counter" },
            .timeout_window = .no_timeout,
        },
    };
    try expectMatchesFixture(
        types.OnchainEffect,
        value,
        corpus.borsh.model.onchain_effect_update_timeout_no,
    );
}

test "fixture: OnchainEffect::UpdateTimeoutWindow(Timeout{100,200})" {
    const value: types.OnchainEffect = .{
        .update_timeout_window = .{
            .contract_name = .{ .value = "counter" },
            .timeout_window = .{ .timeout = .{
                .hard_timeout = .{ .height = 100 },
                .soft_timeout = .{ .height = 200 },
            } },
        },
    };
    try expectMatchesFixture(
        types.OnchainEffect,
        value,
        corpus.borsh.model.onchain_effect_update_timeout_yes,
    );
}

test "fixture: HyliOutput" {
    const blobs = &[_]types.IndexedBlobEntry{
        .{
            .index = .{ .index = 0 },
            .blob = .{
                .contract_name = .{ .value = "counter" },
                .data = .{ .bytes = &[_]u8{ 0x10, 0x11 } },
            },
        },
    };
    const tx_ctx: types.TxContext = .{
        .lane_id = .{
            .operator = .{ .bytes = &[_]u8{} },
            .suffix = "default",
        },
        .block_hash = .{ .bytes = &[_]u8{0x55} ** 4 },
        .block_height = .{ .height = 123 },
        .timestamp = .{ .millis = 456 },
        .chain_id = 7,
    };
    const value: types.HyliOutput = .{
        .version = 1,
        .initial_state = .{ .bytes = &[_]u8{ 0x10, 0x11, 0x12, 0x13 } },
        .next_state = .{ .bytes = &[_]u8{ 0x20, 0x21, 0x22, 0x23 } },
        .identity = .{ .value = "alice@counter" },
        .index = .{ .index = 0 },
        .blobs = .{ .blobs = blobs },
        .tx_blob_count = 1,
        .tx_hash = .{ .bytes = &[_]u8{0x77} ** 4 },
        .success = true,
        .state_reads = &[_]types.StateRead{
            .{
                .contract_name = .{ .value = "counter" },
                .state_commitment = .{ .bytes = &[_]u8{ 0x10, 0x11, 0x12, 0x13 } },
            },
        },
        .tx_ctx = tx_ctx,
        .onchain_effects = &[_]types.OnchainEffect{
            .{ .register_contract = sampleRegisterContractEffect() },
        },
        .program_outputs = &[_]u8{ 0xab, 0xcd },
    };
    try expectMatchesFixture(types.HyliOutput, value, corpus.borsh.model.hyli_output);
}

// ---------------------------------------------------------------------------
// Wire layer types — Canal, NodeConnectionData, and the signed envelope.
// The handshake / P2PTcpMessage envelopes themselves are validated in
// `src/wire/handshake.zig`, so this section only covers the model
// dependencies they pull in.
// ---------------------------------------------------------------------------

fn sampleNodeConnectionData() types.NodeConnectionData {
    return .{
        .version = 1,
        .name = "validator-a",
        .current_height = 42,
        .p2p_public_address = "127.0.0.1:4242",
        .da_public_address = "127.0.0.1:4243",
        .start_timestamp = .{ .millis = 1_700_000_000_000 },
    };
}

fn sampleSignedNodeConnectionData() types.Signed(types.NodeConnectionData, types.ValidatorSignature) {
    return .{
        .msg = sampleNodeConnectionData(),
        .signature = .{
            .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
            .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
        },
    };
}

test "fixture: Canal(\"p2p\")" {
    try expectMatchesFixture(
        types.Canal,
        .{ .name = "p2p" },
        corpus.borsh.model.canal_p2p,
    );
}

test "fixture: NodeConnectionData" {
    try expectMatchesFixture(
        types.NodeConnectionData,
        sampleNodeConnectionData(),
        corpus.borsh.model.node_connection_data,
    );
}

test "fixture: SignedByValidator<NodeConnectionData>" {
    const SignedT = types.Signed(types.NodeConnectionData, types.ValidatorSignature);
    try expectMatchesFixture(
        SignedT,
        sampleSignedNodeConnectionData(),
        corpus.borsh.model.signed_node_connection_data,
    );
}

// ---------------------------------------------------------------------------
// Consensus markers — single-byte enum tags. The upstream
// `marker_serialization_bytes_are_unique_and_expected` test asserts these
// exact bytes, so we mirror that contract on the Zig side.
// ---------------------------------------------------------------------------

test "fixture: PrepareVoteMarker (byte 0)" {
    try expectMatchesFixture(
        types.ConsensusMarker,
        .prepare_vote,
        corpus.borsh.consensus.marker_prepare_vote,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0},
        corpus.borsh.consensus.marker_prepare_vote,
    );
}

test "fixture: ConfirmAckMarker (byte 1)" {
    try expectMatchesFixture(
        types.ConsensusMarker,
        .confirm_ack,
        corpus.borsh.consensus.marker_confirm_ack,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{1},
        corpus.borsh.consensus.marker_confirm_ack,
    );
}

test "fixture: ConsensusTimeoutMarker (byte 2)" {
    try expectMatchesFixture(
        types.ConsensusMarker,
        .consensus_timeout,
        corpus.borsh.consensus.marker_consensus_timeout,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{2},
        corpus.borsh.consensus.marker_consensus_timeout,
    );
}

test "fixture: NilConsensusTimeoutMarker (byte 3)" {
    try expectMatchesFixture(
        types.ConsensusMarker,
        .nil_consensus_timeout,
        corpus.borsh.consensus.marker_nil_consensus_timeout,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{3},
        corpus.borsh.consensus.marker_nil_consensus_timeout,
    );
}

// ---------------------------------------------------------------------------
// Quorum certificates — `(AggregateSignature, marker_byte)`. The four QC
// types differ only in the trailing marker byte.
// ---------------------------------------------------------------------------

fn sampleAggregateSignature() types.AggregateSignature {
    return .{
        .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
        .validators = &[_]types.ValidatorPublicKey{
            .{ .bytes = &[_]u8{0x01} ** 4 },
            .{ .bytes = &[_]u8{0x02} ** 4 },
        },
    };
}

test "fixture: PrepareQC = (AggregateSignature, PrepareVoteMarker)" {
    const value: types.PrepareQC = .{
        .aggregate = sampleAggregateSignature(),
        .marker = .prepare_vote,
    };
    try expectMatchesFixture(types.PrepareQC, value, corpus.borsh.consensus.prepare_qc);
}

test "fixture: CommitQC = (AggregateSignature, ConfirmAckMarker)" {
    const value: types.CommitQC = .{
        .aggregate = sampleAggregateSignature(),
        .marker = .confirm_ack,
    };
    try expectMatchesFixture(types.CommitQC, value, corpus.borsh.consensus.commit_qc);
}

test "fixture: TimeoutQC = (AggregateSignature, ConsensusTimeoutMarker)" {
    const value: types.TimeoutQC = .{
        .aggregate = sampleAggregateSignature(),
        .marker = .consensus_timeout,
    };
    try expectMatchesFixture(types.TimeoutQC, value, corpus.borsh.consensus.timeout_qc);
}

test "fixture: NilQC = (AggregateSignature, NilConsensusTimeoutMarker)" {
    const value: types.NilQC = .{
        .aggregate = sampleAggregateSignature(),
        .marker = .nil_consensus_timeout,
    };
    try expectMatchesFixture(types.NilQC, value, corpus.borsh.consensus.nil_qc);
}

test "Prepare/Commit QC bytes differ only in the trailing marker byte" {
    const prepare = corpus.borsh.consensus.prepare_qc;
    const commit = corpus.borsh.consensus.commit_qc;
    try testing.expectEqual(prepare.len, commit.len);
    try testing.expectEqualSlices(u8, prepare[0 .. prepare.len - 1], commit[0 .. commit.len - 1]);
    try testing.expect(prepare[prepare.len - 1] != commit[commit.len - 1]);
}

// ---------------------------------------------------------------------------
// PrepareVote / ConfirmAck — signed envelopes around a (cph, marker) tuple.
// ---------------------------------------------------------------------------

fn sampleValidatorSignature() types.ValidatorSignature {
    return .{
        .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
        .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
    };
}

test "fixture: PrepareVote = SignedByValidator<(cph, PrepareVoteMarker)>" {
    const value: types.PrepareVote = .{
        .msg = .{
            .consensus_proposal_hash = .{ .bytes = "cp-1" },
            .marker = .prepare_vote,
        },
        .signature = sampleValidatorSignature(),
    };
    try expectMatchesFixture(types.PrepareVote, value, corpus.borsh.consensus.prepare_vote);
}

test "fixture: ConfirmAck = SignedByValidator<(cph, ConfirmAckMarker)>" {
    const value: types.ConfirmAck = .{
        .msg = .{
            .consensus_proposal_hash = .{ .bytes = "cp-1" },
            .marker = .confirm_ack,
        },
        .signature = sampleValidatorSignature(),
    };
    try expectMatchesFixture(types.ConfirmAck, value, corpus.borsh.consensus.confirm_ack);
}

// ---------------------------------------------------------------------------
// Ticket
// ---------------------------------------------------------------------------

test "fixture: Ticket::Genesis" {
    try expectMatchesFixture(
        types.Ticket,
        .genesis,
        corpus.borsh.consensus.ticket_genesis,
    );
}

test "fixture: Ticket::CommitQC(commit_qc)" {
    const value: types.Ticket = .{
        .commit_qc = .{
            .aggregate = sampleAggregateSignature(),
            .marker = .confirm_ack,
        },
    };
    try expectMatchesFixture(
        types.Ticket,
        value,
        corpus.borsh.consensus.ticket_commit_qc,
    );
}

// ---------------------------------------------------------------------------
// ConsensusNetMessage variants. Each one is a separate test so a regression
// in any single variant points to exactly the tag/payload that drifted.
// ---------------------------------------------------------------------------

fn sampleConsensusProposalFull() types.ConsensusProposal {
    const lane: types.LaneId = .{
        .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
        .suffix = "lane-a",
    };
    return .{
        .slot = 7,
        .parent_hash = .{ .bytes = "prev-cp" },
        .cut = &[_]types.CutEntry{
            .{
                .lane_id = lane,
                .dp_hash = .{ .bytes = "dp-hash" },
                .lane_bytes_size = .{ .bytes = 8192 },
                .aggregate_signature = .{
                    .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
                    .validators = &[_]types.ValidatorPublicKey{
                        .{ .bytes = &[_]u8{0x01} ** 4 },
                    },
                },
            },
        },
        .staking_actions = &[_]types.ConsensusStakingAction{
            .{ .pay_fees_for_dadi = .{
                .lane_id = lane,
                .cumul_size = .{ .bytes = 8192 },
            } },
        },
        .timestamp = .{ .millis = 9999 },
    };
}

fn sampleConsensusProposalEmpty() types.ConsensusProposal {
    return .{
        .slot = 1,
        .parent_hash = .{ .bytes = "genesis" },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = 1234 },
    };
}

test "fixture: ConsensusNetMessage::Prepare" {
    // The Prepare fixture now carries a CommitQC ticket so it stays
    // structurally valid for slot=7 (Genesis would only be legal at
    // slot=1).
    const value: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = sampleConsensusProposalFull(),
            .ticket = .{ .commit_qc = .{
                .aggregate = sampleAggregateSignature(),
                .marker = .confirm_ack,
            } },
            .view = 7,
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_prepare,
    );
}

test "fixture: ConsensusNetMessage::PrepareVote" {
    const value: types.ConsensusNetMessage = .{
        .prepare_vote = .{
            .msg = .{
                .consensus_proposal_hash = .{ .bytes = "cp-1" },
                .marker = .prepare_vote,
            },
            .signature = sampleValidatorSignature(),
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_prepare_vote,
    );
}

test "fixture: ConsensusNetMessage::Confirm" {
    const value: types.ConsensusNetMessage = .{
        .confirm = .{
            .prepare_qc = .{
                .aggregate = sampleAggregateSignature(),
                .marker = .prepare_vote,
            },
            .consensus_proposal_hash = .{ .bytes = "cp-1" },
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_confirm,
    );
}

test "fixture: ConsensusNetMessage::ConfirmAck" {
    const value: types.ConsensusNetMessage = .{
        .confirm_ack = .{
            .msg = .{
                .consensus_proposal_hash = .{ .bytes = "cp-1" },
                .marker = .confirm_ack,
            },
            .signature = sampleValidatorSignature(),
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_confirm_ack,
    );
}

test "fixture: ConsensusNetMessage::Commit" {
    const value: types.ConsensusNetMessage = .{
        .commit = .{
            .commit_qc = .{
                .aggregate = sampleAggregateSignature(),
                .marker = .confirm_ack,
            },
            .consensus_proposal_hash = .{ .bytes = "cp-1" },
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_commit,
    );
}

test "fixture: ConsensusNetMessage::ValidatorCandidacy" {
    const value: types.ConsensusNetMessage = .{
        .validator_candidacy = .{
            .msg = .{ .peer_address = "127.0.0.1:4242" },
            .signature = sampleValidatorSignature(),
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_validator_candidacy,
    );
}

test "fixture: ConsensusNetMessage::SyncRequest" {
    const value: types.ConsensusNetMessage = .{
        .sync_request = .{ .bytes = "cp-1" },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_sync_request,
    );
}

// ---------------------------------------------------------------------------
// Timeout / TimeoutCertificate
// ---------------------------------------------------------------------------

fn sampleTimeoutOuterPayload() types.TimeoutSignedPayload {
    return .{
        .slot = 7,
        .view = 2,
        .consensus_proposal_hash = .{ .bytes = "cp-1" },
        .marker = .consensus_timeout,
    };
}

fn sampleNilProposalSignedPayload() types.TimeoutSignedPayload {
    return .{
        .slot = 7,
        .view = 2,
        .consensus_proposal_hash = .{ .bytes = "cp-1" },
        .marker = .nil_consensus_timeout,
    };
}

test "fixture: TimeoutKind::NilProposal" {
    const value: types.TimeoutKind = .{
        .nil_proposal = .{
            .msg = sampleNilProposalSignedPayload(),
            .signature = sampleValidatorSignature(),
        },
    };
    try expectMatchesFixture(
        types.TimeoutKind,
        value,
        corpus.borsh.consensus.timeout_kind_nil_proposal,
    );
}

test "fixture: TimeoutKind::PrepareQC" {
    const value: types.TimeoutKind = .{
        .prepare_qc = .{
            .quorum_certificate = .{
                .aggregate = sampleAggregateSignature(),
                .marker = .prepare_vote,
            },
            .proposal = sampleConsensusProposalFull(),
        },
    };
    try expectMatchesFixture(
        types.TimeoutKind,
        value,
        corpus.borsh.consensus.timeout_kind_prepare_qc,
    );
}

test "fixture: ConsensusTimeout = (signed_outer, NilProposal)" {
    const value: types.ConsensusTimeout = .{
        .outer = .{
            .msg = sampleTimeoutOuterPayload(),
            .signature = sampleValidatorSignature(),
        },
        .kind = .{
            .nil_proposal = .{
                .msg = sampleNilProposalSignedPayload(),
                .signature = sampleValidatorSignature(),
            },
        },
    };
    try expectMatchesFixture(
        types.ConsensusTimeout,
        value,
        corpus.borsh.consensus.consensus_timeout,
    );
}

test "fixture: ConsensusNetMessage::Timeout" {
    const value: types.ConsensusNetMessage = .{
        .timeout = .{
            .outer = .{
                .msg = sampleTimeoutOuterPayload(),
                .signature = sampleValidatorSignature(),
            },
            .kind = .{
                .nil_proposal = .{
                    .msg = sampleNilProposalSignedPayload(),
                    .signature = sampleValidatorSignature(),
                },
            },
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_timeout,
    );
}

test "fixture: TCKind::NilProposal(NilQC)" {
    const value: types.TcKind = .{
        .nil_proposal = .{
            .aggregate = sampleAggregateSignature(),
            .marker = .nil_consensus_timeout,
        },
    };
    try expectMatchesFixture(
        types.TcKind,
        value,
        corpus.borsh.consensus.tc_kind_nil_proposal,
    );
}

test "fixture: TCKind::PrepareQC((PrepareQC, ConsensusProposal))" {
    const value: types.TcKind = .{
        .prepare_qc = .{
            .quorum_certificate = .{
                .aggregate = sampleAggregateSignature(),
                .marker = .prepare_vote,
            },
            .proposal = sampleConsensusProposalFull(),
        },
    };
    try expectMatchesFixture(
        types.TcKind,
        value,
        corpus.borsh.consensus.tc_kind_prepare_qc,
    );
}

test "fixture: ConsensusNetMessage::TimeoutCertificate" {
    const value: types.ConsensusNetMessage = .{
        .timeout_certificate = .{
            .timeout_qc = .{
                .aggregate = sampleAggregateSignature(),
                .marker = .consensus_timeout,
            },
            .tc_kind = .{
                .nil_proposal = .{
                    .aggregate = sampleAggregateSignature(),
                    .marker = .nil_consensus_timeout,
                },
            },
            .slot = 7,
            .view = 2,
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_timeout_certificate,
    );
}

// ---------------------------------------------------------------------------
// Mempool messages
// ---------------------------------------------------------------------------

fn sampleValidatorDag() types.ValidatorDag {
    return .{
        .msg = .{
            .data_proposal_hash = .{ .bytes = "dp-1" },
            .lane_bytes_size = .{ .bytes = 1024 },
        },
        .signature = sampleValidatorSignature(),
    };
}

fn sampleLaneA() types.LaneId {
    return .{
        .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
        .suffix = "lane-a",
    };
}

fn sampleEmptyDataProposal() types.DataProposal {
    return .{
        .parent_data_proposal_hash = .{ .dp = .{ .bytes = "parent" } },
        .txs = &[_]types.Transaction{},
    };
}

test "fixture: DataProposal (empty txs)" {
    // Cross-check the new Zig DataProposal struct against the existing
    // borsh fixture generated via DataProposal::new("parent", []).
    const value: types.DataProposal = .{
        .parent_data_proposal_hash = .{ .dp = .{ .bytes = "parent" } },
        .txs = &[_]types.Transaction{},
    };
    try expectMatchesFixture(types.DataProposal, value, corpus.borsh.model.data_proposal_empty);
}

test "fixture: ValidatorDAG = SignedByValidator<(dp_hash, lane_size)>" {
    try expectMatchesFixture(
        types.ValidatorDag,
        sampleValidatorDag(),
        corpus.borsh.mempool.validator_dag,
    );
}

test "fixture: MempoolNetMessage::DataProposal" {
    const value: types.MempoolNetMessage = .{
        .data_proposal = .{
            .lane_id = sampleLaneA(),
            .data_proposal_hash = .{ .bytes = "dp-1" },
            .data_proposal = sampleEmptyDataProposal(),
            .validator_dag = sampleValidatorDag(),
        },
    };
    try expectMatchesFixture(
        types.MempoolNetMessage,
        value,
        corpus.borsh.mempool.net_message_data_proposal,
    );
}

test "fixture: MempoolNetMessage::DataVote" {
    const value: types.MempoolNetMessage = .{
        .data_vote = .{
            .lane_id = sampleLaneA(),
            .validator_dag = sampleValidatorDag(),
        },
    };
    try expectMatchesFixture(
        types.MempoolNetMessage,
        value,
        corpus.borsh.mempool.net_message_data_vote,
    );
}

test "fixture: MempoolNetMessage::SyncRequest (Some, Some)" {
    const value: types.MempoolNetMessage = .{
        .sync_request = .{
            .lane_id = sampleLaneA(),
            .from = .{ .bytes = "from" },
            .to = .{ .bytes = "to" },
        },
    };
    try expectMatchesFixture(
        types.MempoolNetMessage,
        value,
        corpus.borsh.mempool.net_message_sync_request,
    );
}

test "fixture: MempoolNetMessage::SyncRequest (None, None)" {
    const value: types.MempoolNetMessage = .{
        .sync_request = .{
            .lane_id = sampleLaneA(),
            .from = null,
            .to = null,
        },
    };
    try expectMatchesFixture(
        types.MempoolNetMessage,
        value,
        corpus.borsh.mempool.net_message_sync_request_none,
    );
}

test "fixture: BlobProofOutput (full struct)" {
    const blobs = &[_]types.IndexedBlobEntry{
        .{
            .index = .{ .index = 0 },
            .blob = .{
                .contract_name = .{ .value = "counter" },
                .data = .{ .bytes = &[_]u8{ 0x10, 0x11 } },
            },
        },
    };
    const tx_ctx: types.TxContext = .{
        .lane_id = .{
            .operator = .{ .bytes = &[_]u8{} },
            .suffix = "default",
        },
        .block_hash = .{ .bytes = &[_]u8{0x55} ** 4 },
        .block_height = .{ .height = 123 },
        .timestamp = .{ .millis = 456 },
        .chain_id = 7,
    };
    const hyli_out: types.HyliOutput = .{
        .version = 1,
        .initial_state = .{ .bytes = &[_]u8{ 0x10, 0x11, 0x12, 0x13 } },
        .next_state = .{ .bytes = &[_]u8{ 0x20, 0x21, 0x22, 0x23 } },
        .identity = .{ .value = "alice@counter" },
        .index = .{ .index = 0 },
        .blobs = .{ .blobs = blobs },
        .tx_blob_count = 1,
        .tx_hash = .{ .bytes = &[_]u8{0x77} ** 4 },
        .success = true,
        .state_reads = &[_]types.StateRead{
            .{
                .contract_name = .{ .value = "counter" },
                .state_commitment = .{ .bytes = &[_]u8{ 0x10, 0x11, 0x12, 0x13 } },
            },
        },
        .tx_ctx = tx_ctx,
        .onchain_effects = &[_]types.OnchainEffect{
            .{ .register_contract = sampleRegisterContractEffect() },
        },
        .program_outputs = &[_]u8{ 0xab, 0xcd },
    };
    var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
    hasher.update(&[_]u8{0x42} ** 16);
    var proof_hash: [32]u8 = undefined;
    hasher.final(&proof_hash);
    const value: types.BlobProofOutput = .{
        .blob_tx_hash = .{ .bytes = &[_]u8{0x77} ** 4 },
        .original_proof_hash = .{ .bytes = &proof_hash },
        .hyli_output = hyli_out,
        .program_id = .{ .bytes = &[_]u8{0xaa} ** 8 },
        .verifier = .{ .value = "risc0" },
    };
    try expectMatchesFixture(
        types.BlobProofOutput,
        value,
        corpus.borsh.model.blob_proof_output_sample,
    );
}

test "fixture: SignedBlock (one lane, one empty DataProposal, cp_full)" {
    const dps = &[_]types.DataProposal{sampleEmptyDataProposal()};
    const lane_dps = &[_]types.LaneDataProposals{
        .{
            .lane_id = sampleLaneA(),
            .data_proposals = dps,
        },
    };
    const value: types.SignedBlock = .{
        .data_proposals = lane_dps,
        .consensus_proposal = sampleConsensusProposalFull(),
        .certificate = sampleAggregateSignature(),
    };
    try expectMatchesFixture(types.SignedBlock, value, corpus.borsh.model.signed_block_sample);
}

// ---------------------------------------------------------------------------
// TransactionMetadata / TransactionKind / TxId
// ---------------------------------------------------------------------------

test "fixture: TxId(\"dp-1\", \"tx-1\")" {
    const value: types.TxId = .{
        .data_proposal_hash = .{ .bytes = "dp-1" },
        .tx_hash = .{ .bytes = "tx-1" },
    };
    try expectMatchesFixture(types.TxId, value, corpus.borsh.model.tx_id_sample);
}

test "fixture: TransactionKind::Blob" {
    try expectMatchesFixture(
        types.TransactionKind,
        .blob,
        corpus.borsh.model.transaction_kind_blob,
    );
    try testing.expectEqualSlices(u8, &[_]u8{0}, corpus.borsh.model.transaction_kind_blob);
}

test "fixture: TransactionKind::Proof" {
    try expectMatchesFixture(
        types.TransactionKind,
        .proof,
        corpus.borsh.model.transaction_kind_proof,
    );
    try testing.expectEqualSlices(u8, &[_]u8{1}, corpus.borsh.model.transaction_kind_proof);
}

test "fixture: TransactionKind::VerifiedProof" {
    try expectMatchesFixture(
        types.TransactionKind,
        .verified_proof,
        corpus.borsh.model.transaction_kind_verified_proof,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{2},
        corpus.borsh.model.transaction_kind_verified_proof,
    );
}

test "fixture: TransactionMetadata(version=1, Blob, (dp-1, tx-1))" {
    const value: types.TransactionMetadata = .{
        .version = 1,
        .transaction_kind = .blob,
        .id = .{
            .data_proposal_hash = .{ .bytes = "dp-1" },
            .tx_hash = .{ .bytes = "tx-1" },
        },
    };
    try expectMatchesFixture(
        types.TransactionMetadata,
        value,
        corpus.borsh.model.transaction_metadata_blob,
    );
}

// ---------------------------------------------------------------------------
// MempoolStatusEvent
// ---------------------------------------------------------------------------

test "fixture: MempoolStatusEvent::WaitingDissemination" {
    const value: types.MempoolStatusEvent = .{
        .waiting_dissemination = .{
            .parent_data_proposal_hash = .{ .bytes = "parent" },
            .txs = &[_]types.Transaction{},
        },
    };
    try expectMatchesFixture(
        types.MempoolStatusEvent,
        value,
        corpus.borsh.model.mempool_status_event_waiting,
    );
}

test "fixture: MempoolStatusEvent::DataProposalCreated" {
    const value: types.MempoolStatusEvent = .{
        .data_proposal_created = .{
            .parent_data_proposal_hash = .{ .bytes = "parent" },
            .data_proposal_hash = .{ .bytes = "dp-1" },
            .txs_metadatas = &[_]types.TransactionMetadata{
                .{
                    .version = 1,
                    .transaction_kind = .blob,
                    .id = .{
                        .data_proposal_hash = .{ .bytes = "dp-1" },
                        .tx_hash = .{ .bytes = "tx-1" },
                    },
                },
            },
        },
    };
    try expectMatchesFixture(
        types.MempoolStatusEvent,
        value,
        corpus.borsh.model.mempool_status_event_created,
    );
}

// ---------------------------------------------------------------------------
// DataAvailabilityRequest / DataAvailabilityEvent
// ---------------------------------------------------------------------------

test "fixture: DataAvailabilityRequest::StreamFromHeight(42)" {
    const value: types.DataAvailabilityRequest = .{
        .stream_from_height = .{ .height = 42 },
    };
    try expectMatchesFixture(
        types.DataAvailabilityRequest,
        value,
        corpus.borsh.model.da_request_stream,
    );
}

test "fixture: DataAvailabilityRequest::BlockRequest(42)" {
    const value: types.DataAvailabilityRequest = .{
        .block_request = .{ .height = 42 },
    };
    try expectMatchesFixture(
        types.DataAvailabilityRequest,
        value,
        corpus.borsh.model.da_request_block,
    );
}

test "fixture: DataAvailabilityEvent::SignedBlock(...)" {
    const dps = &[_]types.DataProposal{sampleEmptyDataProposal()};
    const lane_dps = &[_]types.LaneDataProposals{
        .{
            .lane_id = sampleLaneA(),
            .data_proposals = dps,
        },
    };
    const sb: types.SignedBlock = .{
        .data_proposals = lane_dps,
        .consensus_proposal = sampleConsensusProposalFull(),
        .certificate = sampleAggregateSignature(),
    };
    const value: types.DataAvailabilityEvent = .{
        .signed_block = sb,
    };
    try expectMatchesFixture(
        types.DataAvailabilityEvent,
        value,
        corpus.borsh.model.da_event_signed_block,
    );
}

test "fixture: DataAvailabilityEvent::MempoolStatusEvent(...)" {
    const value: types.DataAvailabilityEvent = .{
        .mempool_status_event = .{
            .data_proposal_created = .{
                .parent_data_proposal_hash = .{ .bytes = "parent" },
                .data_proposal_hash = .{ .bytes = "dp-1" },
                .txs_metadatas = &[_]types.TransactionMetadata{
                    .{
                        .version = 1,
                        .transaction_kind = .blob,
                        .id = .{
                            .data_proposal_hash = .{ .bytes = "dp-1" },
                            .tx_hash = .{ .bytes = "tx-1" },
                        },
                    },
                },
            },
        },
    };
    try expectMatchesFixture(
        types.DataAvailabilityEvent,
        value,
        corpus.borsh.model.da_event_status,
    );
}

test "fixture: DataAvailabilityEvent::BlockNotFound(99)" {
    const value: types.DataAvailabilityEvent = .{
        .block_not_found = .{ .height = 99 },
    };
    try expectMatchesFixture(
        types.DataAvailabilityEvent,
        value,
        corpus.borsh.model.da_event_not_found,
    );
}

// ---------------------------------------------------------------------------
// StakingAction
// ---------------------------------------------------------------------------

test "fixture: StakingAction::Stake { amount = 100 }" {
    const value: types.StakingAction = .{ .stake = 100 };
    try expectMatchesFixture(
        types.StakingAction,
        value,
        corpus.borsh.model.staking_action_stake,
    );
}

test "fixture: StakingAction::Delegate { validator = [0x01;4] }" {
    const value: types.StakingAction = .{
        .delegate = .{ .bytes = &[_]u8{0x01} ** 4 },
    };
    try expectMatchesFixture(
        types.StakingAction,
        value,
        corpus.borsh.model.staking_action_delegate,
    );
}

test "fixture: StakingAction::DepositForFees" {
    const value: types.StakingAction = .{
        .deposit_for_fees = .{
            .holder = .{ .bytes = &[_]u8{0x02} ** 4 },
            .amount = 50,
        },
    };
    try expectMatchesFixture(
        types.StakingAction,
        value,
        corpus.borsh.model.staking_action_deposit_for_fees,
    );
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

test "fixture: Contract sample" {
    const value: types.Contract = .{
        .name = .{ .value = "counter" },
        .program_id = .{ .bytes = &[_]u8{0xaa} ** 8 },
        .state = .{ .bytes = &[_]u8{0xbb} ** 8 },
        .verifier = .{ .value = "risc0" },
        .timeout_window = .{ .timeout = .{
            .hard_timeout = .{ .height = 50 },
            .soft_timeout = .{ .height = 100 },
        } },
    };
    try expectMatchesFixture(types.Contract, value, corpus.borsh.model.contract_sample);
}

// ---------------------------------------------------------------------------
// TransactionStateEvent — the per-transaction lifecycle the indexer
// renders. Each variant gets its own pin.
// ---------------------------------------------------------------------------

test "fixture: TransactionStateEvent::Sequenced" {
    const value: types.TransactionStateEvent = .sequenced;
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_sequenced,
    );
}

test "fixture: TransactionStateEvent::Settled" {
    const value: types.TransactionStateEvent = .settled;
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_settled,
    );
}

test "fixture: TransactionStateEvent::SettledAsFailed" {
    const value: types.TransactionStateEvent = .settled_as_failed;
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_settled_as_failed,
    );
}

test "fixture: TransactionStateEvent::TimedOut" {
    const value: types.TransactionStateEvent = .timed_out;
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_timed_out,
    );
}

test "fixture: TransactionStateEvent::DroppedAsDuplicate" {
    const value: types.TransactionStateEvent = .dropped_as_duplicate;
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_dropped,
    );
}

test "fixture: TransactionStateEvent::Error(\"validation failed\")" {
    const value: types.TransactionStateEvent = .{ .@"error" = "validation failed" };
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_error,
    );
}

test "fixture: TransactionStateEvent::NewProof" {
    const value: types.TransactionStateEvent = .{
        .new_proof = .{
            .blob_index = .{ .index = 0 },
            .proof_tx_hash = .{ .bytes = &[_]u8{0x77} ** 4 },
            .program_output = &[_]u8{ 0xab, 0xcd },
        },
    };
    try expectMatchesFixture(
        types.TransactionStateEvent,
        value,
        corpus.borsh.model.transaction_state_event_new_proof,
    );
}

test "fixture: MempoolNetMessage::SyncReply" {
    const dags = &[_]types.ValidatorDag{sampleValidatorDag()};
    const value: types.MempoolNetMessage = .{
        .sync_reply = .{
            .lane_id = sampleLaneA(),
            .metadata = dags,
            .data_proposal = sampleEmptyDataProposal(),
        },
    };
    try expectMatchesFixture(
        types.MempoolNetMessage,
        value,
        corpus.borsh.mempool.net_message_sync_reply,
    );
}

test "fixture: ConsensusNetMessage::SyncReply" {
    const value: types.ConsensusNetMessage = .{
        .sync_reply = .{
            .sender = .{ .bytes = &[_]u8{0x03} ** 4 },
            .proposal = sampleConsensusProposalEmpty(),
            .ticket = .genesis,
            .view = 12,
        },
    };
    try expectMatchesFixture(
        types.ConsensusNetMessage,
        value,
        corpus.borsh.consensus.net_message_sync_reply,
    );
}

test "fixture: ConsensusProposal (one cut entry, one PayFeesForDaDi)" {
    const lane: types.LaneId = .{
        .operator = .{ .bytes = &[_]u8{0x01} ** 4 },
        .suffix = "lane-a",
    };
    const value: types.ConsensusProposal = .{
        .slot = 7,
        .parent_hash = .{ .bytes = "prev-cp" },
        .cut = &[_]types.CutEntry{
            .{
                .lane_id = lane,
                .dp_hash = .{ .bytes = "dp-hash" },
                .lane_bytes_size = .{ .bytes = 8192 },
                .aggregate_signature = .{
                    .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
                    .validators = &[_]types.ValidatorPublicKey{
                        .{ .bytes = &[_]u8{0x01} ** 4 },
                    },
                },
            },
        },
        .staking_actions = &[_]types.ConsensusStakingAction{
            .{ .pay_fees_for_dadi = .{
                .lane_id = lane,
                .cumul_size = .{ .bytes = 8192 },
            } },
        },
        .timestamp = .{ .millis = 9999 },
    };
    try expectMatchesFixture(
        types.ConsensusProposal,
        value,
        corpus.borsh.model.consensus_proposal_full,
    );
}
