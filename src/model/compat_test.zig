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
