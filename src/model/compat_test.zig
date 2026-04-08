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
