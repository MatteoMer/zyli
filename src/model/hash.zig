//! Hyli protocol hash functions.
//!
//! Hyli is unusual: most of its consensus-critical hashes are NOT
//! `sha3_256(borsh(self))`. They feed selected fields directly into the
//! hasher in a specific order, with no length prefixes and (sometimes)
//! `to_string()`-style projections of inner types. The Zig side has to
//! mirror that update sequence byte-for-byte, so this module is the single
//! source of truth for those custom constructions and is exercised against
//! the `corpus.hash.model.*` golden vectors.
//!
//! Conventions:
//! - Every hash function takes the value by `*const T` and returns a
//!   stack-allocated `Digest32` so callers do not need an allocator for
//!   the common case.
//! - Hash inputs that come from a Hyli `String` newtype are fed in raw
//!   (no length prefix) — Hyli relies on `String::as_bytes`.
//! - Numeric inputs are converted to little-endian bytes to match
//!   `u64::to_le_bytes` and friends on the Rust side.

const std = @import("std");
const types = @import("types.zig");

const Sha3_256 = std.crypto.hash.sha3.Sha3_256;

/// 32-byte digest, the output of every Hyli hash. Returned by value so
/// callers can stash it in a struct without an allocator.
pub const Digest32 = [32]u8;

/// Convenience wrapper around `Sha3_256` that mirrors the small subset of
/// the Rust API Hyli uses (`update`, `finalize` → `Digest32`). Hyli only
/// ever feeds raw byte slices into the hasher, so we expose the same.
pub const Hasher = struct {
    inner: Sha3_256,

    pub fn init() Hasher {
        return .{ .inner = Sha3_256.init(.{}) };
    }

    pub fn update(self: *Hasher, bytes: []const u8) void {
        self.inner.update(bytes);
    }

    /// Append the little-endian bytes of an integer. Used for hashing
    /// `BlockHeight(u64)` and `Slot(u64)` exactly the way Hyli does via
    /// `u64::to_le_bytes`.
    pub fn updateLeInt(self: *Hasher, comptime T: type, value: T) void {
        const info = @typeInfo(T).int;
        const byte_count = @divExact(info.bits, 8);
        var buf: [16]u8 = undefined;
        std.mem.writeInt(T, buf[0..byte_count], value, .little);
        self.inner.update(buf[0..byte_count]);
    }

    pub fn finalize(self: *Hasher) Digest32 {
        var out: Digest32 = undefined;
        self.inner.final(&out);
        return out;
    }
};

/// One-shot SHA3-256 of a single byte slice. Mirrors `sha3::Sha3_256::digest`.
pub fn sha3_256(bytes: []const u8) Digest32 {
    var h = Hasher.init();
    h.update(bytes);
    return h.finalize();
}

// ---------------------------------------------------------------------------
// Hyli protocol hashes
// ---------------------------------------------------------------------------

/// `hyli_model::Blob::hashed` from `crates/hyli-model/src/contract.rs`.
///
/// Update order (no length prefixes):
/// 1. `contract_name.as_bytes()`
/// 2. `data`
pub fn blobHashed(blob: *const types.Blob) Digest32 {
    var h = Hasher.init();
    h.update(blob.contract_name.value);
    h.update(blob.data.bytes);
    return h.finalize();
}

/// `hyli_model::RegisterContractAction::hashed` (contract.rs).
///
/// Update order:
/// 1. `verifier.as_bytes()`
/// 2. `program_id`
/// 3. `state_commitment`
/// 4. `contract_name.as_bytes()`
/// 5. timeout window: `0u8.to_le_bytes()` for `NoTimeout`, otherwise
///    `hard_timeout.0.to_le_bytes()` then `soft_timeout.0.to_le_bytes()`.
///    The whole step is skipped if `timeout_window == None`.
/// 6. `constructor_metadata` is intentionally NOT hashed.
pub const TimeoutWindow = union(enum) {
    no_timeout,
    timeout: struct {
        hard_timeout: u64,
        soft_timeout: u64,
    },
};

pub const RegisterContractActionInput = struct {
    verifier: types.Verifier,
    program_id: types.ProgramId,
    state_commitment: types.StateCommitment,
    contract_name: types.ContractName,
    timeout_window: ?TimeoutWindow,
    // constructor_metadata exists on the wire but is excluded from the hash.
};

pub fn registerContractActionHashed(input: *const RegisterContractActionInput) Digest32 {
    var h = Hasher.init();
    h.update(input.verifier.value);
    h.update(input.program_id.bytes);
    h.update(input.state_commitment.bytes);
    h.update(input.contract_name.value);
    if (input.timeout_window) |tw| {
        switch (tw) {
            .no_timeout => h.update(&[_]u8{0}),
            .timeout => |t| {
                h.updateLeInt(u64, t.hard_timeout);
                h.updateLeInt(u64, t.soft_timeout);
            },
        }
    }
    return h.finalize();
}

/// `hyli_model::ProofData::hashed` (`sha3_256(self.0)`).
pub fn proofDataHashed(proof: *const types.ProofData) Digest32 {
    return sha3_256(proof.bytes);
}

/// `hyli_model::BlobTransaction::hashed`.
///
/// Update order:
/// 1. `identity.as_bytes()` (no length prefix)
/// 2. for each blob: `blob.hashed()` (the SHA3-256 of contract_name‖data)
pub fn blobTransactionHashed(tx: *const types.BlobTransaction) Digest32 {
    var h = Hasher.init();
    h.update(tx.identity.value);
    for (tx.blobs) |*blob| {
        const blob_hash = blobHashed(blob);
        h.update(&blob_hash);
    }
    return h.finalize();
}

/// `hyli_model::ProofTransaction::hashed`.
///
/// Update order:
/// 1. `contract_name.as_bytes()`
/// 2. `program_id`
/// 3. `verifier.as_bytes()`
/// 4. `proof.hashed().0` — i.e. SHA3-256 of the raw proof bytes.
pub fn proofTransactionHashed(tx: *const types.ProofTransaction) Digest32 {
    var h = Hasher.init();
    h.update(tx.contract_name.value);
    h.update(tx.program_id.bytes);
    h.update(tx.verifier.value);
    const proof_hash = proofDataHashed(&tx.proof);
    h.update(&proof_hash);
    return h.finalize();
}

/// `hyli_model::VerifiedProofTransaction::hashed`.
///
/// Same field order as `ProofTransaction::hashed` but the proof digest
/// comes pre-computed on the struct (`proof_hash`) so we don't need the
/// raw proof bytes.
pub fn verifiedProofTransactionHashed(tx: *const types.VerifiedProofTransaction) Digest32 {
    var h = Hasher.init();
    h.update(tx.contract_name.value);
    h.update(tx.program_id.bytes);
    h.update(tx.verifier.value);
    h.update(tx.proof_hash.bytes);
    return h.finalize();
}

/// `hyli_model::DataProposal::hashed` from `crates/hyli-model/src/node/mempool.rs`.
///
/// Update order:
/// 1. parent: if `LaneRoot(lane_id)`, `lane_id.to_string().as_bytes()`
///    (i.e. `hex(operator)-suffix`); if `DP(hash)`, the raw hash bytes.
/// 2. for each transaction in order, the bytes of `tx.hashed()`.
///
/// `txHashes` is a pre-computed list of TX hashes so this function stays
/// pure: callers compute each `tx.hashed()` themselves and pass the
/// resulting digests in.
pub fn dataProposalHashed(
    parent: types.DataProposalParent,
    tx_hashes: []const Digest32,
) Digest32 {
    var h = Hasher.init();
    switch (parent) {
        .lane_root => |lane_id| {
            // The Rust impl uses `lane_id.to_string()` which formats as
            // `hex_lower(operator) ++ "-" ++ suffix`. Reproduce that here
            // without allocating: the operator is a BLS12-381 G1 compressed
            // pubkey (48 bytes), so 256 bytes of stack space covers any
            // realistic validator key with margin.
            var hex_buf: [512]u8 = undefined;
            const operator = lane_id.operator.bytes;
            std.debug.assert(operator.len * 2 <= hex_buf.len);
            const hex_chars = "0123456789abcdef";
            for (operator, 0..) |byte, i| {
                hex_buf[i * 2] = hex_chars[byte >> 4];
                hex_buf[i * 2 + 1] = hex_chars[byte & 0x0f];
            }
            h.update(hex_buf[0 .. operator.len * 2]);
            h.update("-");
            h.update(lane_id.suffix);
        },
        .dp => |hash| h.update(hash.bytes),
    }
    for (tx_hashes) |tx_hash| h.update(&tx_hash);
    return h.finalize();
}

// ---------------------------------------------------------------------------
// Compatibility tests against `corpus.hash.*`.
// ---------------------------------------------------------------------------

const testing = std.testing;
const corpus = @import("corpus");

test "sha3_256 of empty input matches reference" {
    const expected = corpus.hash.primitives.sha3_256_empty;
    const got = sha3_256("");
    try testing.expectEqualSlices(u8, expected, &got);
}

test "Blob::hashed matches Rust fixture" {
    const blob: types.Blob = .{
        .contract_name = .{ .value = "hyli" },
        .data = .{ .bytes = &[_]u8{ 0x01, 0x02, 0x03 } },
    };
    const got = blobHashed(&blob);
    try testing.expectEqualSlices(u8, corpus.hash.model.blob_simple, &got);
}

test "RegisterContractAction::hashed matches Rust fixture" {
    const input: RegisterContractActionInput = .{
        .verifier = .{ .value = "risc0" },
        .program_id = .{ .bytes = &[_]u8{0xaa} ** 8 },
        .state_commitment = .{ .bytes = &[_]u8{0xbb} ** 8 },
        .contract_name = .{ .value = "counter" },
        .timeout_window = .{ .timeout = .{ .hard_timeout = 50, .soft_timeout = 100 } },
    };
    const got = registerContractActionHashed(&input);
    try testing.expectEqualSlices(
        u8,
        corpus.hash.model.register_contract_action,
        &got,
    );
}

test "DataProposal::hashed matches Rust fixture (DP variant, empty txs)" {
    const parent: types.DataProposalParent = .{
        .dp = .{ .bytes = "parent" },
    };
    const got = dataProposalHashed(parent, &[_]Digest32{});
    try testing.expectEqualSlices(u8, corpus.hash.model.data_proposal_empty, &got);
}

test "ProofData::hashed matches Rust fixture" {
    const proof: types.ProofData = .{ .bytes = &[_]u8{0x42} ** 16 };
    const got = proofDataHashed(&proof);
    try testing.expectEqualSlices(u8, corpus.hash.model.proof_data, &got);
}

test "BlobTransaction::hashed matches Rust fixture" {
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
    const tx: types.BlobTransaction = .{
        .identity = .{ .value = "alice@hyli" },
        .blobs = blobs,
    };
    const got = blobTransactionHashed(&tx);
    try testing.expectEqualSlices(u8, corpus.hash.model.blob_transaction, &got);
}

test "ProofTransaction::hashed matches Rust fixture" {
    const tx: types.ProofTransaction = .{
        .contract_name = .{ .value = "counter" },
        .program_id = .{ .bytes = &[_]u8{ 0xde, 0xad } },
        .verifier = .{ .value = "risc0" },
        .proof = .{ .bytes = &[_]u8{0x42} ** 16 },
    };
    const got = proofTransactionHashed(&tx);
    try testing.expectEqualSlices(u8, corpus.hash.model.proof_transaction, &got);
}

test "VerifiedProofTransaction::hashed matches ProofTransaction::hashed" {
    // Both hashes feed contract_name‖program_id‖verifier‖proof_hash, so the
    // resulting digest must be identical to the matching ProofTransaction
    // fixture even though the wire shapes differ.
    const proof = sha3_256(&[_]u8{0x42} ** 16);
    const tx: types.VerifiedProofTransaction = .{
        .contract_name = .{ .value = "counter" },
        .program_id = .{ .bytes = &[_]u8{ 0xde, 0xad } },
        .verifier = .{ .value = "risc0" },
        .proof = null,
        .proof_hash = .{ .bytes = &proof },
        .proof_size = 16,
        .proven_blobs = &[_]types.BlobProofOutput{},
        .is_recursive = false,
    };
    const got = verifiedProofTransactionHashed(&tx);
    try testing.expectEqualSlices(u8, corpus.hash.model.verified_proof_transaction, &got);
    // Sanity: the two TX-hash variants must agree.
    try testing.expectEqualSlices(u8, corpus.hash.model.proof_transaction, &got);
}
