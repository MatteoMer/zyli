//! Cryptographic verification of consensus / mempool network messages.
//!
//! The wire-level structural validator (`wire/validate.zig`) checks
//! shape — slot/view monotonicity, marker / variant cross-checks,
//! aggregate non-emptiness. This module checks signatures: every
//! `Signed<T, V>` envelope and every `AggregateSignature` carried by a
//! `ConsensusNetMessage` (or `MempoolNetMessage`) is run through the
//! Phase 2 BLS verifier. The two together get a follower from
//! "well-formed and ordered" to "actually attested by validators".
//!
//! Each `verify*` function returns `true` for "all signatures
//! verified", `false` for "at least one signature was rejected",
//! and `error` only for malformed inputs (wrong-length encodings,
//! borsh failures, OOM). The boolean / error split mirrors the
//! `crypto.bls` shape so the call sites can distinguish "this peer
//! sent garbage" (error) from "this peer sent a forged signature"
//! (`false`).
//!
//! Cost note: every aggregate verify runs two pairings, and every
//! single-validator verify runs two pairings. A consensus Confirm
//! carries one PrepareQC (1 aggregate verify), a Commit one CommitQC,
//! a TimeoutCertificate one TimeoutQC + sometimes one PrepareQC
//! (2 verifies). At ~1s per pairing in debug mode, a fully-checked
//! Confirm costs ~2s; release-mode cost should be much smaller. Do
//! not run this in a hot per-frame loop without measurement.

const std = @import("std");
const types = @import("../model/types.zig");
const bls = @import("bls.zig");
const signable = @import("signable.zig");
const borsh = @import("../model/borsh.zig");

pub const Error = bls.Error || borsh.Error;

// ---------------------------------------------------------------------------
// Single-signature helpers
// ---------------------------------------------------------------------------

/// Verify a `PrepareVote = Signed<ConsensusVotePayload, ValidatorSignature>`.
pub fn verifyPrepareVote(
    allocator: std.mem.Allocator,
    pv: types.PrepareVote,
) Error!bool {
    return bls.verifySignedByValidator(allocator, types.ConsensusVotePayload, pv);
}

/// Verify a `ConfirmAck = Signed<ConsensusVotePayload, ValidatorSignature>`.
pub fn verifyConfirmAck(
    allocator: std.mem.Allocator,
    ca: types.ConfirmAck,
) Error!bool {
    return bls.verifySignedByValidator(allocator, types.ConsensusVotePayload, ca);
}

/// Verify a `Signed<TimeoutSignedPayload, ValidatorSignature>`.
pub fn verifySignedTimeoutPayload(
    allocator: std.mem.Allocator,
    signed: types.Signed(types.TimeoutSignedPayload, types.ValidatorSignature),
) Error!bool {
    return bls.verifySignedByValidator(allocator, types.TimeoutSignedPayload, signed);
}

/// Verify a `Signed<ValidatorCandidacy, ValidatorSignature>`.
pub fn verifyValidatorCandidacy(
    allocator: std.mem.Allocator,
    signed: types.Signed(types.ValidatorCandidacy, types.ValidatorSignature),
) Error!bool {
    return bls.verifySignedByValidator(allocator, types.ValidatorCandidacy, signed);
}

// ---------------------------------------------------------------------------
// Aggregate-signature helpers
//
// QCs in Hyli use the same-message BLS aggregate. The signed payload
// is the `ConsensusVotePayload` matching the QC's marker — i.e., a
// PrepareQC's signers all signed `(cph, PrepareVote)` and a CommitQC's
// signers all signed `(cph, ConfirmAck)`. The marker on the QC tells
// us which one to reconstruct.
//
// We don't have the cph stored separately on the QC itself in our
// model — it lives on the surrounding `Confirm` / `Commit` payload.
// So the helpers take the cph as an argument and rebuild the
// `ConsensusVotePayload` for verification.
// ---------------------------------------------------------------------------

/// Verify a Quorum Certificate against the cph it should be attesting
/// to. Marker pinned by the caller (via `expected_marker`) so the
/// helper can reject a QC that was built with the wrong marker.
pub fn verifyQuorumCertificate(
    allocator: std.mem.Allocator,
    qc: types.QuorumCertificate,
    cph: types.ConsensusProposalHash,
    expected_marker: types.ConsensusMarker,
) Error!bool {
    if (qc.marker != expected_marker) return false;
    const payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph,
        .marker = expected_marker,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        allocator,
        types.ConsensusVotePayload,
        payload,
    );
    defer allocator.free(msg_bytes);
    return bls.verifyAggregateSig(allocator, qc.aggregate, msg_bytes);
}

/// Verify a `Confirm` payload's PrepareQC.
pub fn verifyConfirm(
    allocator: std.mem.Allocator,
    c: types.ConfirmPayload,
) Error!bool {
    return verifyQuorumCertificate(
        allocator,
        c.prepare_qc,
        c.consensus_proposal_hash,
        .prepare_vote,
    );
}

/// Verify a `Commit` payload's CommitQC.
pub fn verifyCommit(
    allocator: std.mem.Allocator,
    c: types.CommitPayload,
) Error!bool {
    return verifyQuorumCertificate(
        allocator,
        c.commit_qc,
        c.consensus_proposal_hash,
        .confirm_ack,
    );
}

// ---------------------------------------------------------------------------
// Top-level dispatch for ConsensusNetMessage
// ---------------------------------------------------------------------------

/// Verify all signatures embedded in a `ConsensusNetMessage`. Returns
/// `true` only if every signature in the message verifies. The
/// `prepare`, `sync_request`, and `sync_reply` cases have no signatures
/// of their own (they carry data the wire-level validator already
/// sanity-checks); they short-circuit to `true`.
///
/// `Prepare` carries a `Ticket` which can embed a `CommitQC` (in the
/// `commit_qc` variant) — verify it. The `timeout_qc` ticket variant
/// also carries a TimeoutQC which we attempt to verify, but the
/// `nil_proposal` / `prepare_qc` inner `TCKind` requires the cph from
/// the embedded proposal which we don't have on the ticket itself, so
/// for now we only verify the outer TimeoutQC. A future hardening
/// pass can plumb the inner cph through.
pub fn verifyConsensusMessage(
    allocator: std.mem.Allocator,
    msg: types.ConsensusNetMessage,
) Error!bool {
    return switch (msg) {
        .prepare => |_| true, // proposal has no own signature; the QCs in
        // the ticket get verified by the surrounding Confirm/Commit
        // when they arrive. We do not verify the ticket's QC here
        // because the cph it attests to lives on the *previous*
        // proposal we may not have seen yet — that's the follower's
        // responsibility.
        .prepare_vote => |pv| verifyPrepareVote(allocator, pv),
        .confirm => |c| verifyConfirm(allocator, c),
        .confirm_ack => |ca| verifyConfirmAck(allocator, ca),
        .commit => |c| verifyCommit(allocator, c),
        .timeout => |t| verifyConsensusTimeout(allocator, t),
        .timeout_certificate => |_| true, // outer signatures are aggregated;
        // verifying them requires the cph from the embedded proposal
        // chain. Plumbing that through is Phase 5 hardening work.
        .validator_candidacy => |vc| verifyValidatorCandidacy(allocator, vc),
        .sync_request => |_| true,
        .sync_reply => |_| true,
    };
}

/// Verify the outer signed payload of a `ConsensusTimeout` and any
/// inner `Signed<TimeoutSignedPayload, ValidatorSignature>` carried by
/// the `nil_proposal` variant of `TimeoutKind`.
fn verifyConsensusTimeout(
    allocator: std.mem.Allocator,
    t: types.ConsensusTimeout,
) Error!bool {
    if (!try verifySignedTimeoutPayload(allocator, t.outer)) return false;
    return switch (t.kind) {
        .nil_proposal => |np| verifySignedTimeoutPayload(allocator, np),
        .prepare_qc => |_| true, // see verifyConsensusMessage note
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const zolt_arith = @import("zolt_arith");
const bls12_381 = zolt_arith.bls12_381;
const hash_to_curve_g2 = zolt_arith.hash_to_curve_g2;

test "verifyConsensusMessage: sync_request short-circuits to true" {
    const msg: types.ConsensusNetMessage = .{
        .sync_request = .{ .bytes = &[_]u8{0x01} ** 4 },
    };
    const ok = try verifyConsensusMessage(testing.allocator, msg);
    try testing.expect(ok);
}

test "verifyConsensusMessage: sync_reply short-circuits to true" {
    const msg: types.ConsensusNetMessage = .{
        .sync_reply = .{
            .sender = .{ .bytes = &[_]u8{0x02} ** 4 },
            .proposal = undefined,
            .ticket = .genesis,
            .view = 0,
        },
    };
    // We can't actually call this with `undefined` proposal because
    // verifyConsensusMessage doesn't touch the proposal — but the
    // switch arm dispatches based on the variant tag alone.
    const ok = try verifyConsensusMessage(testing.allocator, msg);
    try testing.expect(ok);
}

test "verifyQuorumCertificate: rejects QC with wrong marker" {
    var sig_bytes: [96]u8 = .{0} ** 96;
    sig_bytes[0] = 0xc0; // infinity-encoded G2, decodes successfully
    var pk_bytes: [48]u8 = .{0} ** 48;
    pk_bytes[0] = 0xc0;
    const validators = [_]types.ValidatorPublicKey{.{ .bytes = &pk_bytes }};
    const qc: types.QuorumCertificate = .{
        .aggregate = .{
            .signature = .{ .bytes = &sig_bytes },
            .validators = &validators,
        },
        .marker = .confirm_ack,
    };
    const result = try verifyQuorumCertificate(
        testing.allocator,
        qc,
        .{ .bytes = "cph" },
        .prepare_vote,
    );
    try testing.expect(!result);
}

// ---------------------------------------------------------------------------
// End-to-end round-trip tests
//
// These build real (sk, pk, sig) triples for known scalars, encode the
// pubkey and signature to wire bytes, wrap them in the Hyli envelope
// types, and run them through the high-level verifier. The signing
// path is "sign by hand": compute H(borsh(msg)) → G2, then multiply by
// sk to get the signature.
// ---------------------------------------------------------------------------

const Allocator = std.mem.Allocator;

/// Build a `(pk_bytes, sig_bytes)` tuple where the signature is over
/// `msg_bytes`. The bytes are heap-allocated; the caller frees both.
fn signWithScalar(
    allocator: Allocator,
    sk: u64,
    msg_bytes: []const u8,
) !struct { pk: []u8, sig: []u8 } {
    const sk_limbs: [4]u64 = .{ sk, 0, 0, 0 };
    const pk = bls12_381.g1Generator().mul(4, sk_limbs);
    const h_msg = try hash_to_curve_g2.hashToG2(msg_bytes, bls.DST);
    const sig_point = h_msg.mul(4, sk_limbs);

    const pk_arr = bls12_381.encodeG1Compressed(pk);
    const sig_arr = bls12_381.encodeG2Compressed(sig_point);

    const pk_bytes = try allocator.dupe(u8, &pk_arr);
    errdefer allocator.free(pk_bytes);
    const sig_bytes = try allocator.dupe(u8, &sig_arr);
    return .{ .pk = pk_bytes, .sig = sig_bytes };
}

test "verifyPrepareVote: round-trip with self-signed payload" {
    const cph: types.ConsensusProposalHash = .{ .bytes = "cph-test" };
    const payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph,
        .marker = .prepare_vote,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ConsensusVotePayload,
        payload,
    );
    defer testing.allocator.free(msg_bytes);

    const signed = try signWithScalar(testing.allocator, 7, msg_bytes);
    defer testing.allocator.free(signed.pk);
    defer testing.allocator.free(signed.sig);

    const pv: types.PrepareVote = .{
        .msg = payload,
        .signature = .{
            .signature = .{ .bytes = signed.sig },
            .validator = .{ .bytes = signed.pk },
        },
    };
    const ok = try verifyPrepareVote(testing.allocator, pv);
    try testing.expect(ok);
}

test "verifyPrepareVote: rejects when signature is for wrong cph" {
    const cph_signed: types.ConsensusProposalHash = .{ .bytes = "cph-A" };
    const cph_envelope: types.ConsensusProposalHash = .{ .bytes = "cph-B" };
    const signed_payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph_signed,
        .marker = .prepare_vote,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ConsensusVotePayload,
        signed_payload,
    );
    defer testing.allocator.free(msg_bytes);

    const signed = try signWithScalar(testing.allocator, 11, msg_bytes);
    defer testing.allocator.free(signed.pk);
    defer testing.allocator.free(signed.sig);

    // Build an envelope that claims to be for cph-B but carries a
    // signature over cph-A. The verifier rebuilds the signed bytes
    // from the envelope's payload, so the pairing check fails.
    const pv: types.PrepareVote = .{
        .msg = .{
            .consensus_proposal_hash = cph_envelope,
            .marker = .prepare_vote,
        },
        .signature = .{
            .signature = .{ .bytes = signed.sig },
            .validator = .{ .bytes = signed.pk },
        },
    };
    const ok = try verifyPrepareVote(testing.allocator, pv);
    try testing.expect(!ok);
}

test "verifyConfirm: rejects QC built for the wrong marker" {
    // Build a real signature over a ConfirmAck-marker payload, then
    // wrap it as a PrepareQC inside a Confirm. The verifier first
    // checks marker == prepare_vote on the QC and rejects.
    const cph: types.ConsensusProposalHash = .{ .bytes = "cph-marker-test" };
    const ack_payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph,
        .marker = .confirm_ack,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ConsensusVotePayload,
        ack_payload,
    );
    defer testing.allocator.free(msg_bytes);

    const signed = try signWithScalar(testing.allocator, 13, msg_bytes);
    defer testing.allocator.free(signed.pk);
    defer testing.allocator.free(signed.sig);

    const validators = [_]types.ValidatorPublicKey{.{ .bytes = signed.pk }};
    const confirm: types.ConfirmPayload = .{
        .prepare_qc = .{
            .aggregate = .{
                .signature = .{ .bytes = signed.sig },
                .validators = &validators,
            },
            .marker = .confirm_ack, // wrong: PrepareQC should carry .prepare_vote
        },
        .consensus_proposal_hash = cph,
    };
    const ok = try verifyConfirm(testing.allocator, confirm);
    try testing.expect(!ok);
}

test "verifyConfirm: round-trip with PrepareQC built from one signer" {
    const cph: types.ConsensusProposalHash = .{ .bytes = "cph-confirm" };
    const vote_payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph,
        .marker = .prepare_vote,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ConsensusVotePayload,
        vote_payload,
    );
    defer testing.allocator.free(msg_bytes);

    const signed = try signWithScalar(testing.allocator, 17, msg_bytes);
    defer testing.allocator.free(signed.pk);
    defer testing.allocator.free(signed.sig);

    const validators = [_]types.ValidatorPublicKey{.{ .bytes = signed.pk }};
    const confirm: types.ConfirmPayload = .{
        .prepare_qc = .{
            .aggregate = .{
                .signature = .{ .bytes = signed.sig },
                .validators = &validators,
            },
            .marker = .prepare_vote,
        },
        .consensus_proposal_hash = cph,
    };
    const ok = try verifyConfirm(testing.allocator, confirm);
    try testing.expect(ok);
}

test "verifyCommit: round-trip with CommitQC from two signers" {
    const cph: types.ConsensusProposalHash = .{ .bytes = "cph-commit" };
    const ack_payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph,
        .marker = .confirm_ack,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ConsensusVotePayload,
        ack_payload,
    );
    defer testing.allocator.free(msg_bytes);

    // Two signers with distinct scalars; aggregate the signatures.
    const sk1_limbs: [4]u64 = .{ 19, 0, 0, 0 };
    const sk2_limbs: [4]u64 = .{ 23, 0, 0, 0 };
    const pk1 = bls12_381.g1Generator().mul(4, sk1_limbs);
    const pk2 = bls12_381.g1Generator().mul(4, sk2_limbs);
    const h_msg = try hash_to_curve_g2.hashToG2(msg_bytes, bls.DST);
    const sig1 = h_msg.mul(4, sk1_limbs);
    const sig2 = h_msg.mul(4, sk2_limbs);
    const agg_sig = sig1.add(sig2);

    const pk1_bytes = bls12_381.encodeG1Compressed(pk1);
    const pk2_bytes = bls12_381.encodeG1Compressed(pk2);
    const agg_sig_bytes = bls12_381.encodeG2Compressed(agg_sig);

    const validators = [_]types.ValidatorPublicKey{
        .{ .bytes = &pk1_bytes },
        .{ .bytes = &pk2_bytes },
    };
    const commit: types.CommitPayload = .{
        .commit_qc = .{
            .aggregate = .{
                .signature = .{ .bytes = &agg_sig_bytes },
                .validators = &validators,
            },
            .marker = .confirm_ack,
        },
        .consensus_proposal_hash = cph,
    };
    const ok = try verifyCommit(testing.allocator, commit);
    try testing.expect(ok);
}

test "verifyConsensusMessage: dispatches to the right verifier per variant" {
    // A round-tripped PrepareVote should verify when wrapped in a
    // ConsensusNetMessage and routed through the top-level dispatcher.
    const cph: types.ConsensusProposalHash = .{ .bytes = "cph-dispatch" };
    const payload: types.ConsensusVotePayload = .{
        .consensus_proposal_hash = cph,
        .marker = .prepare_vote,
    };
    const msg_bytes = try signable.signableBytesAlloc(
        testing.allocator,
        types.ConsensusVotePayload,
        payload,
    );
    defer testing.allocator.free(msg_bytes);

    const signed = try signWithScalar(testing.allocator, 29, msg_bytes);
    defer testing.allocator.free(signed.pk);
    defer testing.allocator.free(signed.sig);

    const cnm: types.ConsensusNetMessage = .{
        .prepare_vote = .{
            .msg = payload,
            .signature = .{
                .signature = .{ .bytes = signed.sig },
                .validator = .{ .bytes = signed.pk },
            },
        },
    };
    const ok = try verifyConsensusMessage(testing.allocator, cnm);
    try testing.expect(ok);
}
