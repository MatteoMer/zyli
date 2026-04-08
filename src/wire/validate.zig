//! Structural validation for decoded `ConsensusNetMessage` and
//! `MempoolNetMessage` values.
//!
//! "Structural" means the checks that don't need cryptographic
//! verification: each per-step QC carries the right marker byte for
//! its variant, the inner Signed payload's marker matches the outer
//! enum tag, slot/view fields are within plausible ranges, and so on.
//!
//! These checks live in the wire layer because they only depend on
//! the borsh-decoded message bytes — no per-validator state, no
//! signature verification, and no consensus history. The follower
//! state machine layers semantic checks (slot ordering, view
//! progression, vote weight) on top.
//!
//! All predicates return `bool` so they compose into a single
//! `validateStructural` entry point that does not allocate.

const std = @import("std");
const types = @import("../model/types.zig");

/// `PrepareQC` must carry the `prepare_vote` marker; `CommitQC` must
/// carry the `confirm_ack` marker; `TimeoutQC` carries
/// `consensus_timeout`; `NilQC` carries `nil_consensus_timeout`. The
/// upstream `quorum_certificate_cannot_be_reused_across_steps` test
/// in hyli/src/consensus/network.rs enforces exactly this invariant.
pub fn isPrepareQC(qc: types.QuorumCertificate) bool {
    return qc.marker == .prepare_vote;
}

pub fn isCommitQC(qc: types.QuorumCertificate) bool {
    return qc.marker == .confirm_ack;
}

pub fn isTimeoutQC(qc: types.QuorumCertificate) bool {
    return qc.marker == .consensus_timeout;
}

pub fn isNilQC(qc: types.QuorumCertificate) bool {
    return qc.marker == .nil_consensus_timeout;
}

/// A non-empty `AggregateSignature.validators` list is a structural
/// requirement for any QC: a QC over zero validators trivially
/// "passes" any threshold and would be a byzantine attempt to skip
/// the consensus check.
pub fn isNonEmptyAggregate(agg: types.AggregateSignature) bool {
    return agg.validators.len > 0;
}

/// Validate a decoded `ConsensusNetMessage` for structural
/// self-consistency. Returns `true` if every per-variant invariant
/// holds.
///
/// Specifically:
///   - `Prepare`: the inner ticket is one of the legal kinds (no
///     forced-commit-qc on the wire from peers); the slot must be ≥ 1
///     (slot 0 doesn't exist); a Genesis ticket implies slot == 1.
///   - `PrepareVote`: inner Signed payload's marker is `prepare_vote`.
///   - `Confirm`: inner QC is a `PrepareQC` (marker = prepare_vote)
///     with at least one validator.
///   - `ConfirmAck`: inner Signed payload's marker is `confirm_ack`.
///   - `Commit`: inner QC is a `CommitQC` (marker = confirm_ack) with
///     at least one validator.
///   - `Timeout`: outer signed payload's marker is `consensus_timeout`,
///     and the kind's nested signed payload (if NilProposal) carries
///     `nil_consensus_timeout`.
///   - `TimeoutCertificate`: outer QC is a `TimeoutQC` with at least
///     one validator, and the `TCKind` payload uses the matching marker
///     variants.
///   - `ValidatorCandidacy`, `SyncRequest`, `SyncReply`: no QC
///     invariants — the borsh decoder already enforced the structure.
pub fn validateConsensusMessage(msg: types.ConsensusNetMessage) bool {
    return switch (msg) {
        .prepare => |p| validatePrepare(p),
        .prepare_vote => |pv| pv.msg.marker == .prepare_vote,
        .confirm => |c| isPrepareQC(c.prepare_qc) and isNonEmptyAggregate(c.prepare_qc.aggregate),
        .confirm_ack => |ca| ca.msg.marker == .confirm_ack,
        .commit => |c| isCommitQC(c.commit_qc) and isNonEmptyAggregate(c.commit_qc.aggregate),
        .timeout => |t| validateTimeout(t),
        .timeout_certificate => |tc| validateTimeoutCertificate(tc) and
            isNonEmptyAggregate(tc.timeout_qc.aggregate),
        .validator_candidacy => true,
        .sync_request => true,
        .sync_reply => |sr| validateTicket(sr.ticket, .from_peer),
    };
}

/// Cross-check the Prepare's ticket against its proposal slot. Mirrors
/// the upstream check from
/// hyli/src/consensus/role_follower.rs ("Genesis ticket is only valid
/// for the first slot").
pub fn validatePrepare(p: types.PreparePayload) bool {
    if (p.proposal.slot == 0) return false;
    switch (p.ticket) {
        .genesis => if (p.proposal.slot != 1) return false,
        else => {},
    }
    return validateTicket(p.ticket, .from_peer);
}

/// Stateless monotonicity check between two consecutive proposals.
/// `prev` is the last accepted proposal, `next` is what just arrived.
/// Returns `true` if the next proposal is a plausible successor —
/// the slot must strictly increase (or stay the same with a higher
/// view), and the timestamp must strictly increase. Mirrors the
/// upstream `verify_timestamp` and the slot/view ordering rules
/// from `hyli/src/consensus/role_follower.rs`.
///
/// `prev_view` is what the follower's BFT round state would have
/// recorded for `prev` — the caller passes it explicitly so this
/// remains a pure function.
pub fn validateProposalSucceeds(
    prev: types.ConsensusProposal,
    prev_view: types.View,
    next: types.ConsensusProposal,
    next_view: types.View,
) bool {
    if (next.slot < prev.slot) return false;
    if (next.slot == prev.slot and next_view <= prev_view) return false;
    // Strict timestamp monotonicity. The upstream check has a
    // configurable upper bound that depends on slot duration; we only
    // enforce the lower bound here because the upper bound needs
    // chain-config knowledge the validator doesn't carry yet.
    if (next.timestamp.millis <= prev.timestamp.millis) return false;
    return true;
}

/// Tickets accepted on the wire from a peer. The internal
/// `ForcedCommitQC` variant is never sent — it exists only as a
/// runtime hint for the leader. Any peer that emits one is malformed.
pub const TicketSource = enum { from_peer, internal };

pub fn validateTicket(ticket: types.Ticket, source: TicketSource) bool {
    return switch (ticket) {
        .genesis => true,
        .commit_qc => |qc| isCommitQC(qc),
        .timeout_qc => |t| isTimeoutQC(t.timeout_qc) and validateTcKind(t.tc_kind),
        .forced_commit_qc => source == .internal,
    };
}

pub fn validateTcKind(kind: types.TcKind) bool {
    return switch (kind) {
        .nil_proposal => |qc| isNilQC(qc),
        .prepare_qc => |qp| isPrepareQC(qp.quorum_certificate),
    };
}

pub fn validateTimeoutKind(kind: types.TimeoutKind) bool {
    return switch (kind) {
        .nil_proposal => |signed| signed.msg.marker == .nil_consensus_timeout,
        .prepare_qc => |qp| isPrepareQC(qp.quorum_certificate),
    };
}

pub fn validateTimeout(t: types.ConsensusTimeout) bool {
    return t.outer.msg.marker == .consensus_timeout and validateTimeoutKind(t.kind);
}

pub fn validateTimeoutCertificate(tc: types.TimeoutCertificatePayload) bool {
    return isTimeoutQC(tc.timeout_qc) and validateTcKind(tc.tc_kind);
}

/// `MempoolNetMessage` has no QC marker invariants — the borsh decoder
/// already enforces the variant structure. This stub exists so the
/// observer can hand every decoded message through a single
/// `validate*` entry point.
pub fn validateMempoolMessage(msg: types.MempoolNetMessage) bool {
    _ = msg;
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleAggregate() types.AggregateSignature {
    return .{
        .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
        .validators = &[_]types.ValidatorPublicKey{
            .{ .bytes = &[_]u8{0x01} ** 4 },
        },
    };
}

fn sampleValidatorSig() types.ValidatorSignature {
    return .{
        .signature = .{ .bytes = &[_]u8{0xff} ** 8 },
        .validator = .{ .bytes = &[_]u8{0x01} ** 4 },
    };
}

fn sampleProposal() types.ConsensusProposal {
    return .{
        .slot = 1,
        .parent_hash = .{ .bytes = "p" },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = 0 },
    };
}

test "isPrepareQC / isCommitQC / isTimeoutQC / isNilQC" {
    const agg = sampleAggregate();
    try testing.expect(isPrepareQC(.{ .aggregate = agg, .marker = .prepare_vote }));
    try testing.expect(!isPrepareQC(.{ .aggregate = agg, .marker = .confirm_ack }));
    try testing.expect(isCommitQC(.{ .aggregate = agg, .marker = .confirm_ack }));
    try testing.expect(!isCommitQC(.{ .aggregate = agg, .marker = .prepare_vote }));
    try testing.expect(isTimeoutQC(.{ .aggregate = agg, .marker = .consensus_timeout }));
    try testing.expect(isNilQC(.{ .aggregate = agg, .marker = .nil_consensus_timeout }));
}

test "validateConsensusMessage: PrepareVote with right marker" {
    const msg: types.ConsensusNetMessage = .{
        .prepare_vote = .{
            .msg = .{
                .consensus_proposal_hash = .{ .bytes = "cp" },
                .marker = .prepare_vote,
            },
            .signature = sampleValidatorSig(),
        },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateConsensusMessage: PrepareVote with wrong marker fails" {
    const msg: types.ConsensusNetMessage = .{
        .prepare_vote = .{
            .msg = .{
                .consensus_proposal_hash = .{ .bytes = "cp" },
                .marker = .confirm_ack, // wrong!
            },
            .signature = sampleValidatorSig(),
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: Confirm with PrepareQC" {
    const msg: types.ConsensusNetMessage = .{
        .confirm = .{
            .prepare_qc = .{ .aggregate = sampleAggregate(), .marker = .prepare_vote },
            .consensus_proposal_hash = .{ .bytes = "cp" },
        },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateConsensusMessage: Confirm with CommitQC fails (marker swap)" {
    const msg: types.ConsensusNetMessage = .{
        .confirm = .{
            .prepare_qc = .{ .aggregate = sampleAggregate(), .marker = .confirm_ack },
            .consensus_proposal_hash = .{ .bytes = "cp" },
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: Commit with CommitQC" {
    const msg: types.ConsensusNetMessage = .{
        .commit = .{
            .commit_qc = .{ .aggregate = sampleAggregate(), .marker = .confirm_ack },
            .consensus_proposal_hash = .{ .bytes = "cp" },
        },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateConsensusMessage: Timeout with NilProposal kind" {
    const msg: types.ConsensusNetMessage = .{
        .timeout = .{
            .outer = .{
                .msg = .{
                    .slot = 5,
                    .view = 1,
                    .consensus_proposal_hash = .{ .bytes = "cp" },
                    .marker = .consensus_timeout,
                },
                .signature = sampleValidatorSig(),
            },
            .kind = .{
                .nil_proposal = .{
                    .msg = .{
                        .slot = 5,
                        .view = 1,
                        .consensus_proposal_hash = .{ .bytes = "cp" },
                        .marker = .nil_consensus_timeout,
                    },
                    .signature = sampleValidatorSig(),
                },
            },
        },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateConsensusMessage: Timeout outer marker mismatch fails" {
    const msg: types.ConsensusNetMessage = .{
        .timeout = .{
            .outer = .{
                .msg = .{
                    .slot = 5,
                    .view = 1,
                    .consensus_proposal_hash = .{ .bytes = "cp" },
                    .marker = .prepare_vote, // wrong!
                },
                .signature = sampleValidatorSig(),
            },
            .kind = .{
                .nil_proposal = .{
                    .msg = .{
                        .slot = 5,
                        .view = 1,
                        .consensus_proposal_hash = .{ .bytes = "cp" },
                        .marker = .nil_consensus_timeout,
                    },
                    .signature = sampleValidatorSig(),
                },
            },
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: TimeoutCertificate with TCKind::NilProposal" {
    const msg: types.ConsensusNetMessage = .{
        .timeout_certificate = .{
            .timeout_qc = .{ .aggregate = sampleAggregate(), .marker = .consensus_timeout },
            .tc_kind = .{
                .nil_proposal = .{ .aggregate = sampleAggregate(), .marker = .nil_consensus_timeout },
            },
            .slot = 5,
            .view = 1,
        },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateConsensusMessage: TimeoutCertificate outer-marker mismatch" {
    const msg: types.ConsensusNetMessage = .{
        .timeout_certificate = .{
            .timeout_qc = .{ .aggregate = sampleAggregate(), .marker = .confirm_ack },
            .tc_kind = .{
                .nil_proposal = .{ .aggregate = sampleAggregate(), .marker = .nil_consensus_timeout },
            },
            .slot = 5,
            .view = 1,
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateTicket: ForcedCommitQC rejected from peer, accepted internal" {
    const ticket: types.Ticket = .{ .forced_commit_qc = 0 };
    try testing.expect(!validateTicket(ticket, .from_peer));
    try testing.expect(validateTicket(ticket, .internal));
}

test "validateConsensusMessage: Prepare with ForcedCommitQC ticket fails (peer source)" {
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = sampleProposal(),
            .ticket = .{ .forced_commit_qc = 0 },
            .view = 1,
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: Prepare with Genesis ticket succeeds at slot=1" {
    // sampleProposal() returns a proposal with slot=1, which is the
    // only slot a Genesis ticket is legal for.
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = sampleProposal(),
            .ticket = .genesis,
            .view = 0,
        },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateConsensusMessage: Prepare with Genesis ticket at slot=2 fails" {
    var p = sampleProposal();
    p.slot = 2;
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = p,
            .ticket = .genesis,
            .view = 0,
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: Prepare with slot=0 fails" {
    var p = sampleProposal();
    p.slot = 0;
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = p,
            .ticket = .genesis,
            .view = 0,
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: Confirm with empty validators QC fails" {
    const empty_qc: types.AggregateSignature = .{
        .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
        .validators = &[_]types.ValidatorPublicKey{},
    };
    const msg: types.ConsensusNetMessage = .{
        .confirm = .{
            .prepare_qc = .{ .aggregate = empty_qc, .marker = .prepare_vote },
            .consensus_proposal_hash = .{ .bytes = "cp" },
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: Commit with empty validators QC fails" {
    const empty_qc: types.AggregateSignature = .{
        .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
        .validators = &[_]types.ValidatorPublicKey{},
    };
    const msg: types.ConsensusNetMessage = .{
        .commit = .{
            .commit_qc = .{ .aggregate = empty_qc, .marker = .confirm_ack },
            .consensus_proposal_hash = .{ .bytes = "cp" },
        },
    };
    try testing.expect(!validateConsensusMessage(msg));
}

test "validateConsensusMessage: SyncRequest is always valid" {
    const msg: types.ConsensusNetMessage = .{
        .sync_request = .{ .bytes = "cp" },
    };
    try testing.expect(validateConsensusMessage(msg));
}

test "validateProposalSucceeds: same slot, higher view, newer ts" {
    const prev = sampleProposal(); // slot=1, ts=0
    var next = sampleProposal();
    next.timestamp.millis = 1;
    try testing.expect(validateProposalSucceeds(prev, 0, next, 1));
}

test "validateProposalSucceeds: next slot, newer ts" {
    const prev = sampleProposal(); // slot=1, ts=0
    var next = sampleProposal();
    next.slot = 2;
    next.timestamp.millis = 100;
    try testing.expect(validateProposalSucceeds(prev, 0, next, 0));
}

test "validateProposalSucceeds: rewinding the slot fails" {
    var prev = sampleProposal();
    prev.slot = 5;
    prev.timestamp.millis = 100;
    var next = sampleProposal();
    next.slot = 4;
    next.timestamp.millis = 200;
    try testing.expect(!validateProposalSucceeds(prev, 0, next, 0));
}

test "validateProposalSucceeds: same slot/view fails" {
    const prev = sampleProposal();
    var next = sampleProposal();
    next.timestamp.millis = 100;
    // Same slot=1, view=0 → next must bump the view.
    try testing.expect(!validateProposalSucceeds(prev, 0, next, 0));
}

test "validateProposalSucceeds: stale timestamp fails" {
    var prev = sampleProposal();
    prev.timestamp.millis = 100;
    var next = sampleProposal();
    next.slot = 2;
    next.timestamp.millis = 100; // not strictly greater
    try testing.expect(!validateProposalSucceeds(prev, 0, next, 0));
}

test "validateMempoolMessage: stub returns true" {
    const msg: types.MempoolNetMessage = .{
        .data_vote = .{
            .lane_id = .{ .operator = .{ .bytes = &[_]u8{} }, .suffix = "default" },
            .validator_dag = .{
                .msg = .{
                    .data_proposal_hash = .{ .bytes = "dp" },
                    .lane_bytes_size = .{ .bytes = 0 },
                },
                .signature = sampleValidatorSig(),
            },
        },
    };
    try testing.expect(validateMempoolMessage(msg));
}
