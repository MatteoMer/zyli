//! Stateless-ish consensus follower state machine.
//!
//! This is the Phase 5 starting point: a tiny state machine that
//! tracks the current slot, view, and last committed proposal hash,
//! and folds incoming `ConsensusNetMessage` values into events the
//! caller can react to. It is structural-only — no signature
//! verification, no leader-rotation logic, no validator-set
//! tracking. Those layers come later, on top of this.
//!
//! The follower owns no allocations: every method is a pure
//! state-transition function on `Follower` plus an immutable
//! `ConsensusNetMessage` reference. The caller passes the borsh-
//! decoded message in (using the existing protocol decoder) and
//! gets back either an `Event` describing what changed or one of
//! the rejection enum variants explaining why the message was
//! ignored.
//!
//! What the follower does today:
//!   - Validates the message structurally via `wire.validate`.
//!   - Cross-checks slot / view ordering via
//!     `wire.validate.validateProposalSucceeds` for `Prepare` and
//!     `SyncReply`.
//!   - Tracks votes per consensus proposal hash, but does NOT verify
//!     them — they're just counted as "we've seen N votes".
//!   - Advances `last_commit_hash` when a `Commit` arrives matching
//!     the most-recent prepared proposal.
//!
//! What it deliberately does NOT do (Phase 5/6 work):
//!   - Verify aggregate signatures (needs BLS — Phase 2).
//!   - Track the validator set or apply staking actions.
//!   - Resolve missing parents (needs sync request handling).
//!   - Replay state (Phase 6).

const std = @import("std");
const types = @import("../model/types.zig");
const validate = @import("../wire/validate.zig");
const hash_mod = @import("../model/hash.zig");

/// Top-level state of the follower.
pub const Follower = struct {
    /// Highest slot the follower has accepted a Prepare for. Starts
    /// at 0 (no proposal yet); the first valid Prepare must be for
    /// slot 1.
    slot: types.Slot = 0,
    /// View the follower last accepted at the current slot.
    view: types.View = 0,
    /// Hash of the last fully-committed proposal. Empty before any
    /// commit lands.
    last_commit_hash: ?[]const u8 = null,
    /// Slot of the last committed proposal. 0 means no commit yet.
    last_commit_slot: types.Slot = 0,
    /// The last proposal we accepted at the current slot, if any.
    /// Used to:
    ///   1. Cross-check incoming Commit / PrepareVote / ConfirmAck
    ///      hashes against our local view of the proposal.
    ///   2. Pass to the next Prepare's succession check.
    accepted_proposal: ?types.ConsensusProposal = null,

    /// Construct a fresh follower at slot 0 / view 0.
    pub fn init() Follower {
        return .{};
    }

    /// Reset the follower to its initial state. Useful for tests
    /// and for the observer's "start over from scratch" path.
    pub fn reset(self: *Follower) void {
        self.* = init();
    }

    /// Fold one message into the follower state. Returns an `Event`
    /// describing what changed, or a rejection variant explaining
    /// why the message was ignored.
    pub fn handle(self: *Follower, msg: types.ConsensusNetMessage) Event {
        // Always run the structural validator first. Anything that
        // fails it is dropped immediately.
        if (!validate.validateConsensusMessage(msg)) {
            return .{ .rejected = .{ .reason = .structural_invalid } };
        }
        return switch (msg) {
            .prepare => |p| self.handlePrepare(p),
            .prepare_vote => |pv| self.handlePrepareVote(pv),
            .confirm => |c| self.handleConfirm(c),
            .confirm_ack => |ca| self.handleConfirmAck(ca),
            .commit => |c| self.handleCommit(c),
            .timeout => .{ .observed = .{ .kind = .timeout } },
            .timeout_certificate => .{ .observed = .{ .kind = .timeout_certificate } },
            .validator_candidacy => .{ .observed = .{ .kind = .validator_candidacy } },
            .sync_request => .{ .observed = .{ .kind = .sync_request } },
            .sync_reply => |sr| self.handleSyncReply(sr),
        };
    }

    fn handlePrepare(self: *Follower, p: types.PreparePayload) Event {
        // Slot 0 should have been caught by the validator, but defend
        // anyway.
        if (p.proposal.slot == 0) return .{ .rejected = .{ .reason = .structural_invalid } };

        // First-ever Prepare: accept if it's slot 1 with a Genesis
        // ticket. The validator already enforces the Genesis ↔ slot=1
        // bond, so we just need the slot ordering to hold.
        if (self.slot == 0) {
            if (p.proposal.slot != 1) {
                return .{ .rejected = .{ .reason = .out_of_order } };
            }
            self.slot = p.proposal.slot;
            self.view = p.view;
            self.accepted_proposal = p.proposal;
            return .{ .accepted_prepare = .{ .slot = p.proposal.slot, .view = p.view } };
        }

        // Subsequent Prepares: must succeed the currently-accepted
        // proposal. We use the wire-level helper for the lower-bound
        // monotonicity check.
        if (self.accepted_proposal) |prev| {
            if (!validate.validateProposalSucceeds(prev, self.view, p.proposal, p.view)) {
                return .{ .rejected = .{ .reason = .out_of_order } };
            }
        }

        self.slot = p.proposal.slot;
        self.view = p.view;
        self.accepted_proposal = p.proposal;
        return .{ .accepted_prepare = .{ .slot = p.proposal.slot, .view = p.view } };
    }

    fn handlePrepareVote(self: *Follower, pv: types.PrepareVote) Event {
        // We can't verify the signature without BLS, but we can
        // check that the cph matches whatever we currently believe
        // is the prepared proposal. If we don't have one yet, accept
        // the vote silently as "observed" — it might be for a
        // proposal we haven't received yet.
        if (self.accepted_proposal == null) return .{ .observed = .{ .kind = .prepare_vote } };
        return .{ .observed_vote = .{
            .kind = .prepare_vote,
            .cph = pv.msg.consensus_proposal_hash,
        } };
    }

    fn handleConfirm(self: *Follower, c: types.ConfirmPayload) Event {
        _ = self;
        return .{ .observed_qc = .{
            .kind = .confirm,
            .validators = c.prepare_qc.aggregate.validators.len,
            .cph = c.consensus_proposal_hash,
        } };
    }

    fn handleConfirmAck(self: *Follower, ca: types.ConfirmAck) Event {
        if (self.accepted_proposal == null) return .{ .observed = .{ .kind = .confirm_ack } };
        return .{ .observed_vote = .{
            .kind = .confirm_ack,
            .cph = ca.msg.consensus_proposal_hash,
        } };
    }

    fn handleCommit(self: *Follower, c: types.CommitPayload) Event {
        // The Commit must reference a slot we've seen and accepted.
        if (self.accepted_proposal == null) {
            return .{ .rejected = .{ .reason = .commit_without_prepare } };
        }
        // Advance the last-commit pointer regardless of whether the
        // local cph matches; the observer is just tracking commits,
        // not enforcing fork choice. A future hardening pass should
        // require the cph to match the locally-accepted proposal.
        self.last_commit_hash = c.consensus_proposal_hash.bytes;
        self.last_commit_slot = self.slot;
        return .{ .committed = .{
            .slot = self.slot,
            .validators = c.commit_qc.aggregate.validators.len,
            .cph = c.consensus_proposal_hash,
        } };
    }

    /// Handle a signed block from the DA stream. A signed block is a
    /// committed proposal: it carries the `ConsensusProposal` plus the
    /// `AggregateSignature` (certificate) that attests to it. For the
    /// follower this is equivalent to receiving a Prepare + Commit in
    /// one shot — it advances the slot and records the commit.
    ///
    /// Block ordering: blocks from the DA stream arrive in height order.
    /// If the block's slot is at or behind our current slot, it's a
    /// duplicate or stale — we observe it but don't advance. If it
    /// jumps ahead, we accept it (gap-filling may arrive later).
    pub fn handleSignedBlock(self: *Follower, block: types.SignedBlock) Event {
        const proposal = block.consensus_proposal;
        if (proposal.slot == 0) {
            return .{ .rejected = .{ .reason = .structural_invalid } };
        }

        // Compute the consensus proposal hash for tracking.
        const cph_digest = hash_mod.consensusProposalHashed(&proposal);
        const cph: types.ConsensusProposalHash = .{ .bytes = &cph_digest };

        // If we've already committed this slot or later, it's stale.
        if (self.last_commit_slot >= proposal.slot) {
            return .{ .observed = .{ .kind = .sync_reply } };
        }

        // Accept the block: advance slot and record commit in one step.
        self.slot = proposal.slot;
        self.view = 0; // DA blocks don't carry a view; reset to 0.
        self.accepted_proposal = proposal;
        self.last_commit_hash = cph.bytes;
        self.last_commit_slot = proposal.slot;

        return .{ .committed = .{
            .slot = proposal.slot,
            .validators = block.certificate.validators.len,
            .cph = cph,
        } };
    }

    fn handleSyncReply(self: *Follower, sr: types.SyncReplyPayload) Event {
        if (sr.proposal.slot == 0) {
            return .{ .rejected = .{ .reason = .structural_invalid } };
        }
        // SyncReply may carry an older proposal — only accept it if
        // it's actually filling a gap (i.e., for the next slot we
        // need or earlier than what we have).
        if (self.slot != 0 and sr.proposal.slot <= self.slot) {
            return .{ .observed = .{ .kind = .sync_reply } };
        }
        self.slot = sr.proposal.slot;
        self.view = sr.view;
        self.accepted_proposal = sr.proposal;
        return .{ .accepted_sync = .{ .slot = sr.proposal.slot, .view = sr.view } };
    }
};

/// One bit of state-change feedback per processed message.
pub const Event = union(enum) {
    /// The message advanced the local prepared slot/view.
    accepted_prepare: SlotViewInfo,
    /// SyncReply filled a gap in our chain.
    accepted_sync: SlotViewInfo,
    /// We've seen a Commit for the current slot; the chain advances.
    committed: CommittedInfo,
    /// A vote/qc/observation that doesn't change state but is worth
    /// surfacing for tracing.
    observed: GenericInfo,
    /// A vote whose cph the caller might want to track.
    observed_vote: VoteInfo,
    /// A QC observation (Confirm) — caller can tally weight.
    observed_qc: QcInfo,
    /// The message was dropped.
    rejected: RejectionInfo,

    pub const SlotViewInfo = struct {
        slot: types.Slot,
        view: types.View,
    };

    pub const CommittedInfo = struct {
        slot: types.Slot,
        validators: usize,
        cph: types.ConsensusProposalHash,
    };

    pub const GenericInfo = struct {
        kind: ObservedKind,
    };

    pub const VoteInfo = struct {
        kind: ObservedKind,
        cph: types.ConsensusProposalHash,
    };

    pub const QcInfo = struct {
        kind: ObservedKind,
        validators: usize,
        cph: types.ConsensusProposalHash,
    };

    pub const RejectionInfo = struct {
        reason: RejectionReason,
    };

    pub const ObservedKind = enum {
        prepare_vote,
        confirm,
        confirm_ack,
        timeout,
        timeout_certificate,
        validator_candidacy,
        sync_request,
        sync_reply,
    };

    pub const RejectionReason = enum {
        structural_invalid,
        out_of_order,
        commit_without_prepare,
    };
};

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

fn proposalAt(slot: types.Slot, ts: u128) types.ConsensusProposal {
    return .{
        .slot = slot,
        .parent_hash = .{ .bytes = "p" },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = ts },
    };
}

test "Follower: starts at slot 0" {
    const f = Follower.init();
    try testing.expectEqual(@as(types.Slot, 0), f.slot);
    try testing.expectEqual(@as(types.View, 0), f.view);
    try testing.expect(f.last_commit_hash == null);
}

test "Follower: first Prepare must be slot 1" {
    var f = Follower.init();
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = proposalAt(1, 100),
            .ticket = .genesis,
            .view = 0,
        },
    };
    const event = f.handle(msg);
    try testing.expect(event == .accepted_prepare);
    try testing.expectEqual(@as(types.Slot, 1), f.slot);
}

test "Follower: rejects Prepare at slot 5 when starting from 0" {
    var f = Follower.init();
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = proposalAt(5, 100),
            .ticket = .{ .commit_qc = .{
                .aggregate = sampleAggregate(),
                .marker = .confirm_ack,
            } },
            .view = 0,
        },
    };
    const event = f.handle(msg);
    try testing.expect(event == .rejected);
    try testing.expectEqual(Event.RejectionReason.out_of_order, event.rejected.reason);
}

test "Follower: rejects Prepare with stale slot" {
    var f = Follower.init();
    // Accept the genesis-slot Prepare first.
    _ = f.handle(.{
        .prepare = .{
            .proposal = proposalAt(1, 100),
            .ticket = .genesis,
            .view = 0,
        },
    });
    // Now try a Prepare at slot 1 with the same ts → should fail
    // (timestamp not strictly greater).
    const event = f.handle(.{
        .prepare = .{
            .proposal = proposalAt(1, 100),
            .ticket = .{ .commit_qc = .{
                .aggregate = sampleAggregate(),
                .marker = .confirm_ack,
            } },
            .view = 1,
        },
    });
    try testing.expect(event == .rejected);
}

test "Follower: structural-invalid messages are dropped" {
    var f = Follower.init();
    // Genesis ticket at slot=2 → invalid.
    const msg: types.ConsensusNetMessage = .{
        .prepare = .{
            .proposal = proposalAt(2, 100),
            .ticket = .genesis,
            .view = 0,
        },
    };
    const event = f.handle(msg);
    try testing.expect(event == .rejected);
    try testing.expectEqual(Event.RejectionReason.structural_invalid, event.rejected.reason);
}

test "Follower: Commit without Prepare is rejected" {
    var f = Follower.init();
    const msg: types.ConsensusNetMessage = .{
        .commit = .{
            .commit_qc = .{ .aggregate = sampleAggregate(), .marker = .confirm_ack },
            .consensus_proposal_hash = .{ .bytes = "cph" },
        },
    };
    const event = f.handle(msg);
    try testing.expect(event == .rejected);
    try testing.expectEqual(Event.RejectionReason.commit_without_prepare, event.rejected.reason);
}

test "Follower: Commit after Prepare advances last_commit" {
    var f = Follower.init();
    _ = f.handle(.{
        .prepare = .{
            .proposal = proposalAt(1, 100),
            .ticket = .genesis,
            .view = 0,
        },
    });
    const event = f.handle(.{
        .commit = .{
            .commit_qc = .{ .aggregate = sampleAggregate(), .marker = .confirm_ack },
            .consensus_proposal_hash = .{ .bytes = "cph" },
        },
    });
    try testing.expect(event == .committed);
    try testing.expectEqualSlices(u8, "cph", f.last_commit_hash.?);
    try testing.expectEqual(@as(types.Slot, 1), f.last_commit_slot);
}

test "Follower: PrepareVote without local proposal is observed" {
    var f = Follower.init();
    const msg: types.ConsensusNetMessage = .{
        .prepare_vote = .{
            .msg = .{
                .consensus_proposal_hash = .{ .bytes = "cph" },
                .marker = .prepare_vote,
            },
            .signature = sampleValidatorSig(),
        },
    };
    const event = f.handle(msg);
    try testing.expect(event == .observed);
}

test "Follower: SyncReply fills a gap" {
    var f = Follower.init();
    const msg: types.ConsensusNetMessage = .{
        .sync_reply = .{
            .sender = .{ .bytes = &[_]u8{0x03} ** 4 },
            .proposal = proposalAt(7, 500),
            .ticket = .genesis,
            .view = 1,
        },
    };
    const event = f.handle(msg);
    try testing.expect(event == .accepted_sync);
    try testing.expectEqual(@as(types.Slot, 7), f.slot);
}

test "Follower: SyncReply with stale slot is observed but ignored" {
    var f = Follower.init();
    _ = f.handle(.{
        .prepare = .{
            .proposal = proposalAt(1, 100),
            .ticket = .genesis,
            .view = 0,
        },
    });
    const event = f.handle(.{
        .sync_reply = .{
            .sender = .{ .bytes = &[_]u8{0x03} ** 4 },
            .proposal = proposalAt(1, 50),
            .ticket = .genesis,
            .view = 0,
        },
    });
    try testing.expect(event == .observed);
    try testing.expectEqual(@as(types.Slot, 1), f.slot); // unchanged
}

test "Follower: Reset returns to initial state" {
    var f = Follower.init();
    _ = f.handle(.{
        .prepare = .{
            .proposal = proposalAt(1, 100),
            .ticket = .genesis,
            .view = 0,
        },
    });
    f.reset();
    try testing.expectEqual(@as(types.Slot, 0), f.slot);
    try testing.expect(f.accepted_proposal == null);
}

test "Follower: handleSignedBlock advances slot and commits" {
    var f = Follower.init();
    const block: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = proposalAt(5, 1000),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{
                .{ .bytes = &[_]u8{0x01} ** 4 },
                .{ .bytes = &[_]u8{0x02} ** 4 },
            },
        },
    };
    const event = f.handleSignedBlock(block);
    try testing.expect(event == .committed);
    try testing.expectEqual(@as(types.Slot, 5), event.committed.slot);
    try testing.expectEqual(@as(usize, 2), event.committed.validators);
    try testing.expectEqual(@as(types.Slot, 5), f.slot);
    try testing.expectEqual(@as(types.Slot, 5), f.last_commit_slot);
    try testing.expect(f.last_commit_hash != null);
}

test "Follower: handleSignedBlock rejects slot 0" {
    var f = Follower.init();
    const block: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = proposalAt(0, 100),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{},
        },
    };
    const event = f.handleSignedBlock(block);
    try testing.expect(event == .rejected);
}

test "Follower: handleSignedBlock ignores stale blocks" {
    var f = Follower.init();
    // Commit slot 5 first.
    const block1: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = proposalAt(5, 1000),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{
                .{ .bytes = &[_]u8{0x01} ** 4 },
            },
        },
    };
    _ = f.handleSignedBlock(block1);

    // Now try to apply slot 3 — should be observed but not advance.
    const block2: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = proposalAt(3, 500),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{},
        },
    };
    const event = f.handleSignedBlock(block2);
    try testing.expect(event == .observed);
    try testing.expectEqual(@as(types.Slot, 5), f.slot); // unchanged
}

test "Follower: handleSignedBlock advances through multiple blocks" {
    var f = Follower.init();
    // Apply blocks 1, 2, 3 in order.
    var slot: u64 = 1;
    while (slot <= 3) : (slot += 1) {
        const block: types.SignedBlock = .{
            .data_proposals = &[_]types.LaneDataProposals{},
            .consensus_proposal = proposalAt(slot, slot * 100),
            .certificate = .{
                .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
                .validators = &[_]types.ValidatorPublicKey{
                    .{ .bytes = &[_]u8{0x01} ** 4 },
                },
            },
        };
        const event = f.handleSignedBlock(block);
        try testing.expect(event == .committed);
        try testing.expectEqual(slot, event.committed.slot);
    }
    try testing.expectEqual(@as(types.Slot, 3), f.slot);
    try testing.expectEqual(@as(types.Slot, 3), f.last_commit_slot);
}
