//! `zyli/node` — node modes (observer, follower, lane manager,
//! validator) and the supporting state machines.
//!
//! Today this is a single tiny piece: a structural consensus
//! follower that folds borsh-decoded `ConsensusNetMessage` values
//! into events without doing any cryptographic verification. The
//! observer subcommand can wire it in once a per-canal context
//! exists; for now it stands on its own as the Phase 5 starting
//! point.

pub const follower = @import("follower.zig");
pub const handshake = @import("handshake.zig");
pub const da_sync = @import("da_sync.zig");
pub const identity = @import("identity.zig");

test {
    _ = follower;
    _ = handshake;
    _ = da_sync;
    _ = identity;
    _ = @import("integration_test.zig");
}
