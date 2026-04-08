//! State subsystem: block replay engine, contract state tracking,
//! and settlement logic. See Phase 6 in `docs/implementation-plan.md`.

pub const replay = @import("replay.zig");

test {
    _ = replay;
}
