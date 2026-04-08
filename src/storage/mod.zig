//! Storage subsystem: persistent, append-oriented block and lane
//! storage with integrity checks. See `docs/implementation-plan.md`
//! for the durable boundary definition.

pub const block_store = @import("block_store.zig");

test {
    _ = block_store;
}
