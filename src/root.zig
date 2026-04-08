//! Zyli — a Zig implementation of the Hyli protocol.
//!
//! `root.zig` is the only entry point downstream consumers should rely on.
//! Each subsystem corresponds to a durable responsibility from the
//! implementation plan, not to a Rust crate boundary.

pub const model = @import("model/mod.zig");
pub const crypto = @import("crypto/mod.zig");
pub const wire = @import("wire/mod.zig");
pub const node = @import("node/mod.zig");
pub const storage = @import("storage/mod.zig");
pub const state = @import("state/mod.zig");

test {
    _ = model;
    _ = crypto;
    _ = wire;
    _ = node;
    _ = storage;
    _ = state;
}
