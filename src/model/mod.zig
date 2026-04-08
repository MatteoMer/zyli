//! `zyli/model` — protocol and storage types, plus the codecs and hashing
//! primitives required to reproduce Hyli's exact byte and digest formats.
//!
//! Membership rules:
//! - No networking, storage backends, timers, or subprocess logic.
//! - Pure CPU-bound transforms over byte buffers and protocol structs.
//! - All consensus-critical encodings live here so that fixture-based
//!   compatibility tests have a single import surface.

pub const borsh = @import("borsh.zig");
pub const types = @import("types.zig");
pub const hash = @import("hash.zig");

test {
    _ = borsh;
    _ = types;
    _ = hash;
    _ = @import("compat_test.zig");
}
