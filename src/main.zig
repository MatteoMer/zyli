//! Node executable entry point.
//!
//! This binary is intentionally minimal: configuration parsing, logging
//! setup, and a hand-off into the node runtime live here. All protocol logic
//! belongs inside `zyli/node` and below.

const std = @import("std");
const zyli = @import("zyli");

pub fn main() !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("zyli: not yet runnable — see docs/implementation-plan.md\n", .{});
    try stdout.flush();
    _ = zyli;
}
