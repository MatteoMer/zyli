//! Node executable entry point.
//!
//! Intentionally minimal: configuration parsing, logging setup, and a
//! hand-off into the node runtime live here. All protocol logic belongs
//! inside `zyli/node` and below.
//!
//! Today the executable supports a single subcommand: `observe ADDR:PORT`,
//! which connects to a Hyli peer, decodes the framing layer, classifies
//! each frame as `PING` vs `Data`, and prints a one-line summary. It is
//! the simplest possible exercise of the wire layer end-to-end and exists
//! so the wire-layer code has a real-world consumer to keep it honest.

const std = @import("std");
const zyli = @import("zyli");

const Subcommand = enum {
    help,
    observe,
};

fn parseSubcommand(arg: []const u8) ?Subcommand {
    if (std.mem.eql(u8, arg, "observe")) return .observe;
    if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "help"))
        return .help;
    return null;
}

fn printUsage(stdout: anytype) !void {
    try stdout.writeAll(
        \\zyli — observer-grade Hyli node (early development)
        \\
        \\USAGE:
        \\    zyli <subcommand>
        \\
        \\SUBCOMMANDS:
        \\    observe <host>:<port>    Connect to a Hyli peer, decode frames, print message labels.
        \\    help                     Show this help text.
        \\
        \\See docs/implementation-plan.md for the full roadmap.
        \\
    );
}

pub fn main() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage(stdout);
        return;
    }

    const sub = parseSubcommand(args[1]) orelse {
        try stdout.print("unknown subcommand: {s}\n\n", .{args[1]});
        try printUsage(stdout);
        return;
    };

    switch (sub) {
        .help => try printUsage(stdout),
        .observe => {
            if (args.len < 3) {
                try stdout.writeAll("observe: missing <host>:<port> argument\n");
                return;
            }
            try observe(allocator, stdout, args[2]);
        },
    }
}

/// Connect to a Hyli peer at `addr_port` (e.g. `127.0.0.1:4242`) and pull
/// frames in a loop, printing one line per frame. Returns when the
/// connection closes cleanly.
///
/// This intentionally does NOT speak the handshake yet — that is BLS
/// territory. Pinging Hyli's TCP listener with random bytes will get the
/// connection closed, but the framing layer is exercised end-to-end either
/// way as long as some bytes flow.
fn observe(
    allocator: std.mem.Allocator,
    stdout: anytype,
    addr_port: []const u8,
) !void {
    const sep = std.mem.lastIndexOfScalar(u8, addr_port, ':') orelse {
        try stdout.print("observe: address must be host:port, got `{s}`\n", .{addr_port});
        return;
    };
    const host = addr_port[0..sep];
    const port_str = addr_port[sep + 1 ..];
    const port = std.fmt.parseUnsigned(u16, port_str, 10) catch {
        try stdout.print("observe: invalid port `{s}`\n", .{port_str});
        return;
    };

    const address = std.net.Address.parseIp(host, port) catch |err| {
        try stdout.print("observe: failed to parse host `{s}`: {s}\n", .{ host, @errorName(err) });
        return;
    };

    try stdout.print("observe: connecting to {s}:{d}\n", .{ host, port });
    try stdout.flush();
    var stream = std.net.tcpConnectToAddress(address) catch |err| {
        try stdout.print("observe: connection failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer stream.close();

    // Adapter: the StreamFrameReader is generic over a `read([]u8) !usize`
    // method. `std.net.Stream.read` matches that shape directly.
    const StreamReader = struct {
        inner: std.net.Stream,
        pub fn read(self: *@This(), buf: []u8) !usize {
            return self.inner.read(buf);
        }
    };
    var stream_reader: StreamReader = .{ .inner = stream };
    var frames = zyli.wire.framing.StreamFrameReader(*StreamReader).init(allocator);
    defer frames.deinit();

    var frame_count: usize = 0;
    while (true) {
        const maybe_frame = frames.nextFrame(&stream_reader) catch |err| {
            try stdout.print("observe: frame read error after {d} frames: {s}\n", .{
                frame_count,
                @errorName(err),
            });
            return;
        };
        const frame = maybe_frame orelse {
            try stdout.print("observe: peer closed cleanly after {d} frames\n", .{frame_count});
            return;
        };
        frame_count += 1;
        const kind = zyli.wire.tcp_message.classifyFrame(frame);
        switch (kind) {
            .ping => try stdout.print("frame {d}: PING ({d} bytes)\n", .{ frame_count, frame.len }),
            .data => try stdout.print("frame {d}: DATA ({d} bytes)\n", .{ frame_count, frame.len }),
        }
        try stdout.flush();
    }
}
