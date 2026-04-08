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
const types = zyli.model.types;

const Subcommand = enum {
    help,
    observe,
    replay,
    record,
    da_sync,
};

fn parseSubcommand(arg: []const u8) ?Subcommand {
    if (std.mem.eql(u8, arg, "observe")) return .observe;
    if (std.mem.eql(u8, arg, "replay")) return .replay;
    if (std.mem.eql(u8, arg, "record")) return .record;
    if (std.mem.eql(u8, arg, "da-sync")) return .da_sync;
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
        \\    observe <host>:<port>          Connect to a Hyli peer, decode, print summaries.
        \\    record <host>:<port> <file>    Connect, capture framed bytes to a file.
        \\    replay <file>                  Decode framed bytes from a file using the same pipeline.
        \\    da-sync <host>:<port> [height] Sync signed blocks from a DA server.
        \\    help                           Show this help text.
        \\
        \\OPTIONS:
        \\    --identity <path>              Load or create a persistent BLS keypair at <path>.
        \\                                   Without this, a fresh ephemeral key is used per run.
        \\    --store <path>                 (da-sync) Persist blocks to file. Resumes on restart.
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
            try observe(allocator, stdout, args[2], resolveIdentity(args));
        },
        .replay => {
            if (args.len < 3) {
                try stdout.writeAll("replay: missing <file> argument\n");
                return;
            }
            try replay(allocator, stdout, args[2]);
        },
        .record => {
            if (args.len < 4) {
                try stdout.writeAll("record: missing <host>:<port> <file> arguments\n");
                return;
            }
            try record(allocator, stdout, args[2], args[3], resolveIdentity(args));
        },
        .da_sync => {
            if (args.len < 3) {
                try stdout.writeAll("da-sync: missing <host>:<port> argument\n");
                return;
            }
            const start: u64 = if (args.len >= 4)
                std.fmt.parseUnsigned(u64, args[3], 10) catch {
                    try stdout.print("da-sync: invalid height `{s}`\n", .{args[3]});
                    return;
                }
            else
                0;
            const store_path = resolveStoreFlag(args);
            try zyli.node.da_sync.syncAndReport(allocator, stdout, args[2], start, store_path);
        },
    }
}

/// Resolve the --store <path> flag for the da-sync subcommand.
fn resolveStoreFlag(args: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--store") and i + 1 < args.len) {
            return args[i + 1];
        }
    }
    return null;
}

/// Resolve the BLS secret key: if an `--identity <path>` flag was given,
/// load or generate at that path; otherwise generate a fresh ephemeral key.
fn resolveIdentity(args: []const []const u8) [4]u64 {
    // Scan for --identity <path> anywhere in the argument list.
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--identity") and i + 1 < args.len) {
            return zyli.node.identity.loadOrGenerate(args[i + 1]) catch {
                return zyli.node.identity.generateEphemeralKey();
            };
        }
    }
    return zyli.node.identity.generateEphemeralKey();
}

/// Connect to a Hyli peer at `addr_port` (e.g. `127.0.0.1:4242`),
/// perform a BLS-signed handshake, then pull frames in a loop,
/// printing one line per frame. Returns when the connection closes
/// cleanly.
fn observe(
    allocator: std.mem.Allocator,
    stdout: anytype,
    addr_port: []const u8,
    sk: [4]u64,
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

    // --- BLS handshake ---
    // Send a signed Hello to the peer. The key is either ephemeral or
    // loaded from --identity <path>.
    const now_ms: u128 = @intCast(std.time.milliTimestamp());
    var hello_bundle = zyli.node.handshake.buildHelloFrame(
        allocator,
        types.ConsensusNetMessage,
        .{
            .sk = sk,
            .name = "zyli-observer",
            .p2p_public_address = addr_port,
            .da_public_address = "0.0.0.0:0",
            .start_timestamp = .{ .millis = now_ms },
            .handshake_timestamp = .{ .millis = now_ms },
            .canal = "consensus",
        },
    ) catch |err| {
        try stdout.print("observe: handshake build failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer hello_bundle.deinit(allocator);

    // Send the framed Hello.
    stream.writeAll(hello_bundle.framed) catch |err| {
        try stdout.print("observe: handshake send failed: {s}\n", .{@errorName(err)});
        return;
    };
    try stdout.print("observe: handshake Hello sent ({d} bytes), waiting for Verack…\n", .{hello_bundle.framed.len});
    try stdout.flush();

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

    // Read the Verack response (the first frame after Hello).
    const verack_frame = blk: {
        const maybe = frames.nextFrame(&stream_reader) catch |err| {
            try stdout.print("observe: handshake Verack read error: {s}\n", .{@errorName(err)});
            return;
        };
        break :blk maybe orelse {
            try stdout.print("observe: peer closed before sending Verack\n", .{});
            return;
        };
    };

    // Decode the Verack frame. It should be P2PTcpMessage::Handshake(Verack(...)).
    const verack_kind = zyli.wire.tcp_message.classifyFrame(verack_frame);
    switch (verack_kind) {
        .ping => {
            try stdout.print("observe: expected Verack, got PING\n", .{});
            return;
        },
        .data => {
            // Try to decode as a P2PTcpMessage to see if it's a Handshake.
            var decoded = zyli.wire.protocol.decodeP2PTcpMessage(
                allocator,
                types.ConsensusNetMessage,
                verack_frame,
            ) catch {
                try stdout.print("observe: expected Verack, got undecipherable frame ({d} bytes)\n", .{verack_frame.len});
                return;
            };
            defer decoded.deinit();

            switch (decoded.value) {
                .handshake => |hs| switch (hs) {
                    .verack => |vp| {
                        const peer_name = vp.signed_node_connection_data.msg.name;
                        // Verify the peer's BLS signature on the NodeConnectionData.
                        const verack_sig_ok = zyli.crypto.bls.verifySignedByValidator(
                            allocator,
                            types.NodeConnectionData,
                            vp.signed_node_connection_data,
                        ) catch false;
                        if (verack_sig_ok) {
                            try stdout.print("observe: handshake complete! peer={s} (verified)\n", .{peer_name});
                        } else {
                            try stdout.print("observe: handshake complete! peer={s} (BLS UNVERIFIED)\n", .{peer_name});
                        }
                    },
                    .hello => {
                        try stdout.print("observe: expected Verack, got Hello\n", .{});
                        return;
                    },
                },
                .data => {
                    try stdout.print("observe: expected Verack, got Data frame\n", .{});
                    return;
                },
            }
        },
    }

    try stdout.flush();

    // --- Enter the main frame-reading loop ---
    var follower = zyli.node.follower.Follower.init();

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
            .ping => {
                try stdout.print("frame {d}: PING\n", .{frame_count});
                // Echo the PING back to keep the connection alive.
                const ping_framed = zyli.wire.framing.encodeFrameAlloc(allocator, zyli.wire.tcp_message.ping_magic) catch continue;
                defer allocator.free(ping_framed);
                stream.writeAll(ping_framed) catch {};
            },
            .data => try printDataFrame(allocator, stdout, frame_count, frame, &follower),
        }
        try stdout.flush();
    }
}

/// Connect to a Hyli peer and write the raw framed bytes to a file. Pairs
/// with `replay` for offline analysis: capture once, decode many times.
///
/// File format matches what `replay` consumes — the on-the-wire framing
/// (4-byte BE length prefix + payload) is written verbatim. Each frame
/// is also classified and printed to stdout in real time so the user
/// sees progress.
fn record(
    allocator: std.mem.Allocator,
    stdout: anytype,
    addr_port: []const u8,
    out_path: []const u8,
    sk: [4]u64,
) !void {
    const sep = std.mem.lastIndexOfScalar(u8, addr_port, ':') orelse {
        try stdout.print("record: address must be host:port, got `{s}`\n", .{addr_port});
        return;
    };
    const host = addr_port[0..sep];
    const port_str = addr_port[sep + 1 ..];
    const port = std.fmt.parseUnsigned(u16, port_str, 10) catch {
        try stdout.print("record: invalid port `{s}`\n", .{port_str});
        return;
    };

    const address = std.net.Address.parseIp(host, port) catch |err| {
        try stdout.print("record: failed to parse host `{s}`: {s}\n", .{ host, @errorName(err) });
        return;
    };

    var out_file = std.fs.cwd().createFile(out_path, .{ .truncate = true }) catch |err| {
        try stdout.print("record: failed to open `{s}` for write: {s}\n", .{
            out_path,
            @errorName(err),
        });
        return;
    };
    defer out_file.close();

    try stdout.print("record: connecting to {s}:{d}, writing to {s}\n", .{ host, port, out_path });
    try stdout.flush();
    var stream = std.net.tcpConnectToAddress(address) catch |err| {
        try stdout.print("record: connection failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer stream.close();

    // --- BLS handshake (same as observe) ---
    const now_ms: u128 = @intCast(std.time.milliTimestamp());
    var hello_bundle = zyli.node.handshake.buildHelloFrame(
        allocator,
        types.ConsensusNetMessage,
        .{
            .sk = sk,
            .name = "zyli-recorder",
            .p2p_public_address = addr_port,
            .da_public_address = "0.0.0.0:0",
            .start_timestamp = .{ .millis = now_ms },
            .handshake_timestamp = .{ .millis = now_ms },
            .canal = "consensus",
        },
    ) catch |err| {
        try stdout.print("record: handshake build failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer hello_bundle.deinit(allocator);

    stream.writeAll(hello_bundle.framed) catch |err| {
        try stdout.print("record: handshake send failed: {s}\n", .{@errorName(err)});
        return;
    };
    try stdout.print("record: handshake Hello sent ({d} bytes), waiting for Verack…\n", .{hello_bundle.framed.len});
    try stdout.flush();

    const StreamReader = struct {
        inner: std.net.Stream,
        pub fn read(self: *@This(), buf: []u8) !usize {
            return self.inner.read(buf);
        }
    };
    var stream_reader: StreamReader = .{ .inner = stream };
    var frames = zyli.wire.framing.StreamFrameReader(*StreamReader).init(allocator);
    defer frames.deinit();

    // Read and validate the Verack response.
    const verack_frame = blk: {
        const maybe = frames.nextFrame(&stream_reader) catch |err| {
            try stdout.print("record: handshake Verack read error: {s}\n", .{@errorName(err)});
            return;
        };
        break :blk maybe orelse {
            try stdout.print("record: peer closed before sending Verack\n", .{});
            return;
        };
    };

    const verack_kind = zyli.wire.tcp_message.classifyFrame(verack_frame);
    switch (verack_kind) {
        .ping => {
            try stdout.print("record: expected Verack, got PING\n", .{});
            return;
        },
        .data => {
            var decoded = zyli.wire.protocol.decodeP2PTcpMessage(
                allocator,
                types.ConsensusNetMessage,
                verack_frame,
            ) catch {
                try stdout.print("record: expected Verack, got undecipherable frame ({d} bytes)\n", .{verack_frame.len});
                return;
            };
            defer decoded.deinit();

            switch (decoded.value) {
                .handshake => |hs| switch (hs) {
                    .verack => |vp| {
                        const peer_name = vp.signed_node_connection_data.msg.name;
                        const verack_sig_ok = zyli.crypto.bls.verifySignedByValidator(
                            allocator,
                            types.NodeConnectionData,
                            vp.signed_node_connection_data,
                        ) catch false;
                        if (verack_sig_ok) {
                            try stdout.print("record: handshake complete! peer={s} (verified)\n", .{peer_name});
                        } else {
                            try stdout.print("record: handshake complete! peer={s} (BLS UNVERIFIED)\n", .{peer_name});
                        }
                    },
                    .hello => {
                        try stdout.print("record: expected Verack, got Hello\n", .{});
                        return;
                    },
                },
                .data => {
                    try stdout.print("record: expected Verack, got Data frame\n", .{});
                    return;
                },
            }
        },
    }

    try stdout.flush();

    var frame_count: usize = 0;
    var total_bytes_written: usize = 0;
    while (true) {
        const maybe_frame = frames.nextFrame(&stream_reader) catch |err| {
            try stdout.print("record: frame read error after {d} frames: {s}\n", .{
                frame_count,
                @errorName(err),
            });
            return;
        };
        const frame = maybe_frame orelse {
            try stdout.print("record: peer closed cleanly after {d} frames ({d} bytes)\n", .{
                frame_count,
                total_bytes_written,
            });
            return;
        };
        frame_count += 1;
        // Re-frame the payload with its 4-byte BE length prefix and write
        // to disk. The on-the-wire bytes are exactly what `replay` will
        // re-decode.
        var len_prefix: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_prefix, @intCast(frame.len), .big);
        try out_file.writeAll(&len_prefix);
        try out_file.writeAll(frame);
        total_bytes_written += 4 + frame.len;

        const kind = zyli.wire.tcp_message.classifyFrame(frame);
        switch (kind) {
            .ping => {
                try stdout.print("frame {d}: PING\n", .{frame_count});
                // Echo PING back.
                const ping_framed = zyli.wire.framing.encodeFrameAlloc(allocator, zyli.wire.tcp_message.ping_magic) catch continue;
                defer allocator.free(ping_framed);
                stream.writeAll(ping_framed) catch {};
            },
            .data => try stdout.print("frame {d}: DATA ({d} bytes)\n", .{ frame_count, frame.len }),
        }
        try stdout.flush();
    }
}

/// Decode framed bytes from a file using the same pipeline as `observe`.
/// Useful for offline analysis of captured testnet traffic — feed
/// previously-recorded P2PTcpMessage frames in and get the same decode +
/// validate + format output without needing a live socket.
///
/// File format: a sequence of length-delimited frames using the same
/// 4-byte BE length prefix `tokio_util::LengthDelimitedCodec` produces
/// (see `src/wire/framing.zig`).
fn replay(
    allocator: std.mem.Allocator,
    stdout: anytype,
    path: []const u8,
) !void {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("replay: failed to open `{s}`: {s}\n", .{ path, @errorName(err) });
        return;
    };
    defer file.close();
    try stdout.print("replay: reading {s}\n", .{path});
    try stdout.flush();

    // Adapter: StreamFrameReader is generic over a `read([]u8) !usize`
    // shape. std.fs.File.read matches that directly.
    const FileReader = struct {
        inner: std.fs.File,
        pub fn read(self: *@This(), buf: []u8) !usize {
            return self.inner.read(buf);
        }
    };
    var file_reader: FileReader = .{ .inner = file };
    var frames = zyli.wire.framing.StreamFrameReader(*FileReader).init(allocator);
    defer frames.deinit();

    var follower = zyli.node.follower.Follower.init();

    var frame_count: usize = 0;
    while (true) {
        const maybe_frame = frames.nextFrame(&file_reader) catch |err| {
            try stdout.print("replay: frame read error after {d} frames: {s}\n", .{
                frame_count,
                @errorName(err),
            });
            return;
        };
        const frame = maybe_frame orelse {
            try stdout.print("replay: end of file after {d} frames\n", .{frame_count});
            return;
        };
        frame_count += 1;
        const kind = zyli.wire.tcp_message.classifyFrame(frame);
        switch (kind) {
            .ping => try stdout.print("frame {d}: PING ({d} bytes)\n", .{ frame_count, frame.len }),
            .data => try printDataFrame(allocator, stdout, frame_count, frame, &follower),
        }
        try stdout.flush();
    }
}

/// Decode a `P2PTcpMessage<ConsensusNetMessage>` from a Data frame and
/// print a detailed one-line summary plus the structural validation
/// verdict and the follower-state event. We assume the canal is
/// `"p2p"` for now — until the observer learns to track per-canal
/// context, treating every Data frame as a consensus message is the
/// right default.
fn printDataFrame(
    allocator: std.mem.Allocator,
    stdout: anytype,
    frame_index: usize,
    frame: []const u8,
    follower: *zyli.node.follower.Follower,
) !void {
    var decoded = zyli.wire.protocol.decodeP2PTcpMessage(
        allocator,
        zyli.model.types.ConsensusNetMessage,
        frame,
    ) catch |err| {
        try stdout.print("frame {d}: DATA ({d} bytes) — decode error: {s}\n", .{
            frame_index,
            frame.len,
            @errorName(err),
        });
        return;
    };
    defer decoded.deinit();
    const ok = zyli.wire.protocol.validateMessage(
        zyli.model.types.ConsensusNetMessage,
        decoded.value,
    );
    const verdict: []const u8 = if (ok) "ok" else "INVALID";
    try stdout.print("frame {d}: DATA ({d} bytes) — ", .{ frame_index, frame.len });
    try zyli.wire.protocol.formatMessage(
        zyli.model.types.ConsensusNetMessage,
        decoded.value,
        stdout,
    );
    try stdout.print(" [{s}]", .{verdict});

    // Fold the message through the follower and report what changed.
    // Handshake-only frames don't reach here; this only runs on
    // P2PTcpMessage::Data variants whose inner type is
    // ConsensusNetMessage.
    if (decoded.value == .data) {
        const event = follower.handle(decoded.value.data);
        try printFollowerEvent(stdout, event);

        // Cryptographic verification: run the BLS verifier over every
        // signature embedded in the message. We compute the verdict
        // separately from the structural one because pairing is slow
        // and we want the structural reject to short-circuit it. The
        // result is reported as `bls=ok|BAD|err` so live testnet
        // traffic can be eyeballed for forged or stale signatures.
        const bls_verdict = zyli.crypto.consensus_verify.verifyConsensusMessage(
            allocator,
            decoded.value.data,
        ) catch |err| {
            try stdout.print(" {{bls=err: {s}}}", .{@errorName(err)});
            try stdout.print("\n", .{});
            return;
        };
        const bls_label: []const u8 = if (bls_verdict) "ok" else "BAD";
        try stdout.print(" {{bls={s}}}", .{bls_label});
    }
    try stdout.print("\n", .{});
}

fn printFollowerEvent(stdout: anytype, event: zyli.node.follower.Event) !void {
    switch (event) {
        .accepted_prepare => |info| try stdout.print(
            " {{follower: prepared slot={d}/view={d}}}",
            .{ info.slot, info.view },
        ),
        .accepted_sync => |info| try stdout.print(
            " {{follower: sync-fill slot={d}/view={d}}}",
            .{ info.slot, info.view },
        ),
        .committed => |info| try stdout.print(
            " {{follower: committed slot={d} validators={d}}}",
            .{ info.slot, info.validators },
        ),
        .gap_detected => |info| try stdout.print(
            " {{follower: GAP our_slot={d} their_slot={d}}}",
            .{ info.our_slot, info.their_slot },
        ),
        .observed => |info| try stdout.print(" {{follower: observed {s}}}", .{@tagName(info.kind)}),
        .observed_vote => |info| try stdout.print(
            " {{follower: vote {s}}}",
            .{@tagName(info.kind)},
        ),
        .observed_qc => |info| try stdout.print(
            " {{follower: qc {s} validators={d}}}",
            .{ @tagName(info.kind), info.validators },
        ),
        .rejected => |info| try stdout.print(
            " {{follower: REJECTED {s}}}",
            .{@tagName(info.reason)},
        ),
    }
}
