//! Length-delimited TCP framing.
//!
//! Hyli wraps every P2P payload in a default `tokio_util::LengthDelimitedCodec`
//! frame, which is a 4-byte BIG-ENDIAN length prefix followed by `len` bytes
//! of payload. This module exposes a small encoder + a streaming decoder so
//! the higher layers can build/parse frames without touching raw byte
//! arithmetic.
//!
//! The decoder is intentionally pull-based: callers feed bytes in and ask
//! for the next frame. This makes it trivial to drop in over an `std.net`
//! socket later, but also lets the unit tests poke at the boundary
//! conditions (partial header, partial body, oversized frame) without any
//! I/O at all.

const std = @import("std");

/// Errors the framing layer can surface to its caller.
pub const Error = error{
    BufferTooShort,
    FrameTooLarge,
    OutOfMemory,
};

/// Maximum payload length we are willing to accept on the wire. Hyli does
/// not configure `LengthDelimitedCodec::set_max_frame_length` for the
/// default P2P codec, so the upstream limit is `usize::MAX` on the Rust
/// side. We pin a much smaller cap here on purpose: a 64 MiB ceiling is
/// generous enough for any realistic protocol message and doubles as a
/// resource-exhaustion safeguard for an observer-grade node.
pub const default_max_frame_len: usize = 64 * 1024 * 1024;

/// Encode a single frame into `out`. The destination must have at least
/// `4 + payload.len()` bytes of capacity available; this function does not
/// allocate.
pub fn encodeFrameInto(out: []u8, payload: []const u8) Error!usize {
    if (out.len < 4 + payload.len) return Error.BufferTooShort;
    const len: u32 = std.math.cast(u32, payload.len) orelse return Error.FrameTooLarge;
    std.mem.writeInt(u32, out[0..4], len, .big);
    @memcpy(out[4 .. 4 + payload.len], payload);
    return 4 + payload.len;
}

/// Encode a single frame into a freshly-allocated buffer owned by the
/// caller. Used in tests and one-shot encode helpers.
pub fn encodeFrameAlloc(allocator: std.mem.Allocator, payload: []const u8) Error![]u8 {
    if (payload.len > std.math.maxInt(u32)) return Error.FrameTooLarge;
    const buf = allocator.alloc(u8, 4 + payload.len) catch return Error.OutOfMemory;
    errdefer allocator.free(buf);
    const written = try encodeFrameInto(buf, payload);
    std.debug.assert(written == buf.len);
    return buf;
}

/// Result of a streaming decode attempt.
pub const DecodeResult = union(enum) {
    /// A complete frame was extracted. The slice borrows from the input
    /// buffer that was passed to the decoder.
    frame: []const u8,
    /// Not enough bytes for a full frame yet. The decoder reports how many
    /// more bytes are needed before another `decode` call is worth trying.
    need_more: usize,
};

/// Stream-driven frame reader. Wraps a growable buffer and a generic
/// reader and exposes `nextFrame` — the simplest possible "give me one
/// complete frame, blocking on the underlying source as needed" API. This
/// is what the observer drives once it has a `std.net.Stream`.
///
/// `Reader` is comptime-duck-typed: any value with a method
/// `read(self, []u8) !usize` works (`std.net.Stream`, `std.fs.File`,
/// or a test fake). Returning `0` from `read` is treated as EOF.
///
/// Buffer management:
/// - The internal `buf` grows as bytes arrive and shrinks (via memmove)
///   when the consumed prefix would otherwise dominate the buffer. This
///   keeps the steady-state memory bounded by `max_frame_len`.
/// - Returned slices borrow from the internal buffer and remain valid
///   until the next `nextFrame` call. Callers that need to keep frame
///   bytes longer should copy them out.
pub fn StreamFrameReader(comptime Reader: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        buf: std.ArrayList(u8),
        /// Number of bytes at the start of `buf` that have already been
        /// returned to the caller. Compacted away once it crosses 4 KiB
        /// or half the buffer length, whichever is larger.
        consumed: usize = 0,
        max_frame_len: usize = default_max_frame_len,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .buf = .empty,
            };
        }

        pub fn initWithLimit(allocator: std.mem.Allocator, max: usize) Self {
            return .{
                .allocator = allocator,
                .buf = .empty,
                .max_frame_len = max,
            };
        }

        pub fn deinit(self: *Self) void {
            self.buf.deinit(self.allocator);
            self.consumed = 0;
        }

        /// Read at most one frame from the wire. Returns `null` on EOF
        /// after a clean (mid-buffer) cut, or an error if EOF arrives in
        /// the middle of a frame. The returned slice is valid until the
        /// next call.
        pub fn nextFrame(self: *Self, reader: Reader) !?[]const u8 {
            while (true) {
                // Try to decode a frame from whatever is already buffered.
                const buffered = self.buf.items[self.consumed..];
                var decoder = FrameDecoder.initWithLimit(buffered, self.max_frame_len);
                const result = try decoder.decode();
                switch (result) {
                    .frame => |bytes| {
                        // Advance the consumed cursor past the 4-byte
                        // header and the payload, then opportunistically
                        // compact.
                        self.consumed += 4 + bytes.len;
                        self.maybeCompact();
                        return bytes;
                    },
                    .need_more => {},
                }
                // Read more bytes from the underlying source. Grow the
                // buffer by a generous chunk so a back-to-back frame
                // burst doesn't churn the allocator.
                const chunk = try self.buf.addManyAsSlice(self.allocator, 4096);
                const n = try reader.read(chunk);
                if (n == 0) {
                    // EOF: shrink the buffer back to whatever was
                    // actually read (none) and report EOF only if we
                    // were sitting on a clean cut.
                    self.buf.items.len -= chunk.len;
                    if (self.consumed == self.buf.items.len) return null;
                    return error.UnexpectedEof;
                }
                // Trim the over-allocated tail back to what was read.
                self.buf.items.len -= chunk.len - n;
            }
        }

        fn maybeCompact(self: *Self) void {
            // Compact when more than half the buffer is dead bytes AND
            // the dead prefix is at least 4 KiB. The thresholds avoid
            // memmove-on-every-frame in the common case while still
            // bounding the steady-state buffer size.
            if (self.consumed < 4096) return;
            if (self.consumed * 2 < self.buf.items.len) return;
            const live = self.buf.items[self.consumed..];
            std.mem.copyForwards(u8, self.buf.items[0..live.len], live);
            self.buf.items.len = live.len;
            self.consumed = 0;
        }
    };
}

/// Pull-based decoder over an in-memory byte buffer. The decoder does not
/// own the buffer — it carries a cursor into it. Callers refill the buffer
/// from a socket and then call `decode` in a loop until they get
/// `need_more`.
pub const FrameDecoder = struct {
    buf: []const u8,
    pos: usize = 0,
    max_frame_len: usize = default_max_frame_len,

    pub fn init(buf: []const u8) FrameDecoder {
        return .{ .buf = buf };
    }

    pub fn initWithLimit(buf: []const u8, max: usize) FrameDecoder {
        return .{ .buf = buf, .max_frame_len = max };
    }

    pub fn remaining(self: FrameDecoder) usize {
        return self.buf.len - self.pos;
    }

    /// Try to extract one complete frame from the buffer. The returned
    /// slice is a view into `self.buf` and is valid until the next call
    /// that mutates the buffer.
    pub fn decode(self: *FrameDecoder) Error!DecodeResult {
        if (self.remaining() < 4) {
            return DecodeResult{ .need_more = 4 - self.remaining() };
        }
        const len_bytes = self.buf[self.pos .. self.pos + 4];
        const payload_len = std.mem.readInt(u32, len_bytes[0..4], .big);
        if (payload_len > self.max_frame_len) return Error.FrameTooLarge;
        const total = 4 + @as(usize, payload_len);
        if (self.remaining() < total) {
            return DecodeResult{ .need_more = total - self.remaining() };
        }
        const frame = self.buf[self.pos + 4 .. self.pos + total];
        self.pos += total;
        return DecodeResult{ .frame = frame };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const corpus = @import("corpus");

test "encodeFrameAlloc matches corpus PING frame" {
    const out = try encodeFrameAlloc(testing.allocator, "PING");
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, corpus.wire.messages.tcp_message_ping_framed, out);
}

test "encodeFrameAlloc matches corpus simple-data frame" {
    const inner = corpus.wire.messages.tcp_message_data_simple_inner;
    const out = try encodeFrameAlloc(testing.allocator, inner);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(
        u8,
        corpus.wire.messages.tcp_message_data_simple_framed,
        out,
    );
}

test "FrameDecoder pulls a single complete frame" {
    var decoder = FrameDecoder.init(corpus.wire.messages.tcp_message_ping_framed);
    const result = try decoder.decode();
    switch (result) {
        .frame => |bytes| try testing.expectEqualSlices(u8, "PING", bytes),
        .need_more => return error.TestUnexpectedResult,
    }
    // No more bytes — second call must report `need_more = 4` for the next header.
    const next = try decoder.decode();
    switch (next) {
        .need_more => |n| try testing.expectEqual(@as(usize, 4), n),
        .frame => return error.TestUnexpectedResult,
    }
}

test "FrameDecoder reports need_more when the header is incomplete" {
    var decoder = FrameDecoder.init(&[_]u8{ 0, 0 });
    const result = try decoder.decode();
    switch (result) {
        .need_more => |n| try testing.expectEqual(@as(usize, 2), n),
        .frame => return error.TestUnexpectedResult,
    }
}

test "FrameDecoder reports need_more when the body is incomplete" {
    var decoder = FrameDecoder.init(&[_]u8{ 0, 0, 0, 5, 0xaa, 0xbb });
    const result = try decoder.decode();
    switch (result) {
        .need_more => |n| try testing.expectEqual(@as(usize, 3), n),
        .frame => return error.TestUnexpectedResult,
    }
}

test "FrameDecoder pulls back-to-back frames out of one buffer" {
    // Two PING frames concatenated.
    const a = corpus.wire.messages.tcp_message_ping_framed;
    const b = corpus.wire.messages.tcp_message_ping_framed;
    var combined = try testing.allocator.alloc(u8, a.len + b.len);
    defer testing.allocator.free(combined);
    @memcpy(combined[0..a.len], a);
    @memcpy(combined[a.len..], b);
    var decoder = FrameDecoder.init(combined);
    var count: usize = 0;
    while (true) {
        const result = try decoder.decode();
        switch (result) {
            .frame => |bytes| {
                try testing.expectEqualSlices(u8, "PING", bytes);
                count += 1;
            },
            .need_more => break,
        }
    }
    try testing.expectEqual(@as(usize, 2), count);
}

test "FrameDecoder rejects frames over the configured limit" {
    // Header advertises 1 MiB but the decoder is capped at 1 KiB.
    const header = [_]u8{ 0, 0x10, 0, 0 };
    var decoder = FrameDecoder.initWithLimit(&header, 1024);
    try testing.expectError(Error.FrameTooLarge, decoder.decode());
}

// ---------------------------------------------------------------------------
// StreamFrameReader tests. We back the reader with a slice fake instead of
// a real socket so the tests stay hermetic and fast.
// ---------------------------------------------------------------------------

const SliceReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    /// If non-zero, deliver at most `chunk` bytes per `read` call. Used to
    /// exercise the buffered-grow path.
    chunk: usize = 0,

    pub fn init(bytes: []const u8) SliceReader {
        return .{ .bytes = bytes };
    }

    pub fn initChunked(bytes: []const u8, chunk: usize) SliceReader {
        return .{ .bytes = bytes, .chunk = chunk };
    }

    pub fn read(self: *SliceReader, buf: []u8) !usize {
        const remaining = self.bytes[self.pos..];
        if (remaining.len == 0) return 0;
        var n = @min(remaining.len, buf.len);
        if (self.chunk != 0) n = @min(n, self.chunk);
        @memcpy(buf[0..n], remaining[0..n]);
        self.pos += n;
        return n;
    }
};

test "StreamFrameReader pulls a single PING frame from a slice reader" {
    var src = SliceReader.init(corpus.wire.messages.tcp_message_ping_framed);
    var reader = StreamFrameReader(*SliceReader).init(testing.allocator);
    defer reader.deinit();
    const frame = try reader.nextFrame(&src);
    try testing.expect(frame != null);
    try testing.expectEqualSlices(u8, "PING", frame.?);
    // Second call: clean EOF.
    try testing.expect((try reader.nextFrame(&src)) == null);
}

test "StreamFrameReader handles back-to-back frames" {
    const a = corpus.wire.messages.tcp_message_ping_framed;
    const b = corpus.wire.messages.tcp_message_data_simple_framed;
    var combined = try testing.allocator.alloc(u8, a.len + b.len);
    defer testing.allocator.free(combined);
    @memcpy(combined[0..a.len], a);
    @memcpy(combined[a.len..], b);

    var src = SliceReader.init(combined);
    var reader = StreamFrameReader(*SliceReader).init(testing.allocator);
    defer reader.deinit();

    const first = try reader.nextFrame(&src);
    try testing.expect(first != null);
    try testing.expectEqualSlices(u8, "PING", first.?);

    const second = try reader.nextFrame(&src);
    try testing.expect(second != null);
    try testing.expectEqualSlices(
        u8,
        corpus.wire.messages.tcp_message_data_simple_inner,
        second.?,
    );

    try testing.expect((try reader.nextFrame(&src)) == null);
}

test "StreamFrameReader stitches a frame split across many tiny reads" {
    // 1-byte chunks force the reader to loop several times before a full
    // frame is available.
    var src = SliceReader.initChunked(
        corpus.wire.messages.tcp_message_data_header_framed,
        1,
    );
    var reader = StreamFrameReader(*SliceReader).init(testing.allocator);
    defer reader.deinit();

    const frame = try reader.nextFrame(&src);
    try testing.expect(frame != null);
    try testing.expectEqualSlices(
        u8,
        corpus.wire.messages.tcp_message_data_header_inner,
        frame.?,
    );
    try testing.expect((try reader.nextFrame(&src)) == null);
}

test "StreamFrameReader reports UnexpectedEof on a truncated frame" {
    // The corpus PING frame is `00 00 00 04 P I N G`. Truncate it after
    // the header so the reader has bytes but never gets a complete frame.
    const truncated = corpus.wire.messages.tcp_message_ping_framed[0..6];
    var src = SliceReader.init(truncated);
    var reader = StreamFrameReader(*SliceReader).init(testing.allocator);
    defer reader.deinit();
    try testing.expectError(error.UnexpectedEof, reader.nextFrame(&src));
}

test "StreamFrameReader respects the frame length limit" {
    // Header advertises 64 bytes but the reader is capped at 8.
    var src = SliceReader.init(&[_]u8{ 0, 0, 0, 64 });
    var reader = StreamFrameReader(*SliceReader).initWithLimit(testing.allocator, 8);
    defer reader.deinit();
    try testing.expectError(Error.FrameTooLarge, reader.nextFrame(&src));
}
