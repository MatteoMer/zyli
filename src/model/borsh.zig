//! Borsh codec.
//!
//! Borsh (https://borsh.io/) is the canonical serialization format that
//! every consensus-critical Hyli surface relies on. This module is the
//! single Zig source of truth for Borsh; all higher-level Hyli encodings
//! must build on top of these primitives so that fixture-based equivalence
//! tests against Rust Hyli have one place to fail loudly when they drift.
//!
//! Compatibility notes (Borsh 1.x):
//! - All scalar integers and floats are little-endian.
//! - Length prefixes for `Vec`, `String`, maps, and sets are `u32`.
//! - Fixed arrays (`[T; N]`) carry no length prefix.
//! - `Option<T>` is `0u8` for `None` and `1u8` followed by the payload.
//! - `bool` is `0u8` or `1u8`; any other value is rejected on decode.
//! - Enums (Rust tagged unions) are encoded as a `u8` discriminant followed
//!   by the variant payload, in declaration order.
//! - Maps and sets must be sorted by key/element bytes — that ordering is
//!   the responsibility of the caller, not this codec, because the source
//!   data structure (HashMap/BTreeMap) determines it on the Rust side.
//! - NaN floats are forbidden by spec; we mirror that on encode and reject
//!   them on decode so we never silently round-trip an invalid wire value.

const std = @import("std");
const builtin = @import("builtin");

const native_endian = builtin.cpu.arch.endian();

/// All errors that the Borsh codec can surface. The encode/decode paths
/// share an error set so callers can use a single `try` chain.
pub const Error = error{
    BufferTooShort,
    InvalidBool,
    InvalidOptionTag,
    InvalidEnumTag,
    InvalidUtf8,
    NonCanonicalNan,
    LengthOverflow,
    OutOfMemory,
};

/// Borsh writes length prefixes as `u32`. Encoding a value whose length
/// exceeds `u32` is a programming bug, not a wire-format edge case.
pub const max_collection_len: usize = std.math.maxInt(u32);

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Cursor over a borsh-encoded byte slice. Reader does not own the buffer
/// and never allocates; allocations live in the higher-level decode helpers
/// that need to materialize Zig values such as slices and strings.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn remaining(self: Reader) usize {
        return self.buf.len - self.pos;
    }

    pub fn isEmpty(self: Reader) bool {
        return self.pos == self.buf.len;
    }

    /// Borrow `n` bytes from the underlying buffer without copying. The
    /// returned slice is only valid for as long as the source buffer.
    pub fn readBytes(self: *Reader, n: usize) Error![]const u8 {
        if (self.remaining() < n) return Error.BufferTooShort;
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    pub fn readByte(self: *Reader) Error!u8 {
        const slice = try self.readBytes(1);
        return slice[0];
    }

    pub fn readBool(self: *Reader) Error!bool {
        const byte = try self.readByte();
        return switch (byte) {
            0 => false,
            1 => true,
            else => Error.InvalidBool,
        };
    }

    pub fn readInt(self: *Reader, comptime T: type) Error!T {
        const info = @typeInfo(T).int;
        const byte_count = @divExact(info.bits, 8);
        const slice = try self.readBytes(byte_count);
        return std.mem.readInt(T, slice[0..byte_count], .little);
    }

    pub fn readFloat(self: *Reader, comptime T: type) Error!T {
        const Bits = switch (T) {
            f32 => u32,
            f64 => u64,
            else => @compileError("readFloat only supports f32/f64"),
        };
        const bits = try self.readInt(Bits);
        const value: T = @bitCast(bits);
        if (std.math.isNan(value)) return Error.NonCanonicalNan;
        return value;
    }

    /// Read a Borsh `u32` length prefix and return it as `usize` for index
    /// arithmetic. Lengths must fit in the host `usize`.
    pub fn readLen(self: *Reader) Error!usize {
        const raw = try self.readInt(u32);
        if (raw > std.math.maxInt(usize)) return Error.LengthOverflow;
        return @intCast(raw);
    }
};

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Append-only writer over an `std.ArrayList(u8)`. Encoding always grows
/// the destination — Borsh has no in-place updates — so an array list is
/// the cheapest backing store and avoids juggling allocator state in every
/// helper.
pub const Writer = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, list: *std.ArrayList(u8)) Writer {
        return .{ .list = list, .allocator = allocator };
    }

    pub fn writeBytes(self: Writer, bytes: []const u8) Error!void {
        self.list.appendSlice(self.allocator, bytes) catch return Error.OutOfMemory;
    }

    pub fn writeByte(self: Writer, byte: u8) Error!void {
        self.list.append(self.allocator, byte) catch return Error.OutOfMemory;
    }

    pub fn writeBool(self: Writer, value: bool) Error!void {
        try self.writeByte(if (value) 1 else 0);
    }

    pub fn writeInt(self: Writer, comptime T: type, value: T) Error!void {
        const info = @typeInfo(T).int;
        const byte_count = @divExact(info.bits, 8);
        var buf: [16]u8 = undefined;
        std.mem.writeInt(T, buf[0..byte_count], value, .little);
        try self.writeBytes(buf[0..byte_count]);
    }

    pub fn writeFloat(self: Writer, comptime T: type, value: T) Error!void {
        if (std.math.isNan(value)) return Error.NonCanonicalNan;
        const Bits = switch (T) {
            f32 => u32,
            f64 => u64,
            else => @compileError("writeFloat only supports f32/f64"),
        };
        const bits: Bits = @bitCast(value);
        try self.writeInt(Bits, bits);
    }

    pub fn writeLen(self: Writer, len: usize) Error!void {
        if (len > max_collection_len) return Error.LengthOverflow;
        try self.writeInt(u32, @intCast(len));
    }
};

// ---------------------------------------------------------------------------
// Comptime encode / decode dispatch
// ---------------------------------------------------------------------------

/// Encode a Zig value into Borsh wire form using a comptime-driven dispatch.
///
/// Supported type kinds:
/// - signed/unsigned ints (u8..u128, i8..i128) — emitted little-endian
/// - f32/f64                                   — bit-cast little-endian
/// - bool                                      — single byte
/// - optional `?T`                             — Borsh `Option<T>`
/// - pointer `[]const T` / `[]T`               — Borsh `Vec<T>`
/// - array `[N]T`                              — fixed Borsh array (no len)
/// - struct                                    — fields in declaration order
/// - enum (no payload)                         — discriminant as `u8`
/// - tagged union `union(enum)`                — `u8` tag + payload
pub fn encode(writer: Writer, comptime T: type, value: T) Error!void {
    switch (@typeInfo(T)) {
        .int => try writer.writeInt(T, value),
        .float => try writer.writeFloat(T, value),
        .bool => try writer.writeBool(value),
        .optional => |opt_info| {
            if (value) |inner| {
                try writer.writeByte(1);
                try encode(writer, opt_info.child, inner);
            } else {
                try writer.writeByte(0);
            }
        },
        .array => |arr_info| {
            if (arr_info.child == u8) {
                try writer.writeBytes(value[0..]);
            } else {
                for (value) |element| try encode(writer, arr_info.child, element);
            }
        },
        .pointer => |ptr_info| {
            if (ptr_info.size != .slice) {
                @compileError("borsh.encode only supports slice pointers, not " ++ @typeName(T));
            }
            try writer.writeLen(value.len);
            if (ptr_info.child == u8) {
                try writer.writeBytes(value);
            } else {
                for (value) |element| try encode(writer, ptr_info.child, element);
            }
        },
        .@"struct" => |struct_info| {
            inline for (struct_info.fields) |field| {
                try encode(writer, field.type, @field(value, field.name));
            }
        },
        .@"enum" => |enum_info| {
            const tag_int = @intFromEnum(value);
            if (tag_int < 0 or tag_int > std.math.maxInt(u8)) {
                @compileError("borsh enum discriminants must fit in u8");
            }
            _ = enum_info;
            try writer.writeByte(@intCast(tag_int));
        },
        .@"union" => |union_info| {
            if (union_info.tag_type == null) {
                @compileError("borsh.encode requires tagged unions: " ++ @typeName(T));
            }
            const tag = @intFromEnum(std.meta.activeTag(value));
            if (tag < 0 or tag > std.math.maxInt(u8)) {
                @compileError("borsh union tags must fit in u8");
            }
            try writer.writeByte(@intCast(tag));
            inline for (union_info.fields) |field| {
                if (std.mem.eql(u8, field.name, @tagName(std.meta.activeTag(value)))) {
                    if (field.type != void) {
                        try encode(writer, field.type, @field(value, field.name));
                    }
                }
            }
        },
        .void => {},
        else => @compileError("borsh.encode: unsupported type " ++ @typeName(T)),
    }
}

/// Decode a Borsh-encoded value of type `T` from `reader`.
///
/// Allocator usage:
/// - Slice and string types own freshly allocated buffers, so the caller
///   must `freeDecoded` (or otherwise release them) after use.
/// - Plain-old-data types do not touch the allocator at all.
pub fn decode(comptime T: type, reader: *Reader, allocator: std.mem.Allocator) Error!T {
    switch (@typeInfo(T)) {
        .int => return try reader.readInt(T),
        .float => return try reader.readFloat(T),
        .bool => return try reader.readBool(),
        .optional => |opt_info| {
            const tag = try reader.readByte();
            return switch (tag) {
                0 => null,
                1 => try decode(opt_info.child, reader, allocator),
                else => Error.InvalidOptionTag,
            };
        },
        .array => |arr_info| {
            var out: T = undefined;
            if (arr_info.child == u8) {
                const slice = try reader.readBytes(arr_info.len);
                @memcpy(out[0..], slice);
            } else {
                var i: usize = 0;
                while (i < arr_info.len) : (i += 1) {
                    out[i] = try decode(arr_info.child, reader, allocator);
                }
            }
            return out;
        },
        .pointer => |ptr_info| {
            if (ptr_info.size != .slice) {
                @compileError("borsh.decode only supports slice pointers, not " ++ @typeName(T));
            }
            const len = try reader.readLen();
            const slice = allocator.alloc(ptr_info.child, len) catch return Error.OutOfMemory;
            errdefer allocator.free(slice);
            if (ptr_info.child == u8) {
                const src = try reader.readBytes(len);
                @memcpy(slice, src);
            } else {
                var i: usize = 0;
                while (i < len) : (i += 1) {
                    slice[i] = try decode(ptr_info.child, reader, allocator);
                }
            }
            return slice;
        },
        .@"struct" => |struct_info| {
            var out: T = undefined;
            inline for (struct_info.fields) |field| {
                @field(out, field.name) = try decode(field.type, reader, allocator);
            }
            return out;
        },
        .@"enum" => |enum_info| {
            const raw = try reader.readByte();
            inline for (enum_info.fields) |field| {
                if (field.value == raw) return @field(T, field.name);
            }
            return Error.InvalidEnumTag;
        },
        .@"union" => |union_info| {
            if (union_info.tag_type == null) {
                @compileError("borsh.decode requires tagged unions: " ++ @typeName(T));
            }
            const TagType = union_info.tag_type.?;
            const raw = try reader.readByte();
            // Resolve the tag through the enum so we reject invalid tags
            // before instantiating the union value.
            var maybe_tag: ?TagType = null;
            inline for (@typeInfo(TagType).@"enum".fields) |tag_field| {
                if (tag_field.value == raw) maybe_tag = @field(TagType, tag_field.name);
            }
            const tag = maybe_tag orelse return Error.InvalidEnumTag;
            inline for (union_info.fields) |field| {
                if (std.mem.eql(u8, field.name, @tagName(@as(TagType, tag)))) {
                    if (field.type == void) {
                        return @unionInit(T, field.name, {});
                    }
                    const payload = try decode(field.type, reader, allocator);
                    return @unionInit(T, field.name, payload);
                }
            }
            unreachable;
        },
        .void => return,
        else => @compileError("borsh.decode: unsupported type " ++ @typeName(T)),
    }
}

/// Convenience: encode a value into a fresh `ArrayList(u8)` owned by the
/// caller. Used in tests and one-shot encode helpers.
pub fn encodeAlloc(allocator: std.mem.Allocator, comptime T: type, value: T) Error!std.ArrayList(u8) {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    const writer = Writer.init(allocator, &list);
    try encode(writer, T, value);
    return list;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectEncoded(comptime T: type, value: T, expected: []const u8) !void {
    var list = try encodeAlloc(testing.allocator, T, value);
    defer list.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, expected, list.items);
}

test "encode unsigned ints little-endian" {
    try expectEncoded(u8, 0x12, &[_]u8{0x12});
    try expectEncoded(u16, 0x1234, &[_]u8{ 0x34, 0x12 });
    try expectEncoded(u32, 0x12345678, &[_]u8{ 0x78, 0x56, 0x34, 0x12 });
    try expectEncoded(u64, 0x0102030405060708, &[_]u8{ 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 });
}

test "encode signed ints two's complement" {
    try expectEncoded(i8, -1, &[_]u8{0xff});
    try expectEncoded(i16, -2, &[_]u8{ 0xfe, 0xff });
    try expectEncoded(i32, -1, &[_]u8{ 0xff, 0xff, 0xff, 0xff });
    try expectEncoded(i64, std.math.minInt(i64), &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0x80 });
}

test "encode bool" {
    try expectEncoded(bool, false, &[_]u8{0});
    try expectEncoded(bool, true, &[_]u8{1});
}

test "encode option of u32" {
    try expectEncoded(?u32, null, &[_]u8{0});
    try expectEncoded(?u32, 0xdeadbeef, &[_]u8{ 1, 0xef, 0xbe, 0xad, 0xde });
}

test "encode fixed array of bytes" {
    const bytes: [4]u8 = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    try expectEncoded([4]u8, bytes, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd });
}

test "encode vec of u8 with length prefix" {
    const slice: []const u8 = &[_]u8{ 1, 2, 3 };
    var list = try encodeAlloc(testing.allocator, []const u8, slice);
    defer list.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &[_]u8{ 3, 0, 0, 0, 1, 2, 3 }, list.items);
}

test "encode vec of u32" {
    const slice: []const u32 = &[_]u32{ 1, 2 };
    var list = try encodeAlloc(testing.allocator, []const u32, slice);
    defer list.deinit(testing.allocator);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0 },
        list.items,
    );
}

test "encode struct in declaration order" {
    const S = struct {
        a: u8,
        b: u32,
        c: bool,
    };
    const value: S = .{ .a = 0xab, .b = 1, .c = true };
    try expectEncoded(S, value, &[_]u8{ 0xab, 1, 0, 0, 0, 1 });
}

test "encode payload-less enum as u8" {
    const E = enum(u8) { a, b, c };
    try expectEncoded(E, .a, &[_]u8{0});
    try expectEncoded(E, .b, &[_]u8{1});
    try expectEncoded(E, .c, &[_]u8{2});
}

test "encode tagged union" {
    const Tag = enum(u8) { unit, with_u32 };
    const U = union(Tag) {
        unit: void,
        with_u32: u32,
    };
    try expectEncoded(U, .{ .unit = {} }, &[_]u8{0});
    try expectEncoded(U, .{ .with_u32 = 7 }, &[_]u8{ 1, 7, 0, 0, 0 });
}

test "decode round-trips struct" {
    const S = struct {
        a: u16,
        b: i32,
        c: bool,
    };
    const original: S = .{ .a = 0x4242, .b = -3, .c = true };
    var list = try encodeAlloc(testing.allocator, S, original);
    defer list.deinit(testing.allocator);
    var reader = Reader.init(list.items);
    const decoded = try decode(S, &reader, testing.allocator);
    try testing.expect(reader.isEmpty());
    try testing.expectEqual(original.a, decoded.a);
    try testing.expectEqual(original.b, decoded.b);
    try testing.expectEqual(original.c, decoded.c);
}

test "decode round-trips vec of u32" {
    const original: []const u32 = &[_]u32{ 1, 2, 3, 4 };
    var list = try encodeAlloc(testing.allocator, []const u32, original);
    defer list.deinit(testing.allocator);
    var reader = Reader.init(list.items);
    const decoded = try decode([]u32, &reader, testing.allocator);
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u32, original, decoded);
}

test "decode round-trips optional" {
    var list_a = try encodeAlloc(testing.allocator, ?u64, 42);
    defer list_a.deinit(testing.allocator);
    var reader_a = Reader.init(list_a.items);
    try testing.expectEqual(@as(?u64, 42), try decode(?u64, &reader_a, testing.allocator));

    var list_b = try encodeAlloc(testing.allocator, ?u64, null);
    defer list_b.deinit(testing.allocator);
    var reader_b = Reader.init(list_b.items);
    try testing.expectEqual(@as(?u64, null), try decode(?u64, &reader_b, testing.allocator));
}

test "decode round-trips tagged union with payload" {
    const Tag = enum(u8) { empty, blob };
    const U = union(Tag) {
        empty: void,
        blob: []const u8,
    };
    const value: U = .{ .blob = &[_]u8{ 0xde, 0xad } };
    var list = try encodeAlloc(testing.allocator, U, value);
    defer list.deinit(testing.allocator);
    var reader = Reader.init(list.items);
    const decoded = try decode(U, &reader, testing.allocator);
    defer switch (decoded) {
        .empty => {},
        .blob => |b| testing.allocator.free(b),
    };
    try testing.expect(decoded == .blob);
    try testing.expectEqualSlices(u8, value.blob, decoded.blob);
}

test "decode rejects invalid bool" {
    var reader = Reader.init(&[_]u8{2});
    try testing.expectError(Error.InvalidBool, reader.readBool());
}

test "decode rejects invalid option tag" {
    var reader = Reader.init(&[_]u8{2});
    try testing.expectError(Error.InvalidOptionTag, decode(?u8, &reader, testing.allocator));
}

test "decode rejects invalid enum tag" {
    const E = enum(u8) { a, b };
    var reader = Reader.init(&[_]u8{7});
    try testing.expectError(Error.InvalidEnumTag, decode(E, &reader, testing.allocator));
}

test "decode rejects truncated buffer" {
    var reader = Reader.init(&[_]u8{ 1, 2 });
    try testing.expectError(Error.BufferTooShort, decode(u32, &reader, testing.allocator));
}

test "encode rejects NaN floats" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const writer = Writer.init(testing.allocator, &list);
    const nan: f64 = std.math.nan(f64);
    try testing.expectError(Error.NonCanonicalNan, writer.writeFloat(f64, nan));
}

test "encode floats little-endian" {
    try expectEncoded(f32, 1.0, &[_]u8{ 0, 0, 0x80, 0x3f });
    try expectEncoded(f64, 1.0, &[_]u8{ 0, 0, 0, 0, 0, 0, 0xf0, 0x3f });
}
