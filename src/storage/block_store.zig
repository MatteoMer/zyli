//! Append-only signed block storage.
//!
//! Persists `SignedBlock` values as length-delimited Borsh records in a
//! single file. The on-disk format is trivially simple:
//!
//!   [ 4-byte BE record length | borsh(SignedBlock) ] *
//!
//! This is the same framing convention used on the wire, so the file can
//! be fed directly through the DA decode pipeline if needed.
//!
//! The store maintains an in-memory index mapping consensus slot → file
//! offset so that individual blocks can be retrieved by slot. The index
//! is rebuilt by scanning the file on open, which is fine for the
//! current (moderate) chain sizes.
//!
//! Thread safety: none. The store is designed for single-writer use
//! from the DA sync client. Concurrent access needs external locking.

const std = @import("std");
const borsh = @import("../model/borsh.zig");
const types = @import("../model/types.zig");

pub const Error = error{
    InvalidRecord,
    TruncatedRecord,
    SeekError,
    WriteError,
    ReadError,
    OutOfMemory,
};

/// On-disk header for each record: 4-byte big-endian payload length.
const HEADER_LEN = 4;

/// Persistent, append-only block store backed by a single file.
pub const BlockStore = struct {
    /// The backing file. Opened for read+write+append.
    file: std.fs.File,
    /// Allocator for the in-memory index.
    allocator: std.mem.Allocator,
    /// Slot → file offset (byte offset of the record header).
    index: std.AutoHashMap(types.Slot, u64),
    /// Number of records in the store.
    count: usize,
    /// The highest slot currently stored. 0 means empty.
    latest_slot: types.Slot,
    /// File size in bytes (= the offset where the next append goes).
    file_size: u64,

    /// Open (or create) a block store at `path`. If the file already
    /// exists, it is scanned to rebuild the in-memory index. If it is
    /// empty or does not exist, we start fresh.
    pub fn open(allocator: std.mem.Allocator, path: []const u8) !BlockStore {
        const file = try std.fs.cwd().createFile(path, .{
            .truncate = false,
            .read = true,
        });
        errdefer file.close();

        var store = BlockStore{
            .file = file,
            .allocator = allocator,
            .index = std.AutoHashMap(types.Slot, u64).init(allocator),
            .count = 0,
            .latest_slot = 0,
            .file_size = 0,
        };

        try store.rebuildIndex();
        return store;
    }

    /// Close the store and free the in-memory index.
    pub fn close(self: *BlockStore) void {
        self.index.deinit();
        self.file.close();
    }

    /// Append a signed block to the store. The block is Borsh-encoded,
    /// length-prefixed, and flushed to disk. The in-memory index is
    /// updated. Returns the file offset of the new record.
    pub fn append(self: *BlockStore, block: types.SignedBlock) !u64 {
        const slot = block.consensus_proposal.slot;
        const record_offset = self.file_size;

        // Borsh-encode the block.
        var list = try borsh.encodeAlloc(self.allocator, types.SignedBlock, block);
        const payload = try list.toOwnedSlice(self.allocator);
        defer self.allocator.free(payload);

        // Write the 4-byte BE length header + payload.
        var header: [HEADER_LEN]u8 = undefined;
        std.mem.writeInt(u32, &header, @intCast(payload.len), .big);

        // Seek to end (should already be there, but be safe).
        self.file.seekTo(self.file_size) catch return Error.SeekError;
        self.file.writeAll(&header) catch return Error.WriteError;
        self.file.writeAll(payload) catch return Error.WriteError;

        self.file_size += HEADER_LEN + payload.len;

        // Update index.
        try self.index.put(slot, record_offset);
        self.count += 1;
        if (slot > self.latest_slot) self.latest_slot = slot;

        return record_offset;
    }

    /// Read the signed block at a given slot. Returns null if the slot
    /// is not in the store. The returned `DecodedBlock` must be freed
    /// via `deinit`.
    pub fn getBySlot(self: *BlockStore, slot: types.Slot) !?DecodedBlock {
        const offset = self.index.get(slot) orelse return null;
        return @as(?DecodedBlock, try self.readRecord(offset));
    }

    /// Read a record at a given file offset.
    fn readRecord(self: *BlockStore, offset: u64) !DecodedBlock {
        const arena = try self.allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(self.allocator);
        errdefer {
            arena.deinit();
            self.allocator.destroy(arena);
        }

        // Read the 4-byte header.
        self.file.seekTo(offset) catch return Error.SeekError;
        var header: [HEADER_LEN]u8 = undefined;
        const h_read = self.file.readAll(&header) catch return Error.ReadError;
        if (h_read != HEADER_LEN) return Error.TruncatedRecord;
        const payload_len = std.mem.readInt(u32, &header, .big);

        // Read the payload.
        const payload = arena.allocator().alloc(u8, payload_len) catch return Error.OutOfMemory;
        const p_read = self.file.readAll(payload) catch return Error.ReadError;
        if (p_read != payload_len) return Error.TruncatedRecord;

        // Decode.
        var reader = borsh.Reader.init(payload);
        const block = borsh.decode(types.SignedBlock, &reader, arena.allocator()) catch
            return Error.InvalidRecord;

        return .{
            .value = block,
            .arena = arena,
        };
    }

    /// Return all stored slot numbers as an owned, ascending-sorted slice.
    /// Caller must free the returned slice with `allocator.free`.
    pub fn allSlots(self: *BlockStore, allocator: std.mem.Allocator) ![]types.Slot {
        var slots = try allocator.alloc(types.Slot, self.count);
        errdefer allocator.free(slots);
        var i: usize = 0;
        var it = self.index.keyIterator();
        while (it.next()) |key| {
            slots[i] = key.*;
            i += 1;
        }
        // Sort ascending.
        std.mem.sort(types.Slot, slots[0..i], {}, struct {
            fn lt(_: void, a: types.Slot, b: types.Slot) bool {
                return a < b;
            }
        }.lt);
        return slots[0..i];
    }

    /// Scan the file from the beginning to rebuild the slot → offset index.
    fn rebuildIndex(self: *BlockStore) !void {
        self.file.seekTo(0) catch return;
        var offset: u64 = 0;
        const file_end = self.file.getEndPos() catch return;

        while (offset + HEADER_LEN <= file_end) {
            self.file.seekTo(offset) catch break;
            var header: [HEADER_LEN]u8 = undefined;
            const h_read = self.file.readAll(&header) catch break;
            if (h_read != HEADER_LEN) break;
            const payload_len: u64 = std.mem.readInt(u32, &header, .big);

            if (offset + HEADER_LEN + payload_len > file_end) break;

            // We need to peek at the slot in the payload. The Borsh
            // encoding of SignedBlock starts with `data_proposals: Vec<…>`,
            // which is a 4-byte LE length. To get the slot, we'd need to
            // skip the entire data_proposals array. Instead, just decode
            // the whole record — it's fast enough for the index rebuild.
            const arena_alloc = try self.allocator.create(std.heap.ArenaAllocator);
            arena_alloc.* = std.heap.ArenaAllocator.init(self.allocator);
            defer {
                arena_alloc.deinit();
                self.allocator.destroy(arena_alloc);
            }

            const payload = arena_alloc.allocator().alloc(u8, @intCast(payload_len)) catch break;
            self.file.seekTo(offset + HEADER_LEN) catch break;
            const p_read = self.file.readAll(payload) catch break;
            if (p_read != @as(usize, @intCast(payload_len))) break;

            var reader = borsh.Reader.init(payload);
            const block = borsh.decode(types.SignedBlock, &reader, arena_alloc.allocator()) catch break;
            const slot = block.consensus_proposal.slot;

            try self.index.put(slot, offset);
            self.count += 1;
            if (slot > self.latest_slot) self.latest_slot = slot;

            offset += HEADER_LEN + payload_len;
        }
        self.file_size = offset;
    }
};

/// A decoded signed block with its backing arena. Free via `deinit`.
pub const DecodedBlock = struct {
    value: types.SignedBlock,
    arena: *std.heap.ArenaAllocator,

    pub fn deinit(self: *DecodedBlock) void {
        const child = self.arena.child_allocator;
        self.arena.deinit();
        child.destroy(self.arena);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testProposal(slot: types.Slot, ts: u128) types.ConsensusProposal {
    return .{
        .slot = slot,
        .parent_hash = .{ .bytes = "parent" },
        .cut = &[_]types.CutEntry{},
        .staking_actions = &[_]types.ConsensusStakingAction{},
        .timestamp = .{ .millis = ts },
    };
}

fn testSignedBlock(slot: types.Slot) types.SignedBlock {
    return .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = testProposal(slot, slot * 100),
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xee} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{
                .{ .bytes = &[_]u8{0x01} ** 4 },
            },
        },
    };
}

test "BlockStore: create, append, retrieve" {
    const path = "/tmp/zyli_test_block_store_basic.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = try BlockStore.open(testing.allocator, path);
    defer store.close();

    // Empty store.
    try testing.expectEqual(@as(usize, 0), store.count);
    try testing.expectEqual(@as(types.Slot, 0), store.latest_slot);

    // Append block at slot 1.
    _ = try store.append(testSignedBlock(1));
    try testing.expectEqual(@as(usize, 1), store.count);
    try testing.expectEqual(@as(types.Slot, 1), store.latest_slot);

    // Retrieve it.
    var decoded = (try store.getBySlot(1)).?;
    defer decoded.deinit();
    try testing.expectEqual(@as(types.Slot, 1), decoded.value.consensus_proposal.slot);

    // Nonexistent slot.
    const missing = try store.getBySlot(99);
    try testing.expect(missing == null);
}

test "BlockStore: multiple blocks and ordering" {
    const path = "/tmp/zyli_test_block_store_multi.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = try BlockStore.open(testing.allocator, path);
    defer store.close();

    _ = try store.append(testSignedBlock(1));
    _ = try store.append(testSignedBlock(5));
    _ = try store.append(testSignedBlock(3));

    try testing.expectEqual(@as(usize, 3), store.count);
    try testing.expectEqual(@as(types.Slot, 5), store.latest_slot);

    // Retrieve each.
    var d1 = (try store.getBySlot(1)).?;
    defer d1.deinit();
    try testing.expectEqual(@as(types.Slot, 1), d1.value.consensus_proposal.slot);

    var d5 = (try store.getBySlot(5)).?;
    defer d5.deinit();
    try testing.expectEqual(@as(types.Slot, 5), d5.value.consensus_proposal.slot);

    var d3 = (try store.getBySlot(3)).?;
    defer d3.deinit();
    try testing.expectEqual(@as(types.Slot, 3), d3.value.consensus_proposal.slot);
}

test "BlockStore: reopen and rebuild index" {
    const path = "/tmp/zyli_test_block_store_reopen.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    // Create and populate.
    {
        var store = try BlockStore.open(testing.allocator, path);
        defer store.close();
        _ = try store.append(testSignedBlock(1));
        _ = try store.append(testSignedBlock(2));
        _ = try store.append(testSignedBlock(3));
    }

    // Reopen — index should be rebuilt from the file.
    {
        var store = try BlockStore.open(testing.allocator, path);
        defer store.close();

        try testing.expectEqual(@as(usize, 3), store.count);
        try testing.expectEqual(@as(types.Slot, 3), store.latest_slot);

        var d2 = (try store.getBySlot(2)).?;
        defer d2.deinit();
        try testing.expectEqual(@as(types.Slot, 2), d2.value.consensus_proposal.slot);
    }
}

test "BlockStore: empty file" {
    const path = "/tmp/zyli_test_block_store_empty.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = try BlockStore.open(testing.allocator, path);
    defer store.close();

    try testing.expectEqual(@as(usize, 0), store.count);
    try testing.expectEqual(@as(types.Slot, 0), store.latest_slot);
    const missing = try store.getBySlot(1);
    try testing.expect(missing == null);
}

test "BlockStore: allSlots returns sorted list" {
    const path = "/tmp/zyli_test_block_store_all_slots.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = try BlockStore.open(testing.allocator, path);
    defer store.close();

    // Append out of order.
    _ = try store.append(testSignedBlock(5));
    _ = try store.append(testSignedBlock(1));
    _ = try store.append(testSignedBlock(3));

    const slots = try store.allSlots(testing.allocator);
    defer testing.allocator.free(slots);

    try testing.expectEqual(@as(usize, 3), slots.len);
    try testing.expectEqual(@as(types.Slot, 1), slots[0]);
    try testing.expectEqual(@as(types.Slot, 3), slots[1]);
    try testing.expectEqual(@as(types.Slot, 5), slots[2]);
}

test "BlockStore: round-trip block with non-empty fields" {
    const path = "/tmp/zyli_test_block_store_fields.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    var store = try BlockStore.open(testing.allocator, path);
    defer store.close();

    // Block with non-trivial fields: parent_hash, cut entries, and
    // multiple validators.
    const block: types.SignedBlock = .{
        .data_proposals = &[_]types.LaneDataProposals{},
        .consensus_proposal = .{
            .slot = 42,
            .parent_hash = .{ .bytes = &[_]u8{0xab} ** 32 },
            .cut = &[_]types.CutEntry{
                .{
                    .lane_id = .{ .operator = .{ .bytes = &[_]u8{0x05} ** 4 }, .suffix = "a" },
                    .dp_hash = .{ .bytes = "dphash1" },
                    .lane_bytes_size = .{ .bytes = 512 },
                    .aggregate_signature = .{
                        .signature = .{ .bytes = &[_]u8{0xdd} ** 12 },
                        .validators = &[_]types.ValidatorPublicKey{
                            .{ .bytes = &[_]u8{0x05} ** 4 },
                        },
                    },
                },
            },
            .staking_actions = &[_]types.ConsensusStakingAction{},
            .timestamp = .{ .millis = 1700000000001 },
        },
        .certificate = .{
            .signature = .{ .bytes = &[_]u8{0xcc} ** 12 },
            .validators = &[_]types.ValidatorPublicKey{
                .{ .bytes = &[_]u8{0x01} ** 4 },
                .{ .bytes = &[_]u8{0x02} ** 4 },
                .{ .bytes = &[_]u8{0x03} ** 4 },
            },
        },
    };
    _ = try store.append(block);

    var decoded = (try store.getBySlot(42)).?;
    defer decoded.deinit();

    try testing.expectEqual(@as(types.Slot, 42), decoded.value.consensus_proposal.slot);
    try testing.expectEqualSlices(u8, &[_]u8{0xab} ** 32, decoded.value.consensus_proposal.parent_hash.bytes);
    try testing.expectEqual(@as(usize, 1), decoded.value.consensus_proposal.cut.len);
    try testing.expectEqualSlices(u8, "a", decoded.value.consensus_proposal.cut[0].lane_id.suffix);
    try testing.expectEqualSlices(u8, "dphash1", decoded.value.consensus_proposal.cut[0].dp_hash.bytes);
    try testing.expectEqual(@as(usize, 3), decoded.value.certificate.validators.len);
    try testing.expectEqual(@as(u128, 1700000000001), decoded.value.consensus_proposal.timestamp.millis);
}

test "BlockStore: append after reopen continues correctly" {
    const path = "/tmp/zyli_test_block_store_append_reopen.dat";
    defer std.fs.cwd().deleteFile(path) catch {};

    // Write 2 blocks.
    {
        var store = try BlockStore.open(testing.allocator, path);
        defer store.close();
        _ = try store.append(testSignedBlock(1));
        _ = try store.append(testSignedBlock(2));
    }

    // Reopen and append 1 more.
    {
        var store = try BlockStore.open(testing.allocator, path);
        defer store.close();

        try testing.expectEqual(@as(usize, 2), store.count);
        _ = try store.append(testSignedBlock(3));
        try testing.expectEqual(@as(usize, 3), store.count);
        try testing.expectEqual(@as(types.Slot, 3), store.latest_slot);
    }

    // Reopen and verify all 3 are present.
    {
        var store = try BlockStore.open(testing.allocator, path);
        defer store.close();

        try testing.expectEqual(@as(usize, 3), store.count);

        const slots = try store.allSlots(testing.allocator);
        defer testing.allocator.free(slots);

        try testing.expectEqual(@as(usize, 3), slots.len);
        try testing.expectEqual(@as(types.Slot, 1), slots[0]);
        try testing.expectEqual(@as(types.Slot, 2), slots[1]);
        try testing.expectEqual(@as(types.Slot, 3), slots[2]);
    }
}
