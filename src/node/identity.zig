//! Observer identity — ephemeral or persistent BLS keypair.
//!
//! By default the observer generates a fresh ephemeral key on every
//! run. With `--identity <path>`, the key is loaded from (or generated
//! and saved to) a small on-disk file so the node presents a stable
//! `ValidatorPublicKey` across restarts. This matters for testnet
//! observation where peers track connection identity.
//!
//! File format: 32 raw bytes (the BLS secret key scalar in little-endian
//! form). No header, no checksum — simplest possible representation.
//! The file should be mode 0600 and not committed to VCS.

const std = @import("std");

/// The 32-byte on-disk form of a BLS12-381 secret key (Fr scalar, LE).
pub const SECRET_KEY_LEN = 32;

/// A 4-limb secret key suitable for `buildHelloFrame`.
pub const SecretKey = [4]u64;

/// Load a secret key from a file. Returns error if the file doesn't
/// exist, isn't exactly 32 bytes, or can't be read.
pub fn loadKey(path: []const u8) !SecretKey {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf: [SECRET_KEY_LEN]u8 = undefined;
    const n = try file.readAll(&buf);
    if (n != SECRET_KEY_LEN) return error.InvalidKeyFile;

    return bytesToLimbs(buf);
}

/// Save a secret key to a file. Creates the file if it doesn't exist,
/// overwrites if it does. Sets permissions to owner-only (0o600).
pub fn saveKey(path: []const u8, key: SecretKey) !void {
    const buf = limbsToBytes(key);
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try file.writeAll(&buf);
}

/// Load a key from `path`, or generate a fresh one and save it there.
/// Returns the key either way.
pub fn loadOrGenerate(path: []const u8) !SecretKey {
    return loadKey(path) catch |err| switch (err) {
        error.FileNotFound => {
            const key = generateEphemeralKey();
            try saveKey(path, key);
            return key;
        },
        else => return err,
    };
}

/// Generate an ephemeral BLS secret key from OS entropy. Returns a
/// 4-limb little-endian scalar suitable for `buildHelloFrame`.
pub fn generateEphemeralKey() SecretKey {
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    var limbs: [4]u64 = undefined;
    inline for (0..4) |i| {
        limbs[i] = std.mem.readInt(u64, seed[i * 8 ..][0..8], .little);
    }
    // Ensure non-zero (astronomically unlikely but handle it).
    if (limbs[0] == 0 and limbs[1] == 0 and limbs[2] == 0 and limbs[3] == 0) {
        limbs[0] = 1;
    }
    return limbs;
}

/// Convert 32 raw LE bytes to a 4-limb key.
fn bytesToLimbs(buf: [SECRET_KEY_LEN]u8) SecretKey {
    var limbs: SecretKey = undefined;
    inline for (0..4) |i| {
        limbs[i] = std.mem.readInt(u64, buf[i * 8 ..][0..8], .little);
    }
    return limbs;
}

/// Convert a 4-limb key to 32 raw LE bytes.
fn limbsToBytes(key: SecretKey) [SECRET_KEY_LEN]u8 {
    var buf: [SECRET_KEY_LEN]u8 = undefined;
    inline for (0..4) |i| {
        std.mem.writeInt(u64, buf[i * 8 ..][0..8], key[i], .little);
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "bytesToLimbs and limbsToBytes are inverses" {
    const key: SecretKey = .{ 0xdeadbeef, 0x12345678, 0xaabbccdd, 0x99887766 };
    const bytes = limbsToBytes(key);
    const round_tripped = bytesToLimbs(bytes);
    try testing.expectEqual(key[0], round_tripped[0]);
    try testing.expectEqual(key[1], round_tripped[1]);
    try testing.expectEqual(key[2], round_tripped[2]);
    try testing.expectEqual(key[3], round_tripped[3]);
}

test "generateEphemeralKey returns a non-zero key" {
    const key = generateEphemeralKey();
    const non_zero = key[0] != 0 or key[1] != 0 or key[2] != 0 or key[3] != 0;
    try testing.expect(non_zero);
}

test "saveKey and loadKey round-trip through a temp file" {
    const key: SecretKey = .{ 0x1111, 0x2222, 0x3333, 0x4444 };
    const tmp_path = "/tmp/zyli-test-identity.bin";

    try saveKey(tmp_path, key);
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    const loaded = try loadKey(tmp_path);
    try testing.expectEqual(key[0], loaded[0]);
    try testing.expectEqual(key[1], loaded[1]);
    try testing.expectEqual(key[2], loaded[2]);
    try testing.expectEqual(key[3], loaded[3]);
}

test "loadOrGenerate creates a new file when missing" {
    const tmp_path = "/tmp/zyli-test-identity-new.bin";
    std.fs.cwd().deleteFile(tmp_path) catch {};
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    const key = try loadOrGenerate(tmp_path);
    // Key should be non-zero.
    const non_zero = key[0] != 0 or key[1] != 0 or key[2] != 0 or key[3] != 0;
    try testing.expect(non_zero);

    // Loading again should return the same key.
    const key2 = try loadOrGenerate(tmp_path);
    try testing.expectEqual(key[0], key2[0]);
    try testing.expectEqual(key[1], key2[1]);
    try testing.expectEqual(key[2], key2[2]);
    try testing.expectEqual(key[3], key2[3]);
}

test "loadKey rejects truncated file" {
    const tmp_path = "/tmp/zyli-test-identity-short.bin";
    {
        var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("too short");
    }
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    try testing.expectError(error.InvalidKeyFile, loadKey(tmp_path));
}
