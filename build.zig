const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Public zyli library module. Subsystems (model, crypto, wire, ...) are
    // re-exported through src/root.zig so downstream consumers and the node
    // executable share a single import surface.
    const zyli_module = b.addModule("zyli", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "zyli",
        .root_module = zyli_module,
    });
    b.installArtifact(lib);

    // Node executable. Kept intentionally thin: it should only wire the
    // runtime, configuration, and node modes — no protocol logic.
    const exe = b.addExecutable(.{
        .name = "zyli",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zyli", .module = zyli_module },
            },
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the zyli node executable");
    run_step.dependOn(&run_cmd.step);

    // Library unit tests.
    const lib_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
