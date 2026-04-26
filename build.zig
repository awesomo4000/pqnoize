const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("pqnoize", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "pqnoize",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "pqnoize", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // Test steps:
    //   zig build test         — run everything
    //   zig build test-unit    — inline tests under src/
    //   zig build test-kats    — known-answer vectors
    //   zig build test-e2e     — initiator <-> responder integration
    const unit_tests = b.addTest(.{ .root_module = mod });
    const run_unit = b.addRunArtifact(unit_tests);
    const unit_step = b.step("test-unit", "Run inline tests under src/");
    unit_step.dependOn(&run_unit.step);

    const kats_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/kats.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "pqnoize", .module = mod }},
        }),
    });
    const run_kats = b.addRunArtifact(kats_tests);
    const kats_step = b.step("test-kats", "Run known-answer tests");
    kats_step.dependOn(&run_kats.step);

    const e2e_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/e2e.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "pqnoize", .module = mod }},
        }),
    });
    const run_e2e = b.addRunArtifact(e2e_tests);
    const e2e_step = b.step("test-e2e", "Run end-to-end handshake tests");
    e2e_step.dependOn(&run_e2e.step);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(&run_kats.step);
    test_step.dependOn(&run_e2e.step);
    test_step.dependOn(&run_exe_tests.step);
}
