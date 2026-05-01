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

    const oom_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/oom.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "pqnoize", .module = mod }},
        }),
    });
    const run_oom = b.addRunArtifact(oom_tests);
    const oom_step = b.step("test-oom", "Run OOM injection tests (exhaustive + random)");
    oom_step.dependOn(&run_oom.step);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit.step);
    test_step.dependOn(&run_kats.step);
    test_step.dependOn(&run_e2e.step);
    test_step.dependOn(&run_oom.step);
    test_step.dependOn(&run_exe_tests.step);

    // Fuzz steps — deliberately NOT wired into `zig build test`.
    //
    // Each target is its own test artifact so individual fuzzers can be
    // run in isolation. By default each step does ONE smoke pass through
    // the fuzz targets (CI-suitable). To enter continuous coverage-
    // guided fuzz mode, append `--fuzz` to the `zig build` invocation:
    //
    //   zig build fuzz-framing            — one smoke pass
    //   zig build fuzz-framing --fuzz     — continuous, Ctrl-C to stop
    //   zig build fuzz-connection --fuzz  — same, for Connection.recv
    //   zig build fuzz --fuzz             — continuous, all targets
    //
    // The `--fuzz` flag is consumed by `zig build` itself; the build
    // runner reinstruments the test binary with coverage probes and
    // drives it iteratively.
    //
    // NOTE on optimize mode: 0.16.0's stdlib `test_runner.zig` has a
    // type-mismatch bug in its Debug-mode error-printing path that
    // prevents `--fuzz` from compiling under Debug. Pinning these test
    // artifacts to `.ReleaseSafe` sidesteps the bug entirely while
    // keeping safety checks (overflow, OOB) active — and Release-mode
    // is what serious fuzz campaigns use anyway (more iters/sec).
    // Tracked upstream: ziggit.dev/t/0-16-0-released/14930 (post #15).
    // Revert to inheriting `optimize` once 0.16.1 ships the fix.
    const fuzz_optimize: std.builtin.OptimizeMode = .ReleaseSafe;

    const fuzz_framing_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz_framing.zig"),
            .target = target,
            .optimize = fuzz_optimize,
            .imports = &.{.{ .name = "pqnoize", .module = mod }},
        }),
    });
    const run_fuzz_framing = b.addRunArtifact(fuzz_framing_tests);
    const fuzz_framing_step = b.step("fuzz-framing", "Fuzz framing parser (add --fuzz for continuous mode)");
    fuzz_framing_step.dependOn(&run_fuzz_framing.step);

    const fuzz_connection_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz_connection.zig"),
            .target = target,
            .optimize = fuzz_optimize,
            .imports = &.{.{ .name = "pqnoize", .module = mod }},
        }),
    });
    const run_fuzz_connection = b.addRunArtifact(fuzz_connection_tests);
    const fuzz_connection_step = b.step("fuzz-connection", "Fuzz Connection.recv with random bytes (add --fuzz for continuous mode)");
    fuzz_connection_step.dependOn(&run_fuzz_connection.step);

    const fuzz_transport_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz_transport.zig"),
            .target = target,
            .optimize = fuzz_optimize,
            .imports = &.{.{ .name = "pqnoize", .module = mod }},
        }),
    });
    const run_fuzz_transport = b.addRunArtifact(fuzz_transport_tests);
    const fuzz_transport_step = b.step("fuzz-transport", "Fuzz post-handshake transport with frame mutations (add --fuzz for continuous mode)");
    fuzz_transport_step.dependOn(&run_fuzz_transport.step);

    const fuzz_step = b.step("fuzz", "Run all fuzz targets (add --fuzz for continuous mode)");
    fuzz_step.dependOn(&run_fuzz_framing.step);
    fuzz_step.dependOn(&run_fuzz_connection.step);
    fuzz_step.dependOn(&run_fuzz_transport.step);
}
