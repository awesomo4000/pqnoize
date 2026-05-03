//! Tiny demo entry point. Real usage of pqnoize lives in
//! `examples/client_server/`. This binary just confirms the build
//! works and the library can be linked.

const std = @import("std");
const pqnoize = @import("pqnoize");

pub fn main(init: std.process.Init) !void {
    _ = init;
    std.debug.print("pqnoize: ML-KEM-768 pubkey size = {d} bytes\n", .{pqnoize.kem.public_key_length});
    std.debug.print("See `zig build run-example-server` and `run-example-client` for a TCP demo.\n", .{});
}

test "main module references pqnoize" {
    try std.testing.expectEqual(@as(usize, 1184), pqnoize.kem.public_key_length);
}
