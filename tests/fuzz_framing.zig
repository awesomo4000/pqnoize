//! Fuzz target: length-prefixed framing.
//!
//! Drives `FrameReader` (and a round-trip through `FrameWriter`) through
//! arbitrary Smith-generated push/peek/pop sequences with arbitrary
//! payload bytes. The contract under test:
//!
//!   * No panic, no UB, no slice OOB regardless of input.
//!   * `peek()` returns either `null` or a slice that round-trips through
//!     `pop()` cleanly.
//!   * `std.testing.allocator` shows zero leaks at end of every iteration.
//!
//! Run with:
//!     zig build fuzz-framing            (continuous, --fuzz mode)
//!     zig build fuzz-smoke              (one quick pass, no --fuzz)

const std = @import("std");
const pqnoize = @import("pqnoize");

test "fuzz: FrameReader survives arbitrary push/peek/pop sequences" {
    try std.testing.fuzz({}, fuzzReader, .{});
}

fn fuzzReader(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var r: pqnoize.framing.FrameReader = .empty;
    defer r.deinit(gpa);

    while (!smith.eos()) {
        switch (smith.value(enum { push, peek, pop })) {
            .push => {
                const len = smith.valueRangeAtMost(u32, 0, 256);
                const buf = try gpa.alloc(u8, len);
                defer gpa.free(buf);
                smith.bytes(buf);
                try r.push(gpa, buf);
            },
            .peek => {
                _ = r.peek();
            },
            .pop => {
                if (r.peek() != null) r.pop();
            },
        }
    }
}

test "fuzz: FrameWriter -> FrameReader round-trip preserves payload bytes" {
    try std.testing.fuzz({}, fuzzRoundtrip, .{});
}

fn fuzzRoundtrip(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var w: pqnoize.framing.FrameWriter = .empty;
    defer w.deinit(gpa);
    var r: pqnoize.framing.FrameReader = .empty;
    defer r.deinit(gpa);

    // Recorder of payloads we pushed in, so we can verify they emerge
    // identically on the reader side. Using std.ArrayList of owned slices.
    var pushed: std.ArrayList([]u8) = .empty;
    defer {
        for (pushed.items) |item| gpa.free(item);
        pushed.deinit(gpa);
    }

    while (!smith.eos()) {
        switch (smith.value(enum { push_w, transfer_chunk, pop_r })) {
            .push_w => {
                const len = smith.valueRangeAtMost(u32, 0, 256);
                const payload = try gpa.alloc(u8, len);
                smith.bytes(payload);
                w.push(gpa, payload) catch |err| switch (err) {
                    error.FrameTooLarge => {
                        gpa.free(payload);
                        continue;
                    },
                    else => {
                        gpa.free(payload);
                        return err;
                    },
                };
                try pushed.append(gpa, payload);
            },
            .transfer_chunk => {
                // Move some bytes from writer's outgoing into reader's input,
                // simulating a fragmented socket flush.
                const out = w.outgoing();
                if (out.len == 0) continue;
                const cap: u32 = @intCast(@min(out.len, std.math.maxInt(u32)));
                const n = smith.valueRangeAtMost(u32, 1, cap);
                try r.push(gpa, out[0..n]);
                w.consume(n);
            },
            .pop_r => {
                if (r.peek()) |frame| {
                    if (pushed.items.len == 0) return error.UnexpectedFrame;
                    const expected = pushed.items[0];
                    try std.testing.expectEqualSlices(u8, expected, frame);
                    gpa.free(expected);
                    _ = pushed.orderedRemove(0);
                    r.pop();
                }
            },
        }
    }
}
