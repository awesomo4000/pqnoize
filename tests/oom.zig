//! Out-of-memory injection tests.
//!
//! Exercise every allocation site in the library against simulated OOM
//! and verify nothing leaks, panics, or returns a non-typed error.
//! Two complementary approaches:
//!
//!   * Exhaustive sequential — `std.testing.FailingAllocator` makes the
//!     Nth alloc fail; we walk N from 0 upward through every alloc the
//!     library performs for a full handshake + transport sequence. This
//!     catches bugs in error-handling at *every* alloc site, even rare
//!     ones, deterministically.
//!
//!   * Random injection — `RandomFailingAllocator` fails each alloc
//!     with probability p, driven by a seeded PRNG. Different angle of
//!     attack: simulates real memory-pressure scenarios where multiple
//!     failures may occur within a single session.
//!
//! All allocations route through std.testing.allocator's leak detector
//! via the inner field, so any escaped allocation surfaces as a leak
//! check at test end. Connection.deinit must clean up regardless of
//! where the failure happened.

const std = @import("std");
const pqnoize = @import("pqnoize");
const testing = std.testing;

// ── Random-failure allocator ──────────────────────────────────────────────

/// Wraps an inner allocator; each alloc/resize/remap fails independently
/// with the configured probability. Frees never fail (per Allocator
/// contract). PRNG-driven so tests are deterministic given a fixed seed.
const RandomFailingAllocator = struct {
    inner: std.mem.Allocator,
    prng: *std.Random.DefaultPrng,
    fail_probability: f64,

    pub fn allocator(self: *RandomFailingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn shouldFail(self: *RandomFailingAllocator) bool {
        return self.prng.random().float(f64) < self.fail_probability;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *RandomFailingAllocator = @ptrCast(@alignCast(ctx));
        if (self.shouldFail()) return null;
        return self.inner.rawAlloc(len, alignment, ret);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const self: *RandomFailingAllocator = @ptrCast(@alignCast(ctx));
        if (self.shouldFail()) return false;
        return self.inner.rawResize(memory, alignment, new_len, ret);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self: *RandomFailingAllocator = @ptrCast(@alignCast(ctx));
        if (self.shouldFail()) return null;
        return self.inner.rawRemap(memory, alignment, new_len, ret);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *RandomFailingAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(memory, alignment, ret);
    }
};

// ── Session driver — shared by both tests ────────────────────────────────

fn rngFromSeedStream(s: *pqnoize.testing.SeedStream) pqnoize.Rng {
    return .{
        .ctx = s,
        .fillFn = struct {
            fn fill(ctx: *anyopaque, out: []u8) void {
                const stream: *pqnoize.testing.SeedStream = @ptrCast(@alignCast(ctx));
                stream.bytes(out);
            }
        }.fill,
    };
}

const Setup = struct {
    initiator_static: pqnoize.kem.Kem.KeyPair,
    responder_static: pqnoize.kem.Kem.KeyPair,
};

fn buildSetup() !Setup {
    var stream = pqnoize.testing.SeedStream.init("oom-static-keys");
    return .{
        .initiator_static = try pqnoize.testing.keypair(&stream),
        .responder_static = try pqnoize.testing.keypair(&stream),
    };
}

fn shuttle(from: *pqnoize.Connection, to: *pqnoize.Connection, gpa: std.mem.Allocator) !void {
    const out = from.outgoing();
    if (out.len == 0) return;
    const buf = try gpa.alloc(u8, out.len);
    defer gpa.free(buf);
    @memcpy(buf, out);
    from.consumeOutgoing(out.len);
    try to.recv(buf);
}

/// Run a complete handshake-and-transport session under `gpa`. Every
/// fallible call accepts errors silently — the test contract is "no
/// panic, no leak" regardless of where OOM hits.
fn runSession(gpa: std.mem.Allocator, setup: Setup) !void {
    var i_rng = pqnoize.testing.SeedStream.init("oom-session-i");
    var r_rng = pqnoize.testing.SeedStream.init("oom-session-r");

    var initiator = pqnoize.Connection.initInitiator(gpa, .{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .initiator,
        .rng = rngFromSeedStream(&i_rng),
        .s = setup.initiator_static,
        .rs = setup.responder_static.public_key,
    }) catch |err| switch (err) {
        // Pre-handshake OOM — nothing else to do, conn already cleaned
        // up via initInitiator's errdefer.
        error.OutOfMemory => return,
        else => return err,
    };
    defer initiator.deinit();

    var responder = pqnoize.Connection.initResponder(gpa, .{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .responder,
        .rng = rngFromSeedStream(&r_rng),
        .s = setup.responder_static,
        .rs = setup.initiator_static.public_key,
    });
    defer responder.deinit();

    // Drive handshake. Any error here ends the session early.
    shuttle(&initiator, &responder, gpa) catch return;
    shuttle(&responder, &initiator, gpa) catch return;
    if (!initiator.isEstablished() or !responder.isEstablished()) return;

    // Transport messages, alternating direction. Stop on any error.
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const sender = if (i % 2 == 0) &initiator else &responder;
        const receiver = if (i % 2 == 0) &responder else &initiator;
        sender.send("payload") catch return;
        shuttle(sender, receiver, gpa) catch return;
        while (receiver.nextMessage()) |msg| receiver.freeMessage(msg);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

test "OOM (exhaustive sequential): every alloc site survives a single failure" {
    const setup = try buildSetup();

    // Walk fail_index from 0 upward. Each iteration runs a full session
    // with exactly one alloc forced to fail at position N. We stop when
    // N exceeds the number of allocations a clean session performs (the
    // FailingAllocator simply never fails past that, and the loop hits
    // an iteration where everything completes without error). 256 is
    // far more than we expect.
    var fail_index: usize = 0;
    while (fail_index < 256) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = fail_index,
        });
        try runSession(failing.allocator(), setup);
    }
}

test "OOM (random injection): no leaks across many seeds and failure rates" {
    const setup = try buildSetup();

    const seeds = [_]u64{ 0x1, 0xc0ffee, 0xfeedface, 0xdeadbeef, 0x12345678 };
    const rates = [_]f64{ 0.05, 0.15, 0.30 };

    for (seeds) |seed| {
        for (rates) |rate| {
            var prng = std.Random.DefaultPrng.init(seed);
            var failing: RandomFailingAllocator = .{
                .inner = testing.allocator,
                .prng = &prng,
                .fail_probability = rate,
            };
            try runSession(failing.allocator(), setup);
        }
    }
}
