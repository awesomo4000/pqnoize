//! Fuzz target: post-handshake transport with adversarial frame mutation.
//!
//! Unlike `tests/fuzz_connection.zig` (which feeds random bytes to recv
//! and exclusively exercises rejection paths), this harness gives the
//! fuzzer full participation in a successful handshake, then lets Smith
//! choose how to perturb each transport frame between sender and
//! receiver.
//!
//! Why this target exists:
//!
//! Random-bytes-only fuzzing structurally cannot reach the AEAD-success
//! path of `Connection.recv`. The probability of random bytes
//! deserializing as a valid frame AND verifying under an unknown AEAD
//! key is effectively zero — by design, that's the cryptographic
//! security property holding. But "structurally unreachable for
//! fuzzers" is not the same as "unreachable for attackers." A peer who
//! has somehow gained the ability to produce valid frames (predictable
//! RNG on a fleet of devices, key disclosure, malicious counterparty,
//! side-channel on the handshake) reaches code paths the random-bytes
//! fuzzer never touches:
//!
//!   * AEAD verify SUCCESS path
//!   * plaintext alloc into the inbox
//!   * `nextMessage()` returning a real slice
//!   * `freeMessage()` releasing it
//!   * counter increment after successful decrypt
//!   * any state transitions that happen on real traffic
//!
//! Bugs in those paths — use-after-free in inbox, off-by-one in plaintext
//! length, ownership confusion in freeMessage — would be invisible to
//! `fuzz_connection.zig` but live for any attacker who has valid keys.
//!
//! This harness models that scenario: we generate keys ourselves (so we
//! CAN produce valid frames), then let Smith decide whether each frame
//! flies clean or gets mutated. Both branches are now reachable:
//!
//!   * pass-through frames → success path covered, plaintext-equality
//!     invariant verified
//!   * mutated frames → tamper-detection paths covered, no panic / leak
//!
//! Run with:
//!     zig build fuzz-transport         (one smoke pass)
//!     zig build fuzz-transport --fuzz  (continuous, Ctrl-C to stop)

const std = @import("std");
const pqnoize = @import("pqnoize");

const Setup = struct {
    initiator_static: pqnoize.kem.Kem.KeyPair,
    responder_static: pqnoize.kem.Kem.KeyPair,
};

fn buildSetup() !Setup {
    var stream = pqnoize.testing.SeedStream.init("fuzz-xport-static");
    return .{
        .initiator_static = try pqnoize.testing.keypair(&stream),
        .responder_static = try pqnoize.testing.keypair(&stream),
    };
}

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

fn shuttle(from: *pqnoize.Connection, to: *pqnoize.Connection, gpa: std.mem.Allocator) !void {
    const out = from.outgoing();
    if (out.len == 0) return;
    const buf = try gpa.alloc(u8, out.len);
    defer gpa.free(buf);
    @memcpy(buf, out);
    from.consumeOutgoing(out.len);
    try to.recv(buf);
}

test "fuzz: post-handshake transport with smith-driven mutations" {
    const setup = try buildSetup();
    try std.testing.fuzz(setup, fuzzTransport, .{});
}

fn fuzzTransport(setup: Setup, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;

    var i_rng = pqnoize.testing.SeedStream.init("fuzz-xport-i");
    var r_rng = pqnoize.testing.SeedStream.init("fuzz-xport-r");

    var initiator = try pqnoize.Connection.initInitiator(gpa, .{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .initiator,
        .rng = rngFromSeedStream(&i_rng),
        .s = setup.initiator_static,
        .rs = setup.responder_static.public_key,
    });
    defer initiator.deinit();

    var responder = try pqnoize.Connection.initResponder(gpa, .{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .responder,
        .rng = rngFromSeedStream(&r_rng),
        .s = setup.responder_static,
        .rs = setup.initiator_static.public_key,
    });
    defer responder.deinit();

    // Drive the handshake to completion deterministically. The fuzzer
    // doesn't perturb handshake bytes — that's `fuzz_connection.zig`'s
    // job. Here we want a clean session to start exercising transport.
    try shuttle(&initiator, &responder, gpa);
    try shuttle(&responder, &initiator, gpa);
    if (!initiator.isEstablished() or !responder.isEstablished())
        return error.HandshakeFailed;

    while (!smith.eos()) {
        // Direction: sender / receiver pick.
        const direction = smith.value(enum { i_to_r, r_to_i });
        const sender = if (direction == .i_to_r) &initiator else &responder;
        const receiver = if (direction == .i_to_r) &responder else &initiator;

        // Plaintext: smith picks length and content. Cap at 256 to keep
        // iter cost manageable; that's plenty to exercise the path.
        const pt_len = smith.valueRangeAtMost(u32, 0, 256);
        const plaintext = try gpa.alloc(u8, pt_len);
        defer gpa.free(plaintext);
        smith.bytes(plaintext);

        try sender.send(plaintext);

        // Snapshot the encrypted frame off the sender's outgoing buffer.
        const out = sender.outgoing();
        const frame = try gpa.alloc(u8, out.len);
        defer gpa.free(frame);
        @memcpy(frame, out);
        sender.consumeOutgoing(out.len);

        // Mutation choice. The mutations cover the structural attack
        // shapes a real adversary or transport layer might apply.
        const mutation = smith.value(enum {
            pass_through, // legitimate frame
            flip_byte, // single-bit AEAD tamper
            zero_payload, // overwrite ciphertext with zeros
            truncate, // cut frame short
            extend, // append garbage
        });

        switch (mutation) {
            .pass_through => {
                // Must succeed and the receiver must observe the exact
                // plaintext we sent, with inbox ownership transferring
                // cleanly through nextMessage / freeMessage.
                try receiver.recv(frame);
                const got = receiver.nextMessage() orelse return error.MissingMessage;
                defer receiver.freeMessage(got);
                try std.testing.expectEqualSlices(u8, plaintext, got);
            },
            // For all tamper variants: per Noise spec §11.2, the
            // connection aborts on any decrypt failure. Our impl
            // transitions to `.closed` accordingly. The harness drains
            // anything that legitimately landed in the inbox before
            // the abort (e.g. `extend` may parse a clean prefix
            // successfully before AEAD-failing on the trailing junk),
            // then ends this fuzz iteration. Smith starts the next
            // iteration with fresh connection state.
            .flip_byte => {
                if (frame.len > 0) {
                    const idx = smith.valueRangeAtMost(u32, 0, @intCast(frame.len - 1));
                    const xor = smith.valueRangeAtMost(u8, 1, 255);
                    frame[idx] ^= xor;
                }
                receiver.recv(frame) catch {};
                while (receiver.nextMessage()) |msg| receiver.freeMessage(msg);
                return;
            },
            .zero_payload => {
                // Keep the 2-byte length prefix intact; zero out the
                // ciphertext+tag region. AEAD must reject.
                if (frame.len > 2) @memset(frame[2..], 0);
                receiver.recv(frame) catch {};
                while (receiver.nextMessage()) |msg| receiver.freeMessage(msg);
                return;
            },
            .truncate => {
                if (frame.len > 0) {
                    const new_len = smith.valueRangeAtMost(u32, 0, @intCast(frame.len - 1));
                    receiver.recv(frame[0..new_len]) catch {};
                    while (receiver.nextMessage()) |msg| receiver.freeMessage(msg);
                }
                return;
            },
            .extend => {
                const extra = smith.valueRangeAtMost(u32, 1, 64);
                const ext = try gpa.alloc(u8, frame.len + extra);
                defer gpa.free(ext);
                @memcpy(ext[0..frame.len], frame);
                smith.bytes(ext[frame.len..]);
                // The recv may parse the original frame cleanly and
                // then AEAD-fail on the trailing junk, leaving the
                // legit prefix in inbox. Drain whatever's there, then
                // end the iteration.
                receiver.recv(ext) catch {};
                while (receiver.nextMessage()) |msg| receiver.freeMessage(msg);
                return;
            },
        }
    }
}
