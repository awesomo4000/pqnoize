//! Test-only helpers for deterministic handshake replay.
//!
//! Production code never reaches for `std.crypto.random` directly — every
//! operation that consumes randomness (ephemeral keygen, KEM encapsulation)
//! takes its randomness as an explicit parameter. In tests we use a
//! `SeedStream` to derive a sequence of bytes from a single root seed via
//! SHAKE-256, so a full handshake is reproducible byte-for-byte from
//! `(initiator_seed, responder_seed)`.
//!
//! This is the foundation for golden-trace tests, replay debugging when a
//! fuzzer finds a bug, and property tests like
//!   forall seeds: initiator.tx_key == responder.rx_key after Split.

const std = @import("std");
const kem = @import("../kem.zig");

pub const SeedStream = struct {
    shake: std.crypto.hash.sha3.Shake256,

    pub fn init(seed: []const u8) SeedStream {
        var s: SeedStream = .{ .shake = std.crypto.hash.sha3.Shake256.init(.{}) };
        s.shake.update(seed);
        return s;
    }

    /// Squeeze arbitrary bytes from the stream. SHAKE-256 supports
    /// streaming squeeze so this can be called as many times as needed.
    pub fn bytes(self: *SeedStream, out: []u8) void {
        self.shake.squeeze(out);
    }

    /// Convenience: squeeze a fresh 32-byte seed (e.g. an encaps seed).
    pub fn next(self: *SeedStream) [32]u8 {
        var out: [32]u8 = undefined;
        self.bytes(&out);
        return out;
    }
};

/// Derive an ML-KEM-768 keypair deterministically from the next bytes of
/// the given stream. Same stream state in → same keypair out.
pub fn keypair(stream: *SeedStream) !kem.Kem.KeyPair {
    var seed: [kem.seed_length]u8 = undefined;
    stream.bytes(&seed);
    return kem.Kem.KeyPair.generateDeterministic(seed);
}

/// Encapsulate to `pk` using the next 32 bytes of the stream as the
/// encaps seed. Same stream state in → same `(ciphertext, shared_secret)`.
pub fn encaps(pk: kem.Kem.PublicKey, stream: *SeedStream) kem.Kem.EncapsulatedSecret {
    var seed: [kem.encaps_seed_length]u8 = undefined;
    stream.bytes(&seed);
    return pk.encapsDeterministic(&seed);
}

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "SeedStream is deterministic for a given root seed" {
    var a = SeedStream.init("pqnoize-test-root");
    var b = SeedStream.init("pqnoize-test-root");
    for (0..4) |_| {
        try testing.expectEqualSlices(u8, &a.next(), &b.next());
    }
}

test "SeedStream produces distinct seeds across squeezes" {
    var s = SeedStream.init("pqnoize-test-root");
    const first = s.next();
    const second = s.next();
    try testing.expect(!std.mem.eql(u8, &first, &second));
}

test "different root seeds produce different streams" {
    var a = SeedStream.init("seed-a");
    var b = SeedStream.init("seed-b");
    try testing.expect(!std.mem.eql(u8, &a.next(), &b.next()));
}

test "SeedStream.bytes supports arbitrary lengths" {
    var s = SeedStream.init("long-output");
    var out: [128]u8 = undefined;
    s.bytes(&out);
    // Trivial sanity: not all zero.
    try testing.expect(!std.mem.allEqual(u8, &out, 0));
}

test "deterministic keypair: same stream yields byte-identical public key" {
    var sa = SeedStream.init("kp-test");
    var sb = SeedStream.init("kp-test");
    const ka = try keypair(&sa);
    const kb = try keypair(&sb);
    try testing.expectEqualSlices(u8, &ka.public_key.toBytes(), &kb.public_key.toBytes());
}

test "deterministic encaps: same stream yields byte-identical ciphertext" {
    var sa = SeedStream.init("enc-test");
    var sb = SeedStream.init("enc-test");
    // Burn a keypair off both streams identically so the encaps seed is the
    // same across them.
    const ka = try keypair(&sa);
    const kb = try keypair(&sb);
    const ea = encaps(ka.public_key, &sa);
    const eb = encaps(kb.public_key, &sb);
    try testing.expectEqualSlices(u8, &ea.ciphertext, &eb.ciphertext);
    try testing.expectEqualSlices(u8, &ea.shared_secret, &eb.shared_secret);
}
