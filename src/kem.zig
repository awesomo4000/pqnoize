//! KEM binding for pqnoize.
//!
//! Pinned to ML-KEM-768 in the FIPS-203 form (the `nist` namespace, not
//! the older round-3 `kyber_d00`). All sizes the rest of the library
//! depends on are re-exported as named constants so a future swap to
//! ML-KEM-1024 (or another KEM) localises here.
//!
//! Production code should use `Kem.PublicKey.encaps(pk, io)` and
//! `Kem.KeyPair.generate(io)`, both of which take a `std.Io` for
//! randomness — never reach for `std.crypto.random` directly. Tests
//! use the `*Deterministic` variants seeded from `testing/SeedStream`.

const std = @import("std");

pub const Kem = std.crypto.kem.ml_kem.MLKem768;

pub const seed_length: usize = Kem.seed_length;
pub const encaps_seed_length: usize = Kem.encaps_seed_length;
pub const ciphertext_length: usize = Kem.ciphertext_length;
pub const shared_length: usize = Kem.shared_length;
pub const public_key_length: usize = Kem.PublicKey.encoded_length;
pub const secret_key_length: usize = Kem.SecretKey.encoded_length;

comptime {
    // Sanity-pin the FIPS-203 ML-KEM-768 sizes. These are spec-fixed; a
    // mismatch means we picked up the wrong type.
    std.debug.assert(seed_length == 64);
    std.debug.assert(encaps_seed_length == 32);
    std.debug.assert(shared_length == 32);
    std.debug.assert(ciphertext_length == 1088);
    std.debug.assert(public_key_length == 1184);
}

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "round-trip: keygen -> encaps -> decaps yields matching shared secrets" {
    const kp_seed: [seed_length]u8 = .{0x01} ** seed_length;
    const enc_seed: [encaps_seed_length]u8 = .{0x02} ** encaps_seed_length;

    const kp = try Kem.KeyPair.generateDeterministic(kp_seed);
    const enc = kp.public_key.encapsDeterministic(&enc_seed);
    const ss = try kp.secret_key.decaps(&enc.ciphertext);

    try testing.expectEqualSlices(u8, &enc.shared_secret, &ss);
}

test "decaps on tampered ciphertext yields a different (implicit-rejection) secret" {
    const kp_seed: [seed_length]u8 = .{0x10} ** seed_length;
    const enc_seed: [encaps_seed_length]u8 = .{0x11} ** encaps_seed_length;

    const kp = try Kem.KeyPair.generateDeterministic(kp_seed);
    var enc = kp.public_key.encapsDeterministic(&enc_seed);
    enc.ciphertext[0] ^= 1;

    // ML-KEM uses implicit rejection: decaps always succeeds but returns
    // an unrelated secret on tamper. So the operation succeeds while the
    // bytes diverge — which is exactly what the AEAD layer above will
    // catch as an authentication failure on the next message.
    const ss = try kp.secret_key.decaps(&enc.ciphertext);
    try testing.expect(!std.mem.eql(u8, &enc.shared_secret, &ss));
}
