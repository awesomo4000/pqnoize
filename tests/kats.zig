//! Known-Answer Tests (KATs).
//!
//! Each test takes a frozen `(input, expected_output)` pair from an
//! authoritative source and asserts byte-for-byte equality. KATs catch
//! "I implemented my own slightly-incompatible variant" — exactly the bug
//! class that round-trip tests miss because both ends share the bug.
//!
//! Sources used:
//!   - RFC 8439 §2.8.2  — ChaCha20-Poly1305 AEAD
//!   (more added as we implement higher layers: Noise nonce construction,
//!    HKDF chains, full handshake transcripts.)

const std = @import("std");
const testing = std.testing;
const pqnoize = @import("pqnoize");
const oracle = @import("oracle_vectors.zig");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

// RFC 8439 §2.8.2 — "Sunscreen" test vector.
// Pinned here so that any future change to nonce construction, key handling,
// or AAD ordering in our wrapping code is caught immediately. We use stdlib's
// AEAD directly today; once `CipherState` exists, this same vector will be
// re-run through it to verify our Noise-style framing matches RFC bytes.
test "RFC 8439 §2.8.2 ChaCha20-Poly1305 encrypt produces published ciphertext+tag" {
    const key: [32]u8 = .{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce: [12]u8 = .{
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    const aad: [12]u8 = .{
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    };
    const plaintext: []const u8 =
        "Ladies and Gentlemen of the class of '99: " ++
        "If I could offer you only one tip for the future, " ++
        "sunscreen would be it.";

    const expected_ciphertext = [_]u8{
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    };
    const expected_tag = [_]u8{
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };

    var ciphertext: [114]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, &aad, nonce, key);

    try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    // Round-trip: decrypt back to the original plaintext.
    var decrypted: [114]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, &aad, nonce, key);
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

// Noise rev 34 §12 mandates that the 12-byte ChaCha20-Poly1305 nonce is
// `[0,0,0,0] ++ little_endian_u64(n)`. Any deviation breaks interop. This
// test pins our wiring by encrypting through `CipherState` and decrypting
// through stdlib AEAD with a hand-built nonce — if the constructions ever
// diverge, decryption fails or returns wrong bytes.
test "Noise nonce construction: CipherState output decrypts under hand-built nonce" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);

    const ad = "noise-ad";
    const plaintext = "abcdefghijklmnop";

    // Walk a few counters including high-byte boundaries to catch endianness
    // bugs in the LE u64 layout.
    const counters = [_]u64{ 0, 1, 255, 256, 0x0102030405060708 };

    for (counters) |n| {
        var cs = pqnoize.CipherState.init(key);
        cs.n = n;

        var ct: [plaintext.len + 16]u8 = undefined;
        try cs.encryptWithAd(ad, plaintext, &ct);

        // Hand-build the Noise nonce and decrypt with stdlib directly.
        var nonce: [12]u8 = @splat(0);
        std.mem.writeInt(u64, nonce[4..12], n, .little);

        var pt: [plaintext.len]u8 = undefined;
        const tag: [16]u8 = ct[plaintext.len..][0..16].*;
        try ChaCha20Poly1305.decrypt(&pt, ct[0..plaintext.len], tag, ad, nonce, key);
        try testing.expectEqualSlices(u8, plaintext, &pt);
    }
}

// FIPS-203 fixes the ML-KEM-768 byte sizes. If we accidentally pick up the
// 512 or 1024 variant (or stdlib renames its types), this fires immediately
// at test time rather than producing a working-but-wrong network protocol.
//
// TODO: swap in NIST ACVP byte vectors (seed -> pk/sk/ct/ss) for a full KAT
// once the project takes a network/file dependency. Today we stand on
// stdlib's own NIST KATs for the Kyber d00 line; FIPS-203 nist.* vectors
// aren't checked in stdlib so we'd have to bring our own.
test "ML-KEM-768 wrapper exposes FIPS-203 byte sizes" {
    try testing.expectEqual(@as(usize, 64), pqnoize.kem.seed_length);
    try testing.expectEqual(@as(usize, 32), pqnoize.kem.encaps_seed_length);
    try testing.expectEqual(@as(usize, 32), pqnoize.kem.shared_length);
    try testing.expectEqual(@as(usize, 1088), pqnoize.kem.ciphertext_length);
    try testing.expectEqual(@as(usize, 1184), pqnoize.kem.public_key_length);
}

// Noise rev 34 §4.3 spells out HKDF as a recursive-HMAC chain:
//   temp_key = HMAC(chaining_key, ikm)
//   output1  = HMAC(temp_key, 0x01)
//   output2  = HMAC(temp_key, output1 || 0x02)
//   output3  = HMAC(temp_key, output2 || 0x03)
//
// Stdlib HKDF is byte-identical to this when info is empty and the output
// is N*HASHLEN. We pin that equivalence — and our wiring of it inside
// SymmetricState.mixKey — by hand-rolling the recursive form here and
// asserting the resulting ck/k match what mixKey produced. If anyone
// changes mixKey to pass a non-empty info or swap salt/ikm, this fires.
test "SymmetricState.mixKey matches Noise §4.3 recursive-HMAC HKDF" {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

    var s = pqnoize.SymmetricState.init("Noise_pqKK_kat");
    const ck_before = s.ck;
    const ikm = "input-keying-material";

    var temp_key: [32]u8 = undefined;
    {
        var m = HmacSha256.init(&ck_before);
        m.update(ikm);
        m.final(&temp_key);
    }
    var output1: [32]u8 = undefined;
    {
        var m = HmacSha256.init(&temp_key);
        m.update(&[_]u8{0x01});
        m.final(&output1);
    }
    var output2: [32]u8 = undefined;
    {
        var m = HmacSha256.init(&temp_key);
        m.update(&output1);
        m.update(&[_]u8{0x02});
        m.final(&output2);
    }

    s.mixKey(ikm);
    try testing.expectEqualSlices(u8, &output1, &s.ck);
    try testing.expect(s.cipher != null);
    try testing.expectEqualSlices(u8, &output2, &s.cipher.?.k);
}

test "ChaCha20-Poly1305 rejects tampered ciphertext with AuthenticationFailed" {
    const key: [32]u8 = .{0xaa} ** 32;
    const nonce: [12]u8 = .{0xbb} ** 12;
    const aad = "header";
    const plaintext = "secret payload";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, aad, nonce, key);

    ciphertext[0] ^= 1;

    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, aad, nonce, key),
    );
}

// ── Cross-implementation oracle tests vs. clatter ────────────────────────
//
// `tests/oracle_vectors.zig` is regenerated by `scripts/build-oracle.sh`,
// which drives a clatter-based pqKK handshake under fully pinned inputs
// (statics + ephemeral seeds via FIPS-203 deterministic keygen, encaps
// seeds plumbed into a scripted RNG inside clatter). Our impl runs
// the same handshake against the same pinned inputs and we assert the
// wire bytes, handshake hash, and Split keys all match clatter byte-for-
// byte. This is the test category that catches "we implemented our own
// slightly-incompatible variant."
//
// When `oracle.generated == false` (the placeholder case shipped before
// the script has been run on a given checkout), each test skips itself.

fn rngFromFixed(fixed: *pqnoize.testing.FixedBytesRng) pqnoize.Rng {
    return fixed.rng();
}

test "oracle: initiator produces clatter-identical msg1" {
    if (!oracle.generated) return error.SkipZigTest;

    const i_static = pqnoize.kem.Kem.KeyPair{
        .public_key = try pqnoize.kem.Kem.PublicKey.fromBytes(&oracle.alice_static_pub),
        .secret_key = try pqnoize.kem.Kem.SecretKey.fromBytes(&oracle.alice_static_sec),
    };
    const r_static_pub = try pqnoize.kem.Kem.PublicKey.fromBytes(&oracle.bob_static_pub);
    const i_eph = pqnoize.kem.Kem.KeyPair{
        .public_key = try pqnoize.kem.Kem.PublicKey.fromBytes(&oracle.alice_eph_pub),
        .secret_key = try pqnoize.kem.Kem.SecretKey.fromBytes(&oracle.alice_eph_sec),
    };

    // Initiator's full per-message rng stream (just the skem encaps m
    // for pqKK msg1, since the ephemeral is pre-built).
    var rng = pqnoize.testing.FixedBytesRng.init(&oracle.alice_rng);
    var hs = pqnoize.HandshakeState.init(.{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .initiator,
        .rng = rngFromFixed(&rng),
        .s = i_static,
        .rs = r_static_pub,
        .e = i_eph,
    });

    const m1_len = try hs.writeMessageLen(0);
    try testing.expectEqual(oracle.msg1.len, m1_len);
    const m1 = try testing.allocator.alloc(u8, m1_len);
    defer testing.allocator.free(m1);
    _ = try hs.writeMessage("", m1);

    try testing.expectEqualSlices(u8, &oracle.msg1, m1);
}

test "oracle: responder reads msg1 and produces clatter-identical msg2 + Split" {
    if (!oracle.generated) return error.SkipZigTest;

    const r_static = pqnoize.kem.Kem.KeyPair{
        .public_key = try pqnoize.kem.Kem.PublicKey.fromBytes(&oracle.bob_static_pub),
        .secret_key = try pqnoize.kem.Kem.SecretKey.fromBytes(&oracle.bob_static_sec),
    };
    const i_static_pub = try pqnoize.kem.Kem.PublicKey.fromBytes(&oracle.alice_static_pub);

    // Responder's per-message rng stream: 32 B for ekem encaps + 32 B
    // for skem encaps, in the same order our walker visits them.
    var rng = pqnoize.testing.FixedBytesRng.init(&oracle.bob_rng);

    var hs = pqnoize.HandshakeState.init(.{
        .pattern = &pqnoize.pattern.pqKK,
        .role = .responder,
        .rng = rngFromFixed(&rng),
        .s = r_static,
        .rs = i_static_pub,
    });

    // Read clatter's msg1.
    const p1_len = try hs.readPayloadLen(oracle.msg1.len);
    const p1 = try testing.allocator.alloc(u8, p1_len);
    defer testing.allocator.free(p1);
    const r1 = try hs.readMessage(&oracle.msg1, p1);
    try testing.expect(r1.split == null);

    // Produce msg2 and verify byte-equality with clatter.
    const m2_len = try hs.writeMessageLen(0);
    try testing.expectEqual(oracle.msg2.len, m2_len);
    const m2 = try testing.allocator.alloc(u8, m2_len);
    defer testing.allocator.free(m2);
    const w2 = try hs.writeMessage("", m2);
    try testing.expectEqualSlices(u8, &oracle.msg2, m2);

    // Final handshake hash and Split keys must match.
    const split = w2.split orelse return error.TestExpectedSplit;
    try testing.expectEqualSlices(u8, &oracle.handshake_hash, &hs.handshakeHash());
    try testing.expectEqualSlices(u8, &oracle.c1_key, &split.c1.k);
    try testing.expectEqualSlices(u8, &oracle.c2_key, &split.c2.k);
}
