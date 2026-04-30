//! Noise CipherState — a (key, nonce-counter) pair driving an AEAD.
//!
//! Inherited unchanged from Noise rev 34 §5.1. The cipher binding is fixed
//! by §12: ChaCha20-Poly1305, with a 12-byte nonce constructed as
//!
//!     nonce = [0, 0, 0, 0] ++ little_endian_u64(n)
//!
//! Get this wrong by a byte and we'll only interop with ourselves — see
//! research/pqnoise-comms-library.md for the call-out.
//!
//! Differences from the spec text worth noting:
//!
//!   * The spec defines CipherState over an optional key, with a "no key"
//!     mode that passes plaintext through unchanged. We keep CipherState
//!     always-keyed; the optional-key behavior lives one layer up in
//!     SymmetricState's EncryptAndHash, where it belongs. This keeps the
//!     CipherState API total and the buffer-sizing rule unambiguous.
//!
//!   * Rekey() is not implemented for v1. Add when long-lived sessions
//!     warrant it (research notes flag this as an open question).

const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const key_length = ChaCha20Poly1305.key_length;
pub const tag_length = ChaCha20Poly1305.tag_length;
pub const nonce_length = ChaCha20Poly1305.nonce_length;

comptime {
    std.debug.assert(key_length == 32);
    std.debug.assert(tag_length == 16);
    std.debug.assert(nonce_length == 12);
}

/// The largest nonce a CipherState may use. The Noise spec reserves
/// nonce 2^64 - 1 (for Rekey, when implemented), so usable values are
/// `0 .. max_nonce` inclusive (i.e. 0 .. 2^64 - 2). After using
/// `max_nonce`, the internal counter increments to 2^64 - 1 and the
/// next call fails closed with `error.NonceExhausted`.
pub const max_nonce: u64 = std.math.maxInt(u64) - 1;

pub const Error = error{
    /// The 64-bit counter has reached the reserved value. The session
    /// must be torn down or rekeyed; further sends would risk nonce reuse.
    NonceExhausted,
    /// AEAD tag verification failed. The ciphertext is forged or
    /// truncated; the counter has *not* been advanced.
    AuthenticationFailed,
};

pub const CipherState = struct {
    k: [key_length]u8,
    n: u64 = 0,

    pub fn init(key: [key_length]u8) CipherState {
        return .{ .k = key };
    }

    /// Build the 12-byte ChaCha20-Poly1305 nonce per Noise §12. Public so
    /// tests can pin the byte layout against the spec.
    pub fn nonceBytes(n: u64) [nonce_length]u8 {
        var out: [nonce_length]u8 = @splat(0);
        std.mem.writeInt(u64, out[4..12], n, .little);
        return out;
    }

    /// Required output-buffer size for a given plaintext length.
    pub fn ciphertextLen(plaintext_len: usize) usize {
        return plaintext_len + tag_length;
    }

    /// Encrypt `plaintext` with associated data `ad`, writing
    /// `plaintext.len + tag_length` bytes into `ciphertext_out`. The tag
    /// is appended after the ciphertext to match the on-wire layout.
    /// On success the internal counter is advanced by one.
    pub fn encryptWithAd(
        self: *CipherState,
        ad: []const u8,
        plaintext: []const u8,
        ciphertext_out: []u8,
    ) Error!void {
        std.debug.assert(ciphertext_out.len == ciphertextLen(plaintext.len));
        if (self.n > max_nonce) return error.NonceExhausted;
        const nonce = nonceBytes(self.n);
        const ct = ciphertext_out[0..plaintext.len];
        const tag: *[tag_length]u8 = ciphertext_out[plaintext.len..][0..tag_length];
        ChaCha20Poly1305.encrypt(ct, tag, plaintext, ad, nonce, self.k);
        self.n += 1;
    }

    /// Decrypt `ciphertext` (which carries a trailing 16-byte tag) under
    /// associated data `ad`, writing `ciphertext.len - tag_length` bytes
    /// into `plaintext_out`. Per spec, on AEAD failure the counter is left
    /// unchanged so the caller can recover or close cleanly.
    pub fn decryptWithAd(
        self: *CipherState,
        ad: []const u8,
        ciphertext: []const u8,
        plaintext_out: []u8,
    ) Error!void {
        std.debug.assert(ciphertext.len >= tag_length);
        std.debug.assert(plaintext_out.len == ciphertext.len - tag_length);
        if (self.n > max_nonce) return error.NonceExhausted;
        const nonce = nonceBytes(self.n);
        const ct = ciphertext[0..plaintext_out.len];
        const tag: [tag_length]u8 = ciphertext[plaintext_out.len..][0..tag_length].*;
        ChaCha20Poly1305.decrypt(plaintext_out, ct, tag, ad, nonce, self.k) catch
            return error.AuthenticationFailed;
        self.n += 1;
    }

    /// Best-effort wipe of the key material. Use on session teardown.
    pub fn secureZero(self: *CipherState) void {
        std.crypto.secureZero(u8, &self.k);
        self.n = 0;
    }
};

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "nonceBytes places counter as little-endian u64 after four zero bytes" {
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        &CipherState.nonceBytes(0),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0 },
        &CipherState.nonceBytes(1),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0 },
        &CipherState.nonceBytes(255),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0, 0, 0 },
        &CipherState.nonceBytes(256),
    );
    try testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        &CipherState.nonceBytes(max_nonce),
    );
}

test "encrypt/decrypt round-trips and advances both counters" {
    const key: [key_length]u8 = .{0x42} ** key_length;
    var enc = CipherState.init(key);
    var dec = CipherState.init(key);

    const plaintext = "hello pqnoise";
    const ad = "header bytes";
    var ct: [plaintext.len + tag_length]u8 = undefined;
    try enc.encryptWithAd(ad, plaintext, &ct);
    try testing.expectEqual(@as(u64, 1), enc.n);

    var pt: [plaintext.len]u8 = undefined;
    try dec.decryptWithAd(ad, &ct, &pt);
    try testing.expectEqual(@as(u64, 1), dec.n);
    try testing.expectEqualSlices(u8, plaintext, &pt);
}

test "successive encrypts produce distinct ciphertexts (counter advances)" {
    const key: [key_length]u8 = .{0x11} ** key_length;
    var enc = CipherState.init(key);

    const plaintext = "same plaintext";
    var ct0: [plaintext.len + tag_length]u8 = undefined;
    var ct1: [plaintext.len + tag_length]u8 = undefined;
    try enc.encryptWithAd("", plaintext, &ct0);
    try enc.encryptWithAd("", plaintext, &ct1);
    try testing.expect(!std.mem.eql(u8, &ct0, &ct1));
    try testing.expectEqual(@as(u64, 2), enc.n);
}

test "tampered ciphertext returns AuthenticationFailed and does not advance counter" {
    const key: [key_length]u8 = .{0x33} ** key_length;
    var enc = CipherState.init(key);
    var dec = CipherState.init(key);

    const plaintext = "must be tamper-evident";
    var ct: [plaintext.len + tag_length]u8 = undefined;
    try enc.encryptWithAd("ad", plaintext, &ct);
    ct[3] ^= 1;

    var pt: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        dec.decryptWithAd("ad", &ct, &pt),
    );
    try testing.expectEqual(@as(u64, 0), dec.n);
}

test "tampered associated data returns AuthenticationFailed" {
    const key: [key_length]u8 = .{0x55} ** key_length;
    var enc = CipherState.init(key);
    var dec = CipherState.init(key);

    const plaintext = "ad-bound";
    var ct: [plaintext.len + tag_length]u8 = undefined;
    try enc.encryptWithAd("real-ad", plaintext, &ct);

    var pt: [plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        dec.decryptWithAd("fake-ad", &ct, &pt),
    );
}

test "encryptWithAd rejects nonce exhaustion at the reserved value" {
    const key: [key_length]u8 = .{0x77} ** key_length;
    var enc = CipherState.init(key);
    var ct: [16 + tag_length]u8 = undefined;

    // Last permitted nonce: max_nonce (= 2^64 - 2). Spec says 0..2^64-2
    // are usable; 2^64 - 1 is reserved. Using max_nonce must succeed
    // and advance the counter to the reserved value.
    enc.n = max_nonce;
    try enc.encryptWithAd("", "sixteen byte msg", &ct);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), enc.n);

    // The next call hits the reserved value and must fail closed
    // without advancing or producing output.
    try testing.expectError(
        error.NonceExhausted,
        enc.encryptWithAd("", "sixteen byte msg", &ct),
    );
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), enc.n);
}
