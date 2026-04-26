//! Noise SymmetricState — the chaining-key + handshake-hash machine that
//! every Noise pattern (and every PQNoise pattern) drives during the
//! handshake.
//!
//! This file implements Noise rev 34 §5.2 unchanged. PQNoise inherits
//! this layer verbatim; the only PQ-specific details live in HandshakeState
//! above (KEM-based tokens replace DH).
//!
//! Cipher suite is fixed: SHA-256 / HKDF-SHA256 / ChaCha20-Poly1305.
//!
//! The internal CipherState is optional. Before any MixKey call,
//! EncryptAndHash and DecryptAndHash pass plaintext through unchanged
//! (and only mix the bytes into `h`). After MixKey, they actually encrypt.

const std = @import("std");
const cipher_state = @import("cipher_state.zig");
const CipherState = cipher_state.CipherState;

const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const hash_length = Sha256.digest_length;
pub const block_length = Sha256.block_length;

comptime {
    std.debug.assert(hash_length == 32);
}

pub const Error = error{
    /// Caller's output buffer is the wrong size for the operation.
    InvalidLength,
} || cipher_state.Error;

pub const Split = struct {
    /// Initiator -> Responder direction key.
    c1: CipherState,
    /// Responder -> Initiator direction key.
    c2: CipherState,
};

pub const SymmetricState = struct {
    ck: [hash_length]u8,
    h: [hash_length]u8,
    /// `null` until the first MixKey call. Spec calls this "k is empty."
    cipher: ?CipherState = null,

    /// Per Noise §5.2: if the protocol-name string is at most HASHLEN bytes,
    /// `h` is set to the protocol name padded with zeros; otherwise `h` is
    /// set to its SHA-256 hash. `ck` is initialized equal to `h`.
    pub fn init(protocol_name: []const u8) SymmetricState {
        var s: SymmetricState = .{
            .ck = undefined,
            .h = @splat(0),
        };
        if (protocol_name.len <= hash_length) {
            @memcpy(s.h[0..protocol_name.len], protocol_name);
        } else {
            Sha256.hash(protocol_name, &s.h, .{});
        }
        s.ck = s.h;
        return s;
    }

    pub fn mixHash(self: *SymmetricState, data: []const u8) void {
        var hasher = Sha256.init(.{});
        hasher.update(&self.h);
        hasher.update(data);
        hasher.final(&self.h);
    }

    /// HKDF expand 64 bytes from (salt = ck, ikm). First 32 → new ck;
    /// second 32 → fresh CipherState key.
    pub fn mixKey(self: *SymmetricState, ikm: []const u8) void {
        var out: [hash_length * 2]u8 = undefined;
        const prk = HkdfSha256.extract(&self.ck, ikm);
        HkdfSha256.expand(&out, &.{}, prk);
        @memcpy(&self.ck, out[0..hash_length]);
        var k: [cipher_state.key_length]u8 = undefined;
        @memcpy(&k, out[hash_length..][0..cipher_state.key_length]);
        self.cipher = CipherState.init(k);
        std.crypto.secureZero(u8, &out);
        std.crypto.secureZero(u8, &k);
    }

    /// HKDF expand 96 bytes: new ck, intermediate hash mixin, fresh
    /// CipherState key. Used by PSK patterns.
    pub fn mixKeyAndHash(self: *SymmetricState, ikm: []const u8) void {
        var out: [hash_length * 3]u8 = undefined;
        const prk = HkdfSha256.extract(&self.ck, ikm);
        HkdfSha256.expand(&out, &.{}, prk);
        @memcpy(&self.ck, out[0..hash_length]);
        self.mixHash(out[hash_length..][0..hash_length]);
        var k: [cipher_state.key_length]u8 = undefined;
        @memcpy(&k, out[2 * hash_length ..][0..cipher_state.key_length]);
        self.cipher = CipherState.init(k);
        std.crypto.secureZero(u8, &out);
        std.crypto.secureZero(u8, &k);
    }

    pub fn handshakeHash(self: SymmetricState) [hash_length]u8 {
        return self.h;
    }

    /// Number of bytes written to `out` by `encryptAndHash` for a given
    /// plaintext length. Adds a 16-byte tag iff the cipher is armed.
    pub fn ciphertextLen(self: SymmetricState, plaintext_len: usize) usize {
        const tag: usize = if (self.cipher != null) cipher_state.tag_length else 0;
        return plaintext_len + tag;
    }

    /// Inverse of `ciphertextLen` — what `decryptAndHash` will write.
    pub fn plaintextLen(self: SymmetricState, ciphertext_len: usize) Error!usize {
        if (self.cipher == null) return ciphertext_len;
        if (ciphertext_len < cipher_state.tag_length) return error.InvalidLength;
        return ciphertext_len - cipher_state.tag_length;
    }

    /// AEAD-encrypt `plaintext` with AD = current handshake hash, write
    /// `plaintext.len + tag_length` bytes to `out`, then mix the produced
    /// ciphertext into `h`. Pre-MixKey, this is a memcpy + mixHash.
    pub fn encryptAndHash(
        self: *SymmetricState,
        plaintext: []const u8,
        out: []u8,
    ) Error!usize {
        const expected = self.ciphertextLen(plaintext.len);
        if (out.len != expected) return error.InvalidLength;
        if (self.cipher) |*cs| {
            try cs.encryptWithAd(&self.h, plaintext, out);
        } else {
            @memcpy(out[0..plaintext.len], plaintext);
        }
        self.mixHash(out);
        return expected;
    }

    /// AEAD-decrypt `ciphertext` (which carries the trailing 16-byte tag
    /// when armed) with AD = current handshake hash, write the plaintext
    /// to `out`, then mix the *ciphertext* (not the plaintext!) into `h`.
    /// Per Noise spec, mixing happens regardless of plaintext content;
    /// AEAD failure leaves the cipher counter unchanged but we still
    /// don't advance `h` because we propagate the error.
    pub fn decryptAndHash(
        self: *SymmetricState,
        ciphertext: []const u8,
        out: []u8,
    ) Error!usize {
        const expected = try self.plaintextLen(ciphertext.len);
        if (out.len != expected) return error.InvalidLength;
        if (self.cipher) |*cs| {
            try cs.decryptWithAd(&self.h, ciphertext, out);
        } else {
            @memcpy(out, ciphertext);
        }
        self.mixHash(ciphertext);
        return expected;
    }

    /// Final HKDF expansion that produces the two transport CipherStates.
    /// After calling this, `self` should be considered consumed; the
    /// caller is responsible for not reusing it. (HandshakeState enforces
    /// this via typestate one layer up.)
    pub fn split(self: *SymmetricState) Split {
        var out: [hash_length * 2]u8 = undefined;
        const prk = HkdfSha256.extract(&self.ck, &.{});
        HkdfSha256.expand(&out, &.{}, prk);
        var k1: [cipher_state.key_length]u8 = undefined;
        var k2: [cipher_state.key_length]u8 = undefined;
        @memcpy(&k1, out[0..cipher_state.key_length]);
        @memcpy(&k2, out[hash_length..][0..cipher_state.key_length]);
        const result: Split = .{ .c1 = CipherState.init(k1), .c2 = CipherState.init(k2) };
        std.crypto.secureZero(u8, &out);
        std.crypto.secureZero(u8, &k1);
        std.crypto.secureZero(u8, &k2);
        return result;
    }

    pub fn secureZero(self: *SymmetricState) void {
        std.crypto.secureZero(u8, &self.ck);
        std.crypto.secureZero(u8, &self.h);
        if (self.cipher) |*cs| cs.secureZero();
        self.cipher = null;
    }
};

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "init pads short protocol names to 32 zero bytes; ck == h" {
    const name = "Noise_pqKK";
    const s = SymmetricState.init(name);
    var expected: [hash_length]u8 = @splat(0);
    @memcpy(expected[0..name.len], name);
    try testing.expectEqualSlices(u8, &expected, &s.h);
    try testing.expectEqualSlices(u8, &s.h, &s.ck);
    try testing.expect(s.cipher == null);
}

test "init hashes long protocol names" {
    const long_name = "X" ** 64;
    const s = SymmetricState.init(long_name);
    var expected: [hash_length]u8 = undefined;
    Sha256.hash(long_name, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &s.h);
    try testing.expectEqualSlices(u8, &s.h, &s.ck);
}

test "mixHash is deterministic and order-sensitive" {
    var a = SymmetricState.init("test");
    var b = SymmetricState.init("test");
    a.mixHash("alpha");
    a.mixHash("beta");
    b.mixHash("alpha");
    b.mixHash("beta");
    try testing.expectEqualSlices(u8, &a.h, &b.h);

    var c = SymmetricState.init("test");
    c.mixHash("beta");
    c.mixHash("alpha");
    try testing.expect(!std.mem.eql(u8, &a.h, &c.h));
}

test "mixKey arms the inner CipherState and changes ck" {
    var s = SymmetricState.init("test");
    const ck_before = s.ck;
    try testing.expect(s.cipher == null);

    s.mixKey("input keying material");
    try testing.expect(s.cipher != null);
    try testing.expect(!std.mem.eql(u8, &ck_before, &s.ck));
    try testing.expectEqual(@as(u64, 0), s.cipher.?.n);
}

test "encryptAndHash with no cipher passes through and updates h" {
    var s = SymmetricState.init("test");
    const plaintext = "in the clear";
    var out: [plaintext.len]u8 = undefined;
    const written = try s.encryptAndHash(plaintext, &out);
    try testing.expectEqual(plaintext.len, written);
    try testing.expectEqualSlices(u8, plaintext, &out);
}

test "encryptAndHash with cipher actually encrypts and grows output by 16" {
    var s = SymmetricState.init("test");
    s.mixKey("ikm");
    const plaintext = "secret";
    var out: [plaintext.len + cipher_state.tag_length]u8 = undefined;
    _ = try s.encryptAndHash(plaintext, &out);
    try testing.expect(!std.mem.eql(u8, plaintext, out[0..plaintext.len]));
}

test "encrypt/decrypt round-trip across two parallel SymmetricStates" {
    var a = SymmetricState.init("Noise_pqKK_test");
    var b = SymmetricState.init("Noise_pqKK_test");
    a.mixHash("prologue");
    b.mixHash("prologue");
    a.mixKey("shared-ikm");
    b.mixKey("shared-ikm");

    const plaintext = "handshake payload bytes";
    var ct: [plaintext.len + cipher_state.tag_length]u8 = undefined;
    _ = try a.encryptAndHash(plaintext, &ct);

    var pt: [plaintext.len]u8 = undefined;
    _ = try b.decryptAndHash(&ct, &pt);
    try testing.expectEqualSlices(u8, plaintext, &pt);
    // Both sides must end with identical h after symmetric ops.
    try testing.expectEqualSlices(u8, &a.h, &b.h);
    try testing.expectEqualSlices(u8, &a.ck, &b.ck);
}

test "split produces two CipherStates with distinct keys" {
    var s = SymmetricState.init("Noise_pqKK_test");
    s.mixKey("ikm");
    const sp = s.split();
    try testing.expect(!std.mem.eql(u8, &sp.c1.k, &sp.c2.k));
    try testing.expectEqual(@as(u64, 0), sp.c1.n);
    try testing.expectEqual(@as(u64, 0), sp.c2.n);
}

test "split agrees on both sides after an identical handshake" {
    var a = SymmetricState.init("Noise_pqKK_test");
    var b = SymmetricState.init("Noise_pqKK_test");
    a.mixHash("transcript-bytes");
    b.mixHash("transcript-bytes");
    a.mixKey("ikm-1");
    b.mixKey("ikm-1");
    a.mixKey("ikm-2");
    b.mixKey("ikm-2");

    const sa = a.split();
    const sb = b.split();
    try testing.expectEqualSlices(u8, &sa.c1.k, &sb.c1.k);
    try testing.expectEqualSlices(u8, &sa.c2.k, &sb.c2.k);
}

test "decryptAndHash on tampered ciphertext returns AuthenticationFailed" {
    var a = SymmetricState.init("test");
    var b = SymmetricState.init("test");
    a.mixKey("ikm");
    b.mixKey("ikm");

    const plaintext = "tamper-evident";
    var ct: [plaintext.len + cipher_state.tag_length]u8 = undefined;
    _ = try a.encryptAndHash(plaintext, &ct);
    ct[2] ^= 1;

    var pt: [plaintext.len]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, b.decryptAndHash(&ct, &pt));
}
