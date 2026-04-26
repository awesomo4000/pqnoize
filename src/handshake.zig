//! pqKK handshake state machine — the token-walking interpreter.
//!
//! Walks a `Pattern` (currently always `pqKK`) one message at a time.
//! Each message advances `msg_index`; when the final message is consumed
//! the state machine emits a `Split` with the two transport CipherStates
//! and considers itself finished.
//!
//! Randomness is injected via the `Rng` interface — never reaches for
//! `std.crypto.random` here. This is what lets tests replay handshakes
//! byte-for-byte under a seeded `SeedStream`.
//!
//! The state machine is single-typed for now (one `HandshakeState`,
//! state tracked via `msg_index`). The research notes flag a stronger
//! typestate-via-distinct-types variant; that's a v1.5 if friction
//! warrants it. For now wrong-call returns `error.NotMyTurn` rather
//! than failing at compile time.

const std = @import("std");
const cipher_state = @import("cipher_state.zig");
const symmetric_state = @import("symmetric_state.zig");
const kem = @import("kem.zig");
const pattern = @import("pattern.zig");
const Rng = @import("rng.zig").Rng;

pub const Role = enum { initiator, responder };

pub const Error = error{
    /// `writeMessage` called when it's the peer's turn (or vice versa for
    /// `readMessage`), or after the handshake has emitted Split.
    NotMyTurn,
    /// The handshake is already complete; no more messages may be sent.
    HandshakeAlreadyDone,
    /// Caller's buffer doesn't match `writeMessageLen` / `readPayloadLen`.
    InvalidMessageLength,
    /// Peer-supplied static or ephemeral public key didn't decode.
    InvalidPublicKey,
    /// A token unsupported in message bodies (`.s`, `.psk`) appeared in
    /// the pattern's `messages` slot. Indicates a malformed Pattern.
    InvalidPatternToken,
} || symmetric_state.Error;

pub const Init = struct {
    pattern: *const pattern.Pattern,
    role: Role,
    rng: Rng,
    /// Caller's own static keypair.
    s: kem.Kem.KeyPair,
    /// Peer's static public key (pre-known for pqKK).
    rs: kem.Kem.PublicKey,
    prologue: []const u8 = &.{},
    protocol_name: []const u8 = pattern.pqKK_MLKEM768_protocol_name,
};

pub const WriteResult = struct {
    bytes_written: usize,
    /// Non-null only on the last message of the pattern.
    split: ?symmetric_state.Split = null,
};

pub const ReadResult = struct {
    payload_len: usize,
    split: ?symmetric_state.Split = null,
};

pub const HandshakeState = struct {
    sym: symmetric_state.SymmetricState,
    pat: *const pattern.Pattern,
    role: Role,
    rng: Rng,
    msg_index: u8,

    s: kem.Kem.KeyPair, // own static
    rs: kem.Kem.PublicKey, // peer static (pre-known)
    e: ?kem.Kem.KeyPair = null, // own ephemeral, set on first .e write
    re: ?kem.Kem.PublicKey = null, // peer ephemeral, set on first .e read

    pub fn init(opts: Init) HandshakeState {
        var sym = symmetric_state.SymmetricState.init(opts.protocol_name);
        sym.mixHash(opts.prologue);

        // Pre-message hashing per Noise §7.3: initiator's pre-message
        // public keys first, then responder's. For pqKK both pre-messages
        // are `[s]`, so we hash both static pubkeys regardless of role.
        const initiator_s_pub: [kem.public_key_length]u8 =
            if (opts.role == .initiator) opts.s.public_key.toBytes() else opts.rs.toBytes();
        const responder_s_pub: [kem.public_key_length]u8 =
            if (opts.role == .responder) opts.s.public_key.toBytes() else opts.rs.toBytes();
        sym.mixHash(&initiator_s_pub);
        sym.mixHash(&responder_s_pub);

        return .{
            .sym = sym,
            .pat = opts.pattern,
            .role = opts.role,
            .rng = opts.rng,
            .msg_index = 0,
            .s = opts.s,
            .rs = opts.rs,
        };
    }

    pub fn isFinished(self: HandshakeState) bool {
        return self.msg_index >= self.pat.messages.len;
    }

    /// True iff it's our turn to *send* the next message. The mirror is
    /// also true: when this is false, it's our turn to *read*.
    pub fn isMyTurn(self: HandshakeState) bool {
        if (self.isFinished()) return false;
        const initiator_writes = (self.msg_index % 2 == 0);
        return initiator_writes == (self.role == .initiator);
    }

    fn tokenWireLen(t: pattern.Token) Error!usize {
        return switch (t) {
            .e => kem.public_key_length,
            .ekem, .skem => kem.ciphertext_length,
            .s, .psk => error.InvalidPatternToken,
        };
    }

    fn walkSizes(self: HandshakeState) Error!struct { tokens: usize, will_arm: bool } {
        const tokens = self.pat.messages[self.msg_index];
        var token_total: usize = 0;
        var will_arm = self.sym.cipher != null;
        for (tokens) |t| {
            token_total += try tokenWireLen(t);
            switch (t) {
                .ekem, .skem, .psk => will_arm = true,
                else => {},
            }
        }
        return .{ .tokens = token_total, .will_arm = will_arm };
    }

    /// Total bytes `writeMessage` will emit for the given payload length.
    pub fn writeMessageLen(self: HandshakeState, payload_len: usize) Error!usize {
        if (self.isFinished()) return error.HandshakeAlreadyDone;
        const sizes = try self.walkSizes();
        const tag: usize = if (sizes.will_arm) cipher_state.tag_length else 0;
        return sizes.tokens + payload_len + tag;
    }

    /// Payload-out length for a given received message.
    pub fn readPayloadLen(self: HandshakeState, msg_len: usize) Error!usize {
        if (self.isFinished()) return error.HandshakeAlreadyDone;
        const sizes = try self.walkSizes();
        const tag: usize = if (sizes.will_arm) cipher_state.tag_length else 0;
        const overhead = sizes.tokens + tag;
        if (msg_len < overhead) return error.InvalidMessageLength;
        return msg_len - overhead;
    }

    pub fn writeMessage(
        self: *HandshakeState,
        payload: []const u8,
        out: []u8,
    ) Error!WriteResult {
        if (!self.isMyTurn()) {
            return if (self.isFinished()) error.HandshakeAlreadyDone else error.NotMyTurn;
        }
        const expected = try self.writeMessageLen(payload.len);
        if (out.len != expected) return error.InvalidMessageLength;

        const tokens = self.pat.messages[self.msg_index];
        var pos: usize = 0;
        var rng_buf: [kem.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &rng_buf);

        for (tokens) |t| switch (t) {
            .e => {
                self.rng.bytes(rng_buf[0..kem.seed_length]);
                self.e = kem.Kem.KeyPair.generateDeterministic(rng_buf) catch
                    return error.InvalidPublicKey;
                const e_pub: [kem.public_key_length]u8 = self.e.?.public_key.toBytes();
                @memcpy(out[pos..][0..kem.public_key_length], &e_pub);
                self.sym.mixHash(&e_pub);
                pos += kem.public_key_length;
            },
            .ekem => {
                const re = self.re orelse return error.InvalidPatternToken;
                self.rng.bytes(rng_buf[0..kem.encaps_seed_length]);
                const enc = re.encapsDeterministic(rng_buf[0..kem.encaps_seed_length]);
                @memcpy(out[pos..][0..kem.ciphertext_length], &enc.ciphertext);
                self.sym.mixHash(&enc.ciphertext);
                self.sym.mixKey(&enc.shared_secret);
                pos += kem.ciphertext_length;
            },
            .skem => {
                self.rng.bytes(rng_buf[0..kem.encaps_seed_length]);
                const enc = self.rs.encapsDeterministic(rng_buf[0..kem.encaps_seed_length]);
                @memcpy(out[pos..][0..kem.ciphertext_length], &enc.ciphertext);
                self.sym.mixHash(&enc.ciphertext);
                self.sym.mixKey(&enc.shared_secret);
                pos += kem.ciphertext_length;
            },
            .s, .psk => return error.InvalidPatternToken,
        };

        _ = try self.sym.encryptAndHash(payload, out[pos..]);
        self.msg_index += 1;

        var result: WriteResult = .{ .bytes_written = expected };
        if (self.isFinished()) result.split = self.sym.split();
        return result;
    }

    pub fn readMessage(
        self: *HandshakeState,
        msg: []const u8,
        payload_out: []u8,
    ) Error!ReadResult {
        if (self.isFinished()) return error.HandshakeAlreadyDone;
        if (self.isMyTurn()) return error.NotMyTurn;
        const expected_payload = try self.readPayloadLen(msg.len);
        if (payload_out.len != expected_payload) return error.InvalidMessageLength;

        const tokens = self.pat.messages[self.msg_index];
        var pos: usize = 0;

        for (tokens) |t| switch (t) {
            .e => {
                const re_bytes = msg[pos..][0..kem.public_key_length];
                self.sym.mixHash(re_bytes);
                self.re = kem.Kem.PublicKey.fromBytes(re_bytes) catch
                    return error.InvalidPublicKey;
                pos += kem.public_key_length;
            },
            .ekem => {
                const own_e = self.e orelse return error.InvalidPatternToken;
                const ct = msg[pos..][0..kem.ciphertext_length];
                self.sym.mixHash(ct);
                const ss = own_e.secret_key.decaps(ct) catch
                    return error.InvalidPublicKey;
                self.sym.mixKey(&ss);
                pos += kem.ciphertext_length;
            },
            .skem => {
                const ct = msg[pos..][0..kem.ciphertext_length];
                self.sym.mixHash(ct);
                const ss = self.s.secret_key.decaps(ct) catch
                    return error.InvalidPublicKey;
                self.sym.mixKey(&ss);
                pos += kem.ciphertext_length;
            },
            .s, .psk => return error.InvalidPatternToken,
        };

        _ = try self.sym.decryptAndHash(msg[pos..], payload_out);
        self.msg_index += 1;

        var result: ReadResult = .{ .payload_len = expected_payload };
        if (self.isFinished()) result.split = self.sym.split();
        return result;
    }

    pub fn handshakeHash(self: HandshakeState) [symmetric_state.hash_length]u8 {
        return self.sym.handshakeHash();
    }

    pub fn secureZero(self: *HandshakeState) void {
        self.sym.secureZero();
        // KEM secret keys are large arrays; zero them via the toBytes
        // round-trip surface. Stdlib doesn't expose a clean wipe, so we
        // overwrite the local copies and let the originals on the caller's
        // side be cleared by them.
        std.crypto.secureZero(u8, std.mem.asBytes(&self.s));
        if (self.e) |*ek| std.crypto.secureZero(u8, std.mem.asBytes(ek));
        self.e = null;
        self.re = null;
    }
};

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const SeedStream = @import("testing/deterministic.zig").SeedStream;
const test_helpers = @import("testing/deterministic.zig");

fn rngFromSeedStream(s: *SeedStream) Rng {
    return .{
        .ctx = s,
        .fillFn = struct {
            fn fill(ctx: *anyopaque, out: []u8) void {
                const stream: *SeedStream = @ptrCast(@alignCast(ctx));
                stream.bytes(out);
            }
        }.fill,
    };
}

test "writeMessageLen / readPayloadLen are consistent across all pqKK messages" {
    var setup = SeedStream.init("hs-len");
    const i_kp = try test_helpers.keypair(&setup);
    const r_kp = try test_helpers.keypair(&setup);

    var i_rng = SeedStream.init("hs-len-i");
    var r_rng = SeedStream.init("hs-len-r");

    var initr = HandshakeState.init(.{
        .pattern = &pattern.pqKK,
        .role = .initiator,
        .rng = rngFromSeedStream(&i_rng),
        .s = i_kp,
        .rs = r_kp.public_key,
    });
    var resp = HandshakeState.init(.{
        .pattern = &pattern.pqKK,
        .role = .responder,
        .rng = rngFromSeedStream(&r_rng),
        .s = r_kp,
        .rs = i_kp.public_key,
    });

    // msg 1: only [e], no MixKey yet, no tag.
    try testing.expectEqual(
        @as(usize, kem.public_key_length + 5),
        try initr.writeMessageLen(5),
    );
    // msg 2: [ekem, skem], MixKey runs, tag added.
    // Can't inspect msg-2 sizing until msg-1 is processed (msg_index advances).

    var msg1: [kem.public_key_length + 5]u8 = undefined;
    _ = try initr.writeMessage("hello", &msg1);
    try testing.expectEqual(@as(usize, 5), try resp.readPayloadLen(msg1.len));

    var p1: [5]u8 = undefined;
    _ = try resp.readMessage(&msg1, &p1);
    try testing.expectEqualSlices(u8, "hello", &p1);

    // msg 2 sizing: 2*ct + payload + tag
    try testing.expectEqual(
        @as(usize, 2 * kem.ciphertext_length + 7 + cipher_state.tag_length),
        try resp.writeMessageLen(7),
    );
}

test "isMyTurn alternates with msg_index and respects role" {
    var setup = SeedStream.init("hs-turn");
    const i_kp = try test_helpers.keypair(&setup);
    const r_kp = try test_helpers.keypair(&setup);
    var rng = SeedStream.init("hs-turn-r");

    var initr = HandshakeState.init(.{
        .pattern = &pattern.pqKK,
        .role = .initiator,
        .rng = rngFromSeedStream(&rng),
        .s = i_kp,
        .rs = r_kp.public_key,
    });
    var resp = HandshakeState.init(.{
        .pattern = &pattern.pqKK,
        .role = .responder,
        .rng = rngFromSeedStream(&rng),
        .s = r_kp,
        .rs = i_kp.public_key,
    });

    try testing.expect(initr.isMyTurn());
    try testing.expect(!resp.isMyTurn());

    initr.msg_index = 1;
    resp.msg_index = 1;
    try testing.expect(!initr.isMyTurn());
    try testing.expect(resp.isMyTurn());
}

test "calling writeMessage when it's not your turn returns NotMyTurn" {
    var setup = SeedStream.init("hs-wrong");
    const i_kp = try test_helpers.keypair(&setup);
    const r_kp = try test_helpers.keypair(&setup);
    var rng = SeedStream.init("hs-wrong-r");

    var resp = HandshakeState.init(.{
        .pattern = &pattern.pqKK,
        .role = .responder,
        .rng = rngFromSeedStream(&rng),
        .s = r_kp,
        .rs = i_kp.public_key,
    });

    var out: [kem.public_key_length]u8 = undefined;
    try testing.expectError(error.NotMyTurn, resp.writeMessage("", &out));
}
