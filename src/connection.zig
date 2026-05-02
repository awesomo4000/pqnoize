//! Sans-IO connection: the surface a caller's driver loop interacts with.
//!
//! Lifecycle:
//!
//!   1. `initInitiator(gpa, opts)` or `initResponder(gpa, opts)` builds
//!      a Connection in `.handshaking` state. The initiator's first
//!      handshake message is queued immediately into the outbox.
//!
//!   2. The driver loop shuttles bytes:
//!        * Read from the socket → `recv(bytes)`
//!        * Write `outgoing()` to the socket → `consumeOutgoing(n)`
//!
//!   3. `recv` advances the handshake automatically: when a complete
//!      handshake message has arrived it is processed, and if it's
//!      now our turn to respond the next message is queued.
//!
//!   4. After the final handshake message both sides transition to
//!      `.established`. From then on, `send(plaintext)` encrypts and
//!      queues a transport frame, and `nextMessage()` pops the next
//!      decrypted plaintext that arrived.
//!
//! No part of this file imports `std.net`. The TCP loop lives in the
//! caller's driver, demonstrated in test client/server programs.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cipher_state = @import("cipher_state.zig");
const symmetric_state = @import("symmetric_state.zig");
const handshake = @import("handshake.zig");
const framing = @import("framing.zig");

const CipherState = cipher_state.CipherState;
const HandshakeState = handshake.HandshakeState;
const Role = handshake.Role;

pub const Error = error{
    /// `send` was called before the handshake completed.
    NotEstablished,
    /// Operation called on a connection that has been closed or errored.
    ConnectionClosed,
} || handshake.Error || framing.Error;

pub const Established = struct {
    /// Cipher used to decrypt inbound transport messages.
    rx: CipherState,
    /// Cipher used to encrypt outbound transport messages.
    tx: CipherState,
};

pub const State = union(enum) {
    /// Heap-allocated to keep the union — and therefore Connection —
    /// small once we transition to `.established`. `HandshakeState` is
    /// ~40 KB on x86_64 because ML-KEM-768 keypairs hold polynomials
    /// in NTT form (much bigger than their encoded byte length).
    /// Inlining that into the union would force every long-lived
    /// post-handshake `Connection` to permanently retain those 40 KB
    /// even though the ~80-byte `Established` is the only active
    /// variant. Owner: the enclosing Connection's `gpa`.
    handshaking: *HandshakeState,
    established: Established,
    closed: void,
};

pub const Connection = struct {
    gpa: Allocator,
    state: State,
    rx: framing.FrameReader,
    tx: framing.FrameWriter,
    /// Decrypted transport messages, oldest first. Owned by `gpa`; caller
    /// frees via `freeMessage` after `nextMessage` pops one.
    inbox: std.ArrayList([]u8),

    pub fn initInitiator(gpa: Allocator, opts: handshake.Init) Error!Connection {
        std.debug.assert(opts.role == .initiator);
        const hs = try gpa.create(HandshakeState);
        hs.* = HandshakeState.init(opts);
        var conn: Connection = .{
            .gpa = gpa,
            .state = .{ .handshaking = hs },
            .rx = .empty,
            .tx = .empty,
            .inbox = .empty,
        };
        // If driveOutboundHandshake fails (OOM allocating the message
        // buffer, OOM pushing to tx, etc.) the partially-built conn
        // would otherwise leak both ArrayList allocations and the
        // heap-allocated HandshakeState. Clean up explicitly.
        errdefer conn.deinit();
        try conn.driveOutboundHandshake();
        return conn;
    }

    pub fn initResponder(gpa: Allocator, opts: handshake.Init) Error!Connection {
        std.debug.assert(opts.role == .responder);
        const hs = try gpa.create(HandshakeState);
        hs.* = HandshakeState.init(opts);
        return .{
            .gpa = gpa,
            .state = .{ .handshaking = hs },
            .rx = .empty,
            .tx = .empty,
            .inbox = .empty,
        };
    }

    pub fn deinit(self: *Connection) void {
        self.rx.deinit(self.gpa);
        self.tx.deinit(self.gpa);
        for (self.inbox.items) |msg| self.gpa.free(msg);
        self.inbox.deinit(self.gpa);
        switch (self.state) {
            .handshaking => |hs| {
                hs.secureZero();
                self.gpa.destroy(hs);
            },
            .established => |*est| {
                est.rx.secureZero();
                est.tx.secureZero();
            },
            .closed => {},
        }
        self.state = .closed;
    }

    pub fn isEstablished(self: Connection) bool {
        return self.state == .established;
    }

    /// Caller pushes bytes that arrived from the network. Drives both the
    /// handshake (until `.established`) and the transport (decrypting any
    /// fully-arrived frames into `inbox`).
    pub fn recv(self: *Connection, bytes: []const u8) Error!void {
        if (self.state == .closed) return error.ConnectionClosed;
        try self.rx.push(self.gpa, bytes);
        try self.processInbound();
    }

    /// Encrypt `plaintext` and queue it as a transport frame.
    ///
    /// Errors thrown before any state mutation (`FrameTooLarge`,
    /// `NotEstablished`, `ConnectionClosed`, OOM allocating the frame
    /// buffer) leave the connection usable — the caller can adjust and
    /// retry.
    ///
    /// Errors thrown after the AEAD counter has advanced
    /// (`NonceExhausted` from `encryptWithAd` is checked pre-mutation
    /// so it's safe; OOM on `tx.push` happens after counter advance —
    /// peer is now ahead of us by one message-that-never-shipped) trigger
    /// `closeOnError()`. The session is desynced and continuing to use
    /// it would AEAD-fail on every subsequent decrypt at the peer.
    pub fn send(self: *Connection, plaintext: []const u8) Error!void {
        switch (self.state) {
            .established => |*est| {
                if (plaintext.len + cipher_state.tag_length > framing.max_frame_payload)
                    return error.FrameTooLarge;
                const frame = try self.gpa.alloc(u8, plaintext.len + cipher_state.tag_length);
                defer self.gpa.free(frame);
                est.tx.encryptWithAd(&.{}, plaintext, frame) catch |err| {
                    // Pre-mutation check (NonceExhausted) means counter
                    // is unchanged, but the connection cannot make
                    // forward progress regardless. Close.
                    self.closeOnError();
                    return err;
                };
                self.tx.push(self.gpa, frame) catch |err| {
                    // Counter HAS advanced; we lost the encrypted
                    // message. Peer's rx counter will reject everything
                    // from here on. Close.
                    self.closeOnError();
                    return err;
                };
            },
            .handshaking => return error.NotEstablished,
            .closed => return error.ConnectionClosed,
        }
    }

    /// Pop the next decrypted transport message. Caller takes ownership;
    /// release with `freeMessage`.
    pub fn nextMessage(self: *Connection) ?[]u8 {
        if (self.inbox.items.len == 0) return null;
        return self.inbox.orderedRemove(0);
    }

    pub fn freeMessage(self: *Connection, msg: []u8) void {
        self.gpa.free(msg);
    }

    /// Bytes the caller should write to the socket. Borrowed; invalidated
    /// by any other call. Ack with `consumeOutgoing(n)` once written.
    pub fn outgoing(self: Connection) []const u8 {
        return self.tx.outgoing();
    }

    pub fn consumeOutgoing(self: *Connection, n: usize) void {
        self.tx.consume(n);
    }

    pub fn handshakeHash(self: Connection) ?[symmetric_state.hash_length]u8 {
        return switch (self.state) {
            .handshaking => |hs| hs.handshakeHash(),
            else => null,
        };
    }

    // ── Internal: handshake + transport drivers ───────────────────────

    fn processInbound(self: *Connection) Error!void {
        // Per Noise rev 34 §11.2: "If decryption fails, the parties
        // should abort the session." Any error in the transport- or
        // handshake-decrypt path means the peer is hostile, the wire is
        // corrupted, or our state machine is desynchronized — none of
        // which is recoverable in-stream. Force the connection to
        // `.closed` on any error so subsequent recv/send return
        // ConnectionClosed rather than re-processing poisoned bytes
        // (which the fuzzer caught: a tampered frame would stay in
        // self.rx and fail every subsequent decrypt).
        errdefer if (self.state != .closed) self.closeOnError();

        while (self.rx.peek()) |frame| {
            switch (self.state) {
                .handshaking => |hs| {
                    const payload_len = try hs.readPayloadLen(frame.len);
                    const payload = try self.gpa.alloc(u8, payload_len);
                    defer self.gpa.free(payload);
                    const result = try hs.readMessage(frame, payload);
                    self.rx.pop();
                    if (result.split) |sp| {
                        self.transitionToEstablished(sp);
                        // Loop continues — any further frames are transport.
                    } else {
                        // It's now our turn (or peer's — drive will decide).
                        try self.driveOutboundHandshake();
                    }
                },
                .established => |*est| {
                    if (frame.len < cipher_state.tag_length) return error.InvalidMessageLength;
                    const plaintext_len = frame.len - cipher_state.tag_length;
                    const plaintext = try self.gpa.alloc(u8, plaintext_len);
                    errdefer self.gpa.free(plaintext);
                    try est.rx.decryptWithAd(&.{}, frame, plaintext);
                    try self.inbox.append(self.gpa, plaintext);
                    self.rx.pop();
                },
                .closed => return error.ConnectionClosed,
            }
        }
    }

    /// Wipe key material in-place and transition to `.closed`. Used on
    /// any error path that means the session is dead but we're not
    /// yet at the user's deinit call. ArrayLists stay live for the
    /// caller's eventual `deinit` to clean up.
    fn closeOnError(self: *Connection) void {
        switch (self.state) {
            .handshaking => |hs| {
                hs.secureZero();
                self.gpa.destroy(hs);
            },
            .established => |*est| {
                est.rx.secureZero();
                est.tx.secureZero();
            },
            .closed => return,
        }
        self.state = .closed;
    }

    /// While it's our turn, generate handshake message(s) into the tx
    /// queue. Walks the pattern until either the handshake completes or
    /// it's the peer's turn to send.
    fn driveOutboundHandshake(self: *Connection) Error!void {
        while (true) {
            switch (self.state) {
                .handshaking => |hs| {
                    if (!hs.isMyTurn()) return;
                    const msg_len = try hs.writeMessageLen(0);
                    const buf = try self.gpa.alloc(u8, msg_len);
                    defer self.gpa.free(buf);
                    const result = try hs.writeMessage("", buf);
                    try self.tx.push(self.gpa, buf);
                    if (result.split) |sp| {
                        self.transitionToEstablished(sp);
                        return;
                    }
                },
                else => return,
            }
        }
    }

    fn transitionToEstablished(self: *Connection, sp: symmetric_state.Split) void {
        const role = switch (self.state) {
            .handshaking => |hs| hs.role,
            else => unreachable,
        };
        // Per Noise §5.2: c1 = initiator→responder, c2 = responder→initiator.
        const established: Established = switch (role) {
            .initiator => .{ .tx = sp.c1, .rx = sp.c2 },
            .responder => .{ .tx = sp.c2, .rx = sp.c1 },
        };
        switch (self.state) {
            .handshaking => |hs| {
                hs.secureZero();
                self.gpa.destroy(hs);
            },
            else => {},
        }
        self.state = .{ .established = established };
    }
};

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const kem = @import("kem.zig");
const pattern = @import("pattern.zig");
const Rng = @import("rng.zig").Rng;
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

test "initInitiator queues handshake message 1 in the outgoing buffer" {
    const gpa = testing.allocator;
    var setup = SeedStream.init("conn-init1");
    const i_kp = try test_helpers.keypair(&setup);
    const r_kp = try test_helpers.keypair(&setup);
    var i_rng = SeedStream.init("conn-init1-i");

    var conn = try Connection.initInitiator(gpa, .{
        .pattern = &pattern.pqKK,
        .role = .initiator,
        .rng = rngFromSeedStream(&i_rng),
        .s = i_kp,
        .rs = r_kp.public_key,
    });
    defer conn.deinit();

    // msg1 = [skem, e] + empty AEAD-tagged payload.
    // Frame: 2-byte hdr + ciphertext (1088) + e_pub (1184) + tag (16).
    try testing.expectEqual(
        @as(usize, framing.frame_header_len +
            kem.ciphertext_length +
            kem.public_key_length +
            cipher_state.tag_length),
        conn.outgoing().len,
    );
}

test "send before established returns NotEstablished" {
    const gpa = testing.allocator;
    var setup = SeedStream.init("conn-not-est");
    const i_kp = try test_helpers.keypair(&setup);
    const r_kp = try test_helpers.keypair(&setup);
    var i_rng = SeedStream.init("conn-not-est-i");

    var conn = try Connection.initInitiator(gpa, .{
        .pattern = &pattern.pqKK,
        .role = .initiator,
        .rng = rngFromSeedStream(&i_rng),
        .s = i_kp,
        .rs = r_kp.public_key,
    });
    defer conn.deinit();

    try testing.expectError(error.NotEstablished, conn.send("nope"));
}
