# pqnoize API

Reference for the public surface. All types live under the `pqnoize`
module (re-exported from `src/root.zig`).

## Top-level re-exports

```zig
pub const cipher_state    = @import("cipher_state.zig");
pub const CipherState     = cipher_state.CipherState;

pub const symmetric_state = @import("symmetric_state.zig");
pub const SymmetricState  = symmetric_state.SymmetricState;

pub const kem             = @import("kem.zig");

pub const pattern         = @import("pattern.zig");
pub const Pattern         = pattern.Pattern;
pub const Token           = pattern.Token;

pub const Rng             = @import("rng.zig").Rng;

pub const handshake       = @import("handshake.zig");
pub const HandshakeState  = handshake.HandshakeState;
pub const Role            = handshake.Role;

pub const framing         = @import("framing.zig");
pub const connection      = @import("connection.zig");
pub const Connection      = connection.Connection;

pub const testing         = @import("testing/deterministic.zig");
```

---

## `Connection` — what most callers use

Sans-IO state machine. Drives a pqKK handshake to completion, then
encrypts/decrypts transport messages. Never touches a socket.

### Construction

```zig
pub fn initInitiator(gpa: Allocator, opts: handshake.Init) !Connection;
pub fn initResponder(gpa: Allocator, opts: handshake.Init) Connection;
pub fn deinit(self: *Connection) void;
```

The initiator's first handshake message is queued at construction time.
Both forms take ownership of the static keypair in `opts.s`.

### Driver loop API

```zig
pub fn recv(self: *Connection, bytes: []const u8) !void;
pub fn outgoing(self: Connection) []const u8;
pub fn consumeOutgoing(self: *Connection, n: usize) void;
```

`recv` accepts whatever bytes the socket gave you (may straddle frame
boundaries or be a single-byte fragment) and advances both the handshake
and any post-Split transport processing. `outgoing` returns a borrowed
slice of bytes the caller should write to the socket; `consumeOutgoing`
acks how many bytes were actually written.

### Application API

```zig
pub fn send(self: *Connection, plaintext: []const u8) !void;
pub fn nextMessage(self: *Connection) ?[]u8;
pub fn freeMessage(self: *Connection, msg: []u8) void;
pub fn isEstablished(self: Connection) bool;
```

`send` returns `error.NotEstablished` until the handshake has completed.
`nextMessage` pops the oldest decrypted plaintext from the inbox; the
caller takes ownership and releases via `freeMessage`.

### `handshake.Init` options

```zig
pub const Init = struct {
    pattern:       *const pattern.Pattern,                  // &pqnoize.pattern.pqKK
    role:          Role,                                    // .initiator | .responder
    rng:           Rng,                                     // see "Randomness" below
    s:             kem.Kem.KeyPair,                         // own static keypair
    rs:            kem.Kem.PublicKey,                       // peer static (pre-known)
    prologue:      []const u8 = &.{},
    protocol_name: []const u8 = pattern.pqKK_MLKEM768_protocol_name,
};
```

### Driver-loop sketch

```zig
fn run(stream: std.net.Stream, conn: *pqnoize.Connection) !void {
    var read_buf: [4096]u8 = undefined;
    while (true) {
        const out = conn.outgoing();
        if (out.len > 0) {
            const n = try stream.write(out);
            conn.consumeOutgoing(n);
        }
        const n = try stream.read(&read_buf);
        if (n == 0) return;
        try conn.recv(read_buf[0..n]);
        while (conn.nextMessage()) |msg| {
            defer conn.freeMessage(msg);
            try app.handle(msg);
        }
    }
}
```

This sketch lives outside the library — `Connection` itself never imports
`std.net`.

---

## `HandshakeState` — for callers that want manual control

```zig
pub fn init(opts: Init) HandshakeState;

pub fn writeMessage(
    self: *HandshakeState,
    payload: []const u8,
    out: []u8,
) Error!WriteResult;

pub fn readMessage(
    self: *HandshakeState,
    msg: []const u8,
    payload_out: []u8,
) Error!ReadResult;

pub fn writeMessageLen(self: HandshakeState, payload_len: usize) Error!usize;
pub fn readPayloadLen(self: HandshakeState, msg_len: usize) Error!usize;

pub fn isMyTurn(self: HandshakeState) bool;
pub fn isFinished(self: HandshakeState) bool;
pub fn handshakeHash(self: HandshakeState) [32]u8;
pub fn secureZero(self: *HandshakeState) void;
```

Each `writeMessage` / `readMessage` advances `msg_index`. The result
struct carries an optional `Split` that is non-null only on the final
message; from that point the handshake is finished and the caller should
construct two `CipherState`s from the split for transport.

---

## `Pattern` — protocol as data

```zig
pub const Token = enum { e, s, ekem, skem, psk };

pub const Pattern = struct {
    pre_initiator: []const Token,
    pre_responder: []const Token,
    messages:      []const []const Token,
};

pub const pqKK: Pattern = .{
    .pre_initiator = &.{.s},
    .pre_responder = &.{.s},
    .messages = &.{
        &.{ .skem, .e },
        &.{ .ekem, .skem },
    },
};

pub const pqKK_MLKEM768_protocol_name: []const u8 =
    "Noise_pqKK_MLKEM768_ChaChaPoly_SHA256";
```

Adding a new pattern (e.g. `pqIK`, `pqXX`) is a matter of describing its
token sequence here; the `HandshakeState` interpreter does not change.

---

## `CipherState` — AEAD + nonce-counter

```zig
pub fn init(key: [32]u8) CipherState;

pub fn encryptWithAd(
    self: *CipherState,
    ad: []const u8,
    plaintext: []const u8,
    ciphertext_out: []u8,    // len = plaintext.len + 16
) Error!void;

pub fn decryptWithAd(
    self: *CipherState,
    ad: []const u8,
    ciphertext: []const u8,
    plaintext_out: []u8,     // len = ciphertext.len - 16
) Error!void;

pub fn nonceBytes(n: u64) [12]u8;   // [0,0,0,0] ++ LE(n) — Noise §12
pub fn ciphertextLen(plaintext_len: usize) usize;
pub fn secureZero(self: *CipherState) void;
```

Counter exhaustion (`n == 2^64 - 1`) returns `error.NonceExhausted`
*before* producing output. AEAD tag failure leaves the counter
unchanged.

---

## `SymmetricState` — Noise rev 34 §5.2

```zig
pub fn init(protocol_name: []const u8) SymmetricState;
pub fn mixHash(self: *SymmetricState, data: []const u8) void;
pub fn mixKey(self: *SymmetricState, ikm: []const u8) void;
pub fn mixKeyAndHash(self: *SymmetricState, ikm: []const u8) void;
pub fn encryptAndHash(self: *SymmetricState, plaintext: []const u8, out: []u8) Error!usize;
pub fn decryptAndHash(self: *SymmetricState, ciphertext: []const u8, out: []u8) Error!usize;
pub fn split(self: *SymmetricState) Split;     // -> { c1: CipherState, c2: CipherState }
pub fn ciphertextLen(self: SymmetricState, plaintext_len: usize) usize;
pub fn plaintextLen(self: SymmetricState, ciphertext_len: usize) Error!usize;
pub fn handshakeHash(self: SymmetricState) [32]u8;
pub fn secureZero(self: *SymmetricState) void;
```

Pre-MixKey, `encryptAndHash` is a memcpy + `mixHash`; post-MixKey it
runs the inner CipherState with `ad = h`.

---

## `kem` — ML-KEM-768 wrapper

```zig
pub const Kem = std.crypto.kem.ml_kem.MLKem768;

pub const seed_length:        usize = 64;
pub const encaps_seed_length: usize = 32;
pub const ciphertext_length:  usize = 1088;
pub const shared_length:      usize = 32;
pub const public_key_length:  usize = 1184;
pub const secret_key_length:  usize = …;
```

Use `Kem.KeyPair.generateDeterministic(seed)` for tests, `Kem.KeyPair.generate(io)`
for production. Stick with the `nist` (FIPS-203) variant — never `kyber_d00`.

---

## `framing` — length-prefixed records

```zig
pub const max_frame_payload: usize = 65535;
pub const frame_header_len:  usize = 2;

pub fn writeFrameHeader(out: *[2]u8, payload_len: usize) Error!void;
pub fn readFrameHeader(bytes: *const [2]u8) usize;

pub const FrameReader = struct {
    pub const empty: FrameReader = …;
    pub fn deinit(self: *FrameReader, gpa: Allocator) void;
    pub fn push(self: *FrameReader, gpa: Allocator, bytes: []const u8) Error!void;
    pub fn peek(self: FrameReader) ?[]const u8;   // borrowed; invalidated by push/pop
    pub fn pop(self: *FrameReader) void;
};

pub const FrameWriter = struct {
    pub const empty: FrameWriter = …;
    pub fn deinit(self: *FrameWriter, gpa: Allocator) void;
    pub fn push(self: *FrameWriter, gpa: Allocator, payload: []const u8) Error!void;
    pub fn outgoing(self: FrameWriter) []const u8;
    pub fn consume(self: *FrameWriter, n: usize) void;
};
```

Wire format: `[u16 big-endian length][payload]`. The same framing carries
both handshake messages and post-Split transport ciphertexts.

---

## `Rng` — randomness injection

```zig
pub const Rng = struct {
    ctx:    *anyopaque,
    fillFn: *const fn (ctx: *anyopaque, out: []u8) void,
    pub fn bytes(self: Rng, out: []u8) void;
};
```

The library never reaches for `std.crypto.random` directly. Production
callers wire `Rng` to `std.Io.random` (or another audited CSPRNG); tests
wire it to a `SeedStream` for byte-for-byte handshake replay.

---

## `testing` — deterministic helpers

```zig
pub const SeedStream = struct {
    pub fn init(seed: []const u8) SeedStream;
    pub fn bytes(self: *SeedStream, out: []u8) void;
    pub fn next(self: *SeedStream) [32]u8;
};

pub fn keypair(stream: *SeedStream) !kem.Kem.KeyPair;
pub fn encaps(pk: kem.Kem.PublicKey, stream: *SeedStream) kem.Kem.EncapsulatedSecret;
```

Bridge from a `SeedStream` to an `Rng`:

```zig
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
```

---

## Errors

Every error a caller can encounter is an explicit return type — the
library never panics on user input and never logs. The error sets
compose upward:

```
cipher_state.Error    = { NonceExhausted, AuthenticationFailed }
symmetric_state.Error = cipher_state.Error || { InvalidLength }
handshake.Error       = symmetric_state.Error || {
                          NotMyTurn, HandshakeAlreadyDone,
                          InvalidMessageLength, InvalidPublicKey,
                          InvalidPatternToken,
                        }
framing.Error         = { FrameTooLarge } || Allocator.Error
connection.Error      = handshake.Error || framing.Error || {
                          NotEstablished, ConnectionClosed,
                        }
```

`error.AuthenticationFailed` is the catch-all for "peer sent something
we can't trust" — it covers transport-message tampering, handshake
ciphertext modification, and (indirectly) tampered KEM ciphertexts via
ML-KEM's implicit-rejection behavior.
