# pqnoize API

Reference for the public surface. Types are re-exported from
`src/root.zig`.

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

pub const rng             = @import("rng.zig");
pub const Rng             = rng.Rng;

pub const handshake       = @import("handshake.zig");
pub const HandshakeState  = handshake.HandshakeState;
pub const Role            = handshake.Role;

pub const framing         = @import("framing.zig");
pub const connection      = @import("connection.zig");
pub const Connection      = connection.Connection;

/// All errors any pqnoize call can produce. See "Errors" below.
pub const Error           = connection.Error;

pub const testing         = @import("testing/deterministic.zig");
```

---

## `Connection` — what most callers use

Sans-IO state machine. Drives a pqKK handshake to completion, then
encrypts/decrypts transport messages. Never touches a socket.

### Construction

```zig
pub fn initInitiator(gpa: Allocator, opts: handshake.Init) Error!Connection;
pub fn initResponder(gpa: Allocator, opts: handshake.Init) Error!Connection;
pub fn deinit(self: *Connection) void;
```

Both forms allocate a `*HandshakeState` on `gpa` (~40 KB; freed when
the handshake completes at `Split`, or earlier on error/deinit). The
initiator's first handshake message is queued into the outgoing
buffer at construction time, ready for the caller's first
`outgoing()` read. Both forms take ownership of the static keypair
in `opts.s` (copied by value into the heap HandshakeState).

After `transitionToEstablished`, `@sizeOf(Connection)` is 176 bytes;
the handshake's 40 KB is gone.

### Driver-loop API

```zig
pub fn recv(self: *Connection, bytes: []const u8) Error!void;
pub fn outgoing(self: Connection) []const u8;
pub fn consumeOutgoing(self: *Connection, n: usize) void;
```

`recv` accepts whatever bytes the socket gave you (may straddle
frame boundaries or be a single-byte fragment); it advances both
the handshake (until `.established`) and the transport
(decrypting any fully-arrived frames into the inbox). `outgoing`
returns a borrowed slice of bytes the caller should write to the
socket; `consumeOutgoing` acks how many bytes were actually written.
The slice from `outgoing` is invalidated by any other call.

### Application API

```zig
pub fn send(self: *Connection, plaintext: []const u8) Error!void;
pub fn nextMessage(self: *Connection) ?[]u8;
pub fn freeMessage(self: *Connection, msg: []u8) void;
pub fn isEstablished(self: Connection) bool;
pub fn handshakeHash(self: Connection) ?[32]u8;
```

`send` returns `error.NotEstablished` until the handshake has
completed. `nextMessage` pops the oldest decrypted plaintext from the
inbox; the caller takes ownership and releases via `freeMessage`.
`isEstablished` returns `false` after a successful close-on-error
transition (e.g. AEAD verification failure).

### `handshake.Init`

```zig
pub const Init = struct {
    pattern:       *const pattern.Pattern,                  // &pqnoize.pattern.pqKK
    role:          Role,                                    // .initiator | .responder
    rng:           Rng,                                     // see Rng below
    s:             kem.Kem.KeyPair,                         // own static keypair
    rs:            kem.Kem.PublicKey,                       // peer static (pre-known)
    prologue:      []const u8 = &.{},
    protocol_name: []const u8 = pattern.pqKK_MLKEM768_protocol_name,
    e:             ?kem.Kem.KeyPair = null,                 // TEST-ONLY: pre-built ephemeral
};
```

### Close-on-error semantics

Per Noise §11.2, any decryption failure aborts the session. `recv`
implements this: on AEAD verification failure (or any other error
during inbound processing) the cipher states are wiped via
`secureZero`, the heap HandshakeState is freed, and `state`
transitions to `.closed`. Subsequent `recv` and `send` calls return
`error.ConnectionClosed`.

`send` follows the same rule for errors that leave state mid-mutated:
a counter-exhausted `encryptWithAd` or an OOM in `tx.push` after the
counter has advanced both close the connection. Errors that fire
*before* state mutation (`FrameTooLarge`, `NotEstablished`, OOM
allocating the frame buffer) do not — the caller can retry.

### Driver-loop sketch

```
loop {
    if conn.outgoing().len > 0:
        write to socket; conn.consumeOutgoing(n_written)
    if conn.isEstablished() and have_more_to_send:
        conn.send(next_plaintext)
    bytes = read from socket; if 0: break
    conn.recv(bytes)
    while msg = conn.nextMessage(): handle msg; conn.freeMessage(msg)
}
```

Working code in `examples/client_server/` (real `std.Io.net` over
TCP). The library itself never imports `std.net`.

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

`WriteResult` / `ReadResult` carry an optional `Split` that is
non-null only on the final message. From that point the handshake
is finished; the caller constructs two `CipherState`s from the
split for transport. `Connection` does this internally.

Direct callers must NOT reuse a `HandshakeState` after any of its
methods returns an error — internal symmetric state may be partially
mutated. (`Connection` insulates callers from this via close-on-error.)

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

Adding `pqIK`, `pqXX`, etc. is a matter of describing their token
sequences here; the `HandshakeState` interpreter handles `e`, `ekem`,
`skem`, and `psk` tokens uniformly. Note that `skem` differs from
generic Noise treatment of `s`: it calls `encryptAndHash` on the
KEM ciphertext (so the ct is AEAD-wrapped on the wire when the
cipher is already armed) and `mixKeyAndHash` on the shared secret.
This matches the clatter Rust reference.

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

pub const max_nonce: u64 = std.math.maxInt(u64) - 1;  // 2^64 - 2 (last usable)
```

Counter exhaustion: after using nonce `max_nonce`, the internal
counter advances to `2^64 - 1` (the spec-reserved value), and the
next call returns `error.NonceExhausted` without producing output.
AEAD tag failure leaves the counter unchanged (per Noise §5.1).

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

Pre-MixKey, `encryptAndHash` is a memcpy + `mixHash` (the spec's
"plaintext passthrough" mode); post-MixKey it runs the inner
CipherState with `ad = h`. `decryptAndHash` mixes the *ciphertext*
(input bytes) into `h`, not the plaintext, per spec.

---

## `kem` — ML-KEM-768 wrapper

```zig
pub const Kem = std.crypto.kem.ml_kem.MLKem768;     // FIPS-203 nist namespace

pub const seed_length:        usize = 64;
pub const encaps_seed_length: usize = 32;
pub const ciphertext_length:  usize = 1088;
pub const shared_length:      usize = 32;
pub const public_key_length:  usize = 1184;
pub const secret_key_length:  usize = 2400;
```

These constants are checked at `comptime` against FIPS-203 — a
stdlib rename or a 512/1024 mix-up fails the build. Use
`Kem.KeyPair.generateDeterministic(seed)` for tests,
`Kem.KeyPair.generate(io)` for production. Stick with the FIPS-203
type — `kyber_d00` is the round-3 draft and is non-interoperable.

---

## `framing` — length-prefixed records

```zig
pub const max_frame_payload: usize = 65535;
pub const frame_header_len:  usize = 2;

pub fn writeFrameHeader(out: *[2]u8, payload_len: usize) Error!void;
pub fn readFrameHeader(bytes: *const [2]u8) usize;

pub const FrameReader = struct {
    pub const empty: FrameReader = ...;
    pub fn deinit(self: *FrameReader, gpa: Allocator) void;
    pub fn push(self: *FrameReader, gpa: Allocator, bytes: []const u8) Error!void;
    pub fn peek(self: FrameReader) ?[]const u8;   // borrowed; invalidated by push/pop
    pub fn pop(self: *FrameReader) void;
};

pub const FrameWriter = struct {
    pub const empty: FrameWriter = ...;
    pub fn deinit(self: *FrameWriter, gpa: Allocator) void;
    pub fn push(self: *FrameWriter, gpa: Allocator, payload: []const u8) Error!void;
    pub fn outgoing(self: FrameWriter) []const u8;
    pub fn consume(self: *FrameWriter, n: usize) void;
};
```

Wire format: `[u16 big-endian length][payload]`. The same framing
carries both handshake messages and post-Split transport
ciphertexts.

---

## `rng` — randomness injection

```zig
pub const Rng = struct {
    ctx:    *anyopaque,
    fillFn: *const fn (ctx: *anyopaque, out: []u8) void,
    pub fn bytes(self: Rng, out: []u8) void;
};

/// Production helper: wraps std.Io.randomSecure (syscall-backed CSPRNG).
/// Panics if the underlying Io reports EntropyUnavailable rather than
/// silently using weak randomness. The caller's `io` must outlive the
/// returned Rng.
pub fn fromIo(io: *const std.Io) Rng;
```

The library never reaches for `std.crypto.random` directly. See the
[Entropy requirements](README.md#entropy-requirements) section of
the README for the threat model that motivates this design and the
boot-time-entropy concern.

For tests, see the `testing` namespace below.

---

## `testing` — deterministic helpers (TEST-ONLY)

```zig
pub const SeedStream = struct {
    pub fn init(seed: []const u8) SeedStream;
    pub fn bytes(self: *SeedStream, out: []u8) void;
    pub fn next(self: *SeedStream) [32]u8;
};

pub const FixedBytesRng = struct {
    pub fn init(bytes: []const u8) FixedBytesRng;
    pub fn rng(self: *FixedBytesRng) Rng;
};

pub fn keypair(stream: *SeedStream) !kem.Kem.KeyPair;
pub fn encaps(pk: kem.Kem.PublicKey, stream: *SeedStream) kem.Kem.EncapsulatedSecret;
```

`SeedStream` is SHAKE-256 expansion of a labeled root seed.
Deterministic, byte-stream-style; useful for replayable handshakes.
`FixedBytesRng` returns canned bytes from a slice — used by oracle
tests where every byte of randomness is pinned.

These helpers are TEST-ONLY. Wiring any of them into production
breaks the security properties of the protocol.

Bridging a `SeedStream` to an `Rng`:

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
pqnoize.Error         = connection.Error    // top-level alias
```

What each means:

| Error | Surface | Meaning |
|---|---|---|
| `NonceExhausted` | CipherState / Connection.send | Counter would equal `2^64 - 1` (reserved value). Connection auto-closes. |
| `AuthenticationFailed` | CipherState / Connection.recv | AEAD tag invalid. Peer tampered, wire corrupt, or state desynced. Connection auto-closes. |
| `InvalidLength` | SymmetricState | Caller passed an output buffer of the wrong size. |
| `NotMyTurn` | HandshakeState | `writeMessage` called when it's the peer's turn (or vice versa). |
| `HandshakeAlreadyDone` | HandshakeState | Method called after `Split` was emitted. |
| `InvalidMessageLength` | HandshakeState | Frame doesn't match `writeMessageLen` / `readPayloadLen` for the current step. |
| `InvalidPublicKey` | HandshakeState | Peer-supplied static or ephemeral pubkey didn't decode (NonCanonical). Connection auto-closes. |
| `InvalidPatternToken` | HandshakeState | A token unsupported in `messages` (`s`, `psk`) appeared. Indicates a malformed Pattern. |
| `FrameTooLarge` | framing / Connection.send | Caller asked us to frame a payload larger than 65535 bytes. |
| `OutOfMemory` | framing / Allocator | Allocator returned OOM. May or may not auto-close depending on which alloc site (see Connection.send doc). |
| `NotEstablished` | Connection.send | `send` called before handshake completed. |
| `ConnectionClosed` | Connection.recv / Connection.send | Operation called on a connection in `.closed` state. |

`error.AuthenticationFailed` is the catch-all for "peer sent
something we can't trust" — covers transport-message tampering,
handshake ciphertext modification, and (indirectly) tampered KEM
ciphertexts via ML-KEM's implicit-rejection behavior (decap returns
junk, AEAD then fails).
