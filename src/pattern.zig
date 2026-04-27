//! Noise / PQNoise pattern as data.
//!
//! Encoding the handshake pattern as a list of token sequences (rather
//! than hand-coded message functions) means our protocol "code" is
//! auditable as data — the pattern can be diff'd against the spec line
//! by line, and `HandshakeState` walks it with a generic interpreter.
//!
//! Today only `pqKK` is defined. Adding `pqIK` or `pqXX` is a matter of
//! describing their token sequences here; the interpreter does not change.

const std = @import("std");

pub const Token = enum {
    /// Generate own ephemeral KEM keypair and transmit its public key
    /// (writer side) / receive peer's ephemeral public key (reader side).
    e,
    /// Pre-message sentinel: the static keypair / public key is assumed
    /// already known to both parties before the handshake begins.
    /// Never appears in `messages`; only in `pre_initiator` / `pre_responder`.
    s,
    /// Encapsulate to peer's ephemeral public key (writer) / decapsulate
    /// using own ephemeral secret (reader). Mixes the resulting shared
    /// secret into the symmetric chain.
    ekem,
    /// Same as `ekem` but using static keys. The single token that gives
    /// PQNoise its KEM-only authentication: only the holder of the static
    /// secret can decapsulate.
    skem,
    /// Pre-shared symmetric key mix-in. Reserved for future PSK patterns;
    /// the pqKK pattern does not use it.
    psk,
};

pub const Pattern = struct {
    /// Static-key tokens the initiator pre-communicates to the responder.
    pre_initiator: []const Token,
    /// Static-key tokens the responder pre-communicates to the initiator.
    pre_responder: []const Token,
    /// Token sequences alternating initiator → responder → initiator …
    messages: []const []const Token,
};

/// pqKK — both peers' static KEM keys are pre-known.
///
///   pre_initiator: [s]
///   pre_responder: [s]
///   messages:
///     -> [skem, e]
///     <- [ekem, skem]
///
/// Two messages, mirroring classical Noise KK. Because each side knows
/// the other's static pubkey via the pre-messages, the initiator can
/// `skem` to the responder's static immediately in message 1, alongside
/// its own ephemeral. The responder replies by encapsulating to the just-
/// received ephemeral (`ekem`) and to the pre-known initiator static
/// (`skem`). Mutual KEM authentication completes after 2 RTTs.
///
/// Source: PQNoise paper (eprint 2022/539), Figure 2.
pub const pqKK: Pattern = .{
    .pre_initiator = &.{.s},
    .pre_responder = &.{.s},
    .messages = &.{
        &.{ .skem, .e },
        &.{ .ekem, .skem },
    },
};

/// Protocol-name string fed into `SymmetricState.init`. Per the PQNoise
/// paper's naming convention: `Noise_<pattern>_<KEM>_<cipher>_<hash>`.
/// Length 39 — exceeds 32, so SymmetricState will SHA-256-hash it (fine).
pub const pqKK_MLKEM768_protocol_name: []const u8 =
    "Noise_pqKK_MLKEM768_ChaChaPoly_SHA256";

// ── Inline tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "pqKK token sequence matches PQNoise paper Figure 2" {
    try testing.expectEqual(@as(usize, 1), pqKK.pre_initiator.len);
    try testing.expectEqual(Token.s, pqKK.pre_initiator[0]);
    try testing.expectEqual(@as(usize, 1), pqKK.pre_responder.len);
    try testing.expectEqual(Token.s, pqKK.pre_responder[0]);
    try testing.expectEqual(@as(usize, 2), pqKK.messages.len);

    try testing.expectEqualSlices(Token, &.{ .skem, .e }, pqKK.messages[0]);
    try testing.expectEqualSlices(Token, &.{ .ekem, .skem }, pqKK.messages[1]);
}
