//! Type-erased randomness source for handshake-time entropy.
//!
//! The HandshakeState consumes randomness for two operations only:
//! generating an ephemeral KEM keypair (`.e` token) and producing an
//! encapsulation seed (`.ekem` / `.skem` tokens). Both are channelled
//! through this single interface so that:
//!
//!   * Production callers wire it to `std.Io.random` (or any audited CSPRNG).
//!   * Tests wire it to a `SeedStream` (SHAKE-256 expanded from a root seed)
//!     and replay handshakes byte-for-byte.
//!
//! The library never reaches for `std.crypto.random` directly.

const std = @import("std");

pub const Rng = struct {
    ctx: *anyopaque,
    fillFn: *const fn (ctx: *anyopaque, out: []u8) void,

    pub fn bytes(self: Rng, out: []u8) void {
        self.fillFn(self.ctx, out);
    }
};
