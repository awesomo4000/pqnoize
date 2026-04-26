//! pqnoize — post-quantum Noise sans-IO library.
//!
//! Public API will grow as components are implemented. For now this file
//! exists primarily as the test-aggregation root: any module added under
//! `src/` should be referenced from here so `zig build test` picks it up.

const std = @import("std");

pub const cipher_state = @import("cipher_state.zig");
pub const CipherState = cipher_state.CipherState;

pub const symmetric_state = @import("symmetric_state.zig");
pub const SymmetricState = symmetric_state.SymmetricState;

pub const kem = @import("kem.zig");

pub const pattern = @import("pattern.zig");
pub const Pattern = pattern.Pattern;
pub const Token = pattern.Token;

pub const Rng = @import("rng.zig").Rng;

pub const handshake = @import("handshake.zig");
pub const HandshakeState = handshake.HandshakeState;
pub const Role = handshake.Role;

pub const testing = @import("testing/deterministic.zig");

test {
    // Pull every src/ module into the test binary. Add a line here when a
    // new module is created so its inline tests are picked up.
    _ = @import("cipher_state.zig");
    _ = @import("symmetric_state.zig");
    _ = @import("kem.zig");
    _ = @import("pattern.zig");
    _ = @import("rng.zig");
    _ = @import("handshake.zig");
    _ = @import("testing/deterministic.zig");
}
