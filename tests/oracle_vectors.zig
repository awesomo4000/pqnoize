//! Placeholder oracle vectors. Run `scripts/build-oracle.sh` to populate
//! this file with a real golden trace from clatter.
//!
//! Tests gated on `generated == true` skip themselves until then.

pub const generated: bool = false;

// Dummy values to keep imports valid. Real bytes are emitted by the
// script — DO NOT trust these.
pub const alice_static_pub: [1184]u8 = @splat(0);
pub const alice_static_sec: [2400]u8 = @splat(0);
pub const bob_static_pub: [1184]u8 = @splat(0);
pub const bob_static_sec: [2400]u8 = @splat(0);
pub const alice_eph_pub: [1184]u8 = @splat(0);
pub const alice_eph_sec: [2400]u8 = @splat(0);
pub const skem_msg1_seed: [32]u8 = @splat(0);
pub const ekem_msg2_seed: [32]u8 = @splat(0);
pub const skem_msg2_seed: [32]u8 = @splat(0);
pub const msg1: [0]u8 = .{};
pub const msg2: [0]u8 = .{};
pub const handshake_hash: [32]u8 = @splat(0);
pub const c1_key: [32]u8 = @splat(0);
pub const c2_key: [32]u8 = @splat(0);
