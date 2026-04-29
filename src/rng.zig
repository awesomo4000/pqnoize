//! Type-erased randomness source for handshake-time entropy.
//!
//! The HandshakeState consumes randomness for two operations only:
//! generating an ephemeral KEM keypair (`.e` token) and producing an
//! encapsulation seed (`.ekem` / `.skem` tokens). Both are channelled
//! through this single interface so that:
//!
//!   * Production callers wire it to `std.Io.randomSecure` via `fromIo`.
//!   * Tests wire it to a `SeedStream` (SHAKE-256 expanded from a root
//!     seed) under `pqnoize.testing` and replay handshakes byte-for-byte.
//!
//! The library never reaches for `std.crypto.random` directly.

const std = @import("std");

pub const Rng = struct {
    /// CRITICAL: implementations MUST be cryptographically secure.
    ///
    /// A predictable or low-entropy `Rng` breaks confidentiality and
    /// forward secrecy of every handshake the library produces. Static-
    /// key authentication still holds — a weak-RNG attacker can decrypt
    /// captured traffic but can't impersonate parties — but for any
    /// realistic threat model, "decrypts everything" is plenty bad.
    ///
    /// Canonical disaster: CVE-2008-0166 (Debian OpenSSL, 2008). The
    /// PRNG was seeded with effectively 15 bits of entropy for years;
    /// every "random" key generated under that build was guessable in
    /// minutes. Same shape as the failure mode here.
    ///
    /// Production: use `pqnoize.rng.fromIo(io)`.
    /// Tests: use `pqnoize.testing.SeedStream` (deterministic, NEVER
    /// production).
    ctx: *anyopaque,
    fillFn: *const fn (ctx: *anyopaque, out: []u8) void,

    pub fn bytes(self: Rng, out: []u8) void {
        self.fillFn(self.ctx, out);
    }
};

/// Production randomness source: cryptographically secure entropy
/// drawn from the OS via `std.Io.randomSecure`. On Linux this routes
/// through `getrandom(2)` against the kernel CSPRNG.
///
/// Why `randomSecure` and not the plainer `random`: `Io.random` may
/// fall back to "a less secure mechanism upon failure" (per its doc),
/// and on Io implementations that have no entropy source it returns
/// all zeros. For a crypto library that's catastrophic — we'd
/// silently generate guessable keys. `randomSecure` is documented to
/// always make a syscall and never fall back; we panic if it fails so
/// the failure can't be ignored.
///
/// Boot-time concern: on a freshly-booted system the kernel may not
/// have accumulated initial entropy yet. On Linux ≥5.6 `getrandom(2)`
/// blocks until first seeding completes — so a handshake call here
/// will block briefly rather than producing weak keys. On older
/// systems or weird embedded platforms (no hardware RNG, NTP down, no
/// persisted seed across boots), the same wait can take seconds to
/// minutes after first boot. Defer initiating handshakes until then.
///
/// Lifetime: the `Io` value must outlive any `Connection` (or
/// `HandshakeState`) using the returned `Rng`. Pass a stable pointer
/// to `Io` storage; pointing at a temporary is undefined behavior.
pub fn fromIo(io: *const std.Io) Rng {
    return .{
        .ctx = @ptrCast(@constCast(io)),
        .fillFn = fillFromIoSecure,
    };
}

fn fillFromIoSecure(ctx: *anyopaque, out: []u8) void {
    const io_ptr: *const std.Io = @ptrCast(@alignCast(ctx));
    io_ptr.randomSecure(out) catch |err| std.debug.panic(
        "pqnoize.rng.fromIo: secure entropy unavailable ({t}); " ++
            "refusing to operate with weak randomness",
        .{err},
    );
}

// No inline tests for `fromIo` — exercising it requires a real
// `std.Io` value with a working `randomSecure` syscall, which only
// makes sense at integration / example-program scope. The function
// signature and panic semantics are checked by the build.
