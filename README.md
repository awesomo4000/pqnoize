# pqnoize

A minimal, opinionated, sans-IO post-quantum Noise protocol library in pure
Zig. Single pattern (**pqKK**), single cipher suite (ML-KEM-768 +
ChaCha20-Poly1305 + SHA-256), Zig stdlib only — no vendored dependencies.

## What it is

Greenfield, pure-PQ Noise. All Diffie-Hellman replaced by KEM operations
per the [PQNoise paper][pqnoise] (Angel, Dowling, Hülsing, Schwabe, Weber,
CCS 2022). Confidentiality, authentication, and forward secrecy all rely
on ML-KEM-768 — no classical crypto fallback, no hybrid composition.

The library is sans-IO: it never imports `std.net`, never blocks, never
picks an I/O strategy. The `Connection` state machine consumes byte
slices and produces byte slices; the caller's driver loop handles the
socket. Real TCP usage is intended to live in test client/server example
programs once that work begins.

## Cipher suite

| Role | Choice              | Pinned size                  |
| ---- | ------------------- | ---------------------------- |
| KEM  | ML-KEM-768 (FIPS 203) | pubkey 1184, ct 1088, ss 32 |
| AEAD | ChaCha20-Poly1305   | key 32, nonce 12, tag 16     |
| Hash | SHA-256             | digest 32                    |
| KDF  | HKDF-SHA256         | (Noise §4.3 recursive HMAC)  |

Protocol name (fed to `SymmetricState.init`):
`Noise_pqKK_MLKEM768_ChaChaPoly_SHA256`.

Nonce construction (Noise §12): `[0,0,0,0] ++ little_endian_u64(n)`.

## Pattern (pqKK)

Both peers' static KEM keys are pre-known.

```
pre_initiator: [s]
pre_responder: [s]
messages:
  -> [skem, e]
  <- [ekem, skem]
```

Two messages, mutual KEM authentication via `skem`, no DH anywhere.
Mirrors classical Noise KK (also two messages) — because both sides
already know each other's static, the initiator can encapsulate to the
responder's static in its very first message.
See [API.md](API.md) for the full call surface.

## Build & test

Requires Zig 0.16.

```bash
zig build test           # run all tests (unit + KATs + e2e)
zig build test-unit      # inline tests under src/
zig build test-kats      # known-answer vectors
zig build test-e2e       # initiator <-> responder integration
```

## Layout

```
src/
  cipher_state.zig       AEAD + Noise nonce
  symmetric_state.zig    ck/h, HKDF chain, encrypt/decrypt-and-hash, split
  kem.zig                ML-KEM-768 wrapper
  pattern.zig            tokens, Pattern, pqKK constant
  rng.zig                type-erased randomness injection
  handshake.zig          token-walking pqKK interpreter
  framing.zig            u16-BE length-prefixed records
  connection.zig         Connection (sans-IO surface)
  testing/
    deterministic.zig    SeedStream + ML-KEM helpers for replay tests
tests/
  kats.zig               RFC 8439 + Noise nonce + HKDF chain + KEM sizes
  e2e.zig                full handshake, transport, fragmentation, tamper
```

## Status

Sans-IO core is complete: full pqKK handshake reaches `Established`,
transport messages encrypt/decrypt in both directions, AEAD failures
surface as `error.AuthenticationFailed`, and every byte produced is
deterministic under a seeded RNG.

Not yet implemented: graceful close handshake, rekeying, PSK patterns,
ML-DSA peer-identity certificates. Real TCP usage will appear as a
separate test client/server example program — never inside the library.

## Entropy requirements

Every handshake consumes randomness for ephemeral KEM keypair generation
and KEM encapsulation seeds. The library never reaches for entropy
itself — randomness flows through the `Rng` interface the caller
provides.

**The `Rng` MUST be cryptographically secure.** The production helper
is `pqnoize.rng.fromIo(io)`, which routes through `std.Io.randomSecure`
(syscall-backed, no fallback to weak sources, panics if entropy is
unavailable rather than silently degrading). Anything else MUST be a
real CSPRNG — never a seeded PRNG, never anything time-based.

A predictable or low-entropy RNG breaks confidentiality and forward
secrecy of every handshake the library produces. Static-key
authentication still holds — a weak-RNG attacker can passively decrypt
captured traffic but can't impersonate parties — but for any realistic
deployment, "decrypts everything" is plenty bad. The canonical
disaster is [CVE-2008-0166][cve-debian]: years of "random" Debian
OpenSSL keys generated under a PRNG with effectively 15 bits of
entropy, all guessable in minutes.

**Boot-time concern.** On a freshly-booted system the kernel may not
have accumulated initial entropy yet. On Linux ≥5.6 `getrandom(2)`
blocks until first seeding — a handshake call simply waits rather than
producing weak keys. On embedded systems with no hardware RNG, NTP
down, and no persisted seed across reboots, this can take seconds to
minutes. **Defer initiating handshakes** until the kernel reports
sufficient entropy. Don't pin the system clock with a "good enough"
fallback time and call it good — predictable seeds across a fleet are
the exact failure shape.

The deterministic helpers under `pqnoize.testing` (`SeedStream`,
`FixedBytesRng`, `keypair`, `encaps`) are TEST-ONLY — they're built on
SHAKE-256 expansion of a labeled seed for byte-for-byte handshake
replay. Never wire them into a production code path.

[cve-debian]: https://www.cve.org/CVERecord?id=CVE-2008-0166

## Threat model and scope

- **Greenfield.** No interop with classical Noise, WireGuard, Signal, or
  any deployed PQ system.
- **Single pattern, single cipher suite, single transport mode.** Not a
  general-purpose crypto library.
- **No traffic-analysis resistance.** Standard Noise leaks message
  lengths and timing; pad-and-jitter is out of scope.
- **Harvest-now-decrypt-later** is the motivating threat. Pure-PQ rather
  than hybrid is a deliberate choice for greenfield deployment.

[pqnoise]: https://eprint.iacr.org/2022/539
