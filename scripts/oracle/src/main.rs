//! Clatter-driven pqKK oracle for pqnoize.
//!
//! Drives a complete pqKK handshake using `clatter` (a peer-reviewed Rust
//! Noise/PQNoise implementation) under fully deterministic inputs, then
//! emits the resulting wire bytes and final state as Zig source code.
//! The Zig test suite under `tests/kats.zig` cross-checks our pqnoize
//! implementation against this golden.
//!
//! Determinism strategy:
//!
//!   * A small thread-local-backed `ScriptedRng` returns pre-canned bytes
//!     in order. `Default::default()` for that RNG drains the
//!     thread-local — that's how clatter's `RNG: Default` constraint is
//!     satisfied without giving up reproducibility.
//!
//!   * Static and ephemeral ML-KEM-768 keypairs are produced by feeding
//!     SHA-256-of-label seeds into clatter's `MlKem768::genkey_rng`
//!     wrapper. The resulting keypair *bytes* are emitted into the Zig
//!     vector file; the Zig test deserializes them via `PublicKey.fromBytes`
//!     so we don't depend on Rust and Zig agreeing on internal RNG-byte
//!     layout for keygen — we depend only on FIPS-203 byte format.
//!
//!   * Encapsulation seeds inside clatter's `PqHandshake` are similarly
//!     scripted, set up before each `PqHandshake::new` call.
//!
//! Re-running with the same labels yields byte-identical output. Bumping
//! clatter's pinned version may cause vectors to drift — that's the whole
//! point of regenerating after an oracle bump.

use std::cell::RefCell;
use std::io::Write;

use clatter::bytearray::ByteArray;
use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::hash::Sha256 as ClatterSha256;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem768;
use clatter::handshakepattern::noise_pqkk;
use clatter::traits::{CryptoComponent, Handshaker, Kem};
use clatter::transportstate::TransportState;
use clatter::{KeyPair, PqHandshakeCore};

use sha2::{Digest, Sha256};

// ── Labelled seed derivation ──────────────────────────────────────────────

fn label_bytes(label: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"pqnoize-oracle-v1/");
        h.update(label.as_bytes());
        h.update(b"/");
        h.update(counter.to_be_bytes());
        let chunk: [u8; 32] = h.finalize().into();
        let take = (len - out.len()).min(32);
        out.extend_from_slice(&chunk[..take]);
        counter += 1;
    }
    out
}

// ── Scripted RNG plugged into clatter ─────────────────────────────────────

thread_local! {
    static RNG_BYTES: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    static RNG_CURSOR: RefCell<usize> = RefCell::new(0);
}

fn set_rng_bytes(bytes: Vec<u8>) {
    RNG_BYTES.with(|b| *b.borrow_mut() = bytes);
    RNG_CURSOR.with(|c| *c.borrow_mut() = 0);
}

#[derive(Clone)]
struct ScriptedRng {
    bytes: Vec<u8>,
    cursor: usize,
}

impl Default for ScriptedRng {
    /// Drains the thread-local into its own buffer at construction time.
    /// That way each PqHandshakeCore (or each transient genkey_rng caller)
    /// owns an independent slice of randomness — the thread-local is just
    /// the channel we use to deliver bytes through clatter's
    /// `RNG::default()` constraint.
    fn default() -> Self {
        let bytes = RNG_BYTES.with(|b| std::mem::take(&mut *b.borrow_mut()));
        RNG_CURSOR.with(|c| *c.borrow_mut() = 0);
        Self { bytes, cursor: 0 }
    }
}

impl rand_core::RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let n = dest.len();
        assert!(
            self.cursor + n <= self.bytes.len(),
            "ScriptedRng exhausted: requested {} bytes at cursor {} of {}",
            n,
            self.cursor,
            self.bytes.len()
        );
        dest.copy_from_slice(&self.bytes[self.cursor..self.cursor + n]);
        self.cursor += n;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for ScriptedRng {}
// clatter has a blanket `impl<T> Rng for T where T: RngCore + CryptoRng + Default + Clone`,
// so ScriptedRng picks up `clatter::traits::Rng` automatically.

// ── Helpers ───────────────────────────────────────────────────────────────

type ClatterPubKey = <MlKem768 as Kem>::PubKey;
type ClatterSecretKey = <MlKem768 as Kem>::SecretKey;
type ClatterKp = KeyPair<ClatterPubKey, ClatterSecretKey>;

/// Generate a clatter ML-KEM-768 keypair, drawing randomness from a
/// label-derived byte stream. The exact byte count consumed by
/// `genkey_rng` is an implementation detail of ml-kem (it can be more
/// than the canonical 64-byte FIPS-203 seed if rejection sampling kicks
/// in), so we provide a generous buffer expanded from the label and let
/// the RNG drain whatever it needs. The resulting keypair *bytes* are
/// what we emit to Zig — no determinism dependency on RNG-byte layout.
fn keypair_from_label(label: &str) -> ClatterKp {
    set_rng_bytes(label_bytes(label, 256));
    let mut rng = ScriptedRng::default();
    MlKem768::genkey_rng(&mut rng).expect("ML-KEM keygen")
}

// ── Zig emission ──────────────────────────────────────────────────────────

fn emit_byte_array(w: &mut impl Write, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    writeln!(w, "pub const {}: [{}]u8 = .{{", name, bytes.len())?;
    for (i, byte) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            write!(w, "    ")?;
        }
        write!(w, "0x{:02x},", byte)?;
        if i % 16 == 15 || i == bytes.len() - 1 {
            writeln!(w)?;
        } else {
            write!(w, " ")?;
        }
    }
    writeln!(w, "}};\n")?;
    Ok(())
}

// ── Driver ────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build keypairs through clatter (which uses rust-crypto ml-kem
    //    internally). Bytes are extracted for emission to the Zig file.
    let alice_static_kp = keypair_from_label("alice-static");
    let bob_static_kp = keypair_from_label("bob-static");
    let alice_eph_kp = keypair_from_label("alice-eph");

    // Per-role RNG byte streams. ML-KEM-768 encaps consumes exactly
    // 32 bytes per call (no rejection sampling on the encaps path), so
    // each role's stream is a flat concatenation of (token-order) 32-byte
    // chunks. Naming them per token would imply each is independently
    // drained; they aren't — clatter's RNG sees one continuous buffer.
    //
    //   alice writes msg1 [skem, e]: skem encaps draws 32 B; e is
    //     pre-built so no further draw. Total: 32 B.
    //   bob   writes msg2 [ekem, skem]: ekem 32 B, skem 32 B. Total: 64 B.
    let alice_rng = label_bytes("alice-msg1-rng", 32);
    let bob_rng = label_bytes("bob-msg2-rng", 64);

    let alice_static_pub = alice_static_kp.public.as_slice().to_vec();
    let alice_static_sec = alice_static_kp.secret.as_slice().to_vec();
    let bob_static_pub = bob_static_kp.public.as_slice().to_vec();
    let bob_static_sec = bob_static_kp.secret.as_slice().to_vec();
    let alice_eph_pub = alice_eph_kp.public.as_slice().to_vec();
    let alice_eph_sec = alice_eph_kp.secret.as_slice().to_vec();

    // 3. Construct alice's PqHandshake. Set RNG bytes to alice's encaps
    //    seed; clatter calls RNG::default() once on construction, which
    //    drains the thread-local into the persistent handshake RNG.
    set_rng_bytes(alice_rng.clone());
    let mut alice = PqHandshakeCore::<MlKem768, MlKem768, ChaChaPoly, ClatterSha256, ScriptedRng>::new(
        noise_pqkk(),
        &[],
        true, // initiator
        Some(alice_static_kp.clone()),
        Some(alice_eph_kp.clone()),
        Some(bob_static_kp.public.clone()),
        None,
    )
    .expect("alice PqHandshake init");

    // 4. Construct bob's PqHandshake.
    set_rng_bytes(bob_rng.clone());
    let mut bob = PqHandshakeCore::<MlKem768, MlKem768, ChaChaPoly, ClatterSha256, ScriptedRng>::new(
        noise_pqkk(),
        &[],
        false, // responder
        Some(bob_static_kp.clone()),
        None, // bob has no ephemeral in pqKK
        Some(alice_static_kp.public.clone()),
        None,
    )
    .expect("bob PqHandshake init");

    // 5. Drive the two-message handshake.
    let mut buf_a = vec![0u8; 4096];
    let mut buf_b = vec![0u8; 4096];

    let n1 = alice.write_message(&[], &mut buf_a).expect("alice msg1");
    bob.read_message(&buf_a[..n1], &mut buf_b).expect("bob read msg1");
    let msg1 = buf_a[..n1].to_vec();

    let n2 = bob.write_message(&[], &mut buf_b).expect("bob msg2");
    alice.read_message(&buf_b[..n2], &mut buf_a).expect("alice read msg2");
    let msg2 = buf_b[..n2].to_vec();

    assert!(alice.is_finished() && bob.is_finished());

    // 6. Finalize and extract handshake hash + Split keys.
    let alice_xport: TransportState<ChaChaPoly, ClatterSha256> =
        TransportState::new(alice).expect("alice finalize");
    let bob_xport: TransportState<ChaChaPoly, ClatterSha256> =
        TransportState::new(bob).expect("bob finalize");

    let h = alice_xport.get_handshake_hash();
    let h_bob = bob_xport.get_handshake_hash();
    assert_eq!(h.as_slice(), h_bob.as_slice(), "handshake hashes diverge");

    let alice_states = alice_xport.take();
    let (k1, _) = alice_states.initiator_to_responder.take();
    let (k2, _) = alice_states.responder_to_initiator.take();

    // 7. Emit Zig.
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    writeln!(w, "//! GENERATED by scripts/build-oracle.sh — do not hand-edit.")?;
    writeln!(w, "//!")?;
    writeln!(
        w,
        "//! Frozen golden trace from clatter ({}/{}/{}/{}).",
        MlKem768::name(),
        MlKem768::name(),
        ChaChaPoly::name(),
        ClatterSha256::name()
    )?;
    writeln!(w, "//! Re-run scripts/build-oracle.sh to regenerate.\n")?;
    writeln!(w, "pub const generated: bool = true;\n")?;

    emit_byte_array(&mut w, "alice_static_pub", &alice_static_pub)?;
    emit_byte_array(&mut w, "alice_static_sec", &alice_static_sec)?;
    emit_byte_array(&mut w, "bob_static_pub", &bob_static_pub)?;
    emit_byte_array(&mut w, "bob_static_sec", &bob_static_sec)?;
    emit_byte_array(&mut w, "alice_eph_pub", &alice_eph_pub)?;
    emit_byte_array(&mut w, "alice_eph_sec", &alice_eph_sec)?;
    emit_byte_array(&mut w, "alice_rng", &alice_rng)?;
    emit_byte_array(&mut w, "bob_rng", &bob_rng)?;
    emit_byte_array(&mut w, "msg1", &msg1)?;
    emit_byte_array(&mut w, "msg2", &msg2)?;
    emit_byte_array(&mut w, "handshake_hash", h.as_slice())?;
    emit_byte_array(&mut w, "c1_key", k1.as_slice())?;
    emit_byte_array(&mut w, "c2_key", k2.as_slice())?;

    Ok(())
}
