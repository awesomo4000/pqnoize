//! Clatter-driven pqKK oracle for pqnoize.
//!
//! Drives a complete pqKK handshake using `clatter` (a peer-reviewed Rust
//! Noise/PQNoise implementation) under fully deterministic inputs, then
//! emits the resulting wire bytes and final state as Zig source code.
//! The Zig test suite under `tests/kats.zig` cross-checks our pqnoize
//! implementation against this golden.
//!
//! Determinism:
//!
//!   * Static and ephemeral ML-KEM-768 keypairs are generated via the
//!     `ml-kem` crate's `generate_deterministic(d, z)` API from labelled
//!     SHA-256-derived seeds — spec-canonical, so any FIPS-203 conformant
//!     implementation produces the same keypair from the same `(d, z)`.
//!
//!   * Encapsulation randomness inside `clatter` is provided by a small
//!     thread-local-backed RNG so each operation receives the same 32-byte
//!     `m` we pin here. Both encaps operations in pqKK message 2 (and the
//!     one in message 1) draw from this stream in the order the pattern
//!     walker visits them.
//!
//! Re-running the harness with the same seeds yields byte-identical output;
//! re-running with different seeds yields different vectors. Bumping
//! clatter's pinned version may cause vectors to drift — that's the whole
//! point of regenerating after an oracle bump.

use std::cell::RefCell;
use std::io::Write;

use clatter::bytearray::ByteArray;
use clatter::crypto_impl::cipher::ChaChaPoly;
use clatter::crypto_impl::hash::Sha256 as ClatterSha256;
use clatter::crypto_impl::rust_crypto_ml_kem::MlKem768;
use clatter::handshakepattern::noise_pqkk;
use clatter::traits::{CryptoComponent, Handshaker, Kem, Rng as ClatterRng};
use clatter::{KeyPair, PqHandshakeCore, TransportState};

use ml_kem::kem::{Kem as MlKemKem, EncapsulationKey};
use ml_kem::{KemCore, MlKem768Params, EncodedSizeUser, B32};
use sha2::{Digest, Sha256};

// ── Labelled seed derivation ──────────────────────────────────────────────
//
// All randomness inputs are SHA-256(label) so the harness is reproducible
// from this source file alone. Any change to a label changes the output
// vector — diff is loud and obvious.

fn label32(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pqnoize-oracle-v1/");
    h.update(label.as_bytes());
    h.finalize().into()
}

// ── Custom thread-local RNG plugged into clatter ──────────────────────────

thread_local! {
    static RNG_BYTES: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    static RNG_CURSOR: RefCell<usize> = RefCell::new(0);
}

fn set_rng_bytes(bytes: Vec<u8>) {
    RNG_BYTES.with(|b| *b.borrow_mut() = bytes);
    RNG_CURSOR.with(|c| *c.borrow_mut() = 0);
}

#[derive(Clone, Default)]
struct ScriptedRng;

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
        RNG_BYTES.with(|b| {
            RNG_CURSOR.with(|c| {
                let bytes = b.borrow();
                let mut cur = c.borrow_mut();
                let n = dest.len();
                assert!(
                    *cur + n <= bytes.len(),
                    "ScriptedRng exhausted: requested {} bytes at cursor {} of {}",
                    n,
                    *cur,
                    bytes.len()
                );
                dest.copy_from_slice(&bytes[*cur..*cur + n]);
                *cur += n;
            })
        });
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for ScriptedRng {}
impl ClatterRng for ScriptedRng {}

// ── Helpers ───────────────────────────────────────────────────────────────

fn ml_kem_keypair(d_label: &str, z_label: &str) -> (Vec<u8>, Vec<u8>) {
    let d_arr = label32(d_label);
    let z_arr = label32(z_label);
    let d = B32::from(d_arr);
    let z = B32::from(z_arr);
    let (dk, ek) = <MlKem768Params as KemCore>::generate_deterministic(&d, &z);
    (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
}

type ClatterPubKey = <MlKem768 as Kem>::PubKey;
type ClatterSecretKey = <MlKem768 as Kem>::SecretKey;

fn clatter_keypair_from_bytes(pub_bytes: &[u8], sec_bytes: &[u8]) -> KeyPair<ClatterPubKey, ClatterSecretKey> {
    KeyPair {
        public: ClatterPubKey::from_slice(pub_bytes),
        secret: ClatterSecretKey::from_slice(sec_bytes),
    }
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
    // 1. Generate static and ephemeral keypairs deterministically via ml-kem.
    let (alice_static_pub, alice_static_sec) = ml_kem_keypair("alice-static-d", "alice-static-z");
    let (bob_static_pub, bob_static_sec) = ml_kem_keypair("bob-static-d", "bob-static-z");
    let (alice_eph_pub, alice_eph_sec) = ml_kem_keypair("alice-eph-d", "alice-eph-z");

    let alice_static_kp = clatter_keypair_from_bytes(&alice_static_pub, &alice_static_sec);
    let bob_static_kp = clatter_keypair_from_bytes(&bob_static_pub, &bob_static_sec);
    let alice_eph_kp = clatter_keypair_from_bytes(&alice_eph_pub, &alice_eph_sec);

    // 2. Encaps seeds. Order of consumption matches the pqKK pattern walker:
    //   alice (msg1, [skem, e]):   skem-msg1 (pre-built ephemeral, no keygen draw)
    //   bob   (msg2, [ekem, skem]): ekem-msg2, then skem-msg2
    let skem_msg1_seed = label32("skem-msg1");
    let ekem_msg2_seed = label32("ekem-msg2");
    let skem_msg2_seed = label32("skem-msg2");

    // 3. Construct alice's PqHandshake. Set RNG bytes to alice's encaps seed,
    //    then `RNG::default()` inside `new()` will drain it on init.
    set_rng_bytes(skem_msg1_seed.to_vec());
    let mut alice = PqHandshakeCore::<MlKem768, MlKem768, ChaChaPoly, ClatterSha256, ScriptedRng>::new(
        noise_pqkk(),
        &[],
        true,                      // initiator
        Some(alice_static_kp.clone()),
        Some(alice_eph_kp.clone()),
        Some(bob_static_kp.public.clone()),
        None,
    )?;

    // 4. Construct bob's PqHandshake.
    let mut bob_bytes = Vec::with_capacity(64);
    bob_bytes.extend_from_slice(&ekem_msg2_seed);
    bob_bytes.extend_from_slice(&skem_msg2_seed);
    set_rng_bytes(bob_bytes);
    let mut bob = PqHandshakeCore::<MlKem768, MlKem768, ChaChaPoly, ClatterSha256, ScriptedRng>::new(
        noise_pqkk(),
        &[],
        false,                     // responder
        Some(bob_static_kp.clone()),
        None,                      // bob has no ephemeral in pqKK
        Some(alice_static_kp.public.clone()),
        None,
    )?;

    // 5. Drive the two-message handshake.
    let mut buf_a = vec![0u8; 4096];
    let mut buf_b = vec![0u8; 4096];

    let n1 = alice.write_message(&[], &mut buf_a)?;
    let _ = bob.read_message(&buf_a[..n1], &mut buf_b)?;
    let msg1 = buf_a[..n1].to_vec();

    let n2 = bob.write_message(&[], &mut buf_b)?;
    let _ = alice.read_message(&buf_b[..n2], &mut buf_a)?;
    let msg2 = buf_b[..n2].to_vec();

    assert!(alice.is_finished() && bob.is_finished());

    // 6. Finalize and extract handshake hash + split keys.
    let alice_xport: TransportState<ChaChaPoly, ClatterSha256> = TransportState::new(alice)?;
    let bob_xport: TransportState<ChaChaPoly, ClatterSha256> = TransportState::new(bob)?;

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
    writeln!(w, "//! Frozen golden trace from clatter ({}/{}/{}/{}).", MlKem768::name(), MlKem768::name(), ChaChaPoly::name(), ClatterSha256::name())?;
    writeln!(w, "//! Re-run scripts/build-oracle.sh to regenerate.\n")?;
    writeln!(w, "pub const generated: bool = true;\n")?;

    emit_byte_array(&mut w, "alice_static_pub", &alice_static_pub)?;
    emit_byte_array(&mut w, "alice_static_sec", &alice_static_sec)?;
    emit_byte_array(&mut w, "bob_static_pub", &bob_static_pub)?;
    emit_byte_array(&mut w, "bob_static_sec", &bob_static_sec)?;
    emit_byte_array(&mut w, "alice_eph_pub", &alice_eph_pub)?;
    emit_byte_array(&mut w, "alice_eph_sec", &alice_eph_sec)?;
    emit_byte_array(&mut w, "skem_msg1_seed", &skem_msg1_seed)?;
    emit_byte_array(&mut w, "ekem_msg2_seed", &ekem_msg2_seed)?;
    emit_byte_array(&mut w, "skem_msg2_seed", &skem_msg2_seed)?;
    emit_byte_array(&mut w, "msg1", &msg1)?;
    emit_byte_array(&mut w, "msg2", &msg2)?;
    emit_byte_array(&mut w, "handshake_hash", h.as_slice())?;
    emit_byte_array(&mut w, "c1_key", k1.as_slice())?;
    emit_byte_array(&mut w, "c2_key", k2.as_slice())?;

    Ok(())
}
