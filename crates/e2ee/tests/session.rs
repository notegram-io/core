use e2ee::x3dh::{
    initiator_secret, responder_secret, sign_signed_prekey, verify_signed_prekey, Initiator,
    Responder,
};
use ratchet::DoubleRatchet;

struct Rng(u64);
impl rand_core::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
    fn next_u64(&mut self) -> u64 {
        ((self.next_u32() as u64) << 32) | self.next_u32() as u64
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        for c in d.chunks_mut(4) {
            c.copy_from_slice(&self.next_u32().to_le_bytes()[..c.len()]);
        }
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(d);
        Ok(())
    }
}
impl rand_core::CryptoRng for Rng {}

#[test]
fn x3dh_bootstraps_a_ratchet_session() {
    let mut rng = Rng(0xF00D);

    let bob_device_seed = [0x33u8; 32];
    let (bob_ik, bob_ik_pub) = crypto::x25519_generate(&mut rng);
    let (bob_spk, bob_spk_pub) = crypto::x25519_generate(&mut rng);
    let (bob_opk, bob_opk_pub) = crypto::x25519_generate(&mut rng);
    let spk_sig = sign_signed_prekey(&bob_device_seed, &bob_spk_pub);

    assert!(verify_signed_prekey(
        &crypto::ed25519_public(&bob_device_seed),
        &bob_spk_pub,
        &spk_sig
    ));

    let (alice_ik, alice_ik_pub) = crypto::x25519_generate(&mut rng);
    let (alice_ek, alice_ek_pub) = crypto::x25519_generate(&mut rng);

    let sk_alice = initiator_secret(&Initiator {
        identity_priv: &alice_ik,
        ephemeral_priv: &alice_ek,
        peer_identity_pub: &bob_ik_pub,
        peer_signed_prekey_pub: &bob_spk_pub,
        peer_one_time_prekey_pub: Some(&bob_opk_pub),
    });
    let sk_bob = responder_secret(&Responder {
        identity_priv: &bob_ik,
        signed_prekey_priv: &bob_spk,
        one_time_prekey_priv: Some(&bob_opk),
        peer_identity_pub: &alice_ik_pub,
        peer_ephemeral_pub: &alice_ek_pub,
    });
    assert_eq!(sk_alice, sk_bob, "X3DH must agree");

    let mut alice = DoubleRatchet::init_alice(sk_alice, bob_spk_pub, &mut rng);
    let mut bob = DoubleRatchet::init_bob(sk_bob, bob_spk);

    let ad = b"chat-42";
    let ct = alice.encrypt(b"hello bob", ad).unwrap();
    assert_eq!(bob.decrypt(&ct, ad, &mut rng).unwrap(), b"hello bob");

    let reply = bob.encrypt(b"hi alice", ad).unwrap();
    assert_eq!(alice.decrypt(&reply, ad, &mut rng).unwrap(), b"hi alice");
}
