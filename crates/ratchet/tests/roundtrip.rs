use ratchet::{DoubleRatchet, RatchetError};

struct CounterRng(u64);
impl rand_core::RngCore for CounterRng {
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
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(4) {
            let b = self.next_u32().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core::CryptoRng for CounterRng {}

const AD: &[u8] = b"associated-data";

fn session(rng: &mut CounterRng) -> (DoubleRatchet, DoubleRatchet) {
    let shared = {
        let mut s = [0u8; 32];
        rand_core::RngCore::fill_bytes(rng, &mut s);
        s
    };
    let (bob_priv, bob_pub) = crypto::x25519_generate(rng);
    let alice = DoubleRatchet::init_alice(shared, bob_pub, rng);
    let bob = DoubleRatchet::init_bob(shared, bob_priv);
    (alice, bob)
}

#[test]
fn in_order_ping_pong() {
    let mut rng = CounterRng(1);
    let (mut alice, mut bob) = session(&mut rng);

    for i in 0..5u8 {
        let msg = format!("alice #{i}");
        let ct = alice.encrypt(msg.as_bytes(), AD).unwrap();
        assert_eq!(bob.decrypt(&ct, AD, &mut rng).unwrap(), msg.as_bytes());

        let reply = format!("bob #{i}");
        let ct = bob.encrypt(reply.as_bytes(), AD).unwrap();
        assert_eq!(alice.decrypt(&ct, AD, &mut rng).unwrap(), reply.as_bytes());
    }
}

#[test]
fn bob_cannot_send_before_receiving() {
    let mut rng = CounterRng(2);
    let (_alice, mut bob) = session(&mut rng);
    assert_eq!(
        bob.encrypt(b"too early", AD),
        Err(RatchetError::NotEstablished)
    );
}

#[test]
fn out_of_order_within_a_chain() {
    let mut rng = CounterRng(3);
    let (mut alice, mut bob) = session(&mut rng);

    let m0 = alice.encrypt(b"zero", AD).unwrap();
    let m1 = alice.encrypt(b"one", AD).unwrap();
    let m2 = alice.encrypt(b"two", AD).unwrap();

    assert_eq!(bob.decrypt(&m2, AD, &mut rng).unwrap(), b"two");
    assert_eq!(bob.decrypt(&m0, AD, &mut rng).unwrap(), b"zero");
    assert_eq!(bob.decrypt(&m1, AD, &mut rng).unwrap(), b"one");
}

#[test]
fn out_of_order_across_a_dh_ratchet() {
    let mut rng = CounterRng(4);
    let (mut alice, mut bob) = session(&mut rng);

    let a0 = alice.encrypt(b"a0", AD).unwrap();
    bob.decrypt(&a0, AD, &mut rng).unwrap();
    let b0 = bob.encrypt(b"b0", AD).unwrap();
    alice.decrypt(&b0, AD, &mut rng).unwrap();

    let b1 = bob.encrypt(b"b1", AD).unwrap();
    let b2 = bob.encrypt(b"b2", AD).unwrap();

    assert_eq!(alice.decrypt(&b2, AD, &mut rng).unwrap(), b"b2");
    assert_eq!(alice.decrypt(&b1, AD, &mut rng).unwrap(), b"b1");
}

#[test]
fn tampering_is_rejected() {
    let mut rng = CounterRng(5);
    let (mut alice, mut bob) = session(&mut rng);

    let mut ct = alice.encrypt(b"secret", AD).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert_eq!(bob.decrypt(&ct, AD, &mut rng), Err(RatchetError::Decrypt));

    let ct = alice.encrypt(b"secret", AD).unwrap();
    assert_eq!(
        bob.decrypt(&ct, b"other-ad", &mut rng),
        Err(RatchetError::Decrypt)
    );
}

#[test]
fn session_survives_serialization_mid_conversation() {
    let mut rng = CounterRng(7);
    let (mut alice, mut bob) = session(&mut rng);

    for i in 0..3u8 {
        let ct = alice.encrypt(format!("a{i}").as_bytes(), AD).unwrap();
        bob.decrypt(&ct, AD, &mut rng).unwrap();
        let ct = bob.encrypt(format!("b{i}").as_bytes(), AD).unwrap();
        alice.decrypt(&ct, AD, &mut rng).unwrap();
    }

    let mut alice = DoubleRatchet::deserialize(&alice.serialize()).unwrap();
    let mut bob = DoubleRatchet::deserialize(&bob.serialize()).unwrap();

    let ct = alice.encrypt(b"after restart", AD).unwrap();
    assert_eq!(bob.decrypt(&ct, AD, &mut rng).unwrap(), b"after restart");
    let ct = bob.encrypt(b"still here", AD).unwrap();
    assert_eq!(alice.decrypt(&ct, AD, &mut rng).unwrap(), b"still here");
}

#[test]
fn serialization_preserves_skipped_keys() {
    let mut rng = CounterRng(8);
    let (mut alice, mut bob) = session(&mut rng);

    let m0 = alice.encrypt(b"zero", AD).unwrap();
    let m1 = alice.encrypt(b"one", AD).unwrap();
    let m2 = alice.encrypt(b"two", AD).unwrap();
    assert_eq!(bob.decrypt(&m2, AD, &mut rng).unwrap(), b"two");

    let mut bob = DoubleRatchet::deserialize(&bob.serialize()).unwrap();
    assert_eq!(bob.decrypt(&m0, AD, &mut rng).unwrap(), b"zero");
    assert_eq!(bob.decrypt(&m1, AD, &mut rng).unwrap(), b"one");
}

#[test]
fn deserialize_rejects_corrupt_state() {
    let mut rng = CounterRng(9);
    let (mut alice, _bob) = session(&mut rng);
    let _ = alice.encrypt(b"x", AD).unwrap();
    let good = alice.serialize();

    assert_eq!(
        DoubleRatchet::deserialize(&[]).err(),
        Some(RatchetError::BadState)
    );
    assert_eq!(
        DoubleRatchet::deserialize(&good[..good.len() - 1]).err(),
        Some(RatchetError::BadState)
    );
    let mut bad_version = good.clone();
    bad_version[0] = 0xff;
    assert_eq!(
        DoubleRatchet::deserialize(&bad_version).err(),
        Some(RatchetError::BadState)
    );
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(
        DoubleRatchet::deserialize(&trailing).err(),
        Some(RatchetError::BadState)
    );
}
