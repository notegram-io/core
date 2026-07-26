use ratchet::sender_key::{SenderKeyReceiver, SenderKeySender};
use ratchet::RatchetError;

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

const AD: &[u8] = b"group-99";

#[test]
fn group_broadcast_reaches_all_members() {
    let mut rng = Rng(1);

    let mut alice = SenderKeySender::new(&mut rng);
    let mut bob = SenderKeyReceiver::from_distribution(&alice.distribution());
    let mut carol = SenderKeyReceiver::from_distribution(&alice.distribution());

    for i in 0..4u8 {
        let msg = format!("broadcast {i}");
        let ct = alice.encrypt(msg.as_bytes(), AD);
        assert_eq!(bob.decrypt(&ct, AD).unwrap(), msg.as_bytes());
        assert_eq!(carol.decrypt(&ct, AD).unwrap(), msg.as_bytes());
    }
}

#[test]
fn out_of_order_group_delivery() {
    let mut rng = Rng(2);
    let mut alice = SenderKeySender::new(&mut rng);
    let mut bob = SenderKeyReceiver::from_distribution(&alice.distribution());

    let m0 = alice.encrypt(b"zero", AD);
    let m1 = alice.encrypt(b"one", AD);
    let m2 = alice.encrypt(b"two", AD);

    assert_eq!(bob.decrypt(&m2, AD).unwrap(), b"two");
    assert_eq!(bob.decrypt(&m0, AD).unwrap(), b"zero");
    assert_eq!(bob.decrypt(&m1, AD).unwrap(), b"one");
}

#[test]
fn forged_or_tampered_message_is_rejected() {
    let mut rng = Rng(3);
    let mut alice = SenderKeySender::new(&mut rng);
    let mut bob = SenderKeyReceiver::from_distribution(&alice.distribution());

    let mut impostor = SenderKeySender::new(&mut rng);

    let forged = impostor.encrypt(b"i am alice", AD);
    assert_eq!(bob.decrypt(&forged, AD), Err(RatchetError::Decrypt));

    let mut ct = alice.encrypt(b"genuine", AD);
    ct[10] ^= 0x01;
    assert_eq!(bob.decrypt(&ct, AD), Err(RatchetError::Decrypt));
}

#[test]
fn sender_key_state_survives_serialization() {
    let mut rng = Rng(4);
    let mut alice = SenderKeySender::new(&mut rng);
    let mut bob = SenderKeyReceiver::from_distribution(&alice.distribution());

    let _ = alice.encrypt(b"m0", AD);
    let m1 = alice.encrypt(b"m1", AD);
    let m2 = alice.encrypt(b"m2", AD);
    assert_eq!(bob.decrypt(&m2, AD).unwrap(), b"m2");

    let mut alice = SenderKeySender::deserialize(&alice.serialize()).unwrap();
    let mut bob = SenderKeyReceiver::deserialize(&bob.serialize()).unwrap();

    assert_eq!(bob.decrypt(&m1, AD).unwrap(), b"m1");

    let m3 = alice.encrypt(b"m3", AD);
    assert_eq!(bob.decrypt(&m3, AD).unwrap(), b"m3");

    assert_eq!(
        SenderKeySender::deserialize(&[]).err(),
        Some(RatchetError::BadState)
    );
    assert_eq!(
        SenderKeyReceiver::deserialize(&[0x01, 0x02]).err(),
        Some(RatchetError::BadState)
    );
}
