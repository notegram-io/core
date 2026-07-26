use sdk::{InboundPreKeys, NotegramClient, PeerAddress, PreKeyBundle};
use store::MemoryBackend;

const ALICE_KEY: &[u8; 32] = &[1u8; 32];
const BOB_KEY: &[u8; 32] = &[2u8; 32];
const AD: &[u8] = b"chat-42-associated-data";

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
fn two_clients_establish_and_message_across_a_restart() {
    let mut rng = Rng(0xC0FFEE);

    let alice_id = sdk::Identity::generate(&mut rng);
    let bob_id = sdk::Identity::generate(&mut rng);

    let (bob_spk_priv, bob_spk_pub) = crypto::x25519_generate(&mut rng);
    let (bob_opk_priv, bob_opk_pub) = crypto::x25519_generate(&mut rng);
    let spk_sig = e2ee::x3dh::sign_signed_prekey(&bob_id.signing_seed, &bob_spk_pub);
    let bundle = PreKeyBundle {
        identity_pub: bob_id.identity_pub,
        signing_pub: bob_id.signing_pub,
        signed_prekey_pub: bob_spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekey_pub: Some(bob_opk_pub),
    };

    let alice_addr = PeerAddress {
        user_id: 1001,
        device_id: 1,
    };
    let bob_addr = PeerAddress {
        user_id: 2002,
        device_id: 1,
    };

    let mut alice = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
    let mut bob = NotegramClient::open(BOB_KEY, MemoryBackend::new()).unwrap();
    alice.import_identity(&alice_id).unwrap();
    bob.import_identity(&bob_id).unwrap();
    assert!(!alice.has_session(bob_addr).unwrap());

    let ephemeral = alice.establish_outbound_session(bob_addr, &bundle).unwrap();
    assert!(alice.has_session(bob_addr).unwrap());
    let ct = alice.encrypt(bob_addr, b"hello bob", AD).unwrap();

    bob.establish_inbound_session(
        alice_addr,
        &InboundPreKeys {
            signed_prekey_priv: &bob_spk_priv,
            one_time_prekey_priv: Some(&bob_opk_priv),
        },
        &alice_id.identity_pub,
        &ephemeral,
    )
    .unwrap();
    assert_eq!(bob.decrypt(alice_addr, &ct, AD).unwrap(), b"hello bob");

    let reply = bob.encrypt(alice_addr, b"hi alice", AD).unwrap();
    assert_eq!(alice.decrypt(bob_addr, &reply, AD).unwrap(), b"hi alice");

    let alice = NotegramClient::open(ALICE_KEY, alice.into_backend()).unwrap();
    let bob = NotegramClient::open(BOB_KEY, bob.into_backend()).unwrap();
    let (mut alice, mut bob) = (alice, bob);

    let ct2 = alice.encrypt(bob_addr, b"after restart", AD).unwrap();
    assert_eq!(bob.decrypt(alice_addr, &ct2, AD).unwrap(), b"after restart");
    let reply2 = bob.encrypt(alice_addr, b"still here", AD).unwrap();
    assert_eq!(alice.decrypt(bob_addr, &reply2, AD).unwrap(), b"still here");
}

#[test]
fn operations_require_identity_and_session() {
    let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
    let peer = PeerAddress {
        user_id: 9,
        device_id: 9,
    };

    assert_eq!(
        client.public_identity().err(),
        Some(sdk::SdkError::NoIdentity)
    );

    assert_eq!(
        client.encrypt(peer, b"x", AD).err(),
        Some(sdk::SdkError::NoSession)
    );
}

#[test]
fn outbound_rejects_forged_signed_prekey() {
    let mut rng = Rng(0xBAD5EED);
    let alice_id = sdk::Identity::generate(&mut rng);
    let bob_id = sdk::Identity::generate(&mut rng);
    let attacker_id = sdk::Identity::generate(&mut rng);

    let (_spk_priv, spk_pub) = crypto::x25519_generate(&mut rng);

    let forged_sig = e2ee::x3dh::sign_signed_prekey(&attacker_id.signing_seed, &spk_pub);
    let bundle = PreKeyBundle {
        identity_pub: bob_id.identity_pub,
        signing_pub: bob_id.signing_pub,
        signed_prekey_pub: spk_pub,
        signed_prekey_sig: forged_sig,
        one_time_prekey_pub: None,
    };

    let mut alice = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
    alice.import_identity(&alice_id).unwrap();
    let peer = PeerAddress {
        user_id: 2,
        device_id: 1,
    };
    assert_eq!(
        alice.establish_outbound_session(peer, &bundle).err(),
        Some(sdk::SdkError::BadPrekeySignature)
    );
}
