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

#[test]
fn one_time_prekey_top_ups_never_reuse_an_id() {
    let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::default()).unwrap();
    client.create_identity().unwrap();

    let first = client.generate_prekey_bundle(3).unwrap();
    let second = client.generate_one_time_prekeys(3).unwrap();
    let third = client.generate_one_time_prekeys(2).unwrap();

    let ids: Vec<i32> = first
        .one_time_pre_keys
        .iter()
        .chain(second.iter())
        .chain(third.iter())
        .map(|k| k.id)
        .collect();

    assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8], "ids continue across top-ups");

    // Reusing an id would silently overwrite a private key the server still
    // advertises, so those sessions could never be decrypted.
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "ids must be unique");
}

#[test]
fn message_history_is_per_chat_and_chronological() {
    let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::default()).unwrap();

    let msg = |chat: i64, peer: i64, at: i64, id: &str, text: &str, outgoing: bool| {
        sdk::StoredMessage {
            chat_id: chat,
            peer_user_id: peer,
            outgoing,
            client_msg_id: id.to_string(),
            text: text.to_string(),
            created_at: at,
        }
    };

    // Saved out of order and across two chats.
    client.save_message(&msg(10, 1, 300, "c", "third", false)).unwrap();
    client.save_message(&msg(10, 1, 100, "a", "first", true)).unwrap();
    client.save_message(&msg(20, 2, 150, "x", "other chat", true)).unwrap();
    client.save_message(&msg(10, 1, 200, "b", "second", false)).unwrap();

    let chat10: Vec<String> = client
        .list_messages(10, 0)
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(chat10, vec!["first", "second", "third"]);
    assert_eq!(client.list_messages(20, 0).unwrap().len(), 1);

    // limit keeps the newest tail.
    let tail: Vec<String> = client
        .list_messages(10, 2)
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(tail, vec!["second", "third"]);

    // Re-saving the same client_msg_id updates in place rather than duplicating.
    client.save_message(&msg(10, 1, 200, "b", "second (edited)", false)).unwrap();
    assert_eq!(client.list_messages(10, 0).unwrap().len(), 3);

    let previews = client.list_chat_previews().unwrap();
    assert_eq!(previews.len(), 2, "one row per chat");
    assert_eq!(previews[0].chat_id, 10, "newest chat first");
    assert_eq!(previews[0].text, "third");
}
