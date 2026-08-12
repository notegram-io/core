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

    assert_eq!(
        ids,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        "ids continue across top-ups"
    );

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

    let msg =
        |chat: i64, peer: i64, at: i64, id: &str, text: &str, outgoing: bool| sdk::StoredMessage {
            chat_id: chat,
            peer_user_id: peer,
            outgoing,
            client_msg_id: id.to_string(),
            text: text.to_string(),
            created_at: at,
            status: sdk::MessageStatus::Sent,
            reply_to: None,
            forwarded_from: None,
            forwarded_at: None,
            edited_at: None,
            deleted_at: None,
        };

    // Saved out of order and across two chats.
    client
        .save_message(&msg(10, 1, 300, "c", "third", false))
        .unwrap();
    client
        .save_message(&msg(10, 1, 100, "a", "first", true))
        .unwrap();
    client
        .save_message(&msg(20, 2, 150, "x", "other chat", true))
        .unwrap();
    client
        .save_message(&msg(10, 1, 200, "b", "second", false))
        .unwrap();

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
    client
        .save_message(&msg(10, 1, 200, "b", "second (edited)", false))
        .unwrap();
    assert_eq!(client.list_messages(10, 0).unwrap().len(), 3);

    let previews = client.list_chat_previews().unwrap();
    assert_eq!(previews.len(), 2, "one row per chat");
    assert_eq!(previews[0].chat_id, 10, "newest chat first");
    assert_eq!(previews[0].text, "third");
}

#[test]
fn rotating_the_signed_prekey_keeps_earlier_messages_decryptable() {
    // Alice publishes a bundle; Bob encrypts against it.
    let mut alice = NotegramClient::open(ALICE_KEY, MemoryBackend::default()).unwrap();
    let alice_identity = alice.create_identity().unwrap();
    let first = alice.generate_prekey_bundle(2).unwrap();

    let mut bob = NotegramClient::open(BOB_KEY, MemoryBackend::default()).unwrap();
    bob.create_identity().unwrap();
    let alice_addr = PeerAddress {
        user_id: 1,
        device_id: 1,
    };
    let bob_addr = PeerAddress {
        user_id: 2,
        device_id: 1,
    };
    let otk = first.one_time_pre_keys.first().unwrap();

    let envelope = bob
        .encrypt_message(
            2,
            1,
            alice_addr,
            77,
            "before-rotation",
            &sdk::MessageBody::Text("sent before rotation".into()),
            Some(&sdk::RecipientPreKeyBundle {
                identity_key: first.identity_key,
                signing_pub: alice_identity.signing_pub,
                signed_prekey_id: first.signed_pre_key_id,
                signed_prekey_pub: first.signed_pre_key_pub,
                signed_prekey_sig: first.signed_pre_key_sig,
                one_time_prekey_id: otk.id,
                one_time_prekey_pub: Some(otk.pubkey),
            }),
            None,
        )
        .unwrap();

    // Alice rotates before ever opening that message.
    let rotated = alice.rotate_signed_prekey(2).unwrap();
    assert!(
        rotated.signed_pre_key_id > first.signed_pre_key_id,
        "the server rejects an id that does not strictly increase"
    );
    assert_ne!(rotated.signed_pre_key_pub, first.signed_pre_key_pub);
    assert!(
        rotated.one_time_pre_keys[0].id > first.one_time_pre_keys[1].id,
        "one-time ids keep marching forward across a rotation"
    );

    // The envelope names the *old* signed prekey, so rotation must not have
    // discarded its private half.
    let plaintext = alice
        .decrypt_message(
            bob_addr,
            &envelope.envelope_type,
            &envelope.header,
            &envelope.ciphertext,
            &envelope.associated_data,
        )
        .unwrap();
    assert_eq!(
        plaintext.body,
        sdk::MessageBody::Text("sent before rotation".into())
    );

    // A top-up after rotation must advertise the rotated prekey, not the old one.
    let top_up = alice.prekey_top_up(1).unwrap();
    assert_eq!(top_up.signed_pre_key_id, rotated.signed_pre_key_id);
    assert_eq!(top_up.signed_pre_key_pub, rotated.signed_pre_key_pub);
}

#[test]
fn delivery_status_advances_but_never_regresses() {
    let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::default()).unwrap();
    let outgoing = sdk::StoredMessage {
        chat_id: 5,
        peer_user_id: 9,
        outgoing: true,
        client_msg_id: "m-1".into(),
        text: "hi".into(),
        created_at: 1_000,
        status: sdk::MessageStatus::Sent,
        reply_to: None,
        forwarded_from: None,
        forwarded_at: None,
        edited_at: None,
        deleted_at: None,
    };
    client.save_message(&outgoing).unwrap();

    assert!(client
        .mark_message_status(5, "m-1", sdk::MessageStatus::Delivered)
        .unwrap());
    assert_eq!(
        client.list_messages(5, 0).unwrap()[0].status,
        sdk::MessageStatus::Delivered
    );

    assert!(client
        .mark_message_status(5, "m-1", sdk::MessageStatus::Read)
        .unwrap());

    // Notices can arrive out of order; a late delivery receipt must not undo a
    // read receipt the user already saw.
    assert!(!client
        .mark_message_status(5, "m-1", sdk::MessageStatus::Delivered)
        .unwrap());
    assert_eq!(
        client.list_messages(5, 0).unwrap()[0].status,
        sdk::MessageStatus::Read
    );

    // Unknown ids and incoming messages are left alone.
    assert!(!client
        .mark_message_status(5, "nope", sdk::MessageStatus::Delivered)
        .unwrap());
}

// Builds a live session pair and returns (alice, bob, alice_addr, bob_addr).
// Bob is the sender: he encrypts against Alice's published bundle.
fn session_pair() -> (
    NotegramClient<MemoryBackend>,
    NotegramClient<MemoryBackend>,
    PeerAddress,
    PeerAddress,
) {
    let mut alice = NotegramClient::open(ALICE_KEY, MemoryBackend::default()).unwrap();
    let alice_identity = alice.create_identity().unwrap();
    let bundle = alice.generate_prekey_bundle(2).unwrap();

    let mut bob = NotegramClient::open(BOB_KEY, MemoryBackend::default()).unwrap();
    bob.create_identity().unwrap();

    let alice_addr = PeerAddress {
        user_id: 1,
        device_id: 1,
    };
    let bob_addr = PeerAddress {
        user_id: 2,
        device_id: 1,
    };
    let otk = bundle.one_time_pre_keys.first().unwrap();

    let opening = bob
        .encrypt_message(
            2,
            1,
            alice_addr,
            77,
            "opening",
            &sdk::MessageBody::Text("hello".into()),
            Some(&sdk::RecipientPreKeyBundle {
                identity_key: bundle.identity_key,
                signing_pub: alice_identity.signing_pub,
                signed_prekey_id: bundle.signed_pre_key_id,
                signed_prekey_pub: bundle.signed_pre_key_pub,
                signed_prekey_sig: bundle.signed_pre_key_sig,
                one_time_prekey_id: otk.id,
                one_time_prekey_pub: Some(otk.pubkey),
            }),
            None,
        )
        .unwrap();
    alice
        .decrypt_message(
            bob_addr,
            &opening.envelope_type,
            &opening.header,
            &opening.ciphertext,
            &opening.associated_data,
        )
        .unwrap();
    (alice, bob, alice_addr, bob_addr)
}

#[test]
fn a_reply_names_the_message_it_answers() {
    let (mut alice, mut bob, alice_addr, bob_addr) = session_pair();

    let answered = sdk::message_ref("opening");
    let envelope = bob
        .encrypt_message(
            2,
            1,
            alice_addr,
            77,
            "the-reply",
            &sdk::MessageBody::Text("yes".into()),
            None,
            Some(answered),
        )
        .unwrap();

    let opened = alice
        .decrypt_message(
            bob_addr,
            &envelope.envelope_type,
            &envelope.header,
            &envelope.ciphertext,
            &envelope.associated_data,
        )
        .unwrap();

    assert_eq!(opened.body, sdk::MessageBody::Text("yes".into()));
    assert_eq!(opened.client_msg_id, "the-reply");
    assert_eq!(opened.chat_id, 77);
    assert_eq!(
        opened.reply_to,
        Some(answered),
        "the recipient resolves the parent from the authenticated associated data"
    );

    // An ordinary message stays an ordinary message.
    let plain = bob
        .encrypt_message(
            2,
            1,
            alice_addr,
            77,
            "not-a-reply",
            &sdk::MessageBody::Text("hi".into()),
            None,
            None,
        )
        .unwrap();
    let opened = alice
        .decrypt_message(
            bob_addr,
            &plain.envelope_type,
            &plain.header,
            &plain.ciphertext,
            &plain.associated_data,
        )
        .unwrap();
    assert_eq!(opened.reply_to, None);
}

#[test]
fn associated_data_claiming_another_sender_is_rejected() {
    // The tag covers the associated data, so a relay cannot edit it. What it
    // *can* do is deliver a genuine ciphertext while naming a different sender,
    // or a sender can author associated data that misdescribes itself — either
    // way the message must not be shown under the wrong name.
    let (mut alice, mut bob, _alice_addr, bob_addr) = session_pair();

    let forged = e2ee::build_associated_data_v1(&e2ee::AssociatedDataInput {
        schema: e2ee::SCHEMA_LIBSIGNAL_SESSION_ENVELOPE_V1.to_string(),
        suite: e2ee::MESSAGE_SUITE_LIBSIGNAL_X3DH_DV1.to_string(),
        crypto_policy_profile: e2ee::CRYPTO_POLICY_PROFILE.to_string(),
        crypto_policy_version: e2ee::CRYPTO_POLICY_VERSION,
        crypto_policy_sha256: e2ee::CRYPTO_POLICY_SHA256_HEX.to_string(),
        // Bob encrypts, but claims the message came from user 99.
        sender_user_id: 99,
        sender_device_id: 1,
        chat_id: 77,
        client_msg_id: "impostor".to_string(),
        forward_info: Vec::new(),
        reply_to: None,
    });
    let ciphertext = bob.encrypt(_alice_addr, b"trust me", &forged).unwrap();

    let err = alice
        .decrypt_message(
            bob_addr,
            e2ee::ENVELOPE_TYPE_SIGNAL_V1,
            &[],
            &ciphertext,
            &forged,
        )
        .unwrap_err();
    assert_eq!(err, sdk::SdkError::MisattributedMessage);
}

#[test]
fn a_read_receipt_travels_as_an_ordinary_encrypted_message() {
    // Read state never reaches the server: the receipt is just another
    // ciphertext, indistinguishable from a message until it is decrypted.
    let (mut alice, mut bob, alice_addr, bob_addr) = session_pair();

    let envelope = bob
        .encrypt_message(
            2,
            1,
            alice_addr,
            77,
            "receipt-1",
            &sdk::MessageBody::ReadReceipt {
                up_to_created_at: 1_700_000_000_500,
            },
            None,
            None,
        )
        .unwrap();

    let opened = alice
        .decrypt_message(
            bob_addr,
            &envelope.envelope_type,
            &envelope.header,
            &envelope.ciphertext,
            &envelope.associated_data,
        )
        .unwrap();
    assert_eq!(
        opened.body,
        sdk::MessageBody::ReadReceipt {
            up_to_created_at: 1_700_000_000_500
        }
    );
}

#[test]
fn a_receipt_marks_everything_sent_up_to_its_watermark() {
    let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::default()).unwrap();
    let msg = |at: i64, id: &str, outgoing: bool| sdk::StoredMessage {
        chat_id: 7,
        peer_user_id: 3,
        outgoing,
        client_msg_id: id.to_string(),
        text: "x".into(),
        created_at: at,
        status: sdk::MessageStatus::Sent,
        reply_to: None,
        forwarded_from: None,
        forwarded_at: None,
        edited_at: None,
        deleted_at: None,
    };
    client.save_message(&msg(100, "a", true)).unwrap();
    client.save_message(&msg(200, "b", true)).unwrap();
    client.save_message(&msg(300, "c", true)).unwrap();
    // Their own message must never be marked: we do not report our own reading.
    client.save_message(&msg(150, "theirs", false)).unwrap();

    assert_eq!(client.mark_read_up_to(7, 200).unwrap(), 2);
    let after: Vec<_> = client.list_messages(7, 0).unwrap();
    let status = |id: &str| after.iter().find(|m| m.client_msg_id == id).unwrap().status;
    assert_eq!(status("a"), sdk::MessageStatus::Read);
    assert_eq!(status("b"), sdk::MessageStatus::Read);
    assert_eq!(status("c"), sdk::MessageStatus::Sent, "past the watermark");
    assert_eq!(
        status("theirs"),
        sdk::MessageStatus::Sent,
        "incoming is untouched"
    );

    // Replaying the same receipt is a no-op, and a delivery notice arriving
    // late must not walk a read message backwards.
    assert_eq!(client.mark_read_up_to(7, 200).unwrap(), 0);
    assert!(!client
        .mark_message_status(7, "a", sdk::MessageStatus::Delivered)
        .unwrap());
    assert_eq!(status("a"), sdk::MessageStatus::Read);
}

mod outbox {
    use super::*;
    use sdk::{MessageStatus, OutboxEntry, OutboxRecipient};

    fn entry(client_msg_id: &str, created_at: i64) -> OutboxEntry {
        OutboxEntry {
            client_msg_id: client_msg_id.to_string(),
            chat_id: 42,
            peer_user_id: 7,
            schema: "e2ee.v1".to_string(),
            suite: "libsignal.x3dh".to_string(),
            recipients: vec![OutboxRecipient {
                user_id: 7,
                device_id: 7001,
                envelope_type: "signal.v1".to_string(),
                header: vec![1],
                ciphertext: vec![2, 3, 4],
            }],
            associated_data: b"ad".to_vec(),
            forward_info: None,
            reply_to: None,
            created_at,
            attempts: 0,
        }
    }

    /// The point of the queue: a message the network never took is still there
    /// after the process dies, with its text and its envelope intact. Before
    /// this, an unsent message existed only in a view.
    #[test]
    fn a_queued_message_survives_reopening_the_store() {
        let backend = MemoryBackend::new();
        let mut client = NotegramClient::open(ALICE_KEY, backend).unwrap();
        client.enqueue_outbox(&entry("c-1", 1000), "hello").unwrap();

        let client = NotegramClient::open(ALICE_KEY, client.into_backend()).unwrap();
        let queued = client.pending_outbox().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].client_msg_id, "c-1");
        assert_eq!(
            queued[0].recipients[0].ciphertext,
            vec![2, 3, 4],
            "the envelope is kept, so the retry sends the same bytes"
        );

        let history = client.list_messages(42, 0).unwrap();
        assert_eq!(history.len(), 1, "the user sees it in the chat meanwhile");
        assert_eq!(history[0].text, "hello");
        assert_eq!(history[0].status, MessageStatus::Pending);
    }

    /// Delivering a chat out of order rearranges it for the recipient, and
    /// nothing later undoes that — so the queue hands messages back in the
    /// order they were typed, whatever order they were written in.
    #[test]
    fn the_queue_walks_in_the_order_the_user_typed() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.enqueue_outbox(&entry("c-3", 3000), "third").unwrap();
        client.enqueue_outbox(&entry("c-1", 1000), "first").unwrap();
        client
            .enqueue_outbox(&entry("c-2", 2000), "second")
            .unwrap();

        let ids: Vec<_> = client
            .pending_outbox()
            .unwrap()
            .into_iter()
            .map(|e| e.client_msg_id)
            .collect();
        assert_eq!(ids, vec!["c-1", "c-2", "c-3"]);
    }

    /// Acceptance is the only exit. The row adopts the server's time so this
    /// device orders the conversation the same way every other one will.
    #[test]
    fn acceptance_clears_the_queue_and_adopts_the_servers_time() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.enqueue_outbox(&entry("c-1", 1000), "hello").unwrap();
        client
            .complete_outbox(42, "c-1", 1000, 1_700_000_000_000)
            .unwrap();

        assert!(client.pending_outbox().unwrap().is_empty());
        let history = client.list_messages(42, 0).unwrap();
        assert_eq!(history.len(), 1, "it is not duplicated by the rewrite");
        assert_eq!(history[0].status, MessageStatus::Sent);
        assert_eq!(history[0].created_at, 1_700_000_000_000);
        assert_eq!(history[0].text, "hello", "the text survives the move");
    }

    /// A failed attempt is counted, not punished: the message stays queued,
    /// because a queue that drops messages is the thing being fixed.
    #[test]
    fn a_failed_attempt_leaves_the_message_queued() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.enqueue_outbox(&entry("c-1", 1000), "hello").unwrap();

        assert!(client.note_outbox_attempt("c-1", 1000).unwrap());
        assert!(client.note_outbox_attempt("c-1", 1000).unwrap());

        let queued = client.pending_outbox().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].attempts, 2);
        assert_eq!(
            client.list_messages(42, 0).unwrap()[0].status,
            MessageStatus::Pending,
            "still pending, never failed"
        );
    }

    /// Noting an attempt against something already accepted must not put it
    /// back: a reply that arrives after the queue was cleared is ordinary.
    #[test]
    fn noting_an_attempt_on_an_accepted_message_does_nothing() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.enqueue_outbox(&entry("c-1", 1000), "hello").unwrap();
        client.complete_outbox(42, "c-1", 1000, 2000).unwrap();

        assert!(!client.note_outbox_attempt("c-1", 1000).unwrap());
        assert!(client.pending_outbox().unwrap().is_empty());
    }
}

mod revisions {
    use super::*;
    use sdk::{MessageStatus, Revision, StoredMessage};

    const CHAT: i64 = 42;
    const PEER: i64 = 7;

    fn message(client_msg_id: &str, outgoing: bool, text: &str) -> StoredMessage {
        StoredMessage {
            chat_id: CHAT,
            peer_user_id: PEER,
            outgoing,
            client_msg_id: client_msg_id.to_string(),
            text: text.to_string(),
            created_at: 1_000,
            status: MessageStatus::Sent,
            reply_to: None,
            forwarded_from: None,
            forwarded_at: None,
            edited_at: None,
            deleted_at: None,
        }
    }

    fn only(client: &NotegramClient<MemoryBackend>) -> StoredMessage {
        let all = client.list_messages(CHAT, 0).unwrap();
        assert_eq!(all.len(), 1, "expected exactly one message");
        all.into_iter().next().unwrap()
    }

    #[test]
    fn an_author_can_rewrite_their_own_message() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.save_message(&message("m-1", true, "frist")).unwrap();

        assert!(client
            .apply_edit(CHAT, "m-1", "first", 2_000, None)
            .unwrap());
        let msg = only(&client);
        assert_eq!(msg.text, "first");
        assert_eq!(msg.edited_at, Some(2_000));
    }

    /// The rule that matters most. Without it a peer could rewrite words in
    /// your history that you wrote — a worse power than being able to send you
    /// anything at all.
    #[test]
    fn a_peer_cannot_rewrite_a_message_you_wrote() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client
            .save_message(&message("mine", true, "what I said"))
            .unwrap();

        let refused = client.apply_edit(CHAT, "mine", "what they claim", 2_000, Some(PEER));
        assert!(
            refused.is_err(),
            "an edit from a peer must not touch your own message"
        );
        assert_eq!(only(&client).text, "what I said");
    }

    /// And the mirror: this device may not rewrite what the peer wrote either.
    #[test]
    fn you_cannot_rewrite_a_message_the_peer_wrote() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client
            .save_message(&message("theirs", false, "their words"))
            .unwrap();

        assert!(client
            .apply_edit(CHAT, "theirs", "not their words", 2_000, None)
            .is_err());
        assert_eq!(only(&client).text, "their words");
    }

    #[test]
    fn a_peer_can_rewrite_their_own_message() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client
            .save_message(&message("theirs", false, "typo"))
            .unwrap();

        assert!(client
            .apply_edit(CHAT, "theirs", "fixed", 2_000, Some(PEER))
            .unwrap());
        assert_eq!(only(&client).text, "fixed");
    }

    /// A tombstone, not a removal: the row stays so a redelivered envelope
    /// cannot quietly bring the message back, and the words go so nothing is
    /// kept of what the author withdrew.
    #[test]
    fn deleting_clears_the_words_and_leaves_a_tombstone() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client
            .save_message(&message("m-1", true, "regrettable"))
            .unwrap();

        assert!(client.apply_delete(CHAT, "m-1", 3_000, None).unwrap());
        let msg = only(&client);
        assert_eq!(msg.text, "");
        assert_eq!(msg.deleted_at, Some(3_000));
    }

    #[test]
    fn a_deleted_message_cannot_be_edited_back_into_existence() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.save_message(&message("m-1", true, "gone")).unwrap();
        client.apply_delete(CHAT, "m-1", 3_000, None).unwrap();

        assert!(client.apply_edit(CHAT, "m-1", "back", 4_000, None).unwrap());
        let msg = only(&client);
        assert_eq!(msg.text, "", "a deletion is final");
        assert_eq!(msg.deleted_at, Some(3_000));
    }

    /// Instructions can arrive out of order; the older one must not win.
    #[test]
    fn a_late_edit_does_not_undo_a_newer_one() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();
        client.save_message(&message("m-1", true, "v1")).unwrap();

        client.apply_edit(CHAT, "m-1", "v3", 3_000, None).unwrap();
        client.apply_edit(CHAT, "m-1", "v2", 2_000, None).unwrap();
        assert_eq!(only(&client).text, "v3");
    }

    /// An edit can overtake the message it edits. Dropping it would leave the
    /// reader on text the author has already changed, permanently.
    #[test]
    fn an_edit_that_arrives_first_is_held_and_applied_later() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();

        let held = Revision::Edit {
            target: "m-1".to_string(),
            text: "corrected".to_string(),
            at: 2_000,
        };
        assert!(!client.apply_revision(CHAT, &held, Some(PEER)).unwrap());

        // Now the message itself lands.
        client
            .save_message(&message("m-1", false, "original"))
            .unwrap();
        assert_eq!(client.apply_pending_revisions().unwrap(), 1);
        assert_eq!(only(&client).text, "corrected");

        // And the queue is empty rather than replaying forever.
        assert_eq!(client.apply_pending_revisions().unwrap(), 0);
    }

    #[test]
    fn a_delete_that_arrives_first_is_held_and_applied_later() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();

        let held = Revision::Delete {
            target: "m-1".to_string(),
            at: 2_000,
        };
        assert!(!client.apply_revision(CHAT, &held, Some(PEER)).unwrap());

        client
            .save_message(&message("m-1", false, "arrives late"))
            .unwrap();
        assert_eq!(client.apply_pending_revisions().unwrap(), 1);
        assert_eq!(only(&client).text, "");
        assert!(only(&client).deleted_at.is_some());
    }

    /// A held instruction that turns out to name someone else's message is
    /// dropped rather than retried on every batch forever.
    #[test]
    fn a_held_instruction_for_a_message_it_may_not_touch_is_discarded() {
        let mut client = NotegramClient::open(ALICE_KEY, MemoryBackend::new()).unwrap();

        let held = Revision::Edit {
            target: "mine".to_string(),
            text: "hijacked".to_string(),
            at: 2_000,
        };
        assert!(!client.apply_revision(CHAT, &held, Some(PEER)).unwrap());

        client
            .save_message(&message("mine", true, "what I said"))
            .unwrap();
        assert_eq!(
            client.apply_pending_revisions().unwrap(),
            0,
            "refused, not applied"
        );
        assert_eq!(only(&client).text, "what I said");
        assert_eq!(
            client.apply_pending_revisions().unwrap(),
            0,
            "and not retried forever"
        );
    }
}
