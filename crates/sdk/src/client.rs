use rand_core::{OsRng, RngCore};
use ratchet::DoubleRatchet;
use store::{Backend, Namespace, SecureStore};

use crate::body::MessageBody;
use crate::identity::{Identity, PublicIdentity};
use crate::messages::{
    self, decode_revision, encode_revision, revision_key, MessageStatus, Revision, StoredMessage,
};
use crate::outbox::{self, OutboxEntry, OutboxRecipient};
use crate::session::{
    establish_inbound, establish_outbound, InboundPreKeys, PeerAddress, PreKeyBundle,
};
use crate::{Result, SdkError};

const MESSAGE_NONCE_LEN: usize = 32;

/// Id of the signed prekey currently published. Rotation bumps it, and the
/// server requires the id to strictly increase, so it has to be remembered
/// across restarts.
const SIGNED_PREKEY_ID_KEY: &[u8] = b"signed_prekey_id";

/// Id used before any rotation has happened.
const FIRST_SIGNED_PREKEY_ID: i32 = 1;

/// Next unused one-time prekey id, so top-ups never reuse an id the server may
/// still be handing out.
const ONE_TIME_PREKEY_SEQ_KEY: &[u8] = b"one_time_prekey_seq";

/// The recipient's verified prekey bundle, as returned by C2-KT's
/// `verify_peer_bundle` — required only when there is no existing outbound
/// ratchet session with this peer yet.
pub struct RecipientPreKeyBundle {
    pub identity_key: [u8; 32],
    pub signing_pub: [u8; 32],
    pub signed_prekey_id: i32,
    pub signed_prekey_pub: [u8; 32],
    pub signed_prekey_sig: [u8; 64],
    /// Id of the one-time prekey being consumed, echoed into the bootstrap
    /// contract so the recipient knows which private key to use. 0 when the
    /// peer had none left and the handshake runs without one.
    pub one_time_prekey_id: i32,
    pub one_time_prekey_pub: Option<[u8; 32]>,
}

pub struct OutgoingEnvelope {
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
}

/// An opened message plus the metadata the sender authenticated alongside it.
///
/// Everything here comes out of the associated data, which AEAD verified during
/// decryption — not out of the plaintext fields the server sends beside the
/// envelope, which it is free to lie about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMessage {
    pub body: MessageBody,
    pub chat_id: i64,
    pub client_msg_id: String,
    /// Set when this message is a reply; matches [`crate::message_ref`] of the
    /// message being answered.
    pub reply_to: Option<i64>,
}

const IDENTITY_KEY: &[u8] = b"self";

pub struct OneTimePreKeyPub {
    pub id: i32,
    pub pubkey: [u8; 32],
}

pub struct PreKeyBundleUpload {
    pub identity_key: [u8; 32],
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: [u8; 32],
    pub signed_pre_key_sig: [u8; 64],
    pub one_time_pre_keys: Vec<OneTimePreKeyPub>,
}

pub struct NotegramClient<B: Backend> {
    store: SecureStore<B>,
}

impl<B: Backend> NotegramClient<B> {
    pub fn open(master_key: &[u8], backend: B) -> Result<Self> {
        Ok(NotegramClient {
            store: SecureStore::open(master_key, backend)?,
        })
    }

    pub fn create_identity(&mut self) -> Result<PublicIdentity> {
        let identity = Identity::generate(&mut OsRng);
        self.store
            .put(Namespace::Identity, IDENTITY_KEY, &identity.serialize())?;
        Ok(identity.public())
    }

    pub fn import_identity(&mut self, identity: &Identity) -> Result<PublicIdentity> {
        self.store
            .put(Namespace::Identity, IDENTITY_KEY, &identity.serialize())?;
        Ok(identity.public())
    }

    pub fn public_identity(&self) -> Result<PublicIdentity> {
        Ok(self.load_identity()?.public())
    }

    pub fn generate_prekey_bundle(&mut self, one_time_count: u32) -> Result<PreKeyBundleUpload> {
        let identity = self.load_identity()?;
        let spk_id = FIRST_SIGNED_PREKEY_ID;
        let (spk_pub, spk_sig) = self.mint_signed_prekey(&identity, spk_id)?;
        let one_time_pre_keys = self.generate_one_time_prekeys(one_time_count)?;

        Ok(PreKeyBundleUpload {
            identity_key: identity.identity_pub,
            signed_pre_key_id: spk_id,
            signed_pre_key_pub: spk_pub,
            signed_pre_key_sig: spk_sig,
            one_time_pre_keys,
        })
    }

    /// Replaces the signed prekey with a fresh one under the next id, for when
    /// the server reports the current one is stale. Upload the result to
    /// publish it.
    ///
    /// The previous private key is deliberately kept: messages already in
    /// flight — and any the peer encrypts before it sees the new bundle — name
    /// the old id in their bootstrap contract, and dropping it would make them
    /// permanently undecryptable.
    pub fn rotate_signed_prekey(&mut self, one_time_count: u32) -> Result<PreKeyBundleUpload> {
        let identity = self.load_identity()?;
        // The server rejects an id that does not strictly increase.
        let spk_id = self
            .current_signed_prekey_id()?
            .checked_add(1)
            .ok_or(SdkError::BadKeyMaterial)?;
        let (spk_pub, spk_sig) = self.mint_signed_prekey(&identity, spk_id)?;

        Ok(PreKeyBundleUpload {
            identity_key: identity.identity_pub,
            signed_pre_key_id: spk_id,
            signed_pre_key_pub: spk_pub,
            signed_pre_key_sig: spk_sig,
            one_time_pre_keys: self.generate_one_time_prekeys(one_time_count)?,
        })
    }

    fn mint_signed_prekey(
        &mut self,
        identity: &Identity,
        spk_id: i32,
    ) -> Result<([u8; 32], [u8; 64])> {
        let (spk_priv, spk_pub) = crypto::x25519_generate(&mut OsRng);
        let spk_sig = e2ee::x3dh::sign_signed_prekey(&identity.signing_seed, &spk_pub);
        self.store
            .put(Namespace::SignedPreKey, &spk_id.to_le_bytes(), &spk_priv)?;
        self.store
            .put(Namespace::Meta, SIGNED_PREKEY_ID_KEY, &spk_id.to_le_bytes())?;
        Ok((spk_pub, spk_sig))
    }

    fn current_signed_prekey_id(&self) -> Result<i32> {
        match self.store.get(Namespace::Meta, SIGNED_PREKEY_ID_KEY)? {
            Some(raw) => {
                let bytes: [u8; 4] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| SdkError::BadKeyMaterial)?;
                Ok(i32::from_le_bytes(bytes).max(FIRST_SIGNED_PREKEY_ID))
            }
            None => Ok(FIRST_SIGNED_PREKEY_ID),
        }
    }

    /// Builds an upload that tops up one-time prekeys without disturbing the
    /// rest of the bundle. The server merges one-time keys rather than
    /// replacing them, but rejects a re-used id with a different key and a
    /// changed signed prekey under the same id — so this resends the existing
    /// signed prekey byte-for-byte (its public key and signature are both
    /// recomputed deterministically from the stored private key) and only the
    /// one-time keys are new.
    pub fn prekey_top_up(&mut self, count: u32) -> Result<PreKeyBundleUpload> {
        let identity = self.load_identity()?;
        let spk_id = self.current_signed_prekey_id()?;
        let spk_priv = self
            .store
            .get(Namespace::SignedPreKey, &spk_id.to_le_bytes())?
            .ok_or(SdkError::BadKeyMaterial)?;
        let spk_priv: [u8; 32] = spk_priv
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::BadKeyMaterial)?;
        let spk_pub = crypto::x25519_public(&spk_priv);
        let spk_sig = e2ee::x3dh::sign_signed_prekey(&identity.signing_seed, &spk_pub);

        Ok(PreKeyBundleUpload {
            identity_key: identity.identity_pub,
            signed_pre_key_id: spk_id,
            signed_pre_key_pub: spk_pub,
            signed_pre_key_sig: spk_sig,
            one_time_pre_keys: self.generate_one_time_prekeys(count)?,
        })
    }

    /// Mints more one-time prekeys, continuing the id sequence. Each is handed
    /// out once and then deleted, so a device runs out after enough sessions and
    /// has to top up; ids must never restart, or a fresh private key would
    /// overwrite one the server still advertises and those sessions would fail
    /// to decrypt.
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> Result<Vec<OneTimePreKeyPub>> {
        let mut next_id = self.next_one_time_prekey_id()?;
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (otk_priv, otk_pub) = crypto::x25519_generate(&mut OsRng);
            self.store
                .put(Namespace::PreKey, &next_id.to_le_bytes(), &otk_priv)?;
            out.push(OneTimePreKeyPub {
                id: next_id,
                pubkey: otk_pub,
            });
            next_id += 1;
        }
        self.store.put(
            Namespace::Meta,
            ONE_TIME_PREKEY_SEQ_KEY,
            &next_id.to_le_bytes(),
        )?;
        Ok(out)
    }

    fn next_one_time_prekey_id(&self) -> Result<i32> {
        match self.store.get(Namespace::Meta, ONE_TIME_PREKEY_SEQ_KEY)? {
            Some(raw) => {
                let bytes: [u8; 4] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| SdkError::BadKeyMaterial)?;
                Ok(i32::from_le_bytes(bytes).max(1))
            }
            // Ids are 1-based: the server treats 0 as "no one-time prekey".
            None => Ok(1),
        }
    }

    pub fn into_backend(self) -> B {
        self.store.into_backend()
    }

    pub fn has_session(&self, peer: PeerAddress) -> Result<bool> {
        Ok(self
            .store
            .get(Namespace::Session, &peer.store_key())?
            .is_some())
    }

    pub fn establish_outbound_session(
        &mut self,
        peer: PeerAddress,
        bundle: &PreKeyBundle,
    ) -> Result<[u8; 32]> {
        let identity = self.load_identity()?;
        let session = establish_outbound(&identity, bundle, &mut OsRng)?;
        self.save_session(peer, &session.ratchet)?;
        Ok(session.ephemeral_pub)
    }

    pub fn establish_inbound_session(
        &mut self,
        peer: PeerAddress,
        prekeys: &InboundPreKeys,
        initiator_identity_pub: &[u8; 32],
        initiator_ephemeral_pub: &[u8; 32],
    ) -> Result<()> {
        let identity = self.load_identity()?;
        let ratchet = establish_inbound(
            &identity,
            prekeys,
            initiator_identity_pub,
            initiator_ephemeral_pub,
        );
        self.save_session(peer, &ratchet)
    }

    pub fn encrypt(
        &mut self,
        peer: PeerAddress,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ratchet = self.load_session(peer)?;
        let ciphertext = ratchet.encrypt(plaintext, associated_data)?;
        self.save_session(peer, &ratchet)?;
        Ok(ciphertext)
    }

    /// Encrypts a message for `peer` and builds the associated data + envelope
    /// header the server expects (`e2ee::binding`). Establishes a new outbound
    /// ratchet session first if one doesn't already exist, in which case
    /// `new_session_bundle` must be the peer's C2-KT-verified prekey bundle —
    /// the resulting envelope is `signal-prekey.v1` (X3DH bootstrap contract),
    /// otherwise plain `signal-message.v1`.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_message(
        &mut self,
        sender_user_id: i64,
        sender_device_id: i64,
        peer: PeerAddress,
        chat_id: i64,
        client_msg_id: &str,
        body: &MessageBody,
        new_session_bundle: Option<&RecipientPreKeyBundle>,
        reply_to: Option<i64>,
    ) -> Result<OutgoingEnvelope> {
        let identity = self.load_identity()?;
        let is_new_session = !self.has_session(peer)?;
        // The X3DH ephemeral key only exists while establishing the session, and
        // the recipient cannot derive it from anything else, so it has to be
        // captured here and carried in the bootstrap contract below.
        let mut sender_ephemeral_pub = [0u8; 32];
        if is_new_session {
            let bundle = new_session_bundle.ok_or(SdkError::NoSession)?;
            let prekey_bundle = PreKeyBundle {
                identity_pub: bundle.identity_key,
                signing_pub: bundle.signing_pub,
                signed_prekey_pub: bundle.signed_prekey_pub,
                signed_prekey_sig: bundle.signed_prekey_sig,
                one_time_prekey_pub: bundle.one_time_prekey_pub,
            };
            sender_ephemeral_pub = self.establish_outbound_session(peer, &prekey_bundle)?;
        }

        let ad_input = e2ee::AssociatedDataInput {
            schema: e2ee::SCHEMA_LIBSIGNAL_SESSION_ENVELOPE_V1.to_string(),
            suite: e2ee::MESSAGE_SUITE_LIBSIGNAL_X3DH_DV1.to_string(),
            crypto_policy_profile: e2ee::CRYPTO_POLICY_PROFILE.to_string(),
            crypto_policy_version: e2ee::CRYPTO_POLICY_VERSION,
            crypto_policy_sha256: e2ee::CRYPTO_POLICY_SHA256_HEX.to_string(),
            sender_user_id,
            sender_device_id,
            chat_id,
            client_msg_id: client_msg_id.to_string(),
            forward_info: Vec::new(),
            // Inside the associated data, so the AEAD tag covers it: a relay
            // cannot retarget the reply at a different message without breaking
            // decryption outright.
            reply_to,
        };
        let associated_data = e2ee::build_associated_data_v1(&ad_input);

        let ciphertext = self.encrypt(peer, &body.encode(), &associated_data)?;

        let mut message_nonce = [0u8; MESSAGE_NONCE_LEN];
        OsRng.fill_bytes(&mut message_nonce);

        let envelope_type = if is_new_session {
            e2ee::ENVELOPE_TYPE_SIGNAL_PREKEY_V1
        } else {
            e2ee::ENVELOPE_TYPE_SIGNAL_V1
        };
        let header_input = e2ee::EnvelopeHeaderInput {
            ad: ad_input,
            recipient_user_id: peer.user_id,
            recipient_device_id: peer.device_id,
            envelope_type: envelope_type.to_string(),
        };

        let header = if is_new_session {
            let bundle = new_session_bundle.expect("checked above");
            let bootstrap = e2ee::SignalBootstrapInput {
                suite: e2ee::MESSAGE_SUITE_LIBSIGNAL_X3DH_DV1.to_string(),
                envelope_type: envelope_type.to_string(),
                recipient_user_id: peer.user_id,
                recipient_device_id: peer.device_id,
                recipient_identity_key: bundle.identity_key.to_vec(),
                recipient_signed_pre_key_id: bundle.signed_prekey_id,
                recipient_signed_pre_key_pub: bundle.signed_prekey_pub.to_vec(),
                recipient_signed_pre_key_sig: bundle.signed_prekey_sig.to_vec(),
                recipient_one_time_pre_key_id: bundle.one_time_prekey_id,
                sender_identity_key: identity.identity_pub.to_vec(),
                sender_ephemeral_key: sender_ephemeral_pub.to_vec(),
            };
            e2ee::build_envelope_header_v3(
                &header_input,
                &associated_data,
                &ciphertext,
                &message_nonce,
                &bootstrap,
            )
        } else {
            e2ee::build_envelope_header_v2(
                &header_input,
                &associated_data,
                &ciphertext,
                &message_nonce,
            )
        };

        Ok(OutgoingEnvelope {
            envelope_type: envelope_type.to_string(),
            header,
            ciphertext,
            associated_data,
        })
    }

    /// Opens an incoming message. For a `signal-prekey.v1` envelope this first
    /// establishes the inbound session from the header's bootstrap contract,
    /// using the private prekeys named there from the local store, then
    /// decrypts. The consumed one-time prekey is deleted afterwards: reusing it
    /// would break forward secrecy.
    ///
    /// The returned metadata is read back out of the associated data, which
    /// decryption has just authenticated, and is checked against the sender the
    /// server named — so a server that re-attributes someone else's ciphertext
    /// is rejected rather than displayed under the wrong name.
    pub fn decrypt_message(
        &mut self,
        peer: PeerAddress,
        envelope_type: &str,
        header: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<IncomingMessage> {
        let plaintext =
            self.open_envelope(peer, envelope_type, header, ciphertext, associated_data)?;
        let body = MessageBody::decode(&plaintext);

        let ad =
            e2ee::parse_associated_data(associated_data).ok_or(SdkError::MisattributedMessage)?;
        if ad.sender_user_id != peer.user_id || ad.sender_device_id != peer.device_id {
            return Err(SdkError::MisattributedMessage);
        }
        Ok(IncomingMessage {
            body,
            chat_id: ad.chat_id,
            client_msg_id: ad.client_msg_id,
            reply_to: ad.reply_to,
        })
    }

    fn open_envelope(
        &mut self,
        peer: PeerAddress,
        envelope_type: &str,
        header: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if envelope_type != e2ee::ENVELOPE_TYPE_SIGNAL_PREKEY_V1 {
            return self.decrypt(peer, ciphertext, associated_data);
        }

        // A prekey envelope may still arrive for a session we already have (for
        // example a redelivery that was never acked), so try the existing
        // session first and only rebuild it if that fails.
        if self.has_session(peer)? {
            if let Ok(plaintext) = self.decrypt(peer, ciphertext, associated_data) {
                return Ok(plaintext);
            }
        }

        let bootstrap = e2ee::parse_signal_bootstrap(header).ok_or(SdkError::BadKeyMaterial)?;

        let signed_prekey_priv = self
            .store
            .get(
                Namespace::SignedPreKey,
                &bootstrap.recipient_signed_pre_key_id.to_le_bytes(),
            )?
            .ok_or(SdkError::BadKeyMaterial)?;
        let signed_prekey_priv: [u8; 32] = signed_prekey_priv
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::BadKeyMaterial)?;

        let one_time_key = bootstrap.recipient_one_time_pre_key_id;
        let one_time_priv = if one_time_key > 0 {
            let raw = self
                .store
                .get(Namespace::PreKey, &one_time_key.to_le_bytes())?
                .ok_or(SdkError::BadKeyMaterial)?;
            let key: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| SdkError::BadKeyMaterial)?;
            Some(key)
        } else {
            None
        };

        self.establish_inbound_session(
            peer,
            &InboundPreKeys {
                signed_prekey_priv: &signed_prekey_priv,
                one_time_prekey_priv: one_time_priv.as_ref(),
            },
            &bootstrap.sender_identity_key,
            &bootstrap.sender_ephemeral_key,
        )?;

        let plaintext = self.decrypt(peer, ciphertext, associated_data)?;
        if one_time_key > 0 {
            self.store
                .delete(Namespace::PreKey, &one_time_key.to_le_bytes())?;
        }
        Ok(plaintext)
    }

    pub fn decrypt(
        &mut self,
        peer: PeerAddress,
        message: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ratchet = self.load_session(peer)?;
        let plaintext = ratchet.decrypt(message, associated_data, &mut OsRng)?;
        self.save_session(peer, &ratchet)?;
        Ok(plaintext)
    }

    /// Records a message in local history. Writing the same `client_msg_id`
    /// again overwrites that row, so a redelivered message cannot duplicate.
    pub fn save_message(&mut self, msg: &StoredMessage) -> Result<()> {
        let key = messages::message_key(msg.chat_id, msg.created_at, &msg.client_msg_id);
        self.store
            .put(Namespace::Message, &key, &messages::encode_message(msg))?;
        Ok(())
    }

    /// Messages of one chat, oldest first. `limit` keeps the newest ones when
    /// the history is longer.
    pub fn list_messages(&self, chat_id: i64, limit: u32) -> Result<Vec<StoredMessage>> {
        let prefix = messages::chat_key_prefix(chat_id);
        let mut out = Vec::new();
        for (key, value) in self.store.list(Namespace::Message)? {
            if !key.starts_with(&prefix) {
                continue;
            }
            out.push(messages::decode_message(&value)?);
        }
        out.sort_by_key(|m| (m.created_at, m.client_msg_id.clone()));
        if limit > 0 && out.len() > limit as usize {
            out.drain(..out.len() - limit as usize);
        }
        Ok(out)
    }

    /// Advances the delivery status of an outgoing message, matched by the id
    /// the sender chose. Status only moves forward, so notices arriving out of
    /// order (a delivery receipt after a read receipt) cannot regress it.
    /// Returns whether anything changed.
    pub fn mark_message_status(
        &mut self,
        chat_id: i64,
        client_msg_id: &str,
        status: MessageStatus,
    ) -> Result<bool> {
        let prefix = messages::chat_key_prefix(chat_id);
        for (key, value) in self.store.list(Namespace::Message)? {
            if !key.starts_with(&prefix) {
                continue;
            }
            let mut msg = messages::decode_message(&value)?;
            if msg.client_msg_id != client_msg_id || !msg.outgoing {
                continue;
            }
            if !messages::status_advances(msg.status, status) {
                return Ok(false);
            }
            msg.status = status;
            self.store
                .put(Namespace::Message, &key, &messages::encode_message(&msg))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Applies a read receipt: every message we sent in this chat at or before
    /// `up_to_created_at` becomes `Read`. Returns how many rows changed.
    ///
    /// A watermark rather than a list of ids, so one receipt settles a whole
    /// backlog and re-delivering the same receipt changes nothing — the
    /// forward-only status guard makes it idempotent.
    pub fn mark_read_up_to(&mut self, chat_id: i64, up_to_created_at: i64) -> Result<u32> {
        let prefix = messages::chat_key_prefix(chat_id);
        let mut changed = 0;
        for (key, value) in self.store.list(Namespace::Message)? {
            if !key.starts_with(&prefix) {
                continue;
            }
            let mut msg = messages::decode_message(&value)?;
            if !msg.outgoing || msg.created_at > up_to_created_at {
                continue;
            }
            if !messages::status_advances(msg.status, MessageStatus::Read) {
                continue;
            }
            msg.status = MessageStatus::Read;
            self.store
                .put(Namespace::Message, &key, &messages::encode_message(&msg))?;
            changed += 1;
        }
        Ok(changed)
    }

    /// Our own messages that have not been confirmed delivered yet, newest
    /// first, as (chat_id, client_msg_id).
    ///
    /// The server pushes a delivery notice once; this is what lets the client
    /// ask about the ones it may have missed while the link was down.
    pub fn undelivered_messages(&self, limit: u32) -> Result<Vec<(i64, String)>> {
        let mut out: Vec<StoredMessage> = Vec::new();
        for (_, value) in self.store.list(Namespace::Message)? {
            let msg = messages::decode_message(&value)?;
            if msg.outgoing && msg.status == MessageStatus::Sent {
                out.push(msg);
            }
        }
        out.sort_by_key(|m| std::cmp::Reverse(m.created_at));
        out.truncate(limit as usize);
        Ok(out
            .into_iter()
            .map(|m| (m.chat_id, m.client_msg_id))
            .collect())
    }

    /// Records a message that is ready to send but has not been accepted yet,
    /// and puts it in local history as [`MessageStatus::Pending`] in the same
    /// step.
    ///
    /// Both halves matter. The history row is what the user sees, so writing it
    /// here rather than after the server answers is what makes a message
    /// survive a lost network and a restart. The queue entry carries the
    /// envelope, so the retry sends the same bytes rather than encrypting
    /// again — the server deduplicates on the client id and rejects a second
    /// attempt whose contents differ, which is exactly what a fresh encryption
    /// would be.
    pub fn enqueue_outbox(&mut self, entry: &OutboxEntry, text: &str) -> Result<()> {
        let message = StoredMessage {
            chat_id: entry.chat_id,
            peer_user_id: entry.peer_user_id,
            outgoing: true,
            client_msg_id: entry.client_msg_id.clone(),
            text: text.to_string(),
            created_at: entry.created_at,
            status: MessageStatus::Pending,
            reply_to: entry.reply_to,
            forwarded_from: None,
            forwarded_at: None,
            edited_at: None,
            deleted_at: None,
        };
        self.save_message(&message)?;
        self.store.put(
            Namespace::Outbox,
            &outbox::outbox_key(entry.created_at, &entry.client_msg_id),
            &outbox::encode_entry(entry),
        )?;
        Ok(())
    }

    /// Attaches the encrypted copies to a message that was queued before it
    /// could be encrypted, leaving everything else about it alone.
    ///
    /// Used for the first message to a peer sent while offline: the text was
    /// recorded straight away so it could not be lost, and the envelopes are
    /// built once there is a link to fetch the recipient's bundle over.
    pub fn attach_outbox_envelopes(
        &mut self,
        client_msg_id: &str,
        queued_at: i64,
        recipients: Vec<OutboxRecipient>,
        associated_data: Vec<u8>,
    ) -> Result<bool> {
        let key = outbox::outbox_key(queued_at, client_msg_id);
        let Some(raw) = self.store.get(Namespace::Outbox, &key)? else {
            return Ok(false);
        };
        let mut entry = outbox::decode_entry(&raw)?;
        entry.recipients = recipients;
        entry.associated_data = associated_data;
        self.store
            .put(Namespace::Outbox, &key, &outbox::encode_entry(&entry))?;
        Ok(true)
    }

    /// Rewrites a message the author has edited.
    ///
    /// `from_peer` is who the instruction came from, taken from the AEAD
    /// associated data rather than from anything the server said: `None` means
    /// this device wrote it. **An edit may only touch a message from the same
    /// author** — without that rule a peer could rewrite words in your history
    /// that you wrote, which is a worse power than being able to send you
    /// anything.
    ///
    /// A deleted message stays deleted: an edit naming it is ignored rather
    /// than bringing it back.
    ///
    /// Returns false when the target is not here yet — the caller keeps the
    /// instruction and offers it again, since an edit that arrives before the
    /// message it edits must not be the one thing that gets lost.
    pub fn apply_edit(
        &mut self,
        chat_id: i64,
        target_client_msg_id: &str,
        text: &str,
        edited_at: i64,
        from_peer: Option<i64>,
    ) -> Result<bool> {
        let Some((key, mut msg)) = self.find_message(chat_id, target_client_msg_id)? else {
            return Ok(false);
        };
        if !Self::may_revise(&msg, from_peer) {
            return Err(SdkError::MisattributedMessage);
        }
        // Deletion is final; and a late edit must not undo a later one.
        if msg.deleted_at.is_some() || msg.edited_at.is_some_and(|prev| prev >= edited_at) {
            return Ok(true);
        }
        msg.text = text.to_string();
        msg.edited_at = Some(edited_at);
        self.store
            .put(Namespace::Message, &key, &messages::encode_message(&msg))?;
        Ok(true)
    }

    /// Withdraws a message its author deleted, keeping the row as a tombstone
    /// with its words cleared. Same authorship rule as [`Self::apply_edit`].
    ///
    /// Returns false when the target is not here yet, for the same reason.
    pub fn apply_delete(
        &mut self,
        chat_id: i64,
        target_client_msg_id: &str,
        deleted_at: i64,
        from_peer: Option<i64>,
    ) -> Result<bool> {
        let Some((key, mut msg)) = self.find_message(chat_id, target_client_msg_id)? else {
            return Ok(false);
        };
        if !Self::may_revise(&msg, from_peer) {
            return Err(SdkError::MisattributedMessage);
        }
        if msg.deleted_at.is_some() {
            return Ok(true);
        }
        // The words go, not just a flag: keeping the text of something the
        // author withdrew is exactly what a deletion is for.
        msg.text = String::new();
        msg.deleted_at = Some(deleted_at);
        self.store
            .put(Namespace::Message, &key, &messages::encode_message(&msg))?;
        Ok(true)
    }

    /// Applies an edit or delete, holding on to it if its target has not
    /// arrived yet.
    ///
    /// An instruction can overtake the message it refers to — a page that
    /// failed to decrypt, a peer with two devices — and simply dropping it
    /// would leave the reader looking at words the author has already changed
    /// or withdrawn, permanently and invisibly. Held instructions are retried
    /// by [`Self::apply_pending_revisions`] whenever new messages land.
    pub fn apply_revision(
        &mut self,
        chat_id: i64,
        revision: &Revision,
        from_peer: Option<i64>,
    ) -> Result<bool> {
        let applied = match revision {
            Revision::Edit { target, text, at } => {
                self.apply_edit(chat_id, target, text, *at, from_peer)?
            }
            Revision::Delete { target, at } => {
                self.apply_delete(chat_id, target, *at, from_peer)?
            }
        };
        if !applied {
            self.store.put(
                Namespace::PendingRevision,
                &revision_key(chat_id, revision.target()),
                &encode_revision(chat_id, revision, from_peer),
            )?;
        }
        Ok(applied)
    }

    /// Retries held instructions now that more messages are in. Returns how
    /// many finally applied.
    ///
    /// Cheap when there is nothing waiting, which is the normal case, so this
    /// can run after every batch.
    pub fn apply_pending_revisions(&mut self) -> Result<u32> {
        let held = self.store.list(Namespace::PendingRevision)?;
        if held.is_empty() {
            return Ok(0);
        }
        let mut applied = 0;
        for (key, value) in held {
            let (chat_id, revision, from_peer) = decode_revision(&value)?;
            // A rejected instruction — one that named someone else's message —
            // is dropped rather than retried forever.
            let outcome = self.apply_revision_once(chat_id, &revision, from_peer);
            match outcome {
                Ok(true) | Err(_) => {
                    self.store.delete(Namespace::PendingRevision, &key)?;
                    if outcome.is_ok() {
                        applied += 1;
                    }
                }
                Ok(false) => {}
            }
        }
        Ok(applied)
    }

    fn apply_revision_once(
        &mut self,
        chat_id: i64,
        revision: &Revision,
        from_peer: Option<i64>,
    ) -> Result<bool> {
        match revision {
            Revision::Edit { target, text, at } => {
                self.apply_edit(chat_id, target, text, *at, from_peer)
            }
            Revision::Delete { target, at } => self.apply_delete(chat_id, target, *at, from_peer),
        }
    }

    /// Whether an instruction from `from_peer` is allowed to change `msg`.
    ///
    /// Only its author may: this device for its own outgoing messages, and a
    /// peer only for messages that came from that same peer.
    fn may_revise(msg: &StoredMessage, from_peer: Option<i64>) -> bool {
        match from_peer {
            None => msg.outgoing,
            Some(peer) => !msg.outgoing && msg.peer_user_id == peer,
        }
    }

    fn find_message(
        &self,
        chat_id: i64,
        client_msg_id: &str,
    ) -> Result<Option<(Vec<u8>, StoredMessage)>> {
        let prefix = messages::chat_key_prefix(chat_id);
        for (key, value) in self.store.list(Namespace::Message)? {
            if !key.starts_with(&prefix) {
                continue;
            }
            let msg = messages::decode_message(&value)?;
            if msg.client_msg_id == client_msg_id {
                return Ok(Some((key, msg)));
            }
        }
        Ok(None)
    }

    /// One message of a chat by the id its sender chose, for a caller that has
    /// the id and needs what was written down under it.
    pub fn message_by_client_id(
        &self,
        chat_id: i64,
        client_msg_id: &str,
    ) -> Result<Option<StoredMessage>> {
        let prefix = messages::chat_key_prefix(chat_id);
        for (key, value) in self.store.list(Namespace::Message)? {
            if !key.starts_with(&prefix) {
                continue;
            }
            let msg = messages::decode_message(&value)?;
            if msg.client_msg_id == client_msg_id {
                return Ok(Some(msg));
            }
        }
        Ok(None)
    }

    /// Queues an already-encrypted instruction — an edit or a deletion — with
    /// no row of its own in history.
    ///
    /// It has to be delivered as reliably as a message, so it belongs in the
    /// queue; but it is a change to a message that already exists rather than
    /// a new one, so it must never appear in the transcript. The envelopes are
    /// supplied because an instruction is encrypted before it is queued: there
    /// is no history row to rebuild its body from later.
    pub fn enqueue_outbox_instruction(&mut self, entry: &OutboxEntry) -> Result<()> {
        self.store.put(
            Namespace::Outbox,
            &outbox::outbox_key(entry.created_at, &entry.client_msg_id),
            &outbox::encode_entry(entry),
        )?;
        Ok(())
    }

    /// Everything still waiting, oldest first.
    ///
    /// The order is the order the user typed in, and a caller must send them in
    /// it: delivering a chat's messages out of order rearranges the
    /// conversation for the recipient, and nothing later undoes that.
    pub fn pending_outbox(&self) -> Result<Vec<OutboxEntry>> {
        let mut out = Vec::new();
        for (_, value) in self.store.list(Namespace::Outbox)? {
            out.push(outbox::decode_entry(&value)?);
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.client_msg_id.cmp(&b.client_msg_id))
        });
        Ok(out)
    }

    /// Marks a queued message as accepted: it leaves the queue and its history
    /// row moves to [`MessageStatus::Sent`].
    ///
    /// `created_at` is the server's, which is what every other device will show
    /// it under; the local row is rewritten under that time so the ordering
    /// agrees with the recipient's.
    pub fn complete_outbox(
        &mut self,
        chat_id: i64,
        client_msg_id: &str,
        queued_at: i64,
        server_created_at: i64,
    ) -> Result<()> {
        self.store.delete(
            Namespace::Outbox,
            &outbox::outbox_key(queued_at, client_msg_id),
        )?;
        // Rewritten rather than status-bumped in place: the row is keyed by
        // creation time, so adopting the server's means moving it.
        let old_key = messages::message_key(chat_id, queued_at, client_msg_id);
        if let Some(raw) = self.store.get(Namespace::Message, &old_key)? {
            let mut msg = messages::decode_message(&raw)?;
            msg.created_at = server_created_at;
            msg.status = MessageStatus::Sent;
            self.store.delete(Namespace::Message, &old_key)?;
            self.save_message(&msg)?;
        }
        Ok(())
    }

    /// Records that an attempt was made and did not land. The entry stays: a
    /// message leaves the queue only when the server has it.
    pub fn note_outbox_attempt(&mut self, client_msg_id: &str, queued_at: i64) -> Result<bool> {
        let key = outbox::outbox_key(queued_at, client_msg_id);
        let Some(raw) = self.store.get(Namespace::Outbox, &key)? else {
            return Ok(false);
        };
        let mut entry = outbox::decode_entry(&raw)?;
        entry.attempts = entry.attempts.saturating_add(1);
        self.store
            .put(Namespace::Outbox, &key, &outbox::encode_entry(&entry))?;
        Ok(true)
    }

    /// Drops a queued message the recipient roster has outgrown.
    ///
    /// The stored envelope is addressed to the devices a peer had when it was
    /// encrypted; once they gain one, the server refuses the fan-out as
    /// incomplete and no number of retries will change that. The caller
    /// re-encrypts against a fresh roster and queues again under the same
    /// client id — safe precisely because the refused attempt was never stored.
    pub fn discard_outbox(&mut self, client_msg_id: &str, queued_at: i64) -> Result<()> {
        self.store.delete(
            Namespace::Outbox,
            &outbox::outbox_key(queued_at, client_msg_id),
        )?;
        Ok(())
    }

    /// The most recent message of every chat, newest chat first — enough to
    /// render a chat list without loading full histories.
    pub fn list_chat_previews(&self) -> Result<Vec<StoredMessage>> {
        let mut latest: Vec<StoredMessage> = Vec::new();
        for (_, value) in self.store.list(Namespace::Message)? {
            let msg = messages::decode_message(&value)?;
            match latest.iter_mut().find(|m| m.chat_id == msg.chat_id) {
                Some(existing) if msg.created_at > existing.created_at => *existing = msg,
                Some(_) => {}
                None => latest.push(msg),
            }
        }
        latest.sort_by_key(|m| std::cmp::Reverse(m.created_at));
        Ok(latest)
    }

    fn load_identity(&self) -> Result<Identity> {
        match self.store.get(Namespace::Identity, IDENTITY_KEY)? {
            None => Err(SdkError::NoIdentity),
            Some(bytes) => Identity::deserialize(&bytes),
        }
    }

    fn load_session(&self, peer: PeerAddress) -> Result<DoubleRatchet> {
        match self.store.get(Namespace::Session, &peer.store_key())? {
            None => Err(SdkError::NoSession),
            Some(bytes) => Ok(DoubleRatchet::deserialize(&bytes)?),
        }
    }

    fn save_session(&mut self, peer: PeerAddress, ratchet: &DoubleRatchet) -> Result<()> {
        self.store
            .put(Namespace::Session, &peer.store_key(), &ratchet.serialize())?;
        Ok(())
    }
}
