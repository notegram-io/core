use rand_core::{OsRng, RngCore};
use ratchet::DoubleRatchet;
use store::{Backend, Namespace, SecureStore};

use crate::identity::{Identity, PublicIdentity};
use crate::messages::{self, StoredMessage};
use crate::session::{
    establish_inbound, establish_outbound, InboundPreKeys, PeerAddress, PreKeyBundle,
};
use crate::{Result, SdkError};

const MESSAGE_NONCE_LEN: usize = 32;

/// The device publishes a single signed prekey; rotation is not implemented yet.
const SIGNED_PREKEY_ID: i32 = 1;

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
        let (spk_priv, spk_pub) = crypto::x25519_generate(&mut OsRng);
        let spk_id = SIGNED_PREKEY_ID;
        let spk_sig = e2ee::x3dh::sign_signed_prekey(&identity.signing_seed, &spk_pub);
        self.store
            .put(Namespace::SignedPreKey, &spk_id.to_le_bytes(), &spk_priv)?;

        let one_time_pre_keys = self.generate_one_time_prekeys(one_time_count)?;

        Ok(PreKeyBundleUpload {
            identity_key: identity.identity_pub,
            signed_pre_key_id: spk_id,
            signed_pre_key_pub: spk_pub,
            signed_pre_key_sig: spk_sig,
            one_time_pre_keys,
        })
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
        let spk_id = SIGNED_PREKEY_ID;
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
        plaintext: &[u8],
        new_session_bundle: Option<&RecipientPreKeyBundle>,
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
            reply_to: None,
        };
        let associated_data = e2ee::build_associated_data_v1(&ad_input);

        let ciphertext = self.encrypt(peer, plaintext, &associated_data)?;

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
    pub fn decrypt_message(
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

        let bootstrap =
            e2ee::parse_signal_bootstrap(header).ok_or(SdkError::BadKeyMaterial)?;

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
