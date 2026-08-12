use std::sync::Mutex;

use crate::{
    message_ref as sdk_message_ref, Identity, InboundPreKeys, MessageBody, MessageStatus,
    NotegramClient, OutboxEntry, OutboxRecipient, PeerAddress, PreKeyBundle, PublicIdentity,
    RecipientPreKeyBundle, SdkError, StoredMessage,
};
use store::SqliteBackend;

#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    Store,
    Session,
    NoSession,
    BadPrekeySignature,
    BadKeyMaterial,
    NoIdentity,

    /// The sender named by the server is not the sender the message itself
    /// authenticates. The message must not be shown.
    MisattributedMessage,

    BadInput,

    UntrustedPeerBundleProof(String),
}

impl core::fmt::Display for FfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FfiError::Store => write!(f, "notegram: store error"),
            FfiError::Session => write!(f, "notegram: session error"),
            FfiError::NoSession => write!(f, "notegram: no session for peer"),
            FfiError::BadPrekeySignature => write!(f, "notegram: signed prekey signature invalid"),
            FfiError::BadKeyMaterial => write!(f, "notegram: malformed key material"),
            FfiError::NoIdentity => write!(f, "notegram: no local identity"),
            FfiError::MisattributedMessage => {
                write!(f, "notegram: message does not match its claimed sender")
            }
            FfiError::BadInput => write!(f, "notegram: argument had wrong length"),
            FfiError::UntrustedPeerBundleProof(w) => {
                write!(f, "notegram: peer bundle proof rejected: {w}")
            }
        }
    }
}

impl std::error::Error for FfiError {}

impl From<SdkError> for FfiError {
    fn from(e: SdkError) -> Self {
        match e {
            SdkError::Store(_) => FfiError::Store,
            SdkError::Session(_) => FfiError::Session,
            SdkError::NoSession => FfiError::NoSession,
            SdkError::BadPrekeySignature => FfiError::BadPrekeySignature,
            SdkError::BadKeyMaterial => FfiError::BadKeyMaterial,
            SdkError::NoIdentity => FfiError::NoIdentity,
            SdkError::MisattributedMessage => FfiError::MisattributedMessage,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiPeerAddress {
    pub user_id: i64,
    pub device_id: i64,
}

impl From<FfiPeerAddress> for PeerAddress {
    fn from(a: FfiPeerAddress) -> Self {
        PeerAddress {
            user_id: a.user_id,
            device_id: a.device_id,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiPublicIdentity {
    pub identity_pub: Vec<u8>,
    pub signing_pub: Vec<u8>,
    pub registration_id: u32,
}

impl From<PublicIdentity> for FfiPublicIdentity {
    fn from(p: PublicIdentity) -> Self {
        FfiPublicIdentity {
            identity_pub: p.identity_pub.to_vec(),
            signing_pub: p.signing_pub.to_vec(),
            registration_id: p.registration_id,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiPreKeyBundle {
    pub identity_pub: Vec<u8>,
    pub signing_pub: Vec<u8>,
    pub signed_prekey_pub: Vec<u8>,
    pub signed_prekey_sig: Vec<u8>,
    pub one_time_prekey_pub: Option<Vec<u8>>,
}

/// The recipient's C2-KT-verified prekey bundle — build from
/// `NotegramCore.verify_peer_bundle`'s result. Only needed when there is no
/// existing outbound ratchet session with this peer yet.
#[derive(uniffi::Record)]
pub struct FfiRecipientPreKeyBundle {
    pub identity_key: Vec<u8>,
    pub signing_pub: Vec<u8>,
    pub signed_prekey_id: i32,
    pub signed_prekey_pub: Vec<u8>,
    pub signed_prekey_sig: Vec<u8>,
    pub one_time_prekey_id: i32,
    pub one_time_prekey_pub: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct FfiOutgoingEnvelope {
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
}

/// Trust anchors the app pins for key-transparency verification (analogous to
/// how `server_ed_pub` is supplied by the caller of `NetSession::connect`
/// rather than hardcoded in `core`).
#[derive(uniffi::Record)]
pub struct FfiKeyTransparencyTrust {
    pub signing_public_keys: Vec<Vec<u8>>,
    pub witness_public_keys: Vec<Vec<u8>>,
    pub min_witness_signatures: u32,
}

/// A peer's prekey bundle after its `PrekeyBundleProof` (device-level key
/// transparency chain: receipt signature, checkpoint hash-chain, consistency
/// proof, witness signatures) has been fully verified and the device's
/// trusted signing key extracted, and the signed-prekey signature checked
/// against it. Safe to feed into `establish_outbound_session`.
#[derive(uniffi::Record)]
pub struct FfiVerifiedPrekeyBundle {
    pub user_id: i64,
    pub device_id: i64,
    pub identity_key: Vec<u8>,
    pub device_signing_key: Vec<u8>,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: Vec<u8>,
    pub signed_pre_key_sig: Vec<u8>,
    pub one_time_pre_key_id: i32,
    pub one_time_pre_key_pub: Option<Vec<u8>>,
}

/// One recipient device and the envelope encrypted for it.
#[derive(uniffi::Record)]
pub struct FfiOutboxRecipient {
    pub user_id: i64,
    pub device_id: i64,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A message written down and waiting for the server to take it.
///
/// It carries the finished envelope rather than the text to encrypt again: the
/// server deduplicates on `client_msg_id` and refuses a second attempt whose
/// contents differ, and encrypting again would produce exactly that, since the
/// ratchet advances every time.
#[derive(uniffi::Record)]
pub struct FfiOutboxEntry {
    pub client_msg_id: String,
    pub chat_id: i64,
    pub peer_user_id: i64,
    pub schema: String,
    pub suite: String,
    pub recipients: Vec<FfiOutboxRecipient>,
    pub associated_data: Vec<u8>,
    pub forward_info: Option<Vec<u8>>,
    pub reply_to: Option<i64>,
    pub created_at: i64,
    pub attempts: u32,
}

impl From<FfiOutboxEntry> for OutboxEntry {
    fn from(e: FfiOutboxEntry) -> Self {
        OutboxEntry {
            client_msg_id: e.client_msg_id,
            chat_id: e.chat_id,
            peer_user_id: e.peer_user_id,
            schema: e.schema,
            suite: e.suite,
            recipients: e
                .recipients
                .into_iter()
                .map(|r| OutboxRecipient {
                    user_id: r.user_id,
                    device_id: r.device_id,
                    envelope_type: r.envelope_type,
                    header: r.header,
                    ciphertext: r.ciphertext,
                })
                .collect(),
            associated_data: e.associated_data,
            forward_info: e.forward_info,
            reply_to: e.reply_to,
            created_at: e.created_at,
            attempts: e.attempts,
        }
    }
}

impl From<OutboxEntry> for FfiOutboxEntry {
    fn from(e: OutboxEntry) -> Self {
        FfiOutboxEntry {
            client_msg_id: e.client_msg_id,
            chat_id: e.chat_id,
            peer_user_id: e.peer_user_id,
            schema: e.schema,
            suite: e.suite,
            recipients: e
                .recipients
                .into_iter()
                .map(|r| FfiOutboxRecipient {
                    user_id: r.user_id,
                    device_id: r.device_id,
                    envelope_type: r.envelope_type,
                    header: r.header,
                    ciphertext: r.ciphertext,
                })
                .collect(),
            associated_data: e.associated_data,
            forward_info: e.forward_info,
            reply_to: e.reply_to,
            created_at: e.created_at,
            attempts: e.attempts,
        }
    }
}

/// How far an outgoing message got. Only ever moves forward.
#[derive(uniffi::Enum, Clone, Copy)]
pub enum FfiMessageStatus {
    /// Written down and queued, not yet accepted by the server. Retried until
    /// it lands, so it is a stage rather than a failure.
    Pending,
    Sent,
    Delivered,
    Read,
}

impl From<MessageStatus> for FfiMessageStatus {
    fn from(s: MessageStatus) -> Self {
        match s {
            MessageStatus::Pending => FfiMessageStatus::Pending,
            MessageStatus::Sent => FfiMessageStatus::Sent,
            MessageStatus::Delivered => FfiMessageStatus::Delivered,
            MessageStatus::Read => FfiMessageStatus::Read,
        }
    }
}

impl From<FfiMessageStatus> for MessageStatus {
    fn from(s: FfiMessageStatus) -> Self {
        match s {
            FfiMessageStatus::Pending => MessageStatus::Pending,
            FfiMessageStatus::Sent => MessageStatus::Sent,
            FfiMessageStatus::Delivered => MessageStatus::Delivered,
            FfiMessageStatus::Read => MessageStatus::Read,
        }
    }
}

/// What a decrypted message contains. Read receipts ride inside the ciphertext
/// like any other message, so the server never learns that a chat was read.
#[derive(uniffi::Enum)]
pub enum FfiMessageBody {
    Text {
        text: String,
    },
    /// Everything up to this timestamp has been read by the peer.
    ReadReceipt {
        up_to_created_at: i64,
    },
    /// Relayed from another chat, naming who wrote it first. The attribution
    /// is the forwarder's claim, not a proof — show it, do not trust it.
    Forwarded {
        text: String,
        origin_username: String,
        origin_created_at: i64,
    },
}

impl From<MessageBody> for FfiMessageBody {
    fn from(b: MessageBody) -> Self {
        match b {
            MessageBody::Text(text) => FfiMessageBody::Text { text },
            MessageBody::ReadReceipt { up_to_created_at } => {
                FfiMessageBody::ReadReceipt { up_to_created_at }
            }
            MessageBody::Forwarded {
                text,
                origin_username,
                origin_created_at,
            } => FfiMessageBody::Forwarded {
                text,
                origin_username,
                origin_created_at,
            },
        }
    }
}

impl From<FfiMessageBody> for MessageBody {
    fn from(b: FfiMessageBody) -> Self {
        match b {
            FfiMessageBody::Text { text } => MessageBody::Text(text),
            FfiMessageBody::ReadReceipt { up_to_created_at } => {
                MessageBody::ReadReceipt { up_to_created_at }
            }
            FfiMessageBody::Forwarded {
                text,
                origin_username,
                origin_created_at,
            } => MessageBody::Forwarded {
                text,
                origin_username,
                origin_created_at,
            },
        }
    }
}

/// A decrypted message together with the metadata its sender bound into the
/// associated data — authenticated by the AEAD tag, unlike the copy the server
/// sends alongside it in `FfiIncomingMessage`.
#[derive(uniffi::Record)]
pub struct FfiDecryptedMessage {
    pub body: FfiMessageBody,
    pub chat_id: i64,
    pub client_msg_id: String,
    /// The `message_ref` of the message this one answers, if it is a reply.
    pub reply_to: Option<i64>,
}

/// One of our own messages that has not been confirmed delivered yet.
#[derive(uniffi::Record)]
pub struct FfiUndelivered {
    pub chat_id: i64,
    pub client_msg_id: String,
}

/// A message in local history. The server keeps only ciphertext and drops it on
/// ack, so this is the durable copy of a conversation.
#[derive(uniffi::Record)]
pub struct FfiStoredMessage {
    pub chat_id: i64,
    pub peer_user_id: i64,
    pub outgoing: bool,
    pub client_msg_id: String,
    pub text: String,
    pub created_at: i64,
    /// Delivery state; always Sent for incoming messages.
    pub status: FfiMessageStatus,
    /// Set when this message answers another one, holding that message's
    /// `message_ref`. Null for an ordinary message.
    pub reply_to: Option<i64>,
    /// Who wrote this first, when it was relayed from another chat. Null for
    /// an ordinary message.
    pub forwarded_from: Option<String>,
    /// When the original was written, so a forward shows the original date.
    pub forwarded_at: Option<i64>,
}

impl From<StoredMessage> for FfiStoredMessage {
    fn from(m: StoredMessage) -> Self {
        FfiStoredMessage {
            chat_id: m.chat_id,
            peer_user_id: m.peer_user_id,
            outgoing: m.outgoing,
            client_msg_id: m.client_msg_id,
            text: m.text,
            created_at: m.created_at,
            status: m.status.into(),
            reply_to: m.reply_to,
            forwarded_from: m.forwarded_from,
            forwarded_at: m.forwarded_at,
        }
    }
}

impl From<FfiStoredMessage> for StoredMessage {
    fn from(m: FfiStoredMessage) -> Self {
        StoredMessage {
            chat_id: m.chat_id,
            peer_user_id: m.peer_user_id,
            outgoing: m.outgoing,
            client_msg_id: m.client_msg_id,
            text: m.text,
            created_at: m.created_at,
            status: m.status.into(),
            reply_to: m.reply_to,
            forwarded_from: m.forwarded_from,
            forwarded_at: m.forwarded_at,
        }
    }
}

#[derive(uniffi::Object)]
pub struct NotegramCore {
    inner: Mutex<NotegramClient<SqliteBackend>>,
}

#[uniffi::export]
impl NotegramCore {
    #[uniffi::constructor]
    pub fn open(master_key: Vec<u8>, db_path: String) -> Result<std::sync::Arc<Self>, FfiError> {
        let backend = SqliteBackend::open(&db_path).map_err(SdkError::from)?;
        let client = NotegramClient::open(&master_key, backend)?;
        Ok(std::sync::Arc::new(NotegramCore {
            inner: Mutex::new(client),
        }))
    }

    pub fn create_identity(&self) -> Result<FfiPublicIdentity, FfiError> {
        Ok(self.lock().create_identity()?.into())
    }

    pub fn import_identity(
        &self,
        identity_priv: Vec<u8>,
        signing_seed: Vec<u8>,
        registration_id: u32,
    ) -> Result<FfiPublicIdentity, FfiError> {
        let identity_priv = arr32(&identity_priv)?;
        let signing_seed = arr32(&signing_seed)?;
        let identity = Identity {
            identity_pub: crypto::x25519_public(&identity_priv),
            signing_pub: crypto::ed25519_public(&signing_seed),
            identity_priv,
            signing_seed,
            registration_id,
        };
        Ok(self.lock().import_identity(&identity)?.into())
    }

    pub fn public_identity(&self) -> Result<FfiPublicIdentity, FfiError> {
        Ok(self.lock().public_identity()?.into())
    }

    pub fn generate_prekey_bundle(
        &self,
        one_time_count: u32,
    ) -> Result<crate::net_ffi::FfiPrekeyUpload, FfiError> {
        let b = self.lock().generate_prekey_bundle(one_time_count)?;
        Ok(crate::net_ffi::FfiPrekeyUpload {
            identity_key: b.identity_key.to_vec(),
            signed_pre_key_id: b.signed_pre_key_id,
            signed_pre_key_pub: b.signed_pre_key_pub.to_vec(),
            signed_pre_key_sig: b.signed_pre_key_sig.to_vec(),
            one_time_pre_keys: b
                .one_time_pre_keys
                .into_iter()
                .map(|k| crate::net_ffi::FfiPrekeyUploadOtk {
                    id: k.id,
                    pubkey: k.pubkey.to_vec(),
                })
                .collect(),
        })
    }

    /// Verify a peer's `PrekeyBundleProof` (the `proof` field of a
    /// `KeysPeerBundle` device entry) against pinned key-transparency trust
    /// anchors, and check the signed-prekey signature against the trusted
    /// `DeviceSigningKey` extracted from the proof. See `kt::device` for the
    /// verifier (byte-parity ported from the server's reference
    /// implementation) and `e2ee::x3dh::verify_signed_prekey` for the final
    /// signature check.
    pub fn verify_peer_bundle(
        &self,
        proof: Vec<u8>,
        trust: FfiKeyTransparencyTrust,
    ) -> Result<FfiVerifiedPrekeyBundle, FfiError> {
        let signing_public_keys = trust
            .signing_public_keys
            .iter()
            .map(|k| arr32(k))
            .collect::<Result<Vec<_>, _>>()?;
        let witness_public_keys = trust
            .witness_public_keys
            .iter()
            .map(|k| arr32(k))
            .collect::<Result<Vec<_>, _>>()?;
        let anchors = kt::device::TrustAnchors {
            signing_public_keys: &signing_public_keys,
            witness_public_keys: &witness_public_keys,
            min_witness_signatures: trust.min_witness_signatures as usize,
        };

        let verified = kt::device::verify_prekey_bundle_proof(&proof, &anchors)
            .map_err(|e| FfiError::UntrustedPeerBundleProof(e.to_string()))?;

        if !e2ee::x3dh::verify_signed_prekey(
            &verified.device_signing_key,
            &verified.signed_pre_key_pub,
            &verified.signed_pre_key_sig,
        ) {
            return Err(FfiError::BadPrekeySignature);
        }

        Ok(FfiVerifiedPrekeyBundle {
            user_id: verified.user_id,
            device_id: verified.device_id,
            identity_key: verified.identity_key.to_vec(),
            device_signing_key: verified.device_signing_key.to_vec(),
            signed_pre_key_id: verified.signed_pre_key_id,
            signed_pre_key_pub: verified.signed_pre_key_pub.to_vec(),
            signed_pre_key_sig: verified.signed_pre_key_sig.to_vec(),
            one_time_pre_key_id: verified.one_time_pre_key_id,
            one_time_pre_key_pub: verified.one_time_pre_key_pub.map(|k| k.to_vec()),
        })
    }

    pub fn has_session(&self, peer: FfiPeerAddress) -> Result<bool, FfiError> {
        Ok(self.lock().has_session(peer.into())?)
    }

    pub fn establish_outbound_session(
        &self,
        peer: FfiPeerAddress,
        bundle: FfiPreKeyBundle,
    ) -> Result<Vec<u8>, FfiError> {
        let bundle = PreKeyBundle {
            identity_pub: arr32(&bundle.identity_pub)?,
            signing_pub: arr32(&bundle.signing_pub)?,
            signed_prekey_pub: arr32(&bundle.signed_prekey_pub)?,
            signed_prekey_sig: arr64(&bundle.signed_prekey_sig)?,
            one_time_prekey_pub: bundle
                .one_time_prekey_pub
                .as_deref()
                .map(arr32)
                .transpose()?,
        };
        Ok(self
            .lock()
            .establish_outbound_session(peer.into(), &bundle)?
            .to_vec())
    }

    pub fn establish_inbound_session(
        &self,
        peer: FfiPeerAddress,
        signed_prekey_priv: Vec<u8>,
        one_time_prekey_priv: Option<Vec<u8>>,
        initiator_identity_pub: Vec<u8>,
        initiator_ephemeral_pub: Vec<u8>,
    ) -> Result<(), FfiError> {
        let signed_prekey_priv = arr32(&signed_prekey_priv)?;
        let one_time = one_time_prekey_priv.as_deref().map(arr32).transpose()?;
        let initiator_identity_pub = arr32(&initiator_identity_pub)?;
        let initiator_ephemeral_pub = arr32(&initiator_ephemeral_pub)?;
        self.lock().establish_inbound_session(
            peer.into(),
            &InboundPreKeys {
                signed_prekey_priv: &signed_prekey_priv,
                one_time_prekey_priv: one_time.as_ref(),
            },
            &initiator_identity_pub,
            &initiator_ephemeral_pub,
        )?;
        Ok(())
    }

    pub fn encrypt(
        &self,
        peer: FfiPeerAddress,
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, FfiError> {
        Ok(self
            .lock()
            .encrypt(peer.into(), &plaintext, &associated_data)?)
    }

    pub fn decrypt(
        &self,
        peer: FfiPeerAddress,
        message: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, FfiError> {
        Ok(self
            .lock()
            .decrypt(peer.into(), &message, &associated_data)?)
    }

    /// Builds an upload that adds `count` fresh one-time prekeys when the
    /// server reports the device is running low. Pass the result straight to
    /// `NetSession.keys_upload`: it repeats the existing identity and signed
    /// prekey unchanged (the server rejects a changed one under the same id)
    /// and only the one-time keys are new, with ids continuing the sequence so
    /// nothing the server still advertises is invalidated.
    pub fn prekey_top_up(&self, count: u32) -> Result<crate::net_ffi::FfiPrekeyUpload, FfiError> {
        let b = self.lock().prekey_top_up(count)?;
        Ok(crate::net_ffi::FfiPrekeyUpload {
            identity_key: b.identity_key.to_vec(),
            signed_pre_key_id: b.signed_pre_key_id,
            signed_pre_key_pub: b.signed_pre_key_pub.to_vec(),
            signed_pre_key_sig: b.signed_pre_key_sig.to_vec(),
            one_time_pre_keys: b
                .one_time_pre_keys
                .into_iter()
                .map(|k| crate::net_ffi::FfiPrekeyUploadOtk {
                    id: k.id,
                    pubkey: k.pubkey.to_vec(),
                })
                .collect(),
        })
    }

    /// Publishes a fresh signed prekey under the next id, for when the server
    /// reports the current one is stale. Upload the result with
    /// `NetSession.keys_upload`. The previous private key is retained so
    /// messages already encrypted against it still open.
    pub fn rotate_signed_prekey(
        &self,
        one_time_count: u32,
    ) -> Result<crate::net_ffi::FfiPrekeyUpload, FfiError> {
        let b = self.lock().rotate_signed_prekey(one_time_count)?;
        Ok(crate::net_ffi::FfiPrekeyUpload {
            identity_key: b.identity_key.to_vec(),
            signed_pre_key_id: b.signed_pre_key_id,
            signed_pre_key_pub: b.signed_pre_key_pub.to_vec(),
            signed_pre_key_sig: b.signed_pre_key_sig.to_vec(),
            one_time_pre_keys: b
                .one_time_pre_keys
                .into_iter()
                .map(|k| crate::net_ffi::FfiPrekeyUploadOtk {
                    id: k.id,
                    pubkey: k.pubkey.to_vec(),
                })
                .collect(),
        })
    }

    pub fn save_message(&self, message: FfiStoredMessage) -> Result<(), FfiError> {
        Ok(self.lock().save_message(&message.into())?)
    }

    /// Writes a message down before it is sent, and shows it in the chat as
    /// pending in the same step.
    ///
    /// Call this before the first delivery attempt, not after a failure: the
    /// point is that the message exists on disk from the moment the user
    /// pressed send, so nothing about the network — or about the app being
    /// killed — can lose it.
    pub fn enqueue_outbox(&self, entry: FfiOutboxEntry, text: String) -> Result<(), FfiError> {
        Ok(self.lock().enqueue_outbox(&entry.into(), &text)?)
    }

    /// Attaches the encrypted copies to a message queued before it could be
    /// encrypted — the first message to a peer, sent while offline. Returns
    /// false when the entry is gone, which means it was already accepted.
    pub fn attach_outbox_envelopes(
        &self,
        client_msg_id: String,
        queued_at: i64,
        recipients: Vec<FfiOutboxRecipient>,
        associated_data: Vec<u8>,
    ) -> Result<bool, FfiError> {
        let recipients = recipients
            .into_iter()
            .map(|r| OutboxRecipient {
                user_id: r.user_id,
                device_id: r.device_id,
                envelope_type: r.envelope_type,
                header: r.header,
                ciphertext: r.ciphertext,
            })
            .collect();
        Ok(self.lock().attach_outbox_envelopes(
            &client_msg_id,
            queued_at,
            recipients,
            associated_data,
        )?)
    }

    /// One message by the id its sender chose. What a queued-but-unencrypted
    /// entry needs to be turned into an envelope later.
    pub fn message_by_client_id(
        &self,
        chat_id: i64,
        client_msg_id: String,
    ) -> Result<Option<FfiStoredMessage>, FfiError> {
        Ok(self
            .lock()
            .message_by_client_id(chat_id, &client_msg_id)?
            .map(FfiStoredMessage::from))
    }

    /// Everything still waiting, oldest first. Send them in this order: a chat
    /// delivered out of order stays wrong for the recipient.
    pub fn pending_outbox(&self) -> Result<Vec<FfiOutboxEntry>, FfiError> {
        Ok(self
            .lock()
            .pending_outbox()?
            .into_iter()
            .map(FfiOutboxEntry::from)
            .collect())
    }

    /// Marks a queued message accepted: it leaves the queue and its row becomes
    /// Sent under the server's timestamp, which is the one every other device
    /// will order it by.
    pub fn complete_outbox(
        &self,
        chat_id: i64,
        client_msg_id: String,
        queued_at: i64,
        server_created_at: i64,
    ) -> Result<(), FfiError> {
        Ok(self
            .lock()
            .complete_outbox(chat_id, &client_msg_id, queued_at, server_created_at)?)
    }

    /// Counts a failed attempt. Returns false when the message is no longer
    /// queued, which is what a reply arriving after acceptance looks like.
    pub fn note_outbox_attempt(
        &self,
        client_msg_id: String,
        queued_at: i64,
    ) -> Result<bool, FfiError> {
        Ok(self.lock().note_outbox_attempt(&client_msg_id, queued_at)?)
    }

    /// Drops a queued message whose stored envelope can no longer be delivered
    /// — the peer gained a device, so the fan-out is incomplete and no retry
    /// will fix it. Re-encrypt against the fresh roster and queue again under
    /// the same client id.
    pub fn discard_outbox(&self, client_msg_id: String, queued_at: i64) -> Result<(), FfiError> {
        Ok(self.lock().discard_outbox(&client_msg_id, queued_at)?)
    }

    /// Advances an outgoing message's delivery status, matched by the id the
    /// sender chose. Status never regresses, so notices arriving out of order
    /// are safe to apply. Returns whether anything changed.
    pub fn mark_message_status(
        &self,
        chat_id: i64,
        client_msg_id: String,
        status: FfiMessageStatus,
    ) -> Result<bool, FfiError> {
        Ok(self
            .lock()
            .mark_message_status(chat_id, &client_msg_id, status.into())?)
    }

    /// Our own messages still waiting for confirmation, as (chat_id, client_msg_id).
    /// Feed the ids to `NetSession.delivery_status` and mark whatever comes back.
    pub fn undelivered_messages(&self, limit: u32) -> Result<Vec<FfiUndelivered>, FfiError> {
        Ok(self
            .lock()
            .undelivered_messages(limit)?
            .into_iter()
            .map(|(chat_id, client_msg_id)| FfiUndelivered {
                chat_id,
                client_msg_id,
            })
            .collect())
    }

    /// Applies a peer's read receipt to our own messages in that chat. Returns
    /// how many rows changed, so the caller only redraws when something did.
    pub fn mark_read_up_to(&self, chat_id: i64, up_to_created_at: i64) -> Result<u32, FfiError> {
        Ok(self.lock().mark_read_up_to(chat_id, up_to_created_at)?)
    }

    /// Messages of one chat, oldest first. `limit` of 0 means no cap.
    pub fn list_messages(
        &self,
        chat_id: i64,
        limit: u32,
    ) -> Result<Vec<FfiStoredMessage>, FfiError> {
        Ok(self
            .lock()
            .list_messages(chat_id, limit)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Latest message per chat, newest chat first — for the chat list.
    pub fn list_chat_previews(&self) -> Result<Vec<FfiStoredMessage>, FfiError> {
        Ok(self
            .lock()
            .list_chat_previews()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Opens an incoming message, establishing the inbound session first when
    /// the envelope is a `signal-prekey.v1` handshake. The returned metadata is
    /// what the sender authenticated, not what the server claimed.
    pub fn decrypt_message(
        &self,
        peer: FfiPeerAddress,
        envelope_type: String,
        header: Vec<u8>,
        ciphertext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<FfiDecryptedMessage, FfiError> {
        let opened = self.lock().decrypt_message(
            peer.into(),
            &envelope_type,
            &header,
            &ciphertext,
            &associated_data,
        )?;
        Ok(FfiDecryptedMessage {
            body: opened.body.into(),
            chat_id: opened.chat_id,
            client_msg_id: opened.client_msg_id,
            reply_to: opened.reply_to,
        })
    }

    /// The handle a reply points at, derived from the message's client id. Both
    /// sides compute it the same way, so no id has to be exchanged.
    pub fn message_ref(&self, client_msg_id: String) -> i64 {
        sdk_message_ref(&client_msg_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_message(
        &self,
        sender_user_id: i64,
        sender_device_id: i64,
        peer: FfiPeerAddress,
        chat_id: i64,
        client_msg_id: String,
        body: FfiMessageBody,
        new_session_bundle: Option<FfiRecipientPreKeyBundle>,
        reply_to: Option<i64>,
    ) -> Result<FfiOutgoingEnvelope, FfiError> {
        let bundle = new_session_bundle
            .map(|b| -> Result<RecipientPreKeyBundle, FfiError> {
                Ok(RecipientPreKeyBundle {
                    identity_key: arr32(&b.identity_key)?,
                    signing_pub: arr32(&b.signing_pub)?,
                    signed_prekey_id: b.signed_prekey_id,
                    signed_prekey_pub: arr32(&b.signed_prekey_pub)?,
                    signed_prekey_sig: arr64(&b.signed_prekey_sig)?,
                    one_time_prekey_id: b.one_time_prekey_id,
                    one_time_prekey_pub: b.one_time_prekey_pub.as_deref().map(arr32).transpose()?,
                })
            })
            .transpose()?;

        let env = self.lock().encrypt_message(
            sender_user_id,
            sender_device_id,
            peer.into(),
            chat_id,
            &client_msg_id,
            &body.into(),
            bundle.as_ref(),
            reply_to,
        )?;
        Ok(FfiOutgoingEnvelope {
            envelope_type: env.envelope_type,
            header: env.header,
            ciphertext: env.ciphertext,
            associated_data: env.associated_data,
        })
    }
}

impl NotegramCore {
    fn lock(&self) -> std::sync::MutexGuard<'_, NotegramClient<SqliteBackend>> {
        self.inner.expect_lock()
    }
}

trait ExpectLock<T> {
    fn expect_lock(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> ExpectLock<T> for Mutex<T> {
    fn expect_lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn arr32(v: &[u8]) -> Result<[u8; 32], FfiError> {
    v.try_into().map_err(|_| FfiError::BadInput)
}

fn arr64(v: &[u8]) -> Result<[u8; 64], FfiError> {
    v.try_into().map_err(|_| FfiError::BadInput)
}
