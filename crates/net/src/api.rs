use tokio::io::{AsyncRead, AsyncWrite};

use tl::generated::{
    AuthDevices, AuthGetDevices, DirectoryClaimUsername, DirectoryGetMyProfile,
    DirectoryGetMyUsername, DirectoryGetProfile, DirectoryProfile, DirectoryResolveUsername,
    DirectoryResolved, DirectorySetProfile, DirectoryUsername, KeysDeviceSigningKey,
    KeysGetMyStatus, KeysGetPeerBundle, KeysPeerBundle, KeysSetDeviceSigningKey, KeysStatus,
    KeysUpload, KeysUploaded, MessagesAckEncrypted, MessagesAckEncryptedBatch,
    MessagesDeliveryStatus, MessagesEncryptedAcked, MessagesEncryptedBatch,
    MessagesEncryptedBatchAcked, MessagesEncryptedRecalled, MessagesEncryptedRecipient,
    MessagesEncryptedSent, MessagesGetDeliveryStatus, MessagesGetEncrypted,
    MessagesRecallEncrypted, MessagesSendEncrypted, OneTimePreKey, Ping, Pong, PushRegisterToken,
    PushTokenRegistered, PushTokenUnregistered, PushUnregisterToken, UpdateMessageDelivered,
    UpdateNewMessages,
};
use tl::TlObject;

use crate::error::Result;
use crate::session::Session;

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<S> {
    pub async fn ping(&self, ping_id: i64) -> Result<Pong> {
        self.invoke(&Ping { ping_id }).await
    }

    pub async fn get_devices(&self) -> Result<AuthDevices> {
        self.invoke(&AuthGetDevices).await
    }

    pub async fn resolve_username(&self, name: &str) -> Result<DirectoryResolved> {
        self.invoke(&DirectoryResolveUsername {
            name: name.to_string(),
        })
        .await
    }

    pub async fn claim_username(&self, name: &str) -> Result<DirectoryUsername> {
        self.invoke(&DirectoryClaimUsername {
            name: name.to_string(),
        })
        .await
    }

    pub async fn get_profile(&self, user_id: i64) -> Result<DirectoryProfile> {
        self.invoke(&DirectoryGetProfile { user_id }).await
    }

    pub async fn get_my_profile(&self) -> Result<DirectoryProfile> {
        self.invoke(&DirectoryGetMyProfile).await
    }

    pub async fn get_my_username(&self) -> Result<DirectoryUsername> {
        self.invoke(&DirectoryGetMyUsername).await
    }

    pub async fn set_profile(&self, display_name: &str, bio: &str) -> Result<DirectoryProfile> {
        self.invoke(&DirectorySetProfile {
            display_name: display_name.to_string(),
            bio: bio.to_string(),
        })
        .await
    }

    pub async fn keys_upload(
        &self,
        identity_key: Vec<u8>,
        signed_pre_key_id: i32,
        signed_pre_key_pub: Vec<u8>,
        signed_pre_key_sig: Vec<u8>,
        one_time_pre_keys: Vec<OneTimePreKey>,
    ) -> Result<KeysUploaded> {
        self.invoke(&KeysUpload {
            identity_key,
            signed_pre_key_id,
            signed_pre_key_pub,
            signed_pre_key_sig,
            one_time_pre_keys,
        })
        .await
    }

    pub async fn keys_status(&self) -> Result<KeysStatus> {
        self.invoke(&KeysGetMyStatus).await
    }

    pub async fn set_device_signing_key(
        &self,
        public_key: Vec<u8>,
    ) -> Result<KeysDeviceSigningKey> {
        self.invoke(&KeysSetDeviceSigningKey { public_key }).await
    }

    /// Tells the server where to wake this device when it is not connected.
    ///
    /// The token is an address the push provider issued, never a place to put
    /// content: the push itself carries nothing and the device fetches and
    /// decrypts over this same link.
    pub async fn register_push_token(
        &self,
        provider: &str,
        token: &str,
    ) -> Result<PushTokenRegistered> {
        self.invoke(&PushRegisterToken {
            provider: provider.to_string(),
            token: token.to_string(),
        })
        .await
    }

    /// Withdraws this device's address. Signing out has to do this: nothing
    /// else will, and a device that merely logged out would go on being woken
    /// for an account it can no longer read.
    pub async fn unregister_push_token(&self) -> Result<PushTokenUnregistered> {
        self.invoke(&PushUnregisterToken).await
    }

    pub async fn get_peer_bundle(&self, user_id: i64) -> Result<KeysPeerBundle> {
        self.invoke(&KeysGetPeerBundle { user_id }).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_encrypted(
        &self,
        client_msg_id: &str,
        chat_id: i64,
        schema: &str,
        suite: &str,
        recipients: Vec<MessagesEncryptedRecipient>,
        associated_data: Vec<u8>,
        forward_info: Option<Vec<u8>>,
        reply_to: Option<i64>,
    ) -> Result<MessagesEncryptedSent> {
        self.invoke(&MessagesSendEncrypted {
            client_msg_id: client_msg_id.to_string(),
            chat_id,
            schema: schema.to_string(),
            suite: suite.to_string(),
            recipients,
            associated_data,
            forward_info,
            reply_to,
        })
        .await
    }

    pub async fn get_encrypted_messages(&self, limit: i32) -> Result<MessagesEncryptedBatch> {
        self.invoke(&MessagesGetEncrypted { limit }).await
    }

    /// Server-initiated notices collected since the last call, decoded to the
    /// ones this client understands. They ride the same connection as RPC
    /// replies, so they are picked up whenever any request runs — the keepalive
    /// ping alone is enough to surface them promptly.
    pub async fn take_new_message_updates(&self) -> Vec<UpdateNewMessages> {
        self.take_updates_of::<UpdateNewMessages>().await
    }

    /// Delivery receipts: a recipient device fetched and acked one of our
    /// messages. Drained the same way as new-message notices.
    pub async fn take_delivery_updates(&self) -> Vec<UpdateMessageDelivered> {
        self.take_updates_of::<UpdateMessageDelivered>().await
    }

    /// Constructor ids of everything currently buffered, leaving the queue
    /// untouched. Server-initiated notices are invisible until someone asks for
    /// their exact type, so without this a notice that arrives but is never
    /// recognised looks identical to one that never arrived.
    pub async fn pending_update_kinds(&self) -> Vec<u32> {
        let raw = self.take_updates().await;
        let kinds = raw
            .iter()
            .filter(|r| r.len() >= 4)
            .map(|r| wire::u32_le(&r[0..4]))
            .collect();
        self.restore_updates(raw).await;
        kinds
    }

    /// Pulls out the buffered updates of one type, leaving the rest queued —
    /// draining everything here would discard notices the caller has not asked
    /// for yet.
    async fn take_updates_of<T: TlObject>(&self) -> Vec<T> {
        let mut wanted = Vec::new();
        let mut keep = Vec::new();
        for raw in self.take_updates().await {
            if raw.len() < 4 || wire::u32_le(&raw[0..4]) != T::CTOR {
                keep.push(raw);
                continue;
            }
            // A malformed notice is dropped: it is only a hint, and the message
            // itself is still on the server.
            if let Ok(update) = tl::decode_from::<T>(&raw, tl::Limits::default()) {
                wanted.push(update);
            }
        }
        self.restore_updates(keep).await;
        wanted
    }

    /// Which of our own messages every recipient has already collected.
    ///
    /// The delivery notice is pushed once and lost if the link drops in that
    /// instant, so the same fact is asked for here instead of relied upon.
    pub async fn delivery_status(
        &self,
        client_msg_ids: Vec<String>,
    ) -> Result<MessagesDeliveryStatus> {
        self.invoke(&MessagesGetDeliveryStatus {
            client_msg_i_ds: client_msg_ids,
        })
        .await
    }

    pub async fn ack_encrypted(&self, server_msg_id: &str) -> Result<MessagesEncryptedAcked> {
        self.invoke(&MessagesAckEncrypted {
            server_msg_id: server_msg_id.to_string(),
        })
        .await
    }

    /// Acknowledges a whole batch in one round trip.
    ///
    /// One request per message, in sequence, is what a burst used to cost — the
    /// messages were already fetched and decrypted by then, so the waiting was
    /// pure protocol overhead. Returns the ids the server actually dropped,
    /// which lets a caller tell a real ack from a repeat of one it had already
    /// sent.
    /// Withdraws the sender's own envelopes that nobody has collected yet, for
    /// messages being deleted. Returns the ids that still had something to
    /// withdraw.
    ///
    /// Never the whole of a deletion: anything already fetched is beyond
    /// recall, and only the encrypted notice reaches the copy the recipient
    /// holds. This spares a recipient receiving what its author already
    /// withdrew.
    pub async fn recall_encrypted(
        &self,
        client_msg_ids: Vec<String>,
    ) -> Result<MessagesEncryptedRecalled> {
        self.invoke(&MessagesRecallEncrypted {
            client_msg_i_ds: client_msg_ids,
        })
        .await
    }

    pub async fn ack_encrypted_batch(
        &self,
        server_msg_ids: Vec<String>,
    ) -> Result<MessagesEncryptedBatchAcked> {
        self.invoke(&MessagesAckEncryptedBatch {
            server_msg_i_ds: server_msg_ids,
        })
        .await
    }
}
