use tokio::io::{AsyncRead, AsyncWrite};

use tl::generated::{
    AuthDevices, AuthGetDevices, DirectoryClaimUsername, DirectoryGetMyProfile,
    DirectoryGetMyUsername, DirectoryGetProfile, DirectoryProfile, DirectoryResolveUsername,
    DirectoryResolved, DirectorySetProfile, DirectoryUsername, KeysDeviceSigningKey,
    KeysGetMyStatus, KeysGetPeerBundle, KeysPeerBundle, KeysSetDeviceSigningKey, KeysStatus,
    KeysUpload, KeysUploaded, MessagesAckEncrypted, MessagesDeliveryStatus, MessagesEncryptedAcked,
    MessagesEncryptedBatch, MessagesEncryptedRecipient, MessagesEncryptedSent,
    MessagesGetDeliveryStatus, MessagesGetEncrypted, MessagesSendEncrypted, OneTimePreKey, Ping,
    Pong, UpdateMessageDelivered, UpdateNewMessages,
};
use tl::TlObject;

use crate::error::Result;
use crate::session::Session;

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    pub async fn ping(&mut self, ping_id: i64) -> Result<Pong> {
        self.rpc_mut().invoke(&Ping { ping_id }).await
    }

    pub async fn get_devices(&mut self) -> Result<AuthDevices> {
        self.rpc_mut().invoke(&AuthGetDevices).await
    }

    pub async fn resolve_username(&mut self, name: &str) -> Result<DirectoryResolved> {
        self.rpc_mut()
            .invoke(&DirectoryResolveUsername {
                name: name.to_string(),
            })
            .await
    }

    pub async fn claim_username(&mut self, name: &str) -> Result<DirectoryUsername> {
        self.rpc_mut()
            .invoke(&DirectoryClaimUsername {
                name: name.to_string(),
            })
            .await
    }

    pub async fn get_profile(&mut self, user_id: i64) -> Result<DirectoryProfile> {
        self.rpc_mut()
            .invoke(&DirectoryGetProfile { user_id })
            .await
    }

    pub async fn get_my_profile(&mut self) -> Result<DirectoryProfile> {
        self.rpc_mut().invoke(&DirectoryGetMyProfile).await
    }

    pub async fn get_my_username(&mut self) -> Result<DirectoryUsername> {
        self.rpc_mut().invoke(&DirectoryGetMyUsername).await
    }

    pub async fn set_profile(&mut self, display_name: &str, bio: &str) -> Result<DirectoryProfile> {
        self.rpc_mut()
            .invoke(&DirectorySetProfile {
                display_name: display_name.to_string(),
                bio: bio.to_string(),
            })
            .await
    }

    pub async fn keys_upload(
        &mut self,
        identity_key: Vec<u8>,
        signed_pre_key_id: i32,
        signed_pre_key_pub: Vec<u8>,
        signed_pre_key_sig: Vec<u8>,
        one_time_pre_keys: Vec<OneTimePreKey>,
    ) -> Result<KeysUploaded> {
        self.rpc_mut()
            .invoke(&KeysUpload {
                identity_key,
                signed_pre_key_id,
                signed_pre_key_pub,
                signed_pre_key_sig,
                one_time_pre_keys,
            })
            .await
    }

    pub async fn keys_status(&mut self) -> Result<KeysStatus> {
        self.rpc_mut().invoke(&KeysGetMyStatus).await
    }

    pub async fn set_device_signing_key(
        &mut self,
        public_key: Vec<u8>,
    ) -> Result<KeysDeviceSigningKey> {
        self.rpc_mut()
            .invoke(&KeysSetDeviceSigningKey { public_key })
            .await
    }

    pub async fn get_peer_bundle(&mut self, user_id: i64) -> Result<KeysPeerBundle> {
        self.rpc_mut().invoke(&KeysGetPeerBundle { user_id }).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_encrypted(
        &mut self,
        client_msg_id: &str,
        chat_id: i64,
        schema: &str,
        suite: &str,
        recipients: Vec<MessagesEncryptedRecipient>,
        associated_data: Vec<u8>,
        forward_info: Option<Vec<u8>>,
        reply_to: Option<i64>,
    ) -> Result<MessagesEncryptedSent> {
        self.rpc_mut()
            .invoke(&MessagesSendEncrypted {
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

    pub async fn get_encrypted_messages(&mut self, limit: i32) -> Result<MessagesEncryptedBatch> {
        self.rpc_mut().invoke(&MessagesGetEncrypted { limit }).await
    }

    /// Server-initiated notices collected since the last call, decoded to the
    /// ones this client understands. They ride the same connection as RPC
    /// replies, so they are picked up whenever any request runs — the keepalive
    /// ping alone is enough to surface them promptly.
    pub fn take_new_message_updates(&mut self) -> Vec<UpdateNewMessages> {
        self.take_updates_of::<UpdateNewMessages>()
    }

    /// Delivery receipts: a recipient device fetched and acked one of our
    /// messages. Drained the same way as new-message notices.
    pub fn take_delivery_updates(&mut self) -> Vec<UpdateMessageDelivered> {
        self.take_updates_of::<UpdateMessageDelivered>()
    }

    /// Constructor ids of everything currently buffered, leaving the queue
    /// untouched. Server-initiated notices are invisible until someone asks for
    /// their exact type, so without this a notice that arrives but is never
    /// recognised looks identical to one that never arrived.
    pub fn pending_update_kinds(&mut self) -> Vec<u32> {
        let raw = self.rpc_mut().take_updates();
        let kinds = raw
            .iter()
            .filter(|r| r.len() >= 4)
            .map(|r| wire::u32_le(&r[0..4]))
            .collect();
        self.rpc_mut().restore_updates(raw);
        kinds
    }

    /// Pulls out the buffered updates of one type, leaving the rest queued —
    /// draining everything here would discard notices the caller has not asked
    /// for yet.
    fn take_updates_of<T: TlObject>(&mut self) -> Vec<T> {
        let mut wanted = Vec::new();
        let mut keep = Vec::new();
        for raw in self.rpc_mut().take_updates() {
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
        self.rpc_mut().restore_updates(keep);
        wanted
    }

    /// Which of our own messages every recipient has already collected.
    ///
    /// The delivery notice is pushed once and lost if the link drops in that
    /// instant, so the same fact is asked for here instead of relied upon.
    pub async fn delivery_status(
        &mut self,
        client_msg_ids: Vec<String>,
    ) -> Result<MessagesDeliveryStatus> {
        self.rpc_mut()
            .invoke(&MessagesGetDeliveryStatus {
                client_msg_i_ds: client_msg_ids,
            })
            .await
    }

    /// Objects read off this link, and how many of those were server-initiated.
    /// A push written by the server but never seen here is otherwise
    /// indistinguishable from one that was never sent.
    pub fn traffic_counts(&mut self) -> (u64, u64) {
        self.rpc_mut().traffic_counts()
    }

    pub async fn ack_encrypted(&mut self, server_msg_id: &str) -> Result<MessagesEncryptedAcked> {
        self.rpc_mut()
            .invoke(&MessagesAckEncrypted {
                server_msg_id: server_msg_id.to_string(),
            })
            .await
    }
}
