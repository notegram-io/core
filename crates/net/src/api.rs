use tokio::io::{AsyncRead, AsyncWrite};

use tl::TlObject;
use tl::generated::{
    AuthDevices, AuthGetDevices, DirectoryClaimUsername, DirectoryGetMyProfile,
    DirectoryGetMyUsername, DirectoryGetProfile, DirectoryProfile, DirectoryResolveUsername,
    DirectoryResolved, DirectorySetProfile, DirectoryUsername, KeysDeviceSigningKey,
    KeysGetMyStatus, KeysGetPeerBundle, KeysPeerBundle, KeysSetDeviceSigningKey, KeysStatus,
    KeysUpload, KeysUploaded, MessagesAckEncrypted, MessagesEncryptedAcked, MessagesEncryptedBatch,
    MessagesEncryptedRecipient, MessagesEncryptedSent, MessagesGetEncrypted, MessagesSendEncrypted,
    OneTimePreKey, Ping, Pong, UpdateNewMessages,
};

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
        self.rpc_mut()
            .invoke(&KeysGetPeerBundle { user_id })
            .await
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
        self.rpc_mut()
            .take_updates()
            .into_iter()
            .filter_map(|raw| {
                if raw.len() < 4 || wire::u32_le(&raw[0..4]) != UpdateNewMessages::CTOR {
                    return None;
                }
                tl::decode_from::<UpdateNewMessages>(&raw, tl::Limits::default()).ok()
            })
            .collect()
    }

    pub async fn ack_encrypted(&mut self, server_msg_id: &str) -> Result<MessagesEncryptedAcked> {
        self.rpc_mut()
            .invoke(&MessagesAckEncrypted {
                server_msg_id: server_msg_id.to_string(),
            })
            .await
    }
}
