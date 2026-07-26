use std::sync::Mutex;

use crate::{
    Identity, InboundPreKeys, NotegramClient, PeerAddress, PreKeyBundle, PublicIdentity, SdkError,
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

    BadInput,
}

impl core::fmt::Display for FfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            FfiError::Store => "store error",
            FfiError::Session => "session error",
            FfiError::NoSession => "no session for peer",
            FfiError::BadPrekeySignature => "signed prekey signature invalid",
            FfiError::BadKeyMaterial => "malformed key material",
            FfiError::NoIdentity => "no local identity",
            FfiError::BadInput => "argument had wrong length",
        };
        write!(f, "notegram: {s}")
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
