use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use net::Session;
use tl::generated::AuthVerified;

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Debug, uniffi::Error)]
pub enum FfiNetError {
    Tls,
    Io,
    Admission,
    Handshake,
    Rpc { code: i32, reason: String },
    Closed,
    BadInput,
}

impl core::fmt::Display for FfiNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FfiNetError::Tls => write!(f, "tls handshake failed"),
            FfiNetError::Io => write!(f, "connection io error"),
            FfiNetError::Admission => write!(f, "edge admission failed"),
            FfiNetError::Handshake => write!(f, "auth-key handshake failed"),
            FfiNetError::Rpc { code, reason } => write!(f, "rpc error {code}: {reason}"),
            FfiNetError::Closed => write!(f, "connection closed"),
            FfiNetError::BadInput => write!(f, "argument had wrong length"),
        }
    }
}

impl std::error::Error for FfiNetError {}

impl From<net::NetError> for FfiNetError {
    fn from(e: net::NetError) -> Self {
        use net::NetError as N;
        match e {
            N::Admission(_) => FfiNetError::Admission,
            N::Handshake(_) => FfiNetError::Handshake,
            N::Rpc { code, message } => FfiNetError::Rpc {
                code,
                reason: message,
            },
            N::Closed | N::NoResponse => FfiNetError::Closed,
            _ => FfiNetError::Io,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiSentCode {
    pub email_hash: Vec<u8>,
    pub timeout: i32,
}

#[derive(uniffi::Record)]
pub struct FfiVerified {
    pub user_id: i64,
    pub tmp_token: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiAuthKeys {
    pub auth_key: Vec<u8>,
    pub auth_key_id: u64,
    pub user_id: i64,
}

#[derive(uniffi::Record)]
pub struct FfiPrekeyUploadOtk {
    pub id: i32,
    pub pubkey: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiPrekeyUpload {
    pub identity_key: Vec<u8>,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: Vec<u8>,
    pub signed_pre_key_sig: Vec<u8>,
    pub one_time_pre_keys: Vec<FfiPrekeyUploadOtk>,
}

#[derive(uniffi::Record)]
pub struct FfiResolved {
    pub username: String,
    pub user_id: i64,
    pub display_name: String,
}

#[derive(uniffi::Record)]
pub struct FfiProfile {
    pub user_id: i64,
    pub display_name: String,
    pub bio: String,
}

#[derive(uniffi::Record)]
pub struct FfiDevice {
    pub device_id: i64,
    pub purpose: String,
    pub disabled: bool,
}

#[derive(uniffi::Record)]
pub struct FfiPeerDevice {
    pub device_id: i64,
    pub identity_key: Vec<u8>,
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: Vec<u8>,
    pub signed_pre_key_sig: Vec<u8>,
    pub one_time_pre_key_id: i32,
    pub one_time_pre_key_pub: Vec<u8>,
    /// Raw `PrekeyBundleProof` JSON blob — feed into `NotegramCore.verify_peer_bundle`
    /// before trusting any of the fields above.
    pub proof: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiEncryptedRecipient {
    pub user_id: i64,
    pub device_id: i64,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiEncryptedSent {
    pub server_msg_id: String,
    pub created_at: i64,
    pub recipient_count: i32,
}

/// An encrypted message waiting for this device. Feed `header`, `ciphertext`
/// and `associated_data` into `NotegramCore.decrypt_message`, then ack it by
/// `server_msg_id` so the server stops redelivering it.
#[derive(uniffi::Record)]
pub struct FfiIncomingMessage {
    pub server_msg_id: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,
    pub schema: String,
    pub suite: String,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub associated_data: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn dial_tls(addr: &str) -> Result<Tls, FfiNetError> {
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| addr.to_string());
    let tcp = TcpStream::connect(addr).await.map_err(|_| FfiNetError::Io)?;
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| FfiNetError::Tls)?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let domain = ServerName::try_from(host).map_err(|_| FfiNetError::BadInput)?;
    connector
        .connect(domain, tcp)
        .await
        .map_err(|_| FfiNetError::Tls)
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn arr32(v: &[u8]) -> Result<[u8; 32], FfiNetError> {
    v.try_into().map_err(|_| FfiNetError::BadInput)
}

#[derive(uniffi::Object)]
pub struct NetSession {
    inner: Mutex<Session<Tls>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl NetSession {
    #[uniffi::constructor]
    pub async fn connect(edge_addr: String, route_dc: u32) -> Result<Arc<Self>, FfiNetError> {
        let tls = dial_tls(&edge_addr).await?;
        let session = Session::open(tls, now_nanos(), route_dc).await?;
        Ok(Arc::new(NetSession {
            inner: Mutex::new(session),
        }))
    }

    #[uniffi::constructor]
    pub async fn resume(
        edge_addr: String,
        route_dc: u32,
        auth_key: Vec<u8>,
        auth_key_id: u64,
    ) -> Result<Arc<Self>, FfiNetError> {
        let ak = arr32(&auth_key)?;
        let tls = dial_tls(&edge_addr).await?;
        let session = Session::open_authed(tls, now_nanos(), route_dc, ak, auth_key_id).await?;
        Ok(Arc::new(NetSession {
            inner: Mutex::new(session),
        }))
    }

    pub async fn send_email_code(
        &self,
        email: String,
        purpose: String,
        device_id: i64,
    ) -> Result<FfiSentCode, FfiNetError> {
        let r = self
            .inner
            .lock()
            .await
            .send_email_code(&email, &purpose, device_id)
            .await?;
        Ok(FfiSentCode {
            email_hash: r.email_hash,
            timeout: r.timeout,
        })
    }

    pub async fn verify_email_code(
        &self,
        email: String,
        email_hash: Vec<u8>,
        code: String,
    ) -> Result<FfiVerified, FfiNetError> {
        let r = self
            .inner
            .lock()
            .await
            .verify_email_code(&email, email_hash, &code)
            .await?;
        Ok(FfiVerified {
            user_id: r.user_id,
            tmp_token: r.tmp_token,
        })
    }

    pub async fn authenticate(
        &self,
        verified: FfiVerified,
        client_info: Vec<u8>,
        server_ed_pub: Vec<u8>,
    ) -> Result<FfiAuthKeys, FfiNetError> {
        let ed = arr32(&server_ed_pub)?;
        let user_id = verified.user_id;
        let v = AuthVerified {
            user_id,
            tmp_token: verified.tmp_token,
            expires_in: 0,
        };
        let est = self
            .inner
            .lock()
            .await
            .authenticate(&v, client_info, &ed, &mut OsRng)
            .await?;
        Ok(FfiAuthKeys {
            auth_key: est.auth_key.to_vec(),
            auth_key_id: est.auth_key_id,
            user_id,
        })
    }

    pub async fn resolve_username(&self, name: String) -> Result<FfiResolved, FfiNetError> {
        let r = self.inner.lock().await.resolve_username(&name).await?;
        Ok(FfiResolved {
            username: r.username,
            user_id: r.user_id,
            display_name: r.display_name,
        })
    }

    pub async fn get_my_username(&self) -> Result<String, FfiNetError> {
        Ok(self.inner.lock().await.get_my_username().await?.username)
    }

    pub async fn claim_username(&self, name: String) -> Result<String, FfiNetError> {
        Ok(self.inner.lock().await.claim_username(&name).await?.username)
    }

    pub async fn get_my_profile(&self) -> Result<FfiProfile, FfiNetError> {
        let p = self.inner.lock().await.get_my_profile().await?;
        Ok(FfiProfile {
            user_id: p.user_id,
            display_name: p.display_name,
            bio: p.bio,
        })
    }

    pub async fn set_profile(
        &self,
        display_name: String,
        bio: String,
    ) -> Result<FfiProfile, FfiNetError> {
        let p = self
            .inner
            .lock()
            .await
            .set_profile(&display_name, &bio)
            .await?;
        Ok(FfiProfile {
            user_id: p.user_id,
            display_name: p.display_name,
            bio: p.bio,
        })
    }

    pub async fn get_devices(&self) -> Result<Vec<FfiDevice>, FfiNetError> {
        let d = self.inner.lock().await.get_devices().await?;
        Ok(d.devices
            .into_iter()
            .map(|x| FfiDevice {
                device_id: x.device_id,
                purpose: x.purpose,
                disabled: x.disabled,
            })
            .collect())
    }

    pub async fn ping(&self, ping_id: i64) -> Result<i64, FfiNetError> {
        Ok(self.inner.lock().await.ping(ping_id).await?.now)
    }

    pub async fn keys_upload(&self, bundle: FfiPrekeyUpload) -> Result<i64, FfiNetError> {
        let one_time = bundle
            .one_time_pre_keys
            .into_iter()
            .map(|k| tl::generated::OneTimePreKey {
                id: k.id,
                r#pub: k.pubkey,
            })
            .collect();
        let r = self
            .inner
            .lock()
            .await
            .keys_upload(
                bundle.identity_key,
                bundle.signed_pre_key_id,
                bundle.signed_pre_key_pub,
                bundle.signed_pre_key_sig,
                one_time,
            )
            .await?;
        Ok(r.device_id)
    }

    pub async fn set_device_signing_key(
        &self,
        public_key: Vec<u8>,
    ) -> Result<i64, FfiNetError> {
        let r = self
            .inner
            .lock()
            .await
            .set_device_signing_key(public_key)
            .await?;
        Ok(r.device_id)
    }

    pub async fn get_peer_bundle(&self, user_id: i64) -> Result<Vec<FfiPeerDevice>, FfiNetError> {
        let r = self.inner.lock().await.get_peer_bundle(user_id).await?;
        Ok(r.devices
            .into_iter()
            .map(|d| FfiPeerDevice {
                device_id: d.device_id,
                identity_key: d.identity_key,
                signed_pre_key_id: d.signed_pre_key_id,
                signed_pre_key_pub: d.signed_pre_key_pub,
                signed_pre_key_sig: d.signed_pre_key_sig,
                one_time_pre_key_id: d.one_time_pre_key_id,
                one_time_pre_key_pub: d.one_time_pre_key_pub,
                proof: d.proof,
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_encrypted(
        &self,
        client_msg_id: String,
        chat_id: i64,
        schema: String,
        suite: String,
        recipients: Vec<FfiEncryptedRecipient>,
        associated_data: Vec<u8>,
        forward_info: Option<Vec<u8>>,
        reply_to: Option<i64>,
    ) -> Result<FfiEncryptedSent, FfiNetError> {
        let recipients = recipients
            .into_iter()
            .map(|r| tl::generated::MessagesEncryptedRecipient {
                user_id: r.user_id,
                device_id: r.device_id,
                envelope_type: r.envelope_type,
                header: r.header,
                ciphertext: r.ciphertext,
            })
            .collect();
        let r = self
            .inner
            .lock()
            .await
            .send_encrypted(
                &client_msg_id,
                chat_id,
                &schema,
                &suite,
                recipients,
                associated_data,
                forward_info,
                reply_to,
            )
            .await?;
        Ok(FfiEncryptedSent {
            server_msg_id: r.server_msg_id,
            created_at: r.created_at,
            recipient_count: r.recipient_count,
        })
    }

    pub async fn get_encrypted_messages(
        &self,
        limit: i32,
    ) -> Result<Vec<FfiIncomingMessage>, FfiNetError> {
        let batch = self
            .inner
            .lock()
            .await
            .get_encrypted_messages(limit)
            .await?;
        Ok(batch
            .items
            .into_iter()
            .map(|m| FfiIncomingMessage {
                server_msg_id: m.server_msg_id,
                sender_user_id: m.sender_user_id,
                sender_device_id: m.sender_device_id,
                chat_id: m.chat_id,
                client_msg_id: m.client_msg_id,
                schema: m.schema,
                suite: m.suite,
                envelope_type: m.envelope_type,
                header: m.header,
                ciphertext: m.ciphertext,
                associated_data: m.associated_data,
                created_at: m.created_at,
            })
            .collect())
    }

    pub async fn ack_encrypted(&self, server_msg_id: String) -> Result<bool, FfiNetError> {
        let r = self
            .inner
            .lock()
            .await
            .ack_encrypted(&server_msg_id)
            .await?;
        Ok(r.deleted)
    }
}
