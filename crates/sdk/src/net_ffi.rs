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
}
