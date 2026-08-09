use std::fmt;

use rand_core::{CryptoRng, RngCore};

use crypto::{ed25519_verify, hkdf_sha256, hmac_sha256, sha256, x25519_dh, x25519_generate};
use tl::generated::{
    AuthBeginHandshake, AuthFinishHandshake, AuthHandshakeOk, AuthHandshakeParams,
};

const AUTH_KEY_INFO_LABEL: &str = "session-gateway/auth-key/v2";
const SERVER_PARAMS_LABEL: &str = "session-gateway/server-params/v2";
const CLIENT_FINISHED_LABEL: &str = "client-finished";
const SERVER_FINISHED_LABEL: &str = "server-finished";

const X25519_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    BadField(&'static str),

    Signature,

    AuthKeyIdMismatch,

    ServerFinished,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::BadField(w) => write!(f, "handshake: bad field: {w}"),
            HandshakeError::Signature => write!(f, "handshake: server params signature invalid"),
            HandshakeError::AuthKeyIdMismatch => write!(f, "handshake: auth-key id mismatch"),
            HandshakeError::ServerFinished => write!(f, "handshake: server finished invalid"),
        }
    }
}

impl std::error::Error for HandshakeError {}

pub struct Transcript {
    pub tmp_token: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub server_nonce: Vec<u8>,
    pub client_eph_pub: Vec<u8>,
    pub server_eph_pub: Vec<u8>,
    pub epoch: u32,
    pub session_id: u64,
    pub salt: u64,
}

pub fn transcript_bytes(label: &str, t: &Transcript, server_pub_key_id: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(label.len() + 64);
    buf.extend_from_slice(label.as_bytes());
    append_tl_bytes(&mut buf, &t.tmp_token);
    append_tl_bytes(&mut buf, &t.client_nonce);
    append_tl_bytes(&mut buf, &t.server_nonce);
    append_tl_bytes(&mut buf, &t.client_eph_pub);
    append_tl_bytes(&mut buf, &t.server_eph_pub);
    buf.extend_from_slice(&t.epoch.to_le_bytes());
    buf.extend_from_slice(&t.session_id.to_le_bytes());
    buf.extend_from_slice(&t.salt.to_le_bytes());
    buf.extend_from_slice(&(server_pub_key_id as u64).to_le_bytes());
    buf
}

fn append_tl_bytes(dst: &mut Vec<u8>, src: &[u8]) {
    dst.extend_from_slice(&(src.len() as u32).to_le_bytes());
    dst.extend_from_slice(src);
}

pub fn derive_auth_key(shared_secret: &[u8], t: &Transcript, server_pub_key_id: i64) -> [u8; 32] {
    let info = transcript_bytes(AUTH_KEY_INFO_LABEL, t, server_pub_key_id);
    let mut out = [0u8; 32];
    hkdf_sha256(shared_secret, None, &info, &mut out);
    out
}

pub fn compute_finished(
    auth_key: &[u8; 32],
    label: &str,
    t: &Transcript,
    server_pub_key_id: i64,
) -> [u8; 32] {
    hmac_sha256(auth_key, &transcript_bytes(label, t, server_pub_key_id))
}

pub fn auth_key_id(auth_key: &[u8; 32]) -> u64 {
    wire::u64_le(&sha256(auth_key)[..8])
}

pub fn verify_server_params_sig(
    server_ed_pub: &[u8; 32],
    t: &Transcript,
    server_pub_key_id: i64,
    sig: &[u8; 64],
) -> bool {
    ed25519_verify(
        server_ed_pub,
        &transcript_bytes(SERVER_PARAMS_LABEL, t, server_pub_key_id),
        sig,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSecure {
    pub auth_key: [u8; 32],
    pub auth_key_id: u64,
    pub epoch: u32,
    pub salt: u64,
    pub session_id: u64,
    /// The account's username, carried by the handshake result so a client does
    /// not have to spend another round trip asking. Empty when the account has
    /// none yet, which is what a fresh sign-up looks like.
    pub username: String,
}

pub struct ClientHandshake {
    tmp_token: Vec<u8>,
    client_nonce: Vec<u8>,
    client_eph_priv: [u8; 32],
    client_eph_pub: [u8; 32],
    session_id: u64,
}

pub struct ClientFinishing {
    transcript: Transcript,
    server_pub_key_id: i64,
    established: EstablishedSecure,
}

impl ClientHandshake {
    /// Adopts the token issued alongside the handshake parameters. The merged
    /// sign-in request has no token to send up front — the server mints it in
    /// the same exchange — so the state is completed once the reply arrives.
    pub fn with_tmp_token(mut self, tmp_token: Vec<u8>) -> Self {
        self.tmp_token = tmp_token;
        self
    }

    pub fn begin<R: RngCore + CryptoRng>(
        tmp_token: Vec<u8>,
        client_info: Vec<u8>,
        session_id: u64,
        rng: &mut R,
    ) -> (Self, AuthBeginHandshake) {
        let (client_eph_priv, client_eph_pub) = x25519_generate(rng);
        let mut client_nonce = [0u8; 32];
        rng.fill_bytes(&mut client_nonce);

        let begin = AuthBeginHandshake {
            tmp_token: tmp_token.clone(),
            client_nonce: client_nonce.to_vec(),
            client_eph_pub: client_eph_pub.to_vec(),
            client_info,
        };
        let state = ClientHandshake {
            tmp_token,
            client_nonce: client_nonce.to_vec(),
            client_eph_priv,
            client_eph_pub,
            session_id,
        };
        (state, begin)
    }

    pub fn on_params(
        self,
        params: &AuthHandshakeParams,
        server_ed_pub: &[u8; 32],
    ) -> Result<(AuthFinishHandshake, ClientFinishing), HandshakeError> {
        let server_eph_pub = to_array::<X25519_LEN>(&params.server_eph_pub)
            .ok_or(HandshakeError::BadField("server_eph_pub"))?;
        let sig =
            to_array::<ED25519_SIG_LEN>(&params.sig).ok_or(HandshakeError::BadField("sig"))?;

        let transcript = Transcript {
            tmp_token: self.tmp_token,
            client_nonce: self.client_nonce,
            server_nonce: params.server_nonce.clone(),
            client_eph_pub: self.client_eph_pub.to_vec(),
            server_eph_pub: server_eph_pub.to_vec(),
            epoch: params.epoch as u32,
            session_id: self.session_id,
            salt: params.salt,
        };

        if !verify_server_params_sig(server_ed_pub, &transcript, params.server_pub_key_id, &sig) {
            return Err(HandshakeError::Signature);
        }

        let shared = x25519_dh(&self.client_eph_priv, &server_eph_pub);
        let auth_key = derive_auth_key(&shared, &transcript, params.server_pub_key_id);
        let client_finished = compute_finished(
            &auth_key,
            CLIENT_FINISHED_LABEL,
            &transcript,
            params.server_pub_key_id,
        );

        let finish = AuthFinishHandshake {
            tmp_token: transcript.tmp_token.clone(),
            client_nonce: transcript.client_nonce.clone(),
            server_nonce: transcript.server_nonce.clone(),
            epoch: params.epoch,
            client_finished: client_finished.to_vec(),
        };
        let finishing = ClientFinishing {
            established: EstablishedSecure {
                auth_key,
                auth_key_id: auth_key_id(&auth_key),
                epoch: transcript.epoch,
                salt: transcript.salt,
                session_id: transcript.session_id,
                // Filled in from the server's reply once it arrives.
                username: String::new(),
            },
            transcript,
            server_pub_key_id: params.server_pub_key_id,
        };
        Ok((finish, finishing))
    }
}

impl ClientFinishing {
    pub fn on_ok(self, ok: &AuthHandshakeOk) -> Result<EstablishedSecure, HandshakeError> {
        if ok.auth_key_id != self.established.auth_key_id {
            return Err(HandshakeError::AuthKeyIdMismatch);
        }
        let expected = compute_finished(
            &self.established.auth_key,
            SERVER_FINISHED_LABEL,
            &self.transcript,
            self.server_pub_key_id,
        );
        if !ct_eq(&ok.server_finished, &expected) {
            return Err(HandshakeError::ServerFinished);
        }
        // Only trusted once the server has proven it holds the same key: the
        // username arrives in the same reply, and reading it before the check
        // would mean believing an unauthenticated value.
        let mut established = self.established;
        established.username = ok.username.clone();
        Ok(established)
    }
}

fn to_array<const N: usize>(src: &[u8]) -> Option<[u8; N]> {
    src.try_into().ok()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
