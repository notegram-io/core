use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use rand_core::{CryptoRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, RwLock};

use proto::EstablishedSecure;
use tl::generated::{
    AuthSendEmailCode, AuthSentCode, AuthVerified, AuthVerifyEmailCode, HelpConfig, HelpGetConfig,
};
use tl::TlObject;
use transport::{Connection, SecureState};

use crate::admission;
use crate::client::Client;
use crate::error::{NetError, Result};
use crate::handshake::{apply_authed_state, run_handshake, FRAME_EPOCH, FRAME_SALT};
use crate::rpc::Rpc;

/// Cap on undrained notices, matching the one the handshake transport applies.
const MAX_BUFFERED_UPDATES: usize = 256;

/// One link to the server, in whichever of its two shapes it currently has.
///
/// Signing in and running are different problems. The handshake rewrites the
/// connection's secure state part-way through — the auth key does not exist
/// until the exchange is nearly done — so it needs the socket to itself and
/// strict turn-taking. Afterwards none of that applies, and the useful shape is
/// the opposite: a reader that owns the read half, so notices arrive without
/// anyone having asked a question and requests stop queueing behind each other.
///
/// Both live behind one object because callers should not have to know which
/// phase they are in, and because the typed API in `api.rs` is written once
/// against `invoke` rather than twice against two transports.
pub struct Session<S: AsyncWrite + Unpin> {
    /// Held only while signing in. Taken, and left empty, on going live.
    handshake: Mutex<Option<Rpc<S>>>,
    /// Set once the link is authenticated. Read without holding a lock across
    /// the call, which is what allows requests to overlap.
    live: RwLock<Option<Arc<Client<S>>>>,
    /// Server-initiated notices from whichever transport is in use, so callers
    /// see one queue across the switch.
    updates: Mutex<VecDeque<Vec<u8>>>,
    session_id: u64,
    authed: AtomicBool,
    user_id: AtomicI64,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<S> {
    /// Sends a request and waits for its answer, over whichever transport is
    /// current.
    pub async fn invoke<Req: TlObject, Resp: TlObject>(&self, req: &Req) -> Result<Resp> {
        // Cloned out of the guard so the lock is not held across the call:
        // holding it would serialise every request and undo the point of the
        // reader-owning client.
        let live = self.live.read().await.clone();
        if let Some(client) = live {
            return client.invoke(req).await;
        }
        let mut guard = self.handshake.lock().await;
        let rpc = guard.as_mut().ok_or(NetError::Closed)?;
        let out = rpc.invoke(req).await;
        // Notices seen while waiting move to the shared queue, so they survive
        // the switch to the live transport.
        let seen = rpc.take_updates();
        drop(guard);
        self.buffer_updates(seen).await;
        out
    }

    async fn buffer_updates(&self, seen: Vec<Vec<u8>>) {
        if seen.is_empty() {
            return;
        }
        let mut queue = self.updates.lock().await;
        for obj in seen {
            if queue.len() >= MAX_BUFFERED_UPDATES {
                queue.pop_front();
            }
            queue.push_back(obj);
        }
    }

    /// Moves whatever the live reader has collected into the shared queue and
    /// hands the queue over.
    pub async fn take_updates(&self) -> Vec<Vec<u8>> {
        let live = self.live.read().await.clone();
        if let Some(client) = live {
            let fresh = client.drain_updates().await;
            self.buffer_updates(fresh).await;
        }
        self.updates.lock().await.drain(..).collect()
    }

    /// Puts back notices a caller pulled out but did not consume.
    pub async fn restore_updates(&self, updates: Vec<Vec<u8>>) {
        let mut queue = self.updates.lock().await;
        for obj in updates.into_iter().rev() {
            if queue.len() >= MAX_BUFFERED_UPDATES {
                break;
            }
            queue.push_front(obj);
        }
    }

    /// Hands the socket to a reader of its own.
    ///
    /// Only valid once the connection is authenticated: the reader takes the
    /// read half, and the handshake still has to rewrite the secure state that
    /// both halves copy. Anything the handshake transport had already buffered
    /// is carried over rather than dropped — a notice that arrived during
    /// sign-in is as real as any other.
    async fn go_live(&self) -> Result<()> {
        let mut guard = self.handshake.lock().await;
        let rpc = match guard.take() {
            Some(rpc) => rpc,
            // Already live, or already closed. Both are fine to ask twice.
            None => return Ok(()),
        };
        let mut rpc = rpc;
        let buffered = rpc.take_updates();
        let conn = rpc.into_connection();
        let state = conn.state().clone();
        let client = Client::new(conn.into_inner(), state);
        *self.live.write().await = Some(Arc::new(client));
        drop(guard);
        self.buffer_updates(buffered).await;
        Ok(())
    }

    /// Whether the link is still usable. A finished reader means the socket is
    /// gone, which callers would otherwise only learn one failed request later.
    pub async fn is_live(&self) -> bool {
        match self.live.read().await.as_ref() {
            Some(client) => client.is_live(),
            None => self.handshake.lock().await.is_some(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Session<S> {
    fn from_rpc(rpc: Rpc<S>, session_id: u64, authed: bool) -> Session<S> {
        Session {
            handshake: Mutex::new(Some(rpc)),
            live: RwLock::new(None),
            updates: Mutex::new(VecDeque::new()),
            session_id,
            authed: AtomicBool::new(authed),
            user_id: AtomicI64::new(0),
        }
    }

    pub async fn open(mut stream: S, session_id: u64, route_dc: u32) -> Result<Session<S>> {
        admission::admit(&mut stream, session_id, route_dc).await?;
        let mut state = SecureState::new_client(session_id);

        state.epoch = FRAME_EPOCH;
        state.salt = FRAME_SALT;
        Ok(Session::from_rpc(
            Rpc::new(Connection::new(stream, state)),
            session_id,
            false,
        ))
    }

    /// Opens a link that is already authenticated, and hands it straight to a
    /// reader: there is no handshake to do, so nothing needs the socket to
    /// itself and the useful shape is available immediately.
    pub async fn open_authed(
        mut stream: S,
        session_id: u64,
        route_dc: u32,
        auth_key: [u8; 32],
        auth_key_id: u64,
    ) -> Result<Session<S>> {
        admission::admit(&mut stream, session_id, route_dc).await?;
        let mut state = SecureState::new_client(session_id);
        state.auth_key = Some(auth_key);
        state.auth_key_id = auth_key_id;
        state.epoch = FRAME_EPOCH;
        state.salt = FRAME_SALT;
        let session = Session::from_rpc(Rpc::new(Connection::new(stream, state)), session_id, true);
        session.go_live().await?;
        Ok(session)
    }

    pub async fn help_get_config(&self) -> Result<HelpConfig> {
        self.invoke(&HelpGetConfig).await
    }

    pub async fn send_email_code(
        &self,
        email: &str,
        purpose: &str,
        device_id: i64,
    ) -> Result<AuthSentCode> {
        self.invoke(&AuthSendEmailCode {
            email: email.to_string(),
            purpose: purpose.to_string(),
            device_id,
        })
        .await
    }

    pub async fn verify_email_code(
        &self,
        email: &str,
        email_hash: Vec<u8>,
        code: &str,
    ) -> Result<AuthVerified> {
        self.invoke(&AuthVerifyEmailCode {
            email: email.to_string(),
            email_hash,
            code: code.to_string(),
        })
        .await
    }

    /// Confirms the emailed code and completes the handshake.
    ///
    /// The code check and the opening of the handshake go out together: split
    /// apart, the second request carries only the token the first just issued,
    /// so it costs a round trip over the internet that the user waits out on
    /// the confirm button.
    pub async fn verify_and_authenticate<R: RngCore + CryptoRng>(
        &self,
        email: &str,
        email_hash: Vec<u8>,
        code: &str,
        client_info: Vec<u8>,
        server_ed_pub: &[u8; 32],
        rng: &mut R,
    ) -> Result<EstablishedSecure> {
        // Held for the whole exchange: the auth key does not exist until it is
        // nearly over, and the connection's secure state is rewritten at the
        // end. Nothing else may use the socket in between.
        let mut guard = self.handshake.lock().await;
        let rpc = guard.as_mut().ok_or(NetError::Closed)?;

        let (client, begin) =
            proto::ClientHandshake::begin(Vec::new(), client_info, self.session_id, rng);
        let opened: tl::generated::AuthVerifiedHandshake = rpc
            .invoke(&tl::generated::AuthVerifyAndBegin {
                email: email.to_string(),
                email_hash,
                code: code.to_string(),
                client_nonce: begin.client_nonce,
                client_eph_pub: begin.client_eph_pub,
                client_info: begin.client_info,
            })
            .await?;

        // The token is issued by the same reply, so the handshake state has to
        // adopt it before it can be finished.
        let client = client.with_tmp_token(opened.tmp_token);
        let (finish, finishing) = client
            .on_params(&opened.params, server_ed_pub)
            .map_err(NetError::Handshake)?;
        // Sent without waiting for the acknowledgement.
        //
        // The server authenticated itself in the reply above — its parameters
        // carry a signature that on_params checked — and the key is already
        // derived from them, so the reply to this only tells us something we
        // have established. What it does carry is the client's proof, which the
        // server needs; TCP ordering puts it ahead of every later request, so
        // the server sees it before anything that depends on it.
        //
        // The cost is where a rejection surfaces: instead of failing here, a
        // refused proof shows up as the next request being unauthenticated.
        rpc.send(&finish).await?;

        let mut established = finishing.into_established();
        established.username = opened.username;
        apply_authed_state(rpc.connection_mut(), &established);
        self.authed.store(true, Ordering::Release);
        self.user_id.store(opened.user_id, Ordering::Release);
        drop(guard);
        // The state is settled, so the socket can be handed to its reader.
        self.go_live().await?;
        Ok(established)
    }

    pub async fn authenticate<R: RngCore + CryptoRng>(
        &self,
        verified: &AuthVerified,
        client_info: Vec<u8>,
        server_ed_pub: &[u8; 32],
        rng: &mut R,
    ) -> Result<EstablishedSecure> {
        let mut guard = self.handshake.lock().await;
        let rpc = guard.as_mut().ok_or(NetError::Closed)?;
        let est = run_handshake(
            rpc,
            verified.tmp_token.clone(),
            client_info,
            self.session_id,
            server_ed_pub,
            rng,
        )
        .await?;
        self.authed.store(true, Ordering::Release);
        self.user_id.store(verified.user_id, Ordering::Release);
        drop(guard);
        self.go_live().await?;
        Ok(est)
    }

    pub fn is_authenticated(&self) -> bool {
        self.authed.load(Ordering::Acquire)
    }

    pub fn user_id(&self) -> i64 {
        self.user_id.load(Ordering::Acquire)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{ed25519_public, ed25519_sign, x25519_dh, x25519_generate};
    use proto::handshake::{
        auth_key_id, compute_finished, derive_auth_key, transcript_bytes, Transcript,
    };
    use tl::generated::{
        AuthBeginHandshake, AuthFinishHandshake, AuthHandshakeOk, AuthHandshakeParams,
        InvokeWithLayer, Ping, Pong,
    };
    use tl::{decode_from, encode_to_vec, Limits, TlObject};
    use tokio::io::AsyncWriteExt;
    use transport::DIR_S2C;

    use crate::frame::{build_plain_frame, read_plain_frame, DEFAULT_MAX_FRAME};

    struct CounterRng(u64);
    impl rand_core::RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            ((self.next_u32() as u64) << 32) | self.next_u32() as u64
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(4) {
                let b = self.next_u32().to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for CounterRng {}

    async fn recv_req<S, Req>(conn: &mut Connection<S>) -> Req
    where
        S: AsyncRead + AsyncWrite + Unpin,
        Req: TlObject,
    {
        let (_h, frames) = conn.recv_frames().await.unwrap();
        let invoke = decode_from::<InvokeWithLayer>(&frames[0], Limits::default()).unwrap();
        decode_from::<Req>(&invoke.query, Limits::default()).unwrap()
    }

    /// Answers the request just read, in the envelope naming it — the way the
    /// real server replies. A bare object is a server-initiated notice, not an
    /// answer, so a fake that sends one leaves the client waiting.
    async fn send_obj<S, T>(conn: &mut Connection<S>, obj: &T)
    where
        S: AsyncRead + AsyncWrite + Unpin,
        T: TlObject,
    {
        let body = encode_to_vec(obj).unwrap();
        let answer = encode_to_vec(&tl::generated::RpcAnswer {
            req_msg_id: conn.last_read_msg_id() as i64,
            body,
        })
        .unwrap();
        conn.send_frames(&[&answer]).await.unwrap();
    }

    async fn mock_edge<S: AsyncRead + AsyncWrite + Unpin>(
        mut io: S,
        route_dc: u32,
        session_id: u64,
        server_seed: [u8; 32],
        server_pub_key_id: i64,
        expect_code: &str,
    ) {
        let (_h, init) = read_plain_frame(&mut io, DEFAULT_MAX_FRAME).await.unwrap();
        assert_eq!(init[0], 0, "init tag");
        assert_eq!(wire::u32_le(&init[1..5]), route_dc);
        let ts: u64 = 0x1122_3344;
        let cookie = [0x5Au8; 16];
        let mut ch = [0u8; 29];
        ch[0] = 1;
        ch[1..5].copy_from_slice(&route_dc.to_le_bytes());
        ch[5..13].copy_from_slice(&ts.to_le_bytes());
        ch[13..].copy_from_slice(&cookie);
        io.write_all(&build_plain_frame(session_id, 1, &ch))
            .await
            .unwrap();
        io.flush().await.unwrap();
        let (_h, auth) = read_plain_frame(&mut io, DEFAULT_MAX_FRAME).await.unwrap();
        assert_eq!(auth[0], 2, "auth tag");
        assert_eq!(&auth[13..], &cookie, "auth echoes cookie");
        io.write_all(&build_plain_frame(session_id, 3, &[3]))
            .await
            .unwrap();
        io.flush().await.unwrap();

        let mut st = SecureState::new_client(session_id);
        st.out_direction = DIR_S2C;
        st.epoch = FRAME_EPOCH;
        st.salt = FRAME_SALT;
        let mut conn = Connection::new(io, st);

        let _cfg: HelpGetConfig = recv_req(&mut conn).await;
        send_obj(
            &mut conn,
            &HelpConfig {
                now: 1_700_000_000,
                dc_options: vec![],
            },
        )
        .await;

        let sec: AuthSendEmailCode = recv_req(&mut conn).await;
        let email_hash = vec![0xEEu8; 8];
        send_obj(
            &mut conn,
            &AuthSentCode {
                email: sec.email.clone(),
                email_hash: email_hash.clone(),
                timeout: 60,
            },
        )
        .await;

        let ver: AuthVerifyEmailCode = recv_req(&mut conn).await;
        assert_eq!(ver.email_hash, email_hash);
        assert_eq!(ver.code, expect_code, "server sees the entered code");
        let tmp_token = b"tmp-token-abc".to_vec();
        send_obj(
            &mut conn,
            &AuthVerified {
                user_id: 5001,
                tmp_token: tmp_token.clone(),
                expires_in: 600,
            },
        )
        .await;

        let mut rng = CounterRng(0x9999);
        let (server_eph_priv, server_eph_pub) = x25519_generate(&mut rng);
        let begin: AuthBeginHandshake = recv_req(&mut conn).await;
        assert_eq!(
            begin.tmp_token, tmp_token,
            "begin carries the verified token"
        );
        let client_eph_pub: [u8; 32] = begin.client_eph_pub.clone().try_into().unwrap();
        let t = Transcript {
            tmp_token: begin.tmp_token.clone(),
            client_nonce: begin.client_nonce.clone(),
            server_nonce: b"srv-nonce-0123456789-abcdefghij".to_vec(),
            client_eph_pub: client_eph_pub.to_vec(),
            server_eph_pub: server_eph_pub.to_vec(),
            epoch: 11,
            session_id,
            salt: 0x0102_0304_0506_0708,
        };
        let sig = ed25519_sign(
            &server_seed,
            &transcript_bytes("session-gateway/server-params/v2", &t, server_pub_key_id),
        );
        send_obj(
            &mut conn,
            &AuthHandshakeParams {
                server_nonce: t.server_nonce.clone(),
                server_eph_pub: server_eph_pub.to_vec(),
                server_pub_key_id,
                sig: sig.to_vec(),
                salt: t.salt,
                epoch: t.epoch as i32,
                expires_in: 3600,
            },
        )
        .await;

        let _finish: AuthFinishHandshake = recv_req(&mut conn).await;
        let server_shared = x25519_dh(&server_eph_priv, &client_eph_pub);
        let server_auth_key = derive_auth_key(&server_shared, &t, server_pub_key_id);
        send_obj(
            &mut conn,
            &AuthHandshakeOk {
                auth_key_id: auth_key_id(&server_auth_key),
                epoch: t.epoch as i32,
                server_finished: compute_finished(
                    &server_auth_key,
                    "server-finished",
                    &t,
                    server_pub_key_id,
                )
                .to_vec(),
                expires_in: 3600,
                username: String::new(),
            },
        )
        .await;

        let mut ast = SecureState::new_client(session_id);
        ast.auth_key = Some(server_auth_key);
        ast.auth_key_id = auth_key_id(&server_auth_key);
        ast.epoch = FRAME_EPOCH;
        ast.salt = FRAME_SALT;
        ast.out_direction = DIR_S2C;
        *conn.state_mut() = ast;

        let ping: Ping = recv_req(&mut conn).await;
        send_obj(
            &mut conn,
            &Pong {
                ping_id: ping.ping_id,
                now: 777,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn full_login_flow_over_one_connection() {
        let (client_io, server_io) = tokio::io::duplex(16384);
        let server_seed = [0x33u8; 32];
        let server_ed_pub = ed25519_public(&server_seed);
        let server_pub_key_id: i64 = 9;
        let session_id = 0x0BAD_F00Du64;
        let route_dc = 1u32;

        let edge = tokio::spawn(mock_edge(
            server_io,
            route_dc,
            session_id,
            server_seed,
            server_pub_key_id,
            "123456",
        ));

        let mut session = Session::open(client_io, session_id, route_dc)
            .await
            .expect("open/admit");
        assert!(!session.is_authenticated());

        let cfg = session.help_get_config().await.expect("help");
        assert_eq!(cfg.now, 1_700_000_000);

        let sent = session
            .send_email_code("user@example.com", "login", 7001)
            .await
            .expect("sendEmailCode");
        assert_eq!(sent.timeout, 60);

        let verified = session
            .verify_email_code("user@example.com", sent.email_hash.clone(), "123456")
            .await
            .expect("verifyEmailCode");
        assert_eq!(verified.user_id, 5001);
        assert!(!verified.tmp_token.is_empty());

        let mut rng = CounterRng(0x00C0_FFEE);
        session
            .authenticate(
                &verified,
                br#"{"device":"test"}"#.to_vec(),
                &server_ed_pub,
                &mut rng,
            )
            .await
            .expect("authenticate");
        assert!(session.is_authenticated());
        assert_eq!(session.user_id(), 5001);

        // Through the live transport: authenticating hands the socket to its
        // own reader, so this exercises the switch as well as the ping.
        let pong: Pong = session
            .invoke(&Ping { ping_id: 3 })
            .await
            .expect("authed ping");
        assert_eq!((pong.ping_id, pong.now), (3, 777));

        edge.await.unwrap();
    }
}
