use rand_core::{CryptoRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};

use proto::EstablishedSecure;
use tl::generated::{
    AuthSendEmailCode, AuthSentCode, AuthVerified, AuthVerifyEmailCode, HelpConfig, HelpGetConfig,
};
use transport::{Connection, SecureState};

use crate::admission;
use crate::error::Result;
use crate::handshake::{run_handshake, FRAME_EPOCH, FRAME_SALT};
use crate::rpc::Rpc;

pub struct Session<S> {
    rpc: Rpc<S>,
    session_id: u64,
    authed: bool,
    user_id: i64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {

    pub async fn open(mut stream: S, session_id: u64, route_dc: u32) -> Result<Session<S>> {
        admission::admit(&mut stream, session_id, route_dc).await?;
        let mut state = SecureState::new_client(session_id);

        state.epoch = FRAME_EPOCH;
        state.salt = FRAME_SALT;
        Ok(Session {
            rpc: Rpc::new(Connection::new(stream, state)),
            session_id,
            authed: false,
            user_id: 0,
        })
    }

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
        Ok(Session {
            rpc: Rpc::new(Connection::new(stream, state)),
            session_id,
            authed: true,
            user_id: 0,
        })
    }

    pub async fn help_get_config(&mut self) -> Result<HelpConfig> {
        self.rpc.invoke(&HelpGetConfig).await
    }

    pub async fn send_email_code(
        &mut self,
        email: &str,
        purpose: &str,
        device_id: i64,
    ) -> Result<AuthSentCode> {
        self.rpc
            .invoke(&AuthSendEmailCode {
                email: email.to_string(),
                purpose: purpose.to_string(),
                device_id,
            })
            .await
    }

    pub async fn verify_email_code(
        &mut self,
        email: &str,
        email_hash: Vec<u8>,
        code: &str,
    ) -> Result<AuthVerified> {
        self.rpc
            .invoke(&AuthVerifyEmailCode {
                email: email.to_string(),
                email_hash,
                code: code.to_string(),
            })
            .await
    }

    pub async fn authenticate<R: RngCore + CryptoRng>(
        &mut self,
        verified: &AuthVerified,
        client_info: Vec<u8>,
        server_ed_pub: &[u8; 32],
        rng: &mut R,
    ) -> Result<EstablishedSecure> {
        let est = run_handshake(
            &mut self.rpc,
            verified.tmp_token.clone(),
            client_info,
            self.session_id,
            server_ed_pub,
            rng,
        )
        .await?;
        self.authed = true;
        self.user_id = verified.user_id;
        Ok(est)
    }

    pub fn is_authenticated(&self) -> bool {
        self.authed
    }

    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn rpc_mut(&mut self) -> &mut Rpc<S> {
        &mut self.rpc
    }

    pub fn into_rpc(self) -> Rpc<S> {
        self.rpc
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
        AuthBeginHandshake, AuthFinishHandshake, AuthHandshakeOk, AuthHandshakeParams, InvokeWithLayer,
        Ping, Pong,
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

    async fn send_obj<S, T>(conn: &mut Connection<S>, obj: &T)
    where
        S: AsyncRead + AsyncWrite + Unpin,
        T: TlObject,
    {
        let b = encode_to_vec(obj).unwrap();
        conn.send_frames(&[&b]).await.unwrap();
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
        io.write_all(&build_plain_frame(session_id, 1, &ch)).await.unwrap();
        io.flush().await.unwrap();
        let (_h, auth) = read_plain_frame(&mut io, DEFAULT_MAX_FRAME).await.unwrap();
        assert_eq!(auth[0], 2, "auth tag");
        assert_eq!(&auth[13..], &cookie, "auth echoes cookie");
        io.write_all(&build_plain_frame(session_id, 3, &[3])).await.unwrap();
        io.flush().await.unwrap();

        let mut st = SecureState::new_client(session_id);
        st.out_direction = DIR_S2C;
        st.epoch = FRAME_EPOCH;
        st.salt = FRAME_SALT;
        let mut conn = Connection::new(io, st);

        let _cfg: HelpGetConfig = recv_req(&mut conn).await;
        send_obj(&mut conn, &HelpConfig { now: 1_700_000_000, dc_options: vec![] }).await;

        let sec: AuthSendEmailCode = recv_req(&mut conn).await;
        let email_hash = vec![0xEEu8; 8];
        send_obj(
            &mut conn,
            &AuthSentCode { email: sec.email.clone(), email_hash: email_hash.clone(), timeout: 60 },
        )
        .await;

        let ver: AuthVerifyEmailCode = recv_req(&mut conn).await;
        assert_eq!(ver.email_hash, email_hash);
        assert_eq!(ver.code, expect_code, "server sees the entered code");
        let tmp_token = b"tmp-token-abc".to_vec();
        send_obj(
            &mut conn,
            &AuthVerified { user_id: 5001, tmp_token: tmp_token.clone(), expires_in: 600 },
        )
        .await;

        let mut rng = CounterRng(0x9999);
        let (server_eph_priv, server_eph_pub) = x25519_generate(&mut rng);
        let begin: AuthBeginHandshake = recv_req(&mut conn).await;
        assert_eq!(begin.tmp_token, tmp_token, "begin carries the verified token");
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
        send_obj(&mut conn, &Pong { ping_id: ping.ping_id, now: 777 }).await;
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
            .authenticate(&verified, br#"{"device":"test"}"#.to_vec(), &server_ed_pub, &mut rng)
            .await
            .expect("authenticate");
        assert!(session.is_authenticated());
        assert_eq!(session.user_id(), 5001);

        let pong: Pong = session.rpc_mut().invoke(&Ping { ping_id: 3 }).await.expect("authed ping");
        assert_eq!((pong.ping_id, pong.now), (3, 777));

        edge.await.unwrap();
    }
}
