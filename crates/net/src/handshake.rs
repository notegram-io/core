use rand_core::{CryptoRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};

use proto::{ClientHandshake, EstablishedSecure};
use tl::generated::{AuthHandshakeOk, AuthHandshakeParams};
use transport::{Connection, SecureState, DIR_C2S};

use crate::error::{NetError, Result};
use crate::rpc::Rpc;

pub const FRAME_EPOCH: u32 = 1;
pub const FRAME_SALT: u64 = 1;

pub async fn run_handshake<S, R>(
    rpc: &mut Rpc<S>,
    tmp_token: Vec<u8>,
    client_info: Vec<u8>,
    session_id: u64,
    server_ed_pub: &[u8; 32],
    rng: &mut R,
) -> Result<EstablishedSecure>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: RngCore + CryptoRng,
{
    let (client, begin) = ClientHandshake::begin(tmp_token, client_info, session_id, rng);
    let params: AuthHandshakeParams = rpc.invoke(&begin).await?;
    let (finish, finishing) = client
        .on_params(&params, server_ed_pub)
        .map_err(NetError::Handshake)?;
    let ok: AuthHandshakeOk = rpc.invoke(&finish).await?;
    let established = finishing.on_ok(&ok).map_err(NetError::Handshake)?;
    apply_authed_state(rpc.connection_mut(), &established);
    Ok(established)
}

fn apply_authed_state<S>(conn: &mut Connection<S>, est: &EstablishedSecure) {
    let mut st = SecureState::new_client(est.session_id);
    st.auth_key = Some(est.auth_key);
    st.auth_key_id = est.auth_key_id;
    st.epoch = FRAME_EPOCH;
    st.salt = FRAME_SALT;
    st.out_direction = DIR_C2S;
    *conn.state_mut() = st;
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
    use transport::DIR_S2C;

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

    fn authed_state(session_id: u64, auth_key: [u8; 32], dir: u8) -> SecureState {
        let mut st = SecureState::new_client(session_id);
        st.auth_key = Some(auth_key);
        st.auth_key_id = auth_key_id(&auth_key);
        st.epoch = FRAME_EPOCH;
        st.salt = FRAME_SALT;
        st.out_direction = dir;
        st
    }

    #[tokio::test]
    async fn handshake_establishes_working_authed_channel() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server_seed = [0x77u8; 32];
        let server_ed_pub = ed25519_public(&server_seed);
        let server_pub_key_id: i64 = 5;
        let session_id = 0x00AB_CDEFu64;

        let server = tokio::spawn(async move {
            let mut rng = CounterRng(0x1234);
            let (server_eph_priv, server_eph_pub) = x25519_generate(&mut rng);
            let mut st = SecureState::new_client(session_id);
            st.out_direction = DIR_S2C;
            let mut conn = Connection::new(server_io, st);

            let begin: AuthBeginHandshake = recv_req(&mut conn).await;
            let client_eph_pub: [u8; 32] = begin.client_eph_pub.clone().try_into().unwrap();
            let t = Transcript {
                tmp_token: begin.tmp_token.clone(),
                client_nonce: begin.client_nonce.clone(),
                server_nonce: b"server-nonce-value-0123456789ab".to_vec(),
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

            let finish: AuthFinishHandshake = recv_req(&mut conn).await;
            let server_shared = x25519_dh(&server_eph_priv, &client_eph_pub);
            let server_auth_key = derive_auth_key(&server_shared, &t, server_pub_key_id);
            assert_eq!(
                finish.client_finished,
                compute_finished(&server_auth_key, "client-finished", &t, server_pub_key_id)
                    .to_vec(),
                "client finished must validate"
            );
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

            *conn.state_mut() = authed_state(session_id, server_auth_key, DIR_S2C);
            let ping: Ping = recv_req(&mut conn).await;
            send_obj(
                &mut conn,
                &Pong {
                    ping_id: ping.ping_id,
                    now: 4242,
                },
            )
            .await;
        });

        let mut rng = CounterRng(0x00C0_FFEE);
        let mut client_state = SecureState::new_client(session_id);
        client_state.out_direction = DIR_C2S;
        let mut rpc = Rpc::new(Connection::new(client_io, client_state));

        let est = run_handshake(
            &mut rpc,
            b"tmp-token".to_vec(),
            br#"{"device":"test"}"#.to_vec(),
            session_id,
            &server_ed_pub,
            &mut rng,
        )
        .await
        .expect("handshake");
        assert_eq!(est.session_id, session_id);
        assert_ne!(est.auth_key_id, 0, "auth key id derived");

        let pong: Pong = rpc.invoke(&Ping { ping_id: 7 }).await.expect("authed ping");
        assert_eq!((pong.ping_id, pong.now), (7, 4242));
        server.await.unwrap();
    }
}
