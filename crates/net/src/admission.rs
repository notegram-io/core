use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::{NetError, Result};
use crate::frame::{build_plain_frame, read_plain_frame, DEFAULT_MAX_FRAME};

const MSG_INIT: u8 = 0;
const MSG_CHALLENGE: u8 = 1;
const MSG_AUTH: u8 = 2;
const MSG_OK: u8 = 3;

const COOKIE_LEN: usize = 16;
const INIT_LEN: usize = 1 + 4;
const CHALLENGE_LEN: usize = 1 + 4 + 8 + COOKIE_LEN;

fn build_init(route_dc: u32) -> [u8; INIT_LEN] {
    let mut b = [0u8; INIT_LEN];
    b[0] = MSG_INIT;
    b[1..5].copy_from_slice(&route_dc.to_le_bytes());
    b
}

fn build_auth(route_dc: u32, ts: u64, cookie: &[u8; COOKIE_LEN]) -> [u8; CHALLENGE_LEN] {
    let mut b = [0u8; CHALLENGE_LEN];
    b[0] = MSG_AUTH;
    b[1..5].copy_from_slice(&route_dc.to_le_bytes());
    b[5..13].copy_from_slice(&ts.to_le_bytes());
    b[13..13 + COOKIE_LEN].copy_from_slice(cookie);
    b
}

fn parse_challenge(body: &[u8]) -> Option<(u32, u64, [u8; COOKIE_LEN])> {
    if body.len() != CHALLENGE_LEN || body[0] != MSG_CHALLENGE {
        return None;
    }
    let route_dc = wire::u32_le(&body[1..5]);
    let ts = wire::u64_le(&body[5..13]);
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&body[13..13 + COOKIE_LEN]);
    Some((route_dc, ts, cookie))
}

pub async fn admit<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    session_id: u64,
    route_dc: u32,
) -> Result<()> {
    let init = build_plain_frame(session_id, 0, &build_init(route_dc));
    stream.write_all(&init).await?;
    stream.flush().await?;

    let (hdr, body) = read_plain_frame(stream, DEFAULT_MAX_FRAME).await?;
    let (dc, ts, cookie) =
        parse_challenge(&body).ok_or(NetError::Admission("malformed challenge"))?;
    if dc != route_dc {
        return Err(NetError::Admission("challenge route dc mismatch"));
    }

    let auth = build_plain_frame(hdr.session_id, hdr.seq_no.wrapping_add(1), &build_auth(dc, ts, &cookie));
    stream.write_all(&auth).await?;
    stream.flush().await?;

    let (_, ok_body) = read_plain_frame(stream, DEFAULT_MAX_FRAME).await?;
    if ok_body.len() != 1 || ok_body[0] != MSG_OK {
        return Err(NetError::Admission("unexpected admission ok"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{build_plain_frame, read_plain_frame};

    async fn mock_edge<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, route_dc: u32) {
        let (_, init) = read_plain_frame(stream, DEFAULT_MAX_FRAME).await.unwrap();
        assert_eq!(init[0], MSG_INIT);
        assert_eq!(wire::u32_le(&init[1..5]), route_dc);

        let ts: u64 = 0x0102_0304_0506_0708;
        let cookie = [0xABu8; COOKIE_LEN];
        let mut challenge = [0u8; CHALLENGE_LEN];
        challenge[0] = MSG_CHALLENGE;
        challenge[1..5].copy_from_slice(&route_dc.to_le_bytes());
        challenge[5..13].copy_from_slice(&ts.to_le_bytes());
        challenge[13..].copy_from_slice(&cookie);
        let frame = build_plain_frame(4242, 9, &challenge);
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();

        let (auth_hdr, auth) = read_plain_frame(stream, DEFAULT_MAX_FRAME).await.unwrap();
        assert_eq!(auth[0], MSG_AUTH);
        assert_eq!(wire::u64_le(&auth[5..13]), ts);
        assert_eq!(&auth[13..], &cookie);
        assert_eq!(auth_hdr.seq_no, 10, "auth seq must be challenge seq + 1");
        assert_eq!(auth_hdr.session_id, 4242, "auth adopts the challenge session id");

        let ok = build_plain_frame(4242, 11, &[MSG_OK]);
        stream.write_all(&ok).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn admit_completes_full_handshake() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let edge = tokio::spawn(async move { mock_edge(&mut server, 1).await });
        admit(&mut client, 777, 1).await.expect("admission");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn admit_rejects_wrong_route_dc() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let edge = tokio::spawn(async move {
            let _ = read_plain_frame(&mut server, DEFAULT_MAX_FRAME).await.unwrap();
            let mut challenge = [0u8; CHALLENGE_LEN];
            challenge[0] = MSG_CHALLENGE;
            challenge[1..5].copy_from_slice(&2u32.to_le_bytes());
            let frame = build_plain_frame(1, 0, &challenge);
            stream_write(&mut server, &frame).await;
        });
        let err = admit(&mut client, 1, 1).await.unwrap_err();
        assert!(matches!(err, NetError::Admission(_)));
        edge.await.unwrap();
    }

    async fn stream_write<S: AsyncWrite + Unpin>(s: &mut S, b: &[u8]) {
        s.write_all(b).await.unwrap();
        s.flush().await.unwrap();
    }
}
