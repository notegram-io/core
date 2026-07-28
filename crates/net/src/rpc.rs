use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncWrite};

use tl::generated::{InvokeWithLayer, RpcResult};
use tl::{decode_from, encode_to_vec, Limits, TlObject};
use transport::Connection;

use crate::error::{NetError, Result};

pub const LAYER: i32 = 121;

const MAX_STALE: usize = 16;

pub struct Rpc<S> {
    conn: Connection<S>,
    pending: VecDeque<Vec<u8>>,
}

impl<S> Rpc<S> {
    pub fn new(conn: Connection<S>) -> Self {
        Rpc {
            conn,
            pending: VecDeque::new(),
        }
    }

    pub fn connection_mut(&mut self) -> &mut Connection<S> {
        &mut self.conn
    }

    pub fn into_connection(self) -> Connection<S> {
        self.conn
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Rpc<S> {

    pub async fn invoke<Req: TlObject, Resp: TlObject>(&mut self, req: &Req) -> Result<Resp> {
        self.send(req).await?;
        self.expect::<Resp>().await
    }

    pub async fn send<Req: TlObject>(&mut self, req: &Req) -> Result<()> {
        let raw = encode_to_vec(req).map_err(|_| NetError::Encode)?;
        let invoke = InvokeWithLayer {
            layer: LAYER,
            query: raw,
        };
        let frame = encode_to_vec(&invoke).map_err(|_| NetError::Encode)?;
        self.conn.send_frames(&[&frame]).await?;
        Ok(())
    }

    pub async fn expect<Resp: TlObject>(&mut self) -> Result<Resp> {
        for _ in 0..MAX_STALE {
            let obj = self.next_object().await?;
            let ctor = read_ctor(&obj)?;
            if ctor == Resp::CTOR {
                return decode_from::<Resp>(&obj, Limits::default()).map_err(|_| NetError::Decode);
            }
            if ctor == RpcResult::CTOR {
                let r = decode_from::<RpcResult>(&obj, Limits::default())
                    .map_err(|_| NetError::Decode)?;
                return Err(NetError::Rpc {
                    code: r.code,
                    message: r.message,
                });
            }

        }
        Err(NetError::NoResponse)
    }

    async fn next_object(&mut self) -> Result<Vec<u8>> {
        if let Some(obj) = self.pending.pop_front() {
            return Ok(obj);
        }
        loop {
            let (_hdr, frames) = self.conn.recv_frames().await?;
            let mut it = frames.into_iter();
            if let Some(first) = it.next() {
                self.pending.extend(it);
                return Ok(first);
            }

        }
    }
}

fn read_ctor(obj: &[u8]) -> Result<u32> {
    if obj.len() < 4 {
        return Err(NetError::Decode);
    }
    Ok(wire::u32_le(&obj[0..4]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl::generated::{Ping, Pong};
    use transport::{Connection, SecureState, DIR_S2C};

    fn server_conn<S>(stream: S, session_id: u64) -> Connection<S> {
        let mut state = SecureState::new_client(session_id);
        state.out_direction = DIR_S2C;
        Connection::new(stream, state)
    }

    async fn read_invoked_ping<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut Connection<S>) -> Ping {
        let (_h, frames) = conn.recv_frames().await.unwrap();
        let invoke = decode_from::<InvokeWithLayer>(&frames[0], Limits::default()).unwrap();
        assert_eq!(invoke.layer, LAYER);
        decode_from::<Ping>(&invoke.query, Limits::default()).unwrap()
    }

    #[tokio::test]
    async fn invoke_roundtrips_and_decodes_response() {
        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 55);
        let handle = tokio::spawn(async move {
            let ping = read_invoked_ping(&mut srv).await;
            assert_eq!(ping.ping_id, 42);
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 1000,
            })
            .unwrap();
            srv.send_frames(&[&pong]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(55)));
        let pong: Pong = rpc.invoke(&Ping { ping_id: 42 }).await.expect("invoke");
        assert_eq!((pong.ping_id, pong.now), (42, 1000));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rpc_result_becomes_error() {
        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 7);
        let handle = tokio::spawn(async move {
            let _ = read_invoked_ping(&mut srv).await;
            let err = encode_to_vec(&RpcResult {
                code: 420,
                message: "FLOOD_WAIT".to_string(),
            })
            .unwrap();
            srv.send_frames(&[&err]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(7)));
        let err = rpc.invoke::<Ping, Pong>(&Ping { ping_id: 1 }).await.unwrap_err();
        match err {
            NetError::Rpc { code, message } => {
                assert_eq!(code, 420);
                assert_eq!(message, "FLOOD_WAIT");
            }
            other => panic!("expected rpc error, got {other:?}"),
        }
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn stale_object_is_skipped_before_response() {
        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 9);
        let handle = tokio::spawn(async move {
            let ping = read_invoked_ping(&mut srv).await;

            let stale = encode_to_vec(&Pong { ping_id: 999, now: 1 }).unwrap();
            let real = encode_to_vec(&Pong { ping_id: ping.ping_id, now: 2 }).unwrap();

            srv.send_frames(&[&stale, &real]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(9)));

        let first: Pong = rpc.invoke(&Ping { ping_id: 5 }).await.expect("invoke");
        assert_eq!(first.ping_id, 999);
        let second: Pong = rpc.expect().await.expect("buffered");
        assert_eq!(second.ping_id, 5);
        handle.await.unwrap();
    }
}
