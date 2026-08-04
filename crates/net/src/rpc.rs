use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncWrite};

use tl::generated::{InvokeWithLayer, RpcAnswer, RpcResult};
use tl::{decode_from, encode_to_vec, Limits, TlObject};
use transport::Connection;

use crate::error::{NetError, Result};

pub const LAYER: i32 = 121;

const MAX_STALE: usize = 16;

/// Cap on undrained server-initiated objects, so a client that never reads them
/// cannot grow memory without bound. Losing the oldest notice is harmless: the
/// messages themselves stay on the server until acked.
const MAX_BUFFERED_UPDATES: usize = 256;

pub struct Rpc<S> {
    conn: Connection<S>,
    pending: VecDeque<Vec<u8>>,
    updates: VecDeque<Vec<u8>>,
}

impl<S> Rpc<S> {
    pub fn new(conn: Connection<S>) -> Self {
        Rpc {
            conn,
            pending: VecDeque::new(),
            updates: VecDeque::new(),
        }
    }

    /// Server-initiated objects seen while waiting for RPC replies. They arrive
    /// interleaved with responses on the same connection, so they are set aside
    /// here instead of being discarded.
    pub fn take_updates(&mut self) -> Vec<Vec<u8>> {
        self.updates.drain(..).collect()
    }

    /// Puts back updates a caller pulled out but did not consume, keeping
    /// them available for whoever does want them.
    pub fn restore_updates(&mut self, updates: Vec<Vec<u8>>) {
        for raw in updates.into_iter().rev() {
            if self.updates.len() >= MAX_BUFFERED_UPDATES {
                break;
            }
            self.updates.push_front(raw);
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
            let raw = self.next_object().await?;
            // Replies arrive in an envelope naming the request they answer, so
            // that several can be in flight at once. This client sends one at a
            // time, so the name only has to be unwrapped.
            let obj = match read_ctor(&raw)? {
                RpcAnswer::CTOR => {
                    decode_from::<RpcAnswer>(&raw, Limits::default())
                        .map_err(|_| NetError::Decode)?
                        .body
                }
                _ => raw,
            };
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
            // Anything else is server-initiated (a push). Keep it: dropping it
            // here would silently lose a new-message notice that happened to
            // land while an RPC was in flight.
            self.record_update(obj);
        }
        Err(NetError::NoResponse)
    }

    fn record_update(&mut self, obj: Vec<u8>) {
        // Bound the queue: a client that never drains updates must not grow
        // memory without limit.
        if self.updates.len() >= MAX_BUFFERED_UPDATES {
            self.updates.pop_front();
        }
        self.updates.push_back(obj);
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
    #[tokio::test]
    async fn push_arriving_during_an_rpc_is_kept_not_dropped() {
        use tl::generated::UpdateNewMessages;

        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 11);
        let handle = tokio::spawn(async move {
            let ping = read_invoked_ping(&mut srv).await;
            // The server announces a message and only then answers the ping.
            let push = encode_to_vec(&UpdateNewMessages {
                chat_id: 77,
                sender_user_id: 42,
                pending_count: 1,
            })
            .unwrap();
            let pong = encode_to_vec(&Pong { ping_id: ping.ping_id, now: 3 }).unwrap();
            srv.send_frames(&[&push, &pong]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(11)));
        let pong: Pong = rpc.invoke(&Ping { ping_id: 5 }).await.expect("invoke");
        assert_eq!(pong.ping_id, 5, "the reply still resolves");

        let updates = rpc.take_updates();
        assert_eq!(updates.len(), 1, "the push was retained, not discarded");
        let update = decode_from::<UpdateNewMessages>(&updates[0], Limits::default()).unwrap();
        assert_eq!((update.chat_id, update.sender_user_id), (77, 42));
        assert!(rpc.take_updates().is_empty(), "draining clears the queue");
        handle.await.unwrap();
    }

}

#[cfg(test)]
mod answer_tests {
    use super::*;
    use tl::generated::{Ping, Pong};
    use transport::{Connection, SecureState, DIR_S2C};

    #[tokio::test]
    async fn reply_is_read_out_of_its_envelope() {
        // The server names the request each reply answers so that several can be
        // in flight; the reply itself is inside.
        let (client, server) = tokio::io::duplex(4096);
        let mut state = SecureState::new_client(3);
        state.out_direction = DIR_S2C;
        let mut srv = Connection::new(server, state);

        let handle = tokio::spawn(async move {
            let _ = srv.recv_frames().await.unwrap();
            let body = encode_to_vec(&Pong { ping_id: 5, now: 99 }).unwrap();
            let answer = encode_to_vec(&RpcAnswer {
                req_msg_id: 123456,
                body,
            })
            .unwrap();
            srv.send_frames(&[&answer]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(3)));
        let pong: Pong = rpc.invoke(&Ping { ping_id: 5 }).await.expect("invoke");
        assert_eq!((pong.ping_id, pong.now), (5, 99));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn an_error_inside_an_envelope_is_still_an_error() {
        let (client, server) = tokio::io::duplex(4096);
        let mut state = SecureState::new_client(4);
        state.out_direction = DIR_S2C;
        let mut srv = Connection::new(server, state);

        let handle = tokio::spawn(async move {
            let _ = srv.recv_frames().await.unwrap();
            let body = encode_to_vec(&RpcResult {
                code: 429,
                message: "FLOOD_WAIT".to_string(),
            })
            .unwrap();
            let answer = encode_to_vec(&RpcAnswer { req_msg_id: 1, body }).unwrap();
            srv.send_frames(&[&answer]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(4)));
        let err = rpc.invoke::<Ping, Pong>(&Ping { ping_id: 1 }).await.unwrap_err();
        assert!(matches!(err, NetError::Rpc { code: 429, .. }), "got {err:?}");
        handle.await.unwrap();
    }
}
