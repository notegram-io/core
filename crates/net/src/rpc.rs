use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncWrite};

use tl::generated::{InvokeWithLayer, RpcAnswer, RpcResult};
use tl::{decode_from, encode_to_vec, Limits, TlObject};
use transport::Connection;

use crate::error::{NetError, Result};

pub const LAYER: i32 = 121;

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
        let msg_id = self.send(req).await?;
        self.expect::<Resp>(msg_id).await
    }

    /// Sends a request and reports the transport msg_id it went out under, which
    /// is what the reply names.
    pub async fn send<Req: TlObject>(&mut self, req: &Req) -> Result<u64> {
        let raw = encode_to_vec(req).map_err(|_| NetError::Encode)?;
        let invoke = InvokeWithLayer {
            layer: LAYER,
            query: raw,
        };
        let frame = encode_to_vec(&invoke).map_err(|_| NetError::Encode)?;
        Ok(self.conn.send_frames(&[&frame]).await?)
    }

    /// Reads until the answer to `req_msg_id` arrives, setting aside everything
    /// else as an update.
    ///
    /// Matching by id rather than by type, and waiting rather than counting, is
    /// what keeps the stream in step. The previous version gave up after
    /// sixteen intervening objects — which a burst of message notices reaches
    /// easily — and returned an error while the real reply was still unread.
    /// Every later call then took the previous call's answer, and the connection
    /// stayed one reply out of step until the app was restarted. Liveness comes
    /// from the socket's own read deadline, not from a cap on how many notices
    /// a server is allowed to send.
    pub async fn expect<Resp: TlObject>(&mut self, req_msg_id: u64) -> Result<Resp> {
        loop {
            let raw = self.next_object().await?;
            let ctor = read_ctor(&raw)?;

            if ctor == RpcAnswer::CTOR {
                let answer = decode_from::<RpcAnswer>(&raw, Limits::default())
                    .map_err(|_| NetError::Decode)?;
                if answer.req_msg_id as u64 != req_msg_id {
                    // An answer to a request nobody is waiting for any more —
                    // one abandoned by a cancelled call. Not an update, so it is
                    // dropped rather than handed to the update handler.
                    continue;
                }
                return Self::decode_reply::<Resp>(answer.body);
            }

            // An error the server could not name: raised before it had read a
            // request, so it belongs to this connection rather than to any one
            // call. The caller is the only one here to receive it.
            if ctor == RpcResult::CTOR {
                return Self::decode_reply::<Resp>(raw);
            }

            // Server-initiated. Keep it: dropping it would silently lose a
            // new-message notice that happened to land mid-call.
            self.record_update(raw);
        }
    }

    fn decode_reply<Resp: TlObject>(obj: Vec<u8>) -> Result<Resp> {
        if read_ctor(&obj)? == RpcResult::CTOR {
            let r =
                decode_from::<RpcResult>(&obj, Limits::default()).map_err(|_| NetError::Decode)?;
            return Err(NetError::Rpc {
                code: r.code,
                message: r.message,
            });
        }
        decode_from::<Resp>(&obj, Limits::default()).map_err(|_| NetError::Decode)
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

    /// Reads a ping and reports the msg_id it arrived under, which is what the
    /// answer has to name.
    async fn read_invoked_ping<S: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut Connection<S>,
    ) -> (u64, Ping) {
        let (h, frames) = conn.recv_frames().await.unwrap();
        let invoke = decode_from::<InvokeWithLayer>(&frames[0], Limits::default()).unwrap();
        assert_eq!(invoke.layer, LAYER);
        (
            h.msg_id,
            decode_from::<Ping>(&invoke.query, Limits::default()).unwrap(),
        )
    }

    /// Wraps a reply in the envelope naming its request, the way the real server
    /// does. A bare object is an update, not an answer.
    fn answer(msg_id: u64, body: Vec<u8>) -> Vec<u8> {
        encode_to_vec(&RpcAnswer {
            req_msg_id: msg_id as i64,
            body,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn invoke_roundtrips_and_decodes_response() {
        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 55);
        let handle = tokio::spawn(async move {
            let (msg_id, ping) = read_invoked_ping(&mut srv).await;
            assert_eq!(ping.ping_id, 42);
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 1000,
            })
            .unwrap();
            let a = answer(msg_id, pong);
            srv.send_frames(&[&a]).await.unwrap();
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
        let err = rpc
            .invoke::<Ping, Pong>(&Ping { ping_id: 1 })
            .await
            .unwrap_err();
        match err {
            NetError::Rpc { code, message } => {
                assert_eq!(code, 420);
                assert_eq!(message, "FLOOD_WAIT");
            }
            other => panic!("expected rpc error, got {other:?}"),
        }
        handle.await.unwrap();
    }

    /// A burst of notices ahead of the reply must not cost the reply.
    ///
    /// This is the shape that broke delivery in the field. The old code gave up
    /// after sixteen intervening objects and returned an error while the real
    /// answer sat unread in the stream; every later call then took the previous
    /// call's reply and the connection stayed one out of step until the app was
    /// restarted — which is why a burst of messages "only arrived after
    /// reopening the app". Sixty-four is comfortably past the old limit and
    /// nothing special: a busy chat reaches it in a second.
    #[tokio::test]
    async fn a_long_burst_of_notices_does_not_cost_the_reply() {
        use tl::generated::UpdateNewMessages;

        let (client, server) = tokio::io::duplex(1 << 16);
        let mut srv = server_conn(server, 9);
        let handle = tokio::spawn(async move {
            let (msg_id, ping) = read_invoked_ping(&mut srv).await;
            for i in 0..64 {
                let push = encode_to_vec(&UpdateNewMessages {
                    chat_id: 77,
                    sender_user_id: i,
                    pending_count: 1,
                })
                .unwrap();
                srv.send_frames(&[&push]).await.unwrap();
            }
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 2,
            })
            .unwrap();
            let a = answer(msg_id, pong);
            srv.send_frames(&[&a]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(9)));
        let pong: Pong = rpc.invoke(&Ping { ping_id: 5 }).await.expect("invoke");
        assert_eq!(pong.ping_id, 5, "the caller got its own answer");
        assert_eq!(
            rpc.take_updates().len(),
            64,
            "every notice was kept, not dropped on the way to the reply"
        );
        handle.await.unwrap();
    }

    /// An answer to a request nobody is waiting for is discarded rather than
    /// handed to the update handler, which would treat a reply as a notice.
    #[tokio::test]
    async fn an_answer_to_another_request_is_not_mistaken_for_an_update() {
        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 21);
        let handle = tokio::spawn(async move {
            let (msg_id, ping) = read_invoked_ping(&mut srv).await;
            let stale = encode_to_vec(&Pong {
                ping_id: 999,
                now: 1,
            })
            .unwrap();
            // Named as answering a request that was never sent.
            let orphan = answer(msg_id.wrapping_add(1_000), stale);
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 2,
            })
            .unwrap();
            let a = answer(msg_id, pong);
            srv.send_frames(&[&orphan, &a]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(21)));
        let pong: Pong = rpc.invoke(&Ping { ping_id: 5 }).await.expect("invoke");
        assert_eq!(pong.ping_id, 5, "the orphan did not become the answer");
        assert!(
            rpc.take_updates().is_empty(),
            "an orphaned answer is dropped, not queued as a notice"
        );
        handle.await.unwrap();
    }
    #[tokio::test]
    async fn push_arriving_during_an_rpc_is_kept_not_dropped() {
        use tl::generated::UpdateNewMessages;

        let (client, server) = tokio::io::duplex(4096);
        let mut srv = server_conn(server, 11);
        let handle = tokio::spawn(async move {
            let (msg_id, ping) = read_invoked_ping(&mut srv).await;
            // The server announces a message and only then answers the ping.
            let push = encode_to_vec(&UpdateNewMessages {
                chat_id: 77,
                sender_user_id: 42,
                pending_count: 1,
            })
            .unwrap();
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 3,
            })
            .unwrap();
            let a = answer(msg_id, pong);
            srv.send_frames(&[&push, &a]).await.unwrap();
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
            let body = encode_to_vec(&Pong {
                ping_id: 5,
                now: 99,
            })
            .unwrap();
            let answer = encode_to_vec(&RpcAnswer {
                req_msg_id: srv.last_read_msg_id() as i64,
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
            let answer = encode_to_vec(&RpcAnswer {
                req_msg_id: srv.last_read_msg_id() as i64,
                body,
            })
            .unwrap();
            srv.send_frames(&[&answer]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(4)));
        let err = rpc
            .invoke::<Ping, Pong>(&Ping { ping_id: 1 })
            .await
            .unwrap_err();
        assert!(
            matches!(err, NetError::Rpc { code: 429, .. }),
            "got {err:?}"
        );
        handle.await.unwrap();
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use tl::generated::{Ping, Pong, UpdateMessageDelivered};
    use transport::{Connection, SecureState, DIR_S2C};

    /// A push arriving on its own frame, exactly as the gateway writes it, must
    /// end up in the update queue rather than being dropped or breaking the
    /// reply that follows it.
    #[tokio::test]
    async fn a_push_between_replies_is_queued() {
        let (client, server) = tokio::io::duplex(8192);
        let mut state = SecureState::new_client(11);
        state.out_direction = DIR_S2C;
        let mut srv = Connection::new(server, state);

        let server_side = tokio::spawn(async move {
            let _ = srv.recv_frames().await.unwrap();
            // The gateway writes the notice as its own frame, before the reply.
            let notice = encode_to_vec(&UpdateMessageDelivered {
                chat_id: 77,
                client_msg_id: "abc-123".to_string(),
                recipient_user_id: 5,
                recipient_device_id: 7001,
                delivered_at: 1_700_000_000_000,
            })
            .unwrap();
            srv.send_frames(&[&notice]).await.unwrap();

            let body = encode_to_vec(&Pong { ping_id: 1, now: 2 }).unwrap();
            let answer = encode_to_vec(&RpcAnswer {
                req_msg_id: srv.last_read_msg_id() as i64,
                body,
            })
            .unwrap();
            srv.send_frames(&[&answer]).await.unwrap();
        });

        let mut rpc = Rpc::new(Connection::new(client, SecureState::new_client(11)));
        let pong: Pong = rpc.invoke(&Ping { ping_id: 1 }).await.expect("invoke");
        assert_eq!(pong.ping_id, 1);

        server_side.await.unwrap();
        let queued = rpc.take_updates();
        assert_eq!(queued.len(), 1, "the notice was not queued");
        let update =
            decode_from::<UpdateMessageDelivered>(&queued[0], Limits::default()).expect("decode");
        assert_eq!(update.client_msg_id, "abc-123");
    }
}
