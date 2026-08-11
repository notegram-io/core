use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{split, AsyncRead, AsyncWrite, WriteHalf};
use tokio::sync::{mpsc, oneshot, Mutex};

use tl::generated::{InvokeWithLayer, RpcAnswer, RpcResult};
use tl::{decode_from, encode_to_vec, Limits, TlObject};
use transport::{Connection, SecureState};

use crate::error::{NetError, Result};
use crate::rpc::LAYER;
use crate::session::Session;

/// Requests waiting for an answer, keyed by the transport msg_id they were sent
/// under — the same id the server echoes in `RpcAnswer.ReqMsgID`.
type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Vec<u8>>>>>;

/// A connection with a reader of its own.
///
/// The reason this exists rather than reading replies inline: a request/response
/// client can only notice a server-initiated message while it happens to be
/// waiting for a reply. That forces a client to keep polling — a ping every
/// couple of seconds purely to give the socket a reason to be read — and it
/// still loses anything that arrives in between. Worse, matching replies
/// positionally means a burst of notices arriving before an answer either
/// desynchronises the stream or is dropped.
///
/// Here a single task owns the read half and routes: an `RpcAnswer` goes to
/// whoever is waiting on that msg_id, everything else is an update and goes to
/// the channel. Nobody has to be waiting for an update to arrive, and requests
/// no longer queue behind one another.
pub struct Client<S: AsyncWrite + Unpin> {
    write: Mutex<Connection<WriteHalf<S>>>,
    pending: Pending,
    updates: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    reader: tokio::task::JoinHandle<()>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Client<S> {
    pub fn from_session(session: Session<S>) -> Self {
        let conn = session.into_rpc().into_connection();
        let state = conn.state().clone();
        Self::new(conn.into_inner(), state)
    }

    pub fn new(stream: S, state: SecureState) -> Self {
        let (rd, wr) = split(stream);
        let read_conn = Connection::new(rd, state.clone());
        let write_conn = Connection::new(wr, state);

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (updates_tx, updates_rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(reader_loop(read_conn, pending.clone(), updates_tx));

        Client {
            write: Mutex::new(write_conn),
            pending,
            updates: Mutex::new(updates_rx),
            reader,
        }
    }

    /// Sends one request and waits for its answer.
    ///
    /// Takes `&self` and holds the write lock only for the send, so callers can
    /// have any number of these outstanding at once. That is what makes a batch
    /// of small calls — acking a burst of messages, say — cost one round trip
    /// instead of one per call.
    pub async fn invoke<Req: TlObject, Resp: TlObject>(&self, req: &Req) -> Result<Resp> {
        let raw = encode_to_vec(req).map_err(|_| NetError::Encode)?;
        let frame = encode_to_vec(&InvokeWithLayer {
            layer: LAYER,
            query: raw,
        })
        .map_err(|_| NetError::Encode)?;

        let (tx, rx) = oneshot::channel();
        // The id is only known once the frame is sealed, so the slot cannot be
        // claimed beforehand — and a fast server can answer before this task is
        // scheduled again. Holding the pending lock across the send closes that
        // window: the reader cannot dispatch anything until the slot is in
        // place, so an answer that arrives first waits rather than being
        // mistaken for an update and thrown away.
        let msg_id = {
            let mut write = self.write.lock().await;
            let mut pending = self.pending.lock().await;
            let msg_id = write.send_frames(&[&frame]).await?;
            pending.insert(msg_id, tx);
            msg_id
        };

        let obj = match rx.await {
            Ok(obj) => obj,
            // The reader is gone, which means the link is: drop the slot so a
            // dead request cannot pin memory for the life of the client.
            Err(_) => {
                self.pending.lock().await.remove(&msg_id);
                return Err(NetError::Closed);
            }
        };
        if obj.len() >= 4 && wire::u32_le(&obj[0..4]) == RpcResult::CTOR {
            let r =
                decode_from::<RpcResult>(&obj, Limits::default()).map_err(|_| NetError::Decode)?;
            return Err(NetError::Rpc {
                code: r.code,
                message: r.message,
            });
        }
        decode_from::<Resp>(&obj, Limits::default()).map_err(|_| NetError::Decode)
    }

    pub async fn next_update(&self) -> Option<Vec<u8>> {
        self.updates.lock().await.recv().await
    }
}

impl<S: AsyncWrite + Unpin> Drop for Client<S> {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn reader_loop<R: AsyncRead + Unpin>(
    mut read: Connection<R>,
    pending: Pending,
    updates: mpsc::UnboundedSender<Vec<u8>>,
) {
    loop {
        let frames = match read.recv_frames().await {
            Ok((_, frames)) => frames,
            Err(_) => break,
        };
        for obj in frames {
            if obj.len() < 4 {
                continue;
            }
            // Only a named answer is an answer. Everything else — including a
            // bare reply from a server too old to wrap them — is treated as an
            // update rather than guessed at by type, because guessing is what
            // let a notice be mistaken for a reply and desynchronise the stream.
            if wire::u32_le(&obj[0..4]) == RpcAnswer::CTOR {
                if let Ok(answer) = decode_from::<RpcAnswer>(&obj, Limits::default()) {
                    let waiting = pending.lock().await.remove(&(answer.req_msg_id as u64));
                    match waiting {
                        Some(tx) => {
                            // The receiver having given up is ordinary: the
                            // caller timed out or was cancelled.
                            let _ = tx.send(answer.body);
                        }
                        // Nobody is waiting — a late answer to a request that
                        // was abandoned. Dropping it is right; passing it on as
                        // an update would hand a reply to the update handler.
                        None => continue,
                    }
                    continue;
                }
            }
            // An error the server could not attach to a request: it was
            // rejected before one was read — flood control, or an expired
            // unauthenticated link. It belongs to nobody in particular, so it
            // is given to everybody waiting rather than dropped, which would
            // leave them all hanging for an answer that is never coming.
            if wire::u32_le(&obj[0..4]) == RpcResult::CTOR {
                let waiting: Vec<_> = pending.lock().await.drain().map(|(_, tx)| tx).collect();
                if !waiting.is_empty() {
                    for tx in waiting {
                        let _ = tx.send(obj.clone());
                    }
                    continue;
                }
            }
            if updates.send(obj).is_err() {
                return;
            }
        }
    }

    // The link is gone. Dropping the senders wakes everyone waiting with a
    // closed channel, which invoke turns into NetError::Closed — otherwise a
    // request outstanding at the moment the socket died would hang forever.
    pending.lock().await.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl::generated::{HelpConfig, Ping, Pong};
    use transport::DIR_S2C;

    #[tokio::test]
    async fn response_delivered_and_push_routed_to_updates() {
        let (client_io, server_io) = tokio::io::duplex(8192);

        let server = tokio::spawn(async move {
            let mut st = SecureState::new_client(1);
            st.out_direction = DIR_S2C;
            let mut srv = Connection::new(server_io, st);

            let (h, frames) = srv.recv_frames().await.unwrap();
            let inv = decode_from::<InvokeWithLayer>(&frames[0], Limits::default()).unwrap();
            let ping = decode_from::<Ping>(&inv.query, Limits::default()).unwrap();

            let push = encode_to_vec(&HelpConfig {
                now: 7,
                dc_options: vec![],
            })
            .unwrap();
            srv.send_frames(&[&push]).await.unwrap();
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 42,
            })
            .unwrap();
            let answer = encode_to_vec(&RpcAnswer {
                req_msg_id: h.msg_id as i64,
                body: pong,
            })
            .unwrap();
            srv.send_frames(&[&answer]).await.unwrap();
        });

        let client = Client::new(client_io, SecureState::new_client(1));
        let pong: Pong = client.invoke(&Ping { ping_id: 9 }).await.expect("invoke");
        assert_eq!((pong.ping_id, pong.now), (9, 42));

        let update = client.next_update().await.expect("update");
        assert_eq!(
            wire::u32_le(&update[0..4]),
            HelpConfig::CTOR,
            "push reached updates"
        );

        server.await.unwrap();
    }

    /// The point of matching by msg_id: answers may come back in any order, and
    /// a caller must get its own. Answering in reverse is the sharpest version
    /// of that — under the old positional matching the first caller would have
    /// taken the second's reply.
    #[tokio::test]
    async fn concurrent_requests_each_get_their_own_answer() {
        let (client_io, server_io) = tokio::io::duplex(8192);

        let server = tokio::spawn(async move {
            let mut st = SecureState::new_client(1);
            st.out_direction = DIR_S2C;
            let mut srv = Connection::new(server_io, st);

            let mut seen = Vec::new();
            for _ in 0..2 {
                let (h, frames) = srv.recv_frames().await.unwrap();
                let inv = decode_from::<InvokeWithLayer>(&frames[0], Limits::default()).unwrap();
                let ping = decode_from::<Ping>(&inv.query, Limits::default()).unwrap();
                seen.push((h.msg_id, ping.ping_id));
            }
            for (msg_id, ping_id) in seen.into_iter().rev() {
                let pong = encode_to_vec(&Pong {
                    ping_id,
                    now: ping_id * 10,
                })
                .unwrap();
                let answer = encode_to_vec(&RpcAnswer {
                    req_msg_id: msg_id as i64,
                    body: pong,
                })
                .unwrap();
                srv.send_frames(&[&answer]).await.unwrap();
            }
        });

        let client = Arc::new(Client::new(client_io, SecureState::new_client(1)));
        let first = {
            let c = client.clone();
            tokio::spawn(async move { c.invoke::<_, Pong>(&Ping { ping_id: 1 }).await })
        };
        // Ordered so the server sees 1 then 2 and answers 2 then 1.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let second = {
            let c = client.clone();
            tokio::spawn(async move { c.invoke::<_, Pong>(&Ping { ping_id: 2 }).await })
        };

        let a = first.await.unwrap().expect("first answered");
        let b = second.await.unwrap().expect("second answered");
        assert_eq!(
            (a.ping_id, a.now),
            (1, 10),
            "first caller got its own answer"
        );
        assert_eq!(
            (b.ping_id, b.now),
            (2, 20),
            "second caller got its own answer"
        );

        server.await.unwrap();
    }

    /// An error the server could not name — sent before it had read a request —
    /// must reach the caller. Routed to updates instead, the call would wait for
    /// an answer that was already sent and never comes.
    #[tokio::test]
    async fn an_unnamed_error_fails_the_waiting_call() {
        let (client_io, server_io) = tokio::io::duplex(8192);

        let server = tokio::spawn(async move {
            let mut st = SecureState::new_client(1);
            st.out_direction = DIR_S2C;
            let mut srv = Connection::new(server_io, st);

            let _ = srv.recv_frames().await.unwrap();
            let bare = encode_to_vec(&RpcResult {
                code: 429,
                message: "FLOOD_WAIT".to_string(),
            })
            .unwrap();
            srv.send_frames(&[&bare]).await.unwrap();
        });

        let client = Client::new(client_io, SecureState::new_client(1));
        let err = client
            .invoke::<_, Pong>(&Ping { ping_id: 5 })
            .await
            .expect_err("the unnamed error reached the caller");
        match err {
            NetError::Rpc { code, .. } => assert_eq!(code, 429),
            other => panic!("expected an rpc error, got {other:?}"),
        }

        server.await.unwrap();
    }

    /// A server fast enough to answer before the sending task is scheduled again
    /// must not have its answer mistaken for an update. The reader is held off
    /// until the slot exists; without that this is a lost reply and a hung call.
    #[tokio::test]
    async fn an_answer_arriving_immediately_is_not_lost() {
        let (client_io, server_io) = tokio::io::duplex(8192);

        let server = tokio::spawn(async move {
            let mut st = SecureState::new_client(1);
            st.out_direction = DIR_S2C;
            let mut srv = Connection::new(server_io, st);

            let (h, frames) = srv.recv_frames().await.unwrap();
            let inv = decode_from::<InvokeWithLayer>(&frames[0], Limits::default()).unwrap();
            let ping = decode_from::<Ping>(&inv.query, Limits::default()).unwrap();
            let pong = encode_to_vec(&Pong {
                ping_id: ping.ping_id,
                now: 1,
            })
            .unwrap();
            let answer = encode_to_vec(&RpcAnswer {
                req_msg_id: h.msg_id as i64,
                body: pong,
            })
            .unwrap();
            srv.send_frames(&[&answer]).await.unwrap();
        });

        let client = Client::new(client_io, SecureState::new_client(1));
        let pong = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.invoke::<_, Pong>(&Ping { ping_id: 3 }),
        )
        .await
        .expect("the call did not hang")
        .expect("answered");
        assert_eq!(pong.ping_id, 3);

        server.await.unwrap();
    }
}
