use std::sync::Arc;

use tokio::io::{split, AsyncRead, AsyncWrite, WriteHalf};
use tokio::sync::{mpsc, oneshot, Mutex};

use tl::generated::{InvokeWithLayer, RpcResult};
use tl::{decode_from, encode_to_vec, Limits, TlObject};
use transport::{Connection, SecureState};

use crate::error::{NetError, Result};
use crate::rpc::LAYER;
use crate::session::Session;

type Slot = Option<(u32, oneshot::Sender<Vec<u8>>)>;

pub struct Client<S: AsyncWrite + Unpin> {
    write: Mutex<Connection<WriteHalf<S>>>,
    invoke_lock: Mutex<()>,
    pending: Arc<Mutex<Slot>>,
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

        let pending: Arc<Mutex<Slot>> = Arc::new(Mutex::new(None));
        let (updates_tx, updates_rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(reader_loop(read_conn, pending.clone(), updates_tx));

        Client {
            write: Mutex::new(write_conn),
            invoke_lock: Mutex::new(()),
            pending,
            updates: Mutex::new(updates_rx),
            reader,
        }
    }

    pub async fn invoke<Req: TlObject, Resp: TlObject>(&self, req: &Req) -> Result<Resp> {
        let _guard = self.invoke_lock.lock().await;

        let raw = encode_to_vec(req).map_err(|_| NetError::Encode)?;
        let frame = encode_to_vec(&InvokeWithLayer {
            layer: LAYER,
            query: raw,
        })
        .map_err(|_| NetError::Encode)?;

        let (tx, rx) = oneshot::channel();
        *self.pending.lock().await = Some((Resp::CTOR, tx));

        if let Err(e) = self.write.lock().await.send_frames(&[&frame]).await {
            *self.pending.lock().await = None;
            return Err(e.into());
        }

        let obj = rx.await.map_err(|_| NetError::Closed)?;
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
    pending: Arc<Mutex<Slot>>,
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
            let ctor = wire::u32_le(&obj[0..4]);
            let mut slot = pending.lock().await;
            let deliver =
                matches!(&*slot, Some((exp, _)) if *exp == ctor || ctor == RpcResult::CTOR);
            if deliver {
                if let Some((_, tx)) = slot.take() {
                    let _ = tx.send(obj);
                }
            } else {
                drop(slot);
                if updates.send(obj).is_err() {
                    return;
                }
            }
        }
    }

    *pending.lock().await = None;
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

            let (_h, frames) = srv.recv_frames().await.unwrap();
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
            srv.send_frames(&[&pong]).await.unwrap();
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
}
