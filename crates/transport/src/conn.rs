use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use proto::{open_outer, pack_container, seal_frame, unpack_container, OuterHeader, SealParams};

use crate::error::{Result, TransportError};
use crate::state::{unix_millis, SecureState};

pub const DEFAULT_MAX_FRAME: usize = 8 << 20;

pub struct Connection<S> {
    stream: S,
    state: SecureState,
    max_frame: usize,
    last_read_msg_id: u64,
}

impl<S> Connection<S> {
    pub fn new(stream: S, state: SecureState) -> Self {
        Connection {
            stream,
            state,
            max_frame: DEFAULT_MAX_FRAME,
            last_read_msg_id: 0,
        }
    }

    pub fn with_max_frame(mut self, max_frame: usize) -> Self {
        self.max_frame = max_frame;
        self
    }

    pub fn state_mut(&mut self) -> &mut SecureState {
        &mut self.state
    }

    /// The msg_id of the last frame read, which is what a reply to it has to
    /// name in `RpcAnswer.ReqMsgID`. Mirrors the server side, where answering
    /// without naming the request leaves a pipelined caller waiting forever.
    pub fn last_read_msg_id(&self) -> u64 {
        self.last_read_msg_id
    }

    pub fn state(&self) -> &SecureState {
        &self.state
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncWrite + Unpin> Connection<S> {
    /// Sends `container` and reports the transport msg_id it went out under.
    ///
    /// The id is what a reply names in `RpcAnswer.ReqMsgID`, so a caller that
    /// keeps it can have several requests in flight and still know which answer
    /// belongs to which. Without it replies can only be matched positionally,
    /// which forces every request to wait for the one before it.
    pub async fn send_container(&mut self, container: &[u8]) -> Result<u64> {
        let msg_id = self.state.next_msg_id(unix_millis());
        let seq_no = self.state.next_seq();
        let params = SealParams {
            auth_key: self.state.auth_key.as_ref(),
            salt: self.state.salt,
            epoch: self.state.epoch,
            direction: self.state.out_direction,
            session_id: self.state.session_id,
            auth_key_id: self.state.auth_key_id,
            seq_no,
            msg_id,
        };
        let frame = seal_frame(&params, container)?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(msg_id)
    }

    pub async fn send_frames(&mut self, frames: &[&[u8]]) -> Result<u64> {
        self.send_container(&pack_container(frames)).await
    }
}

impl<S: AsyncRead + Unpin> Connection<S> {
    pub async fn recv_container(&mut self) -> Result<(OuterHeader, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(TransportError::Closed)
            }
            Err(e) => return Err(e.into()),
        }
        let outer_len = wire::u32_le(&len_buf) as usize;
        if outer_len > self.max_frame {
            return Err(TransportError::FrameTooLarge);
        }

        let mut buf = vec![0u8; outer_len];
        self.stream.read_exact(&mut buf).await?;

        let (header, container) = open_outer(&buf, self.state.auth_key.as_ref(), self.state.salt)?;

        let expected = self.state.inbound_direction();
        if header.direction != expected {
            return Err(TransportError::UnexpectedDirection {
                expected,
                got: header.direction,
            });
        }
        self.last_read_msg_id = header.msg_id;
        Ok((header, container))
    }

    pub async fn recv_frames(&mut self) -> Result<(OuterHeader, Vec<Vec<u8>>)> {
        let (header, container) = self.recv_container().await?;
        let frames = unpack_container(&container, self.max_frame)?;
        Ok((header, frames))
    }
}
