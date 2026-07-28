use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};

use proto::{OuterHeader, DIR_C2S, OUTER_HEADER_SIZE, SECURE_VERSION_2};

use crate::error::{NetError, Result};

pub const DEFAULT_MAX_FRAME: usize = 8 << 20;

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn build_plain_frame(session_id: u64, seq_no: u32, body: &[u8]) -> Vec<u8> {
    let hdr = OuterHeader {
        version: SECURE_VERSION_2,
        flags: 0,
        direction: DIR_C2S,
        epoch: 0,
        plain_len: body.len() as u32,
        seq_no,
        auth_key_id: 0,
        session_id,
        msg_id: unix_millis() << 20,
    };
    let payload_len = OUTER_HEADER_SIZE + body.len();
    let mut out = Vec::with_capacity(4 + payload_len);
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    out.extend_from_slice(&hdr.to_bytes());
    out.extend_from_slice(body);
    out
}

pub async fn read_plain_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_frame: usize,
) -> Result<(OuterHeader, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = wire::u32_le(&len_buf) as usize;
    if payload_len > max_frame {
        return Err(NetError::FrameTooLarge);
    }
    if payload_len < OUTER_HEADER_SIZE {
        return Err(NetError::BadFrame);
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    let hdr = OuterHeader::parse(&payload).map_err(|_| NetError::BadFrame)?;
    let body = &payload[OUTER_HEADER_SIZE..];
    let plain_len = hdr.plain_len as usize;
    if plain_len > body.len() {
        return Err(NetError::BadFrame);
    }
    Ok((hdr, body[..plain_len].to_vec()))
}
