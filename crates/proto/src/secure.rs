use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{ProtoError, Result};
use crate::outer::{OuterHeader, OUTER_HEADER_SIZE, SECURE_VERSION_2};

const MSG_KEY_INFO_PREFIX: &[u8] = b"transport/outer/v2";

pub fn derive_msg_key(
    auth_key: &[u8; 32],
    salt: u64,
    epoch: u32,
    direction: u8,
    msg_id: u64,
) -> [u8; 32] {
    let mut info = Vec::with_capacity(MSG_KEY_INFO_PREFIX.len() + 1 + 4 + 8);
    info.extend_from_slice(MSG_KEY_INFO_PREFIX);
    info.push(direction);
    info.extend_from_slice(&epoch.to_le_bytes());
    info.extend_from_slice(&msg_id.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt.to_le_bytes()), auth_key);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32-byte OKM is within HKDF output bounds");
    okm
}

fn nonce12(msg_id: u64, seq_no: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&msg_id.to_le_bytes());
    n[8..].copy_from_slice(&seq_no.to_le_bytes());
    n
}

pub struct SealParams<'a> {
    pub auth_key: Option<&'a [u8; 32]>,
    pub salt: u64,
    pub epoch: u32,
    pub direction: u8,
    pub session_id: u64,

    pub auth_key_id: u64,
    pub seq_no: u32,
    pub msg_id: u64,
}

pub fn seal_frame(p: &SealParams, container: &[u8]) -> Result<Vec<u8>> {
    let header = OuterHeader {
        version: SECURE_VERSION_2,
        flags: 0,
        direction: p.direction,
        epoch: p.epoch,
        plain_len: container.len() as u32,
        seq_no: p.seq_no,
        auth_key_id: p.auth_key_id,
        session_id: p.session_id,
        msg_id: p.msg_id,
    };
    let hdr = header.to_bytes();

    let body = if p.auth_key_id == 0 {
        container.to_vec()
    } else {
        let auth_key = p.auth_key.ok_or(ProtoError::MissingAuthKey)?;
        let key = derive_msg_key(auth_key, p.salt, p.epoch, p.direction, p.msg_id);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = nonce12(p.msg_id, p.seq_no);
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: container,
                    aad: &hdr,
                },
            )
            .map_err(|_| ProtoError::Decrypt)?
    };

    let outer_len = OUTER_HEADER_SIZE + body.len();
    let mut out = Vec::with_capacity(4 + outer_len);
    out.extend_from_slice(&(outer_len as u32).to_le_bytes());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn open_outer(
    buf: &[u8],
    auth_key: Option<&[u8; 32]>,
    salt: u64,
) -> Result<(OuterHeader, Vec<u8>)> {
    if buf.len() < OUTER_HEADER_SIZE {
        return Err(ProtoError::BadHeader);
    }
    let header = OuterHeader::parse(buf)?;
    if header.version != SECURE_VERSION_2 {
        return Err(ProtoError::UnsupportedVersion(header.version));
    }
    let hdr = &buf[..OUTER_HEADER_SIZE];
    let body = &buf[OUTER_HEADER_SIZE..];

    let container = if header.auth_key_id == 0 {
        body.to_vec()
    } else {
        let auth_key = auth_key.ok_or(ProtoError::MissingAuthKey)?;
        let key = derive_msg_key(
            auth_key,
            salt,
            header.epoch,
            header.direction,
            header.msg_id,
        );
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = nonce12(header.msg_id, header.seq_no);
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: hdr,
                },
            )
            .map_err(|_| ProtoError::Decrypt)?
    };

    if container.len() != header.plain_len as usize {
        return Err(ProtoError::BadHeader);
    }
    Ok((header, container))
}

pub fn open_frame(
    frame: &[u8],
    auth_key: Option<&[u8; 32]>,
    salt: u64,
) -> Result<(OuterHeader, Vec<u8>)> {
    if frame.len() < 4 {
        return Err(ProtoError::ShortBuffer);
    }
    let outer_len = wire::u32_le(&frame[..4]) as usize;
    if frame.len() < 4 + outer_len {
        return Err(ProtoError::ShortBuffer);
    }
    open_outer(&frame[4..4 + outer_len], auth_key, salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outer::DIR_C2S;

    fn params(auth_key: &[u8; 32], auth_key_id: u64) -> SealParams<'_> {
        SealParams {
            auth_key: Some(auth_key),
            salt: 0x0102_0304_0506_0708,
            epoch: 3,
            direction: DIR_C2S,
            session_id: 0x1111_2222_3333_4444,
            auth_key_id,
            seq_no: 5,
            msg_id: 0x00ab_cdef_1234_5678,
        }
    }

    #[test]
    fn secure_roundtrip() {
        let auth_key = [0x11u8; 32];
        let p = params(&auth_key, 0x9999);
        let frame = seal_frame(&p, b"inner-container").unwrap();
        let (h, container) = open_frame(&frame, Some(&auth_key), p.salt).unwrap();
        assert_eq!(h.auth_key_id, 0x9999);
        assert_eq!(container, b"inner-container");
    }

    #[test]
    fn tamper_is_rejected() {
        let auth_key = [0x22u8; 32];
        let p = params(&auth_key, 0x9999);
        let mut frame = seal_frame(&p, b"secret").unwrap();
        *frame.last_mut().unwrap() ^= 0x01;
        assert!(matches!(
            open_frame(&frame, Some(&auth_key), p.salt),
            Err(ProtoError::Decrypt)
        ));
    }

    #[test]
    fn wrong_salt_is_rejected() {
        let auth_key = [0x33u8; 32];
        let p = params(&auth_key, 0x9999);
        let frame = seal_frame(&p, b"secret").unwrap();
        assert!(matches!(
            open_frame(&frame, Some(&auth_key), p.salt ^ 1),
            Err(ProtoError::Decrypt)
        ));
    }

    #[test]
    fn unauthenticated_frame_is_cleartext() {
        let p = SealParams {
            auth_key: None,
            auth_key_id: 0,
            ..params(&[0u8; 32], 0)
        };
        let frame = seal_frame(&p, b"handshake").unwrap();
        let (h, container) = open_frame(&frame, None, 0).unwrap();
        assert_eq!(h.auth_key_id, 0);
        assert_eq!(container, b"handshake");
    }
}
