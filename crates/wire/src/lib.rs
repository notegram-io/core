use std::io::{self, Read, Write};

#[derive(Debug)]
pub enum WireError {
    FrameTooLarge,

    Io(io::Error),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::FrameTooLarge => write!(f, "frame too large"),
            WireError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

#[inline]
pub fn u16_le(src: &[u8]) -> u16 {
    u16::from_le_bytes([src[0], src[1]])
}

#[inline]
pub fn u32_le(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

#[inline]
pub fn u64_le(src: &[u8]) -> u64 {
    u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ])
}

#[inline]
pub fn put_u16_le(dst: &mut [u8], v: u16) {
    dst[..2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn put_u32_le(dst: &mut [u8], v: u32) {
    dst[..4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn put_u64_le(dst: &mut [u8], v: u64) {
    dst[..8].copy_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn append_u16_le(dst: &mut Vec<u8>, v: u16) {
    dst.extend_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn append_u32_le(dst: &mut Vec<u8>, v: u32) {
    dst.extend_from_slice(&v.to_le_bytes());
}

#[inline]
pub fn append_u64_le(dst: &mut Vec<u8>, v: u64) {
    dst.extend_from_slice(&v.to_le_bytes());
}

pub fn read_frame<R: Read>(r: &mut R, max_len: usize) -> Result<Vec<u8>, WireError> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32_le(&hdr) as usize;
    if max_len > 0 && n > max_len {
        return Err(WireError::FrameTooLarge);
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), WireError> {
    let mut hdr = [0u8; 4];
    put_u32_le(&mut hdr, payload.len() as u32);
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    Ok(())
}

pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    append_u32_le(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_fixed_width() {
        let mut v = Vec::new();
        append_u16_le(&mut v, 0x0102);
        append_u32_le(&mut v, 0x0304_0506);
        append_u64_le(&mut v, 0x0708_090a_0b0c_0d0e);
        assert_eq!(
            v,
            vec![
                0x02, 0x01, 0x06, 0x05, 0x04, 0x03, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
            ]
        );
        assert_eq!(u16_le(&v[0..]), 0x0102);
        assert_eq!(u32_le(&v[2..]), 0x0304_0506);
        assert_eq!(u64_le(&v[6..]), 0x0708_090a_0b0c_0d0e);
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"hello notegram";
        let framed = encode_frame(payload);
        assert_eq!(u32_le(&framed), payload.len() as u32);
        let mut cur = std::io::Cursor::new(framed);
        let got = read_frame(&mut cur, 1 << 20).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn frame_too_large() {
        let framed = encode_frame(&[0u8; 100]);
        let mut cur = std::io::Cursor::new(framed);
        assert!(matches!(
            read_frame(&mut cur, 10),
            Err(WireError::FrameTooLarge)
        ));
    }

    #[test]
    fn empty_frame() {
        let framed = encode_frame(&[]);
        assert_eq!(framed, vec![0, 0, 0, 0]);
        let mut cur = std::io::Cursor::new(framed);
        assert_eq!(read_frame(&mut cur, 0).unwrap(), Vec::<u8>::new());
    }
}
