use crate::error::{Result, TlError};

pub const VECTOR_CTOR: u32 = 0x1cb5_c415;

pub const BOOL_TRUE_CTOR: u32 = 0x9972_75b5;

pub const BOOL_FALSE_CTOR: u32 = 0xbc79_9737;

const MAX_TL_BYTES_LEN: usize = 0xFF_FFFF;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_total_len: usize,
    pub max_bytes_len: usize,
    pub max_vector_len: usize,
    pub max_nesting: u32,
    pub max_decode_ops: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_total_len: 8 << 20,
            max_bytes_len: 1 << 20,
            max_vector_len: 100_000,
            max_nesting: 64,
            max_decode_ops: 2_000_000,
        }
    }
}

#[inline]
fn pad_len4(written: usize) -> usize {
    (4 - (written % 4)) % 4
}

#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Encoder { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Encoder {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn ctor(&mut self, id: u32) {
        self.buf.extend_from_slice(&id.to_le_bytes());
    }

    pub fn int(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn long(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn uint(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn ulong(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn bool(&mut self, v: bool) {
        self.ctor(if v { BOOL_TRUE_CTOR } else { BOOL_FALSE_CTOR });
    }

    pub fn bytes(&mut self, b: &[u8]) -> Result<()> {
        let n = b.len();
        if n > MAX_TL_BYTES_LEN {
            return Err(TlError::LimitExceeded);
        }
        let header = if n < 254 {
            self.buf.push(n as u8);
            1
        } else {
            self.buf.push(254);
            self.buf.push(n as u8);
            self.buf.push((n >> 8) as u8);
            self.buf.push((n >> 16) as u8);
            4
        };
        self.buf.extend_from_slice(b);
        self.buf.resize(self.buf.len() + pad_len4(header + n), 0);
        Ok(())
    }

    pub fn string(&mut self, s: &str) -> Result<()> {
        self.bytes(s.as_bytes())
    }

    pub fn vector_header(&mut self, len: usize) -> Result<()> {
        if len > i32::MAX as usize {
            return Err(TlError::LimitExceeded);
        }
        self.ctor(VECTOR_CTOR);
        self.int(len as i32);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    off: usize,
    limits: Limits,
    depth: u32,
    ops: u64,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8], limits: Limits) -> Result<Self> {
        if buf.len() > limits.max_total_len {
            return Err(TlError::LimitExceeded);
        }
        Ok(Decoder {
            buf,
            off: 0,
            limits,
            depth: 0,
            ops: 0,
        })
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.off
    }

    pub fn offset(&self) -> usize {
        self.off
    }

    fn add_ops(&mut self, n: u64) -> Result<()> {
        self.ops = self.ops.saturating_add(n);
        if self.limits.max_decode_ops > 0 && self.ops > self.limits.max_decode_ops {
            return Err(TlError::LimitExceeded);
        }
        Ok(())
    }

    fn read_n(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(TlError::ShortBuffer);
        }
        let out = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(out)
    }

    pub fn uint(&mut self) -> Result<u32> {
        self.add_ops(1)?;
        Ok(wire::u32_le(self.read_n(4)?))
    }

    pub fn ctor(&mut self) -> Result<u32> {
        self.uint()
    }

    pub fn int(&mut self) -> Result<i32> {
        Ok(self.uint()? as i32)
    }

    pub fn ulong(&mut self) -> Result<u64> {
        self.add_ops(1)?;
        Ok(wire::u64_le(self.read_n(8)?))
    }

    pub fn long(&mut self) -> Result<i64> {
        Ok(self.ulong()? as i64)
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.ctor()? {
            BOOL_TRUE_CTOR => Ok(true),
            BOOL_FALSE_CTOR => Ok(false),
            _ => Err(TlError::InvalidData),
        }
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        self.add_ops(1)?;
        let first = *self.read_n(1)?.first().expect("read_n(1) yields one byte");

        let (n, header) = if first < 254 {
            (first as usize, 1)
        } else if first == 254 {
            let len3 = self.read_n(3)?;
            let n = len3[0] as usize | (len3[1] as usize) << 8 | (len3[2] as usize) << 16;
            (n, 4)
        } else {
            return Err(TlError::InvalidData);
        };

        if n > self.limits.max_bytes_len {
            return Err(TlError::LimitExceeded);
        }

        let data = self.read_n(n)?.to_vec();

        let pad = pad_len4(header + n);
        if self.read_n(pad)?.iter().any(|&b| b != 0) {
            return Err(TlError::InvalidPadding);
        }
        Ok(data)
    }

    pub fn string(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| TlError::InvalidUtf8)
    }

    pub fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > self.limits.max_nesting {
            self.depth -= 1;
            return Err(TlError::NestingExceeded);
        }
        Ok(())
    }

    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn vector_header(&mut self) -> Result<usize> {
        let ctor = self.ctor()?;
        if ctor != VECTOR_CTOR {
            return Err(TlError::InvalidVector);
        }
        let n = self.int()?;
        if n < 0 || n as usize > self.limits.max_vector_len {
            return Err(TlError::LimitExceeded);
        }
        let n = n as usize;
        self.add_ops(n as u64)?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_bytes(input: &[u8]) {
        let mut e = Encoder::new();
        e.bytes(input).unwrap();
        let encoded = e.into_bytes();
        assert_eq!(encoded.len() % 4, 0, "bytes must pad to 4");
        let mut d = Decoder::new(&encoded, Limits::default()).unwrap();
        assert_eq!(d.bytes().unwrap(), input);
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn bytes_padding_boundaries() {
        for len in [0usize, 1, 2, 3, 4, 253, 254, 255, 600] {
            roundtrip_bytes(&vec![0xABu8; len]);
        }
    }

    #[test]
    fn fixed_integers() {
        let mut e = Encoder::new();
        e.int(-1);
        e.long(-2);
        e.uint(0xDEAD_BEEF);
        e.ulong(0x0102_0304_0506_0708);
        e.bool(true);
        e.bool(false);
        let bytes = e.into_bytes();
        let mut d = Decoder::new(&bytes, Limits::default()).unwrap();
        assert_eq!(d.int().unwrap(), -1);
        assert_eq!(d.long().unwrap(), -2);
        assert_eq!(d.uint().unwrap(), 0xDEAD_BEEF);
        assert_eq!(d.ulong().unwrap(), 0x0102_0304_0506_0708);
        assert!(d.bool().unwrap());
        assert!(!d.bool().unwrap());
    }

    #[test]
    fn vector_roundtrip() {
        let mut e = Encoder::new();
        e.vector_header(3).unwrap();
        for v in [10i32, 20, 30] {
            e.int(v);
        }
        let bytes = e.into_bytes();
        let mut d = Decoder::new(&bytes, Limits::default()).unwrap();
        assert_eq!(d.vector_header().unwrap(), 3);
        assert_eq!(
            (d.int().unwrap(), d.int().unwrap(), d.int().unwrap()),
            (10, 20, 30)
        );
    }

    #[test]
    fn rejects_nonzero_padding() {
        let mut e = Encoder::new();
        e.bytes(b"ab").unwrap();
        let mut bytes = e.into_bytes();
        *bytes.last_mut().unwrap() = 1;
        let mut d = Decoder::new(&bytes, Limits::default()).unwrap();
        assert_eq!(d.bytes(), Err(TlError::InvalidPadding));
    }

    #[test]
    fn rejects_bad_bool() {
        let mut e = Encoder::new();
        e.ctor(0x1234_5678);
        let bytes = e.into_bytes();
        let mut d = Decoder::new(&bytes, Limits::default()).unwrap();
        assert_eq!(d.bool(), Err(TlError::InvalidData));
    }
}
