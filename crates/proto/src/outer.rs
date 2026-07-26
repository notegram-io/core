use crate::error::{ProtoError, Result};

pub const OUTER_HEADER_SIZE: usize = 40;

pub const SECURE_VERSION_2: u8 = 2;

pub const DIR_C2S: u8 = 1;

pub const DIR_S2C: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OuterHeader {
    pub version: u8,
    pub flags: u8,
    pub direction: u8,
    pub epoch: u32,
    pub plain_len: u32,
    pub seq_no: u32,
    pub auth_key_id: u64,
    pub session_id: u64,
    pub msg_id: u64,
}

impl OuterHeader {
    pub fn write_into(&self, dst: &mut [u8; OUTER_HEADER_SIZE]) {
        dst[0] = self.version;
        dst[1] = self.flags;
        dst[2] = self.direction;
        dst[3] = 0;
        dst[4..8].copy_from_slice(&self.epoch.to_le_bytes());
        dst[8..12].copy_from_slice(&self.plain_len.to_le_bytes());
        dst[12..16].copy_from_slice(&self.seq_no.to_le_bytes());
        dst[16..24].copy_from_slice(&self.auth_key_id.to_le_bytes());
        dst[24..32].copy_from_slice(&self.session_id.to_le_bytes());
        dst[32..40].copy_from_slice(&self.msg_id.to_le_bytes());
    }

    pub fn to_bytes(&self) -> [u8; OUTER_HEADER_SIZE] {
        let mut b = [0u8; OUTER_HEADER_SIZE];
        self.write_into(&mut b);
        b
    }

    pub fn parse(src: &[u8]) -> Result<OuterHeader> {
        if src.len() < OUTER_HEADER_SIZE {
            return Err(ProtoError::BadHeader);
        }
        Ok(OuterHeader {
            version: src[0],
            flags: src[1],
            direction: src[2],
            epoch: wire::u32_le(&src[4..8]),
            plain_len: wire::u32_le(&src[8..12]),
            seq_no: wire::u32_le(&src[12..16]),
            auth_key_id: wire::u64_le(&src[16..24]),
            session_id: wire::u64_le(&src[24..32]),
            msg_id: wire::u64_le(&src[32..40]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = OuterHeader {
            version: SECURE_VERSION_2,
            flags: 0,
            direction: DIR_C2S,
            epoch: 7,
            plain_len: 123,
            seq_no: 9,
            auth_key_id: 0x1122_3344_5566_7788,
            session_id: 0xAABB_CCDD_EEFF_0011,
            msg_id: 0xDEAD_BEEF_CAFE_F00D,
        };
        let b = h.to_bytes();
        assert_eq!(b[3], 0, "reserved byte must be zero");
        assert_eq!(OuterHeader::parse(&b).unwrap(), h);
    }
}
