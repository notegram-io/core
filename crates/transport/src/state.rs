use std::time::{SystemTime, UNIX_EPOCH};

use proto::{DIR_C2S, DIR_S2C};

#[derive(Debug, Clone)]
pub struct SecureState {
    pub auth_key: Option<[u8; 32]>,

    pub auth_key_id: u64,
    pub epoch: u32,
    pub salt: u64,
    pub session_id: u64,

    pub out_direction: u8,

    seq: u32,
    msg_ctr: u64,
    last_ms: i64,
}

impl SecureState {
    pub fn new_client(session_id: u64) -> Self {
        SecureState {
            auth_key: None,
            auth_key_id: 0,
            epoch: 0,
            salt: 0,
            session_id,
            out_direction: DIR_C2S,
            seq: 0,
            msg_ctr: 0,
            last_ms: 0,
        }
    }

    pub fn inbound_direction(&self) -> u8 {
        if self.out_direction == DIR_C2S {
            DIR_S2C
        } else {
            DIR_C2S
        }
    }

    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    pub fn next_msg_id(&mut self, now_ms: i64) -> u64 {
        if now_ms == self.last_ms {
            self.msg_ctr = (self.msg_ctr + 1) & ((1 << 20) - 1);
        } else {
            self.msg_ctr = 0;
            self.last_ms = now_ms;
        }
        ((now_ms as u64) << 20) | self.msg_ctr
    }
}

pub(crate) fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_id_layout_and_counter() {
        let mut s = SecureState::new_client(1);
        let a = s.next_msg_id(1000);
        let b = s.next_msg_id(1000);
        assert_eq!(a >> 20, 1000);
        assert_eq!(a & 0xFFFFF, 0);
        assert_eq!(b & 0xFFFFF, 1, "counter increments within a millisecond");
        let c = s.next_msg_id(1001);
        assert_eq!(c >> 20, 1001);
        assert_eq!(c & 0xFFFFF, 0, "counter resets on a new millisecond");
    }

    #[test]
    fn seq_is_monotonic() {
        let mut s = SecureState::new_client(1);
        assert_eq!((s.next_seq(), s.next_seq(), s.next_seq()), (0, 1, 2));
    }
}
