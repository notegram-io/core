use std::sync::OnceLock;

pub const DEPTH: usize = 256;

fn empty_leaf() -> [u8; 32] {
    crypto::sha256(b"notegram-username-smt-empty-v1")
}

fn defaults() -> &'static [[u8; 32]; DEPTH + 1] {
    static D: OnceLock<[[u8; 32]; DEPTH + 1]> = OnceLock::new();
    D.get_or_init(|| {
        let mut d = [[0u8; 32]; DEPTH + 1];
        d[DEPTH] = empty_leaf();
        for i in (0..DEPTH).rev() {
            d[i] = inner_hash(&d[i + 1], &d[i + 1]);
        }
        d
    })
}

fn leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = 0x00;
    buf[1..33].copy_from_slice(key);
    buf[33..].copy_from_slice(value);
    crypto::sha256(&buf)
}

fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    crypto::sha256(&buf)
}

fn bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i >> 3] >> (7 - (i & 7) as u8)) & 1
}

pub fn key(normalized: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(29 + normalized.len());
    input.extend_from_slice(b"notegram-username-smt-key-v1:");
    input.extend_from_slice(normalized.as_bytes());
    crypto::sha256(&input)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub value: [u8; 32],
    pub present: bool,

    pub bitmap: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

pub fn verify(root: &[u8; 32], key: &[u8; 32], proof: &Proof) -> bool {
    let defaults = defaults();
    let mut h = if proof.present {
        leaf_hash(key, &proof.value)
    } else {
        empty_leaf()
    };
    let mut si = 0usize;
    for i in 0..DEPTH {
        let s = if proof.bitmap[i >> 3] & (1 << (7 - (i & 7) as u8)) != 0 {
            match proof.siblings.get(si) {
                Some(s) => {
                    si += 1;
                    *s
                }
                None => return false,
            }
        } else {
            defaults[DEPTH - i]
        };
        let d = DEPTH - 1 - i;
        h = if bit(key, d) == 0 {
            inner_hash(&h, &s)
        } else {
            inner_hash(&s, &h)
        };
    }
    si == proof.siblings.len() && &h == root
}

pub fn serialize(proof: &Proof) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + 32 + 32 + 4 + proof.siblings.len() * 32);
    b.push(u8::from(proof.present));
    b.extend_from_slice(&proof.value);
    b.extend_from_slice(&proof.bitmap);
    wire::append_u32_le(&mut b, proof.siblings.len() as u32);
    for s in &proof.siblings {
        b.extend_from_slice(s);
    }
    b
}

pub fn parse(blob: &[u8]) -> Option<Proof> {
    if blob.len() < 1 + 32 + 32 + 4 {
        return None;
    }
    let present = blob[0] == 1;
    let mut value = [0u8; 32];
    value.copy_from_slice(&blob[1..33]);
    let mut bitmap = [0u8; 32];
    bitmap.copy_from_slice(&blob[33..65]);
    let n = wire::u32_le(&blob[65..69]) as usize;
    if n > DEPTH || 69 + n * 32 != blob.len() {
        return None;
    }
    let mut siblings = Vec::with_capacity(n);
    for i in 0..n {
        let mut s = [0u8; 32];
        s.copy_from_slice(&blob[69 + i * 32..69 + (i + 1) * 32]);
        siblings.push(s);
    }
    Some(Proof {
        value,
        present,
        bitmap,
        siblings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_roundtrip() {
        let p = Proof {
            value: [7u8; 32],
            present: true,
            bitmap: [0xAB; 32],
            siblings: vec![[1u8; 32], [2u8; 32]],
        };
        assert_eq!(parse(&serialize(&p)), Some(p));
    }

    #[test]
    fn parse_rejects_truncated() {
        assert_eq!(parse(&[0u8; 10]), None);
    }

    #[test]
    fn key_is_domain_separated() {
        assert_ne!(key("alice"), crypto::sha256(b"alice"));
        assert_eq!(key("alice"), key("alice"));
    }
}
