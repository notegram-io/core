use std::collections::HashMap;

use crate::smt;

const KT_ENTRY_DOMAIN: &[u8] = b"notegram-username-kt-entry-v1";
const STR_DOMAIN: &[u8] = b"notegram-username-str-v1";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KtEntry {
    pub seq: u64,
    pub event: u8,
    pub normalized: String,
    pub user_id: i64,
    pub allocation: u8,
    pub auth_kind: u8,
    pub owner_ref: String,
    pub auth_proof: Vec<u8>,
    pub created_ms: i64,
    pub prev_hash: Vec<u8>,
    pub entry_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessSig {
    pub id: String,
    pub public: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Str {
    pub epoch: u64,
    pub root: [u8; 32],
    pub prev_root: [u8; 32],
    pub issued_ms: i64,
    pub public: Vec<u8>,
    pub signature: Vec<u8>,
    pub witnesses: Vec<WitnessSig>,
}

fn append_le(dst: &mut Vec<u8>, src: &[u8]) {
    wire::append_u32_le(dst, src.len() as u32);
    dst.extend_from_slice(src);
}

pub fn build_entry_hash(e: &KtEntry) -> [u8; 32] {
    let mut b = Vec::with_capacity(160);
    b.extend_from_slice(KT_ENTRY_DOMAIN);
    wire::append_u64_le(&mut b, e.seq);
    b.push(e.event);
    append_le(&mut b, e.normalized.as_bytes());
    wire::append_u64_le(&mut b, e.user_id as u64);
    b.push(e.allocation);
    b.push(e.auth_kind);
    append_le(&mut b, e.owner_ref.as_bytes());
    append_le(&mut b, &e.auth_proof);
    wire::append_u64_le(&mut b, e.created_ms as u64);
    append_le(&mut b, &e.prev_hash);
    crypto::sha256(&b)
}

fn build_str_msg(s: &Str) -> Vec<u8> {
    let mut b = Vec::with_capacity(STR_DOMAIN.len() + 8 + 32 + 32 + 8);
    b.extend_from_slice(STR_DOMAIN);
    wire::append_u64_le(&mut b, s.epoch);
    b.extend_from_slice(&s.root);
    b.extend_from_slice(&s.prev_root);
    wire::append_u64_le(&mut b, s.issued_ms as u64);
    b
}

fn ed25519_verify_var(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(s)) = (<[u8; 32]>::try_from(public), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    crypto::ed25519_verify(&pk, msg, &s)
}

pub fn verify_str_signature(s: &Str) -> bool {
    if s.public.is_empty() && s.signature.is_empty() {
        return true;
    }
    ed25519_verify_var(&s.public, &build_str_msg(s), &s.signature)
}

pub fn verify_str_witnesses(s: &Str, trusted: &HashMap<String, Vec<u8>>, min: usize) -> bool {
    if min == 0 {
        return true;
    }
    let msg = build_str_msg(s);
    let mut seen = std::collections::HashSet::new();
    let mut count = 0;
    for w in &s.witnesses {
        let Some(pub_key) = trusted.get(&w.id) else {
            continue;
        };
        if pub_key.len() != 32 || pub_key != &w.public {
            continue;
        }
        if !seen.insert(w.id.clone()) {
            continue;
        }
        if ed25519_verify_var(pub_key, &msg, &w.sig) {
            count += 1;
        }
    }
    count >= min
}

pub fn parse_and_verify_membership(blob: &[u8]) -> Option<(KtEntry, Str)> {
    let mut r = Reader::new(blob);
    let e = read_entry(&mut r);
    let smt_blob = r.bytes()?.to_vec();

    let mut s = Str {
        epoch: r.u64()?,
        ..Default::default()
    };
    s.root.copy_from_slice(r.fixed(32)?);
    s.prev_root.copy_from_slice(r.fixed(32)?);
    s.issued_ms = r.u64()? as i64;
    s.public = r.bytes()?.to_vec();
    s.signature = r.bytes()?.to_vec();
    let witness_count = r.u32()?;
    for _ in 0..witness_count {
        s.witnesses.push(WitnessSig {
            id: String::from_utf8(r.bytes()?.to_vec()).ok()?,
            public: r.bytes()?.to_vec(),
            sig: r.bytes()?.to_vec(),
        });
    }
    if r.offset() != blob.len() {
        return None;
    }

    let entry_hash = build_entry_hash(&e);
    if entry_hash.as_slice() != e.entry_hash.as_slice() {
        return None;
    }

    let proof = smt::parse(&smt_blob)?;
    if !proof.present || proof.value != entry_hash {
        return None;
    }
    if !smt::verify(&s.root, &smt::key(&e.normalized), &proof) {
        return None;
    }

    if !verify_str_signature(&s) {
        return None;
    }
    let msg = build_str_msg(&s);
    for w in &s.witnesses {
        if !ed25519_verify_var(&w.public, &msg, &w.sig) {
            return None;
        }
    }
    Some((e, s))
}

fn read_entry(r: &mut Reader) -> KtEntry {
    KtEntry {
        seq: r.u64().unwrap_or(0),
        event: r.u8().unwrap_or(0),
        normalized: String::from_utf8(r.bytes().unwrap_or(&[]).to_vec()).unwrap_or_default(),
        user_id: r.u64().unwrap_or(0) as i64,
        allocation: r.u8().unwrap_or(0),
        auth_kind: r.u8().unwrap_or(0),
        owner_ref: String::from_utf8(r.bytes().unwrap_or(&[]).to_vec()).unwrap_or_default(),
        auth_proof: r.bytes().unwrap_or(&[]).to_vec(),
        created_ms: r.u64().unwrap_or(0) as i64,
        prev_hash: r.bytes().unwrap_or(&[]).to_vec(),
        entry_hash: r.bytes().unwrap_or(&[]).to_vec(),
    }
}

struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, off: 0 }
    }

    fn offset(&self) -> usize {
        self.off
    }

    fn fixed(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.off.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let out = &self.b[self.off..end];
        self.off = end;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        self.fixed(1).map(|s| s[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.fixed(4).map(wire::u32_le)
    }

    fn u64(&mut self) -> Option<u64> {
        self.fixed(8).map(wire::u64_le)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.fixed(n)
    }
}
