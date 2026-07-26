#![forbid(unsafe_code)]

use std::collections::HashMap;

pub mod sender_key;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};

const ROOT_INFO: &[u8] = b"notegram-double-ratchet-root-v1";
const MESSAGE_INFO: &[u8] = b"notegram-double-ratchet-message-v1";
const HEADER_LEN: usize = 32 + 4 + 4;

pub const MAX_SKIP: u32 = 1000;

#[derive(Debug, PartialEq, Eq)]
pub enum RatchetError {
    BadHeader,

    Decrypt,

    TooManySkipped,

    NotEstablished,

    BadState,
}

impl std::fmt::Display for RatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RatchetError::BadHeader => "bad ratchet header",
            RatchetError::Decrypt => "ratchet decrypt failed",
            RatchetError::TooManySkipped => "too many skipped messages",
            RatchetError::NotEstablished => "ratchet sending chain not established",
            RatchetError::BadState => "malformed persisted ratchet state",
        };
        write!(f, "ratchet: {s}")
    }
}

impl std::error::Error for RatchetError {}

pub struct DoubleRatchet {
    dhs_priv: [u8; 32],
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchet {
    pub fn init_alice<R: RngCore + CryptoRng>(
        shared_secret: [u8; 32],
        peer_ratchet_pub: [u8; 32],
        rng: &mut R,
    ) -> Self {
        let (dhs_priv, dhs_pub) = crypto::x25519_generate(rng);
        let dh = crypto::x25519_dh(&dhs_priv, &peer_ratchet_pub);
        let (rk, cks) = kdf_rk(&shared_secret, &dh);
        DoubleRatchet {
            dhs_priv,
            dhs_pub,
            dhr: Some(peer_ratchet_pub),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn init_bob(shared_secret: [u8; 32], ratchet_priv: [u8; 32]) -> Self {
        DoubleRatchet {
            dhs_priv: ratchet_priv,
            dhs_pub: crypto::x25519_public(&ratchet_priv),
            dhr: None,
            rk: shared_secret,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.dhs_pub
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        let ck = self.cks.ok_or(RatchetError::NotEstablished)?;
        let (mk, next_ck) = kdf_ck(&ck);
        self.cks = Some(next_ck);

        let header = encode_header(&self.dhs_pub, self.pn, self.ns);
        self.ns += 1;

        let (enc_key, nonce) = kdf_mk(&mk);
        let ciphertext = aead_seal(&enc_key, &nonce, plaintext, &aad(associated_data, &header));

        let mut out = header.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt<R: RngCore + CryptoRng>(
        &mut self,
        message: &[u8],
        associated_data: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, RatchetError> {
        if message.len() < HEADER_LEN {
            return Err(RatchetError::BadHeader);
        }
        let header = &message[..HEADER_LEN];
        let ciphertext = &message[HEADER_LEN..];
        let (dh_pub, pn, n) = decode_header(header);
        let ad = aad(associated_data, header);

        if let Some(mk) = self.skipped.remove(&(dh_pub, n)) {
            return decrypt_with(&mk, ciphertext, &ad);
        }

        if self.dhr != Some(dh_pub) {
            self.skip_message_keys(pn)?;
            self.dh_ratchet(dh_pub, rng);
        }
        self.skip_message_keys(n)?;

        let ck = self.ckr.ok_or(RatchetError::Decrypt)?;
        let (mk, next_ck) = kdf_ck(&ck);
        self.ckr = Some(next_ck);
        self.nr += 1;
        decrypt_with(&mk, ciphertext, &ad)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if until < self.nr {
            return Ok(());
        }
        if until.saturating_sub(self.nr) > MAX_SKIP {
            return Err(RatchetError::TooManySkipped);
        }
        let Some(dhr) = self.dhr else {
            return Ok(());
        };
        if let Some(ck) = self.ckr {
            let mut ck = ck;
            while self.nr < until {
                let (mk, next) = kdf_ck(&ck);
                self.skipped.insert((dhr, self.nr), mk);
                ck = next;
                self.nr += 1;
            }
            self.ckr = Some(ck);
        }
        Ok(())
    }

    fn dh_ratchet<R: RngCore + CryptoRng>(&mut self, dh_pub: [u8; 32], rng: &mut R) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(dh_pub);

        let (rk, ckr) = kdf_rk(&self.rk, &crypto::x25519_dh(&self.dhs_priv, &dh_pub));
        self.rk = rk;
        self.ckr = Some(ckr);

        let (dhs_priv, dhs_pub) = crypto::x25519_generate(rng);
        self.dhs_priv = dhs_priv;
        self.dhs_pub = dhs_pub;

        let (rk, cks) = kdf_rk(&self.rk, &crypto::x25519_dh(&self.dhs_priv, &dh_pub));
        self.rk = rk;
        self.cks = Some(cks);
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = StateWriter::new(RATCHET_STATE_VERSION);
        w.key(&self.dhs_priv);
        w.key(&self.dhs_pub);
        w.opt_key(&self.dhr);
        w.key(&self.rk);
        w.opt_key(&self.cks);
        w.opt_key(&self.ckr);
        w.u32(self.ns);
        w.u32(self.nr);
        w.u32(self.pn);
        w.u32(self.skipped.len() as u32);

        let mut entries: Vec<_> = self.skipped.iter().collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for ((dh_pub, n), mk) in entries {
            w.key(dh_pub);
            w.u32(*n);
            w.key(mk);
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut r = StateReader::new(bytes, RATCHET_STATE_VERSION)?;
        let dhs_priv = r.key()?;
        let dhs_pub = r.key()?;
        let dhr = r.opt_key()?;
        let rk = r.key()?;
        let cks = r.opt_key()?;
        let ckr = r.opt_key()?;
        let ns = r.u32()?;
        let nr = r.u32()?;
        let pn = r.u32()?;
        let skipped_len = r.u32()? as usize;
        if skipped_len > (MAX_SKIP as usize).saturating_add(1) {
            return Err(RatchetError::BadState);
        }
        let mut skipped = HashMap::with_capacity(skipped_len);
        for _ in 0..skipped_len {
            let dh_pub = r.key()?;
            let n = r.u32()?;
            let mk = r.key()?;
            skipped.insert((dh_pub, n), mk);
        }
        r.finish()?;
        Ok(DoubleRatchet {
            dhs_priv,
            dhs_pub,
            dhr,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
        })
    }
}

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    crypto::hkdf_sha256(dh_out, Some(rk), ROOT_INFO, &mut out);
    let mut root = [0u8; 32];
    let mut chain = [0u8; 32];
    root.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    (root, chain)
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (
        crypto::hmac_sha256(ck, &[0x01]),
        crypto::hmac_sha256(ck, &[0x02]),
    )
}

fn kdf_mk(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut out = [0u8; 44];
    crypto::hkdf_sha256(mk, None, MESSAGE_INFO, &mut out);
    let mut enc_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    enc_key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..]);
    (enc_key, nonce)
}

fn encode_header(dh_pub: &[u8; 32], pn: u32, n: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..32].copy_from_slice(dh_pub);
    h[32..36].copy_from_slice(&pn.to_le_bytes());
    h[36..40].copy_from_slice(&n.to_le_bytes());
    h
}

fn decode_header(h: &[u8]) -> ([u8; 32], u32, u32) {
    let mut dh = [0u8; 32];
    dh.copy_from_slice(&h[..32]);
    let pn = u32::from_le_bytes([h[32], h[33], h[34], h[35]]);
    let n = u32::from_le_bytes([h[36], h[37], h[38], h[39]]);
    (dh, pn, n)
}

fn aad(associated_data: &[u8], header: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(associated_data.len() + header.len());
    v.extend_from_slice(associated_data);
    v.extend_from_slice(header);
    v
}

pub(crate) fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20poly1305 encryption is infallible for valid keys")
}

pub(crate) fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| RatchetError::Decrypt)
}
fn decrypt_with(mk: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let (enc_key, nonce) = kdf_mk(mk);
    aead_open(&enc_key, &nonce, ciphertext, aad)
}

pub(crate) const RATCHET_STATE_VERSION: u8 = 1;

pub(crate) struct StateWriter {
    buf: Vec<u8>,
}

impl StateWriter {
    pub(crate) fn new(version: u8) -> Self {
        StateWriter { buf: vec![version] }
    }

    pub(crate) fn key(&mut self, k: &[u8; 32]) {
        self.buf.extend_from_slice(k);
    }

    pub(crate) fn opt_key(&mut self, k: &Option<[u8; 32]>) {
        match k {
            Some(v) => {
                self.buf.push(1);
                self.buf.extend_from_slice(v);
            }
            None => self.buf.push(0),
        }
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

pub(crate) struct StateReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> StateReader<'a> {
    pub(crate) fn new(buf: &'a [u8], expect_version: u8) -> Result<Self, RatchetError> {
        if buf.first().copied() != Some(expect_version) {
            return Err(RatchetError::BadState);
        }
        Ok(StateReader { buf, pos: 1 })
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], RatchetError> {
        let end = self.pos.checked_add(n).ok_or(RatchetError::BadState)?;
        if end > self.buf.len() {
            return Err(RatchetError::BadState);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn key(&mut self) -> Result<[u8; 32], RatchetError> {
        let s = self.take(32)?;
        let mut k = [0u8; 32];
        k.copy_from_slice(s);
        Ok(k)
    }

    pub(crate) fn opt_key(&mut self) -> Result<Option<[u8; 32]>, RatchetError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(self.key()?)),
            _ => Err(RatchetError::BadState),
        }
    }

    pub(crate) fn u32(&mut self) -> Result<u32, RatchetError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(crate) fn finish(self) -> Result<(), RatchetError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(RatchetError::BadState)
        }
    }
}
