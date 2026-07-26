use std::collections::HashMap;

use crypto::{ed25519_public, ed25519_sign, ed25519_verify, hkdf_sha256, hmac_sha256};
use rand_core::{CryptoRng, RngCore};

use crate::{RatchetError, StateReader, StateWriter, MAX_SKIP, RATCHET_STATE_VERSION};

const MESSAGE_INFO: &[u8] = b"notegram-sender-key-message-v1";
const HEADER_LEN: usize = 4;
const SIG_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyDistribution {
    pub chain_key: [u8; 32],
    pub iteration: u32,
    pub signature_public: [u8; 32],
}

pub struct SenderKeySender {
    chain_key: [u8; 32],
    iteration: u32,
    signature_seed: [u8; 32],
    signature_public: [u8; 32],
}

impl SenderKeySender {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut chain_key = [0u8; 32];
        let mut signature_seed = [0u8; 32];
        rng.fill_bytes(&mut chain_key);
        rng.fill_bytes(&mut signature_seed);
        SenderKeySender {
            chain_key,
            iteration: 0,
            signature_public: ed25519_public(&signature_seed),
            signature_seed,
        }
    }

    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            chain_key: self.chain_key,
            iteration: self.iteration,
            signature_public: self.signature_public,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
        let (mk, next_ck) = chain_step(&self.chain_key);
        self.chain_key = next_ck;
        let iteration = self.iteration;
        self.iteration += 1;

        let header = iteration.to_le_bytes();
        let (enc_key, nonce) = message_keys(&mk);
        let ciphertext =
            crate::aead_seal(&enc_key, &nonce, plaintext, &aad(associated_data, &header));

        let mut signed = header.to_vec();
        signed.extend_from_slice(&ciphertext);
        let sig = ed25519_sign(&self.signature_seed, &signed);

        let mut out = signed;
        out.extend_from_slice(&sig);
        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = StateWriter::new(RATCHET_STATE_VERSION);
        w.key(&self.chain_key);
        w.u32(self.iteration);
        w.key(&self.signature_seed);
        w.key(&self.signature_public);
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut r = StateReader::new(bytes, RATCHET_STATE_VERSION)?;
        let chain_key = r.key()?;
        let iteration = r.u32()?;
        let signature_seed = r.key()?;
        let signature_public = r.key()?;
        r.finish()?;
        Ok(SenderKeySender {
            chain_key,
            iteration,
            signature_seed,
            signature_public,
        })
    }
}

pub struct SenderKeyReceiver {
    chain_key: [u8; 32],
    iteration: u32,
    signature_public: [u8; 32],
    skipped: HashMap<u32, [u8; 32]>,
}

impl SenderKeyReceiver {
    pub fn from_distribution(dist: &SenderKeyDistribution) -> Self {
        SenderKeyReceiver {
            chain_key: dist.chain_key,
            iteration: dist.iteration,
            signature_public: dist.signature_public,
            skipped: HashMap::new(),
        }
    }

    pub fn decrypt(
        &mut self,
        message: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        if message.len() < HEADER_LEN + SIG_LEN {
            return Err(RatchetError::BadHeader);
        }
        let sig_start = message.len() - SIG_LEN;
        let signed = &message[..sig_start];
        let sig: [u8; 64] = message[sig_start..].try_into().unwrap();
        if !ed25519_verify(&self.signature_public, signed, &sig) {
            return Err(RatchetError::Decrypt);
        }

        let header = &signed[..HEADER_LEN];
        let ciphertext = &signed[HEADER_LEN..];
        let iteration = u32::from_le_bytes(header.try_into().unwrap());
        let ad = aad(associated_data, header);

        if let Some(mk) = self.skipped.remove(&iteration) {
            let (enc_key, nonce) = message_keys(&mk);
            return crate::aead_open(&enc_key, &nonce, ciphertext, &ad);
        }
        if iteration < self.iteration {
            return Err(RatchetError::Decrypt);
        }
        if iteration.saturating_sub(self.iteration) > MAX_SKIP {
            return Err(RatchetError::TooManySkipped);
        }
        while self.iteration < iteration {
            let (mk, next) = chain_step(&self.chain_key);
            self.skipped.insert(self.iteration, mk);
            self.chain_key = next;
            self.iteration += 1;
        }
        let (mk, next) = chain_step(&self.chain_key);
        self.chain_key = next;
        self.iteration += 1;
        let (enc_key, nonce) = message_keys(&mk);
        crate::aead_open(&enc_key, &nonce, ciphertext, &ad)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = StateWriter::new(RATCHET_STATE_VERSION);
        w.key(&self.chain_key);
        w.u32(self.iteration);
        w.key(&self.signature_public);
        w.u32(self.skipped.len() as u32);
        let mut entries: Vec<_> = self.skipped.iter().collect();
        entries.sort_unstable_by_key(|(k, _)| **k);
        for (iteration, mk) in entries {
            w.u32(*iteration);
            w.key(mk);
        }
        w.into_vec()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, RatchetError> {
        let mut r = StateReader::new(bytes, RATCHET_STATE_VERSION)?;
        let chain_key = r.key()?;
        let iteration = r.u32()?;
        let signature_public = r.key()?;
        let skipped_len = r.u32()? as usize;
        if skipped_len > (MAX_SKIP as usize).saturating_add(1) {
            return Err(RatchetError::BadState);
        }
        let mut skipped = HashMap::with_capacity(skipped_len);
        for _ in 0..skipped_len {
            let key = r.u32()?;
            let mk = r.key()?;
            skipped.insert(key, mk);
        }
        r.finish()?;
        Ok(SenderKeyReceiver {
            chain_key,
            iteration,
            signature_public,
            skipped,
        })
    }
}

fn chain_step(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (hmac_sha256(ck, &[0x01]), hmac_sha256(ck, &[0x02]))
}

fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut out = [0u8; 44];
    hkdf_sha256(mk, None, MESSAGE_INFO, &mut out);
    let mut enc_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    enc_key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..]);
    (enc_key, nonce)
}

fn aad(associated_data: &[u8], header: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(associated_data.len() + header.len());
    v.extend_from_slice(associated_data);
    v.extend_from_slice(header);
    v
}
