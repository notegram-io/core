use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use crate::{Result, StoreError};

pub const MASTER_KEY_LEN: usize = 32;

const SEAL_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const SUBKEY_INFO_PREFIX: &[u8] = b"notegram.store.subkey.v1:";

pub struct RecordCipher {
    master_key: [u8; MASTER_KEY_LEN],
}

impl RecordCipher {
    pub fn new(master_key: &[u8]) -> Result<Self> {
        if master_key.len() != MASTER_KEY_LEN {
            return Err(StoreError::BadMasterKey);
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(master_key);
        Ok(RecordCipher { master_key: key })
    }

    pub fn seal(&self, namespace: &[u8], record_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.cipher_for(namespace);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = associated_data(namespace, record_key);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("xchacha20poly1305 encryption is infallible for valid keys");

        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(SEAL_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn open(&self, namespace: &[u8], record_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 1 + NONCE_LEN {
            return Err(StoreError::BadRecord);
        }
        if sealed[0] != SEAL_VERSION {
            return Err(StoreError::BadRecord);
        }
        let nonce = XNonce::from_slice(&sealed[1..1 + NONCE_LEN]);
        let ciphertext = &sealed[1 + NONCE_LEN..];
        let aad = associated_data(namespace, record_key);
        self.cipher_for(namespace)
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Decrypt)
    }

    fn cipher_for(&self, namespace: &[u8]) -> XChaCha20Poly1305 {
        let mut info = Vec::with_capacity(SUBKEY_INFO_PREFIX.len() + namespace.len());
        info.extend_from_slice(SUBKEY_INFO_PREFIX);
        info.extend_from_slice(namespace);
        let mut subkey = [0u8; 32];
        crypto::hkdf_sha256(&self.master_key, None, &info, &mut subkey);
        XChaCha20Poly1305::new((&subkey).into())
    }
}

fn associated_data(namespace: &[u8], record_key: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + namespace.len() + record_key.len());
    aad.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
    aad.extend_from_slice(namespace);
    aad.extend_from_slice(record_key);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> RecordCipher {
        RecordCipher::new(&[7u8; MASTER_KEY_LEN]).unwrap()
    }

    #[test]
    fn seal_open_roundtrip() {
        let c = cipher();
        let sealed = c.seal(b"session", b"peer-1", b"ratchet-state");
        assert_eq!(
            c.open(b"session", b"peer-1", &sealed).unwrap(),
            b"ratchet-state"
        );
    }

    #[test]
    fn nonce_is_random_per_seal() {
        let c = cipher();
        let a = c.seal(b"session", b"peer-1", b"x");
        let b = c.seal(b"session", b"peer-1", b"x");
        assert_ne!(a, b, "each seal must use a fresh random nonce");
    }

    #[test]
    fn wrong_namespace_or_key_is_rejected() {
        let c = cipher();
        let sealed = c.seal(b"session", b"peer-1", b"secret");
        assert_eq!(
            c.open(b"prekey", b"peer-1", &sealed),
            Err(StoreError::Decrypt)
        );
        assert_eq!(
            c.open(b"session", b"peer-2", &sealed),
            Err(StoreError::Decrypt)
        );
    }

    #[test]
    fn tampering_and_wrong_master_key_are_rejected() {
        let c = cipher();
        let mut sealed = c.seal(b"session", b"peer-1", b"secret");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(
            c.open(b"session", b"peer-1", &sealed),
            Err(StoreError::Decrypt)
        );

        let other = RecordCipher::new(&[9u8; MASTER_KEY_LEN]).unwrap();
        let good = c.seal(b"session", b"peer-1", b"secret");
        assert_eq!(
            other.open(b"session", b"peer-1", &good),
            Err(StoreError::Decrypt)
        );
    }

    #[test]
    fn malformed_blobs_are_rejected() {
        let c = cipher();
        assert_eq!(
            c.open(b"session", b"peer-1", &[]),
            Err(StoreError::BadRecord)
        );
        assert_eq!(
            c.open(b"session", b"peer-1", &[9u8; 40]),
            Err(StoreError::BadRecord)
        );
    }

    #[test]
    fn bad_master_key_length() {
        assert_eq!(
            RecordCipher::new(&[0u8; 16]).err(),
            Some(StoreError::BadMasterKey)
        );
    }
}
