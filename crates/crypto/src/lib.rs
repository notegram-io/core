#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, out)
        .expect("HKDF output length is within bounds");
}

pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

pub fn x25519_dh(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*secret)
        .diffie_hellman(&PublicKey::from(*peer_public))
        .to_bytes()
}

pub fn x25519_generate<R: RngCore + CryptoRng>(rng: &mut R) -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let public = x25519_public(&secret);
    (secret, public)
}

pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex(&sha256(b"abc")), want);
    }

    #[test]
    fn x25519_dh_is_symmetric() {
        let a = [7u8; 32];
        let b = [9u8; 32];
        let ab = x25519_dh(&a, &x25519_public(&b));
        let ba = x25519_dh(&b, &x25519_public(&a));
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 32]);
    }

    #[test]
    fn ed25519_verify_roundtrip() {
        let seed = [3u8; 32];
        let sig = ed25519_sign(&seed, b"message");
        let pk = ed25519_public(&seed);
        assert!(ed25519_verify(&pk, b"message", &sig));
        assert!(!ed25519_verify(&pk, b"tampered", &sig));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
