const X3DH_INFO: &[u8] = b"notegram-x3dh-v1";
const SIGNED_PREKEY_CONTEXT: &[u8] = b"notegram-signed-prekey-v1";

pub fn sign_signed_prekey(
    device_signing_seed: &[u8; 32],
    signed_prekey_pub: &[u8; 32],
) -> [u8; 64] {
    crypto::ed25519_sign(
        device_signing_seed,
        &signed_prekey_message(signed_prekey_pub),
    )
}

pub fn verify_signed_prekey(
    device_signing_pub: &[u8; 32],
    signed_prekey_pub: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    crypto::ed25519_verify(
        device_signing_pub,
        &signed_prekey_message(signed_prekey_pub),
        signature,
    )
}

fn signed_prekey_message(signed_prekey_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNED_PREKEY_CONTEXT.len() + 32);
    m.extend_from_slice(SIGNED_PREKEY_CONTEXT);
    m.extend_from_slice(signed_prekey_pub);
    m
}

fn derive_secret(dh_outputs: &[[u8; 32]]) -> [u8; 32] {
    let mut ikm = vec![0xFFu8; 32];
    for dh in dh_outputs {
        ikm.extend_from_slice(dh);
    }
    let mut sk = [0u8; 32];
    crypto::hkdf_sha256(&ikm, Some(&[0u8; 32]), X3DH_INFO, &mut sk);
    sk
}

pub struct Initiator<'a> {
    pub identity_priv: &'a [u8; 32],
    pub ephemeral_priv: &'a [u8; 32],
    pub peer_identity_pub: &'a [u8; 32],
    pub peer_signed_prekey_pub: &'a [u8; 32],
    pub peer_one_time_prekey_pub: Option<&'a [u8; 32]>,
}

pub fn initiator_secret(i: &Initiator) -> [u8; 32] {
    let mut dhs = vec![
        crypto::x25519_dh(i.identity_priv, i.peer_signed_prekey_pub),
        crypto::x25519_dh(i.ephemeral_priv, i.peer_identity_pub),
        crypto::x25519_dh(i.ephemeral_priv, i.peer_signed_prekey_pub),
    ];
    if let Some(opk) = i.peer_one_time_prekey_pub {
        dhs.push(crypto::x25519_dh(i.ephemeral_priv, opk));
    }
    derive_secret(&dhs)
}

pub struct Responder<'a> {
    pub identity_priv: &'a [u8; 32],
    pub signed_prekey_priv: &'a [u8; 32],
    pub one_time_prekey_priv: Option<&'a [u8; 32]>,
    pub peer_identity_pub: &'a [u8; 32],
    pub peer_ephemeral_pub: &'a [u8; 32],
}

pub fn responder_secret(r: &Responder) -> [u8; 32] {
    let mut dhs = vec![
        crypto::x25519_dh(r.signed_prekey_priv, r.peer_identity_pub),
        crypto::x25519_dh(r.identity_priv, r.peer_ephemeral_pub),
        crypto::x25519_dh(r.signed_prekey_priv, r.peer_ephemeral_pub),
    ];
    if let Some(opk) = r.one_time_prekey_priv {
        dhs.push(crypto::x25519_dh(opk, r.peer_ephemeral_pub));
    }
    derive_secret(&dhs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{ed25519_public, x25519_generate};

    struct Rng(u64);
    impl rand_core::RngCore for Rng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            (self.0 >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            ((self.next_u32() as u64) << 32) | self.next_u32() as u64
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            for c in d.chunks_mut(4) {
                c.copy_from_slice(&self.next_u32().to_le_bytes()[..c.len()]);
            }
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for Rng {}

    #[test]
    fn initiator_and_responder_agree() {
        let mut rng = Rng(0xABCD);
        let (ik_a, ik_a_pub) = x25519_generate(&mut rng);
        let (ek_a, ek_a_pub) = x25519_generate(&mut rng);
        let (ik_b, ik_b_pub) = x25519_generate(&mut rng);
        let (spk_b, spk_b_pub) = x25519_generate(&mut rng);
        let (opk_b, opk_b_pub) = x25519_generate(&mut rng);

        let sk_a = initiator_secret(&Initiator {
            identity_priv: &ik_a,
            ephemeral_priv: &ek_a,
            peer_identity_pub: &ik_b_pub,
            peer_signed_prekey_pub: &spk_b_pub,
            peer_one_time_prekey_pub: Some(&opk_b_pub),
        });
        let sk_b = responder_secret(&Responder {
            identity_priv: &ik_b,
            signed_prekey_priv: &spk_b,
            one_time_prekey_priv: Some(&opk_b),
            peer_identity_pub: &ik_a_pub,
            peer_ephemeral_pub: &ek_a_pub,
        });
        assert_eq!(sk_a, sk_b, "X3DH secrets must agree");
        assert_ne!(sk_a, [0u8; 32]);
    }

    #[test]
    fn agree_without_one_time_prekey() {
        let mut rng = Rng(0x1234);
        let (ik_a, ik_a_pub) = x25519_generate(&mut rng);
        let (ek_a, ek_a_pub) = x25519_generate(&mut rng);
        let (ik_b, ik_b_pub) = x25519_generate(&mut rng);
        let (spk_b, spk_b_pub) = x25519_generate(&mut rng);

        let sk_a = initiator_secret(&Initiator {
            identity_priv: &ik_a,
            ephemeral_priv: &ek_a,
            peer_identity_pub: &ik_b_pub,
            peer_signed_prekey_pub: &spk_b_pub,
            peer_one_time_prekey_pub: None,
        });
        let sk_b = responder_secret(&Responder {
            identity_priv: &ik_b,
            signed_prekey_priv: &spk_b,
            one_time_prekey_priv: None,
            peer_identity_pub: &ik_a_pub,
            peer_ephemeral_pub: &ek_a_pub,
        });
        assert_eq!(sk_a, sk_b);
    }

    #[test]
    fn signed_prekey_signature_roundtrip() {
        let device_seed = [9u8; 32];
        let (_spk_priv, spk_pub) = x25519_generate(&mut Rng(7));
        let sig = sign_signed_prekey(&device_seed, &spk_pub);
        assert!(verify_signed_prekey(
            &ed25519_public(&device_seed),
            &spk_pub,
            &sig
        ));

        let mut tampered = spk_pub;
        tampered[0] ^= 1;
        assert!(!verify_signed_prekey(
            &ed25519_public(&device_seed),
            &tampered,
            &sig
        ));
    }
}
