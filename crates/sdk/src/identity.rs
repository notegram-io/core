use rand_core::{CryptoRng, RngCore};

use crate::SdkError;

const IDENTITY_VERSION: u8 = 1;

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    pub identity_priv: [u8; 32],

    pub identity_pub: [u8; 32],

    pub signing_seed: [u8; 32],

    pub signing_pub: [u8; 32],

    pub registration_id: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    pub identity_pub: [u8; 32],
    pub signing_pub: [u8; 32],
    pub registration_id: u32,
}

impl Identity {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (identity_priv, identity_pub) = crypto::x25519_generate(rng);
        let mut signing_seed = [0u8; 32];
        rng.fill_bytes(&mut signing_seed);
        let signing_pub = crypto::ed25519_public(&signing_seed);
        Identity {
            identity_priv,
            identity_pub,
            signing_seed,
            signing_pub,
            registration_id: rng.next_u32(),
        }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            identity_pub: self.identity_pub,
            signing_pub: self.signing_pub,
            registration_id: self.registration_id,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 * 4 + 4);
        out.push(IDENTITY_VERSION);
        out.extend_from_slice(&self.identity_priv);
        out.extend_from_slice(&self.identity_pub);
        out.extend_from_slice(&self.signing_seed);
        out.extend_from_slice(&self.signing_pub);
        out.extend_from_slice(&self.registration_id.to_le_bytes());
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, SdkError> {
        if bytes.len() != 1 + 32 * 4 + 4 || bytes[0] != IDENTITY_VERSION {
            return Err(SdkError::BadKeyMaterial);
        }
        let mut o = 1;
        let mut take = |n: usize| {
            let s = &bytes[o..o + n];
            o += n;
            s.to_vec()
        };
        let identity_priv = arr32(&take(32));
        let identity_pub = arr32(&take(32));
        let signing_seed = arr32(&take(32));
        let signing_pub = arr32(&take(32));
        let reg = take(4);
        Ok(Identity {
            identity_priv,
            identity_pub,
            signing_seed,
            signing_pub,
            registration_id: u32::from_le_bytes([reg[0], reg[1], reg[2], reg[3]]),
        })
    }
}

fn arr32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
}
