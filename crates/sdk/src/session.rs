use rand_core::{CryptoRng, RngCore};
use ratchet::DoubleRatchet;

use crate::identity::Identity;
use crate::SdkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddress {
    pub user_id: i64,
    pub device_id: i64,
}

impl PeerAddress {
    pub(crate) fn store_key(&self) -> Vec<u8> {
        let mut k = Vec::with_capacity(16);
        k.extend_from_slice(&self.user_id.to_le_bytes());
        k.extend_from_slice(&self.device_id.to_le_bytes());
        k
    }
}

#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity_pub: [u8; 32],

    pub signing_pub: [u8; 32],

    pub signed_prekey_pub: [u8; 32],

    pub signed_prekey_sig: [u8; 64],

    pub one_time_prekey_pub: Option<[u8; 32]>,
}

pub(crate) struct OutboundSession {
    pub ratchet: DoubleRatchet,
    pub ephemeral_pub: [u8; 32],
}

pub(crate) fn establish_outbound<R: RngCore + CryptoRng>(
    identity: &Identity,
    bundle: &PreKeyBundle,
    rng: &mut R,
) -> Result<OutboundSession, SdkError> {
    if !e2ee::x3dh::verify_signed_prekey(
        &bundle.signing_pub,
        &bundle.signed_prekey_pub,
        &bundle.signed_prekey_sig,
    ) {
        return Err(SdkError::BadPrekeySignature);
    }
    let (ephemeral_priv, ephemeral_pub) = crypto::x25519_generate(rng);
    let secret = e2ee::x3dh::initiator_secret(&e2ee::x3dh::Initiator {
        identity_priv: &identity.identity_priv,
        ephemeral_priv: &ephemeral_priv,
        peer_identity_pub: &bundle.identity_pub,
        peer_signed_prekey_pub: &bundle.signed_prekey_pub,
        peer_one_time_prekey_pub: bundle.one_time_prekey_pub.as_ref(),
    });
    let ratchet = DoubleRatchet::init_alice(secret, bundle.signed_prekey_pub, rng);
    Ok(OutboundSession {
        ratchet,
        ephemeral_pub,
    })
}

pub struct InboundPreKeys<'a> {
    pub signed_prekey_priv: &'a [u8; 32],

    pub one_time_prekey_priv: Option<&'a [u8; 32]>,
}

pub(crate) fn establish_inbound(
    identity: &Identity,
    prekeys: &InboundPreKeys,
    initiator_identity_pub: &[u8; 32],
    initiator_ephemeral_pub: &[u8; 32],
) -> DoubleRatchet {
    let secret = e2ee::x3dh::responder_secret(&e2ee::x3dh::Responder {
        identity_priv: &identity.identity_priv,
        signed_prekey_priv: prekeys.signed_prekey_priv,
        one_time_prekey_priv: prekeys.one_time_prekey_priv,
        peer_identity_pub: initiator_identity_pub,
        peer_ephemeral_pub: initiator_ephemeral_pub,
    });
    DoubleRatchet::init_bob(secret, *prekeys.signed_prekey_priv)
}
