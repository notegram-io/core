use tl::generated::{
    MessageAssociatedData, MessageEnvelopeHeaderV2, MessageEnvelopeHeaderV3,
    MessageEnvelopeHeaderV4, SenderKeyGroupMembershipContract, SignalSessionBootstrapContract,
};

/// Protocol-wide constants mirroring `session-gateway/internal/cryptopolicy/policy.go`.
/// Must stay byte-identical to the server's `cryptopolicy` constants — a mismatch here
/// makes every message rejected with BAD_ASSOCIATED_DATA.
pub const SCHEMA_LIBSIGNAL_SESSION_ENVELOPE_V1: &str = "libsignal-session-envelope.v1";
pub const MESSAGE_SUITE_LIBSIGNAL_X3DH_DV1: &str = "libsignal-x3dh-doubleratchet.v1";
pub const ENVELOPE_TYPE_SIGNAL_PREKEY_V1: &str = "signal-prekey.v1";
pub const ENVELOPE_TYPE_SIGNAL_V1: &str = "signal-message.v1";

pub const CRYPTO_POLICY_PROFILE: &str = "notegram-e2ee-production.v1";
pub const CRYPTO_POLICY_VERSION: i64 = 1;
/// `cryptopolicy.DefaultManifestSHA256()` on the server — sha256 of the
/// canonical-JSON default policy manifest. Computed once from the running
/// server (session-gateway), not re-derived here since the manifest itself
/// isn't part of this crate's concerns, just its hash.
pub const CRYPTO_POLICY_SHA256_HEX: &str =
    "e0321b9400bcbeb437e85e92482321a705ce33e7a59f5b8d14b908eca54c93d8";

pub struct AssociatedDataInput {
    pub schema: String,
    pub suite: String,
    pub crypto_policy_profile: String,
    pub crypto_policy_version: i64,
    pub crypto_policy_sha256: String,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub chat_id: i64,
    pub client_msg_id: String,

    pub forward_info: Vec<u8>,
    pub reply_to: Option<i64>,
}

pub fn build_associated_data_v1(input: &AssociatedDataInput) -> Vec<u8> {
    let forward_info_sha256 = if input.forward_info.is_empty() {
        None
    } else {
        Some(hex_lower(&crypto::sha256(&input.forward_info)))
    };
    let ad = MessageAssociatedData {
        schema: input.schema.clone(),
        suite: input.suite.clone(),
        crypto_policy_profile: input.crypto_policy_profile.clone(),
        crypto_policy_version: input.crypto_policy_version as i32,
        crypto_policy_sha256: input.crypto_policy_sha256.clone(),
        sender_user_id: input.sender_user_id,
        sender_device_id: input.sender_device_id,
        chat_id: input.chat_id,
        client_msg_id: input.client_msg_id.clone(),
        forward_info_sha256,
        reply_to: input.reply_to,
    };
    tl::encode_to_vec(&ad).expect("associated data encodes")
}

pub struct EnvelopeHeaderInput {
    pub ad: AssociatedDataInput,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub envelope_type: String,
}

pub fn build_envelope_header_v2(
    input: &EnvelopeHeaderInput,
    associated_data: &[u8],
    ciphertext: &[u8],
    message_nonce: &[u8],
) -> Vec<u8> {
    let header = envelope_header_v2(input, associated_data, ciphertext, message_nonce);
    tl::encode_to_vec(&header).expect("envelope header v2 encodes")
}

pub struct SignalBootstrapInput {
    pub suite: String,
    pub envelope_type: String,
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub recipient_identity_key: Vec<u8>,
    pub recipient_signed_pre_key_id: i32,
    pub recipient_signed_pre_key_pub: Vec<u8>,
    pub recipient_signed_pre_key_sig: Vec<u8>,

    /// Which of the recipient's one-time prekeys was consumed, so they know
    /// which private key to feed into X3DH. 0 means none was available.
    pub recipient_one_time_pre_key_id: i32,

    /// The initiator's X3DH inputs, as raw keys rather than digests: the
    /// recipient needs them to run Diffie-Hellman. The ephemeral key is
    /// single-use and exists nowhere else, so without it the recipient cannot
    /// establish the inbound session at all.
    pub sender_identity_key: Vec<u8>,
    pub sender_ephemeral_key: Vec<u8>,
}

pub fn build_envelope_header_v3(
    input: &EnvelopeHeaderInput,
    associated_data: &[u8],
    ciphertext: &[u8],
    message_nonce: &[u8],
    bootstrap: &SignalBootstrapInput,
) -> Vec<u8> {
    let contract = signal_bootstrap_contract(bootstrap);
    let contract_sha256 = tl_sha256_hex(&contract, "signal session bootstrap contract encodes");
    let base = envelope_header_v2(input, associated_data, ciphertext, message_nonce);
    let header = MessageEnvelopeHeaderV3 {
        schema: base.schema,
        suite: base.suite,
        crypto_policy_profile: base.crypto_policy_profile,
        crypto_policy_version: base.crypto_policy_version,
        crypto_policy_sha256: base.crypto_policy_sha256,
        envelope_type: base.envelope_type,
        sender_user_id: base.sender_user_id,
        sender_device_id: base.sender_device_id,
        recipient_user_id: base.recipient_user_id,
        recipient_device_id: base.recipient_device_id,
        chat_id: base.chat_id,
        client_msg_id: base.client_msg_id,
        associated_data_sha256: base.associated_data_sha256,
        ciphertext_sha256: base.ciphertext_sha256,
        message_nonce: base.message_nonce,
        signal_session_bootstrap: contract,
        signal_session_bootstrap_sha256: contract_sha256,
    };
    tl::encode_to_vec(&header).expect("envelope header v3 encodes")
}

pub struct SenderKeyMemberDevice {
    pub user_id: i64,
    pub device_id: i64,
}

pub struct SenderKeyMembershipInput {
    pub suite: String,
    pub envelope_type: String,
    pub chat_id: i64,
    pub sender_user_id: i64,
    pub sender_device_id: i64,
    pub membership_epoch: i64,
    pub sender_key_id: String,
    pub member_devices: Vec<SenderKeyMemberDevice>,
}

pub fn build_envelope_header_v4(
    input: &EnvelopeHeaderInput,
    associated_data: &[u8],
    ciphertext: &[u8],
    message_nonce: &[u8],
    membership: &SenderKeyMembershipInput,
) -> Vec<u8> {
    let contract = sender_key_membership_contract(membership);
    let contract_sha256 = tl_sha256_hex(&contract, "sender-key membership contract encodes");
    let base = envelope_header_v2(input, associated_data, ciphertext, message_nonce);
    let header = MessageEnvelopeHeaderV4 {
        schema: base.schema,
        suite: base.suite,
        crypto_policy_profile: base.crypto_policy_profile,
        crypto_policy_version: base.crypto_policy_version,
        crypto_policy_sha256: base.crypto_policy_sha256,
        envelope_type: base.envelope_type,
        sender_user_id: base.sender_user_id,
        sender_device_id: base.sender_device_id,
        recipient_user_id: base.recipient_user_id,
        recipient_device_id: base.recipient_device_id,
        chat_id: base.chat_id,
        client_msg_id: base.client_msg_id,
        associated_data_sha256: base.associated_data_sha256,
        ciphertext_sha256: base.ciphertext_sha256,
        message_nonce: base.message_nonce,
        sender_key_group_membership: contract,
        sender_key_group_membership_sha256: contract_sha256,
    };
    tl::encode_to_vec(&header).expect("envelope header v4 encodes")
}

/// The X3DH parameters a recipient needs to open a `signal-prekey.v1` envelope,
/// read back out of the header's bootstrap contract.
pub struct ParsedSignalBootstrap {
    pub recipient_user_id: i64,
    pub recipient_device_id: i64,
    pub recipient_signed_pre_key_id: i32,
    pub recipient_one_time_pre_key_id: i32,
    pub sender_identity_key: [u8; 32],
    pub sender_ephemeral_key: [u8; 32],
}

/// Decodes a v3 envelope header and returns its bootstrap contract. Returns
/// `None` if the header is not a v3 header, does not carry a contract, or the
/// contract's key material is malformed — all of which mean the recipient
/// cannot establish the inbound session and must reject the message.
pub fn parse_signal_bootstrap(header: &[u8]) -> Option<ParsedSignalBootstrap> {
    let decoded: MessageEnvelopeHeaderV3 = tl::decode_from(header, tl::Limits::default()).ok()?;
    let contract = decoded.signal_session_bootstrap;
    Some(ParsedSignalBootstrap {
        recipient_user_id: contract.recipient_user_id,
        recipient_device_id: contract.recipient_device_id,
        recipient_signed_pre_key_id: contract.recipient_signed_pre_key_id,
        recipient_one_time_pre_key_id: contract.recipient_one_time_pre_key_id,
        sender_identity_key: contract.sender_identity_key.try_into().ok()?,
        sender_ephemeral_key: contract.sender_ephemeral_key.try_into().ok()?,
    })
}

fn envelope_header_v2(
    input: &EnvelopeHeaderInput,
    associated_data: &[u8],
    ciphertext: &[u8],
    message_nonce: &[u8],
) -> MessageEnvelopeHeaderV2 {
    let ad = &input.ad;
    MessageEnvelopeHeaderV2 {
        schema: ad.schema.clone(),
        suite: ad.suite.clone(),
        crypto_policy_profile: ad.crypto_policy_profile.clone(),
        crypto_policy_version: ad.crypto_policy_version as i32,
        crypto_policy_sha256: ad.crypto_policy_sha256.clone(),
        envelope_type: input.envelope_type.clone(),
        sender_user_id: ad.sender_user_id,
        sender_device_id: ad.sender_device_id,
        recipient_user_id: input.recipient_user_id,
        recipient_device_id: input.recipient_device_id,
        chat_id: ad.chat_id,
        client_msg_id: ad.client_msg_id.clone(),
        associated_data_sha256: hex_lower(&crypto::sha256(associated_data)),
        ciphertext_sha256: hex_lower(&crypto::sha256(ciphertext)),
        message_nonce: hex_lower(message_nonce),
    }
}

fn signal_bootstrap_contract(input: &SignalBootstrapInput) -> SignalSessionBootstrapContract {
    SignalSessionBootstrapContract {
        suite: input.suite.clone(),
        envelope_type: input.envelope_type.clone(),
        recipient_user_id: input.recipient_user_id,
        recipient_device_id: input.recipient_device_id,
        recipient_identity_key_sha256: hex_lower(&crypto::sha256(&input.recipient_identity_key)),
        recipient_signed_pre_key_id: input.recipient_signed_pre_key_id,
        recipient_signed_pre_key_pub_sha256: hex_lower(&crypto::sha256(
            &input.recipient_signed_pre_key_pub,
        )),
        recipient_signed_pre_key_sig_sha256: hex_lower(&crypto::sha256(
            &input.recipient_signed_pre_key_sig,
        )),
        recipient_one_time_pre_key_id: input.recipient_one_time_pre_key_id,
        sender_identity_key: input.sender_identity_key.clone(),
        sender_ephemeral_key: input.sender_ephemeral_key.clone(),
    }
}

fn sender_key_membership_contract(
    input: &SenderKeyMembershipInput,
) -> SenderKeyGroupMembershipContract {
    let (member_devices_sha256, member_device_count) =
        sender_key_member_devices_hash(&input.member_devices);
    SenderKeyGroupMembershipContract {
        suite: input.suite.clone(),
        envelope_type: input.envelope_type.clone(),
        chat_id: input.chat_id,
        sender_user_id: input.sender_user_id,
        sender_device_id: input.sender_device_id,
        membership_epoch: input.membership_epoch,
        sender_key_id: input.sender_key_id.clone(),
        member_device_count,
        member_devices_sha256,
    }
}

fn sender_key_member_devices_hash(members: &[SenderKeyMemberDevice]) -> (String, i32) {
    let mut sorted: Vec<(i64, i64)> = members.iter().map(|m| (m.user_id, m.device_id)).collect();
    sorted.sort_unstable();
    let mut buf = Vec::with_capacity(37 + sorted.len() * 16);
    buf.extend_from_slice(b"notegram.sender-key.member-devices.v1");
    for (user_id, device_id) in &sorted {
        buf.extend_from_slice(&user_id.to_le_bytes());
        buf.extend_from_slice(&device_id.to_le_bytes());
    }
    (hex_lower(&crypto::sha256(&buf)), sorted.len() as i32)
}

fn tl_sha256_hex<T: tl::TlObject>(obj: &T, expect: &str) -> String {
    let encoded = tl::encode_to_vec(obj).expect(expect);
    hex_lower(&crypto::sha256(&encoded))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl::{decode_from, Limits};

    fn sample(forward: &[u8], reply: Option<i64>) -> AssociatedDataInput {
        AssociatedDataInput {
            schema: "s".into(),
            suite: "x".into(),
            crypto_policy_profile: "p".into(),
            crypto_policy_version: 1,
            crypto_policy_sha256: "abcd".into(),
            sender_user_id: 7,
            sender_device_id: 1,
            chat_id: 100,
            client_msg_id: "c1".into(),
            forward_info: forward.to_vec(),
            reply_to: reply,
        }
    }

    #[test]
    fn roundtrip_and_optionals() {
        let bytes = build_associated_data_v1(&sample(b"fwd", Some(42)));
        let ad: MessageAssociatedData = decode_from(&bytes, Limits::default()).unwrap();
        assert_eq!(ad.chat_id, 100);
        assert_eq!(ad.reply_to, Some(42));
        assert!(ad.forward_info_sha256.is_some());

        let bare = build_associated_data_v1(&sample(&[], None));
        let ad: MessageAssociatedData = decode_from(&bare, Limits::default()).unwrap();
        assert_eq!(ad.reply_to, None);
        assert_eq!(ad.forward_info_sha256, None);
    }
}
