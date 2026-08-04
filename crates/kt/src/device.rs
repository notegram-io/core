//! Client-side verification of a server-issued `PrekeyBundleProof` (schema
//! `notegram-prekey-bundle-proof.v1`), returned as the `proof` field of a peer's
//! prekey bundle. This is a byte-for-byte port of the server's reference
//! verifier: `session-gateway/internal/store/client_transparency_verifier.go`
//! (`VerifyPrekeyBundleProof`) plus the hash-chain/checkpoint/consistency/
//! receipt/witness primitives in `types.go` and `prekey_bundle_receipts.go`.
//! Byte-parity against that Go implementation is covered by
//! `core/crates/kt/tests/prekey_bundle_proof.rs`.

use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;

const SCHEMA_V1: &str = "notegram-prekey-bundle-proof.v1";

const EVENT_PREKEYS_UPLOADED: &str = "prekeys.uploaded.v1";
const EVENT_DEVICE_SIGNING_KEY_SET: &str = "device_signing_key.set.v1";
const EVENT_DEVICE_MATERIAL_DELETED: &str = "device_material.deleted.v1";

const CHECKPOINT_SIGNATURE_SCHEME_V2: &str = "ed25519-key-transparency-checkpoint.v2";
const WITNESS_SIGNATURE_SCHEME_V1: &str = "ed25519-key-transparency-witness.v1";
const RECEIPT_SIGNATURE_SCHEME_V1: &str = "ed25519-prekey-bundle-receipt.v1";

#[derive(Debug)]
pub enum DeviceProofError {
    Json(String),
    UnsupportedSchema(String),
    BadField(&'static str),
    ChainBroken(&'static str),
    Tampered(&'static str),
    UntrustedSigningKey,
    WitnessThresholdNotMet,
    NoActivePrekeyEntry,
    NoTrustedDeviceSigningKey,
}

impl fmt::Display for DeviceProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceProofError::Json(e) => write!(f, "kt: bad proof json: {e}"),
            DeviceProofError::UnsupportedSchema(s) => {
                write!(f, "kt: unsupported proof schema {s:?}")
            }
            DeviceProofError::BadField(w) => write!(f, "kt: bad field: {w}"),
            DeviceProofError::ChainBroken(w) => write!(f, "kt: chain broken: {w}"),
            DeviceProofError::Tampered(w) => write!(f, "kt: tampered: {w}"),
            DeviceProofError::UntrustedSigningKey => write!(f, "kt: untrusted signing public key"),
            DeviceProofError::WitnessThresholdNotMet => {
                write!(f, "kt: witness signature threshold not met")
            }
            DeviceProofError::NoActivePrekeyEntry => {
                write!(f, "kt: no active prekey transparency entry")
            }
            DeviceProofError::NoTrustedDeviceSigningKey => {
                write!(f, "kt: no trusted device signing key in transparency log")
            }
        }
    }
}

impl std::error::Error for DeviceProofError {}

pub type Result<T> = core::result::Result<T, DeviceProofError>;

/// Trust anchors the caller pins (e.g. from app config), analogous to how
/// `server_ed_pub` is supplied by the caller of `NetSession::connect` rather
/// than hardcoded in `core`.
pub struct TrustAnchors<'a> {
    pub signing_public_keys: &'a [[u8; 32]],
    pub witness_public_keys: &'a [[u8; 32]],
    pub min_witness_signatures: usize,
}

#[derive(Debug, Clone)]
pub struct VerifiedPrekeyBundle {
    pub user_id: i64,
    pub device_id: i64,
    pub identity_key: [u8; 32],
    pub device_signing_key: [u8; 32],
    pub signed_pre_key_id: i32,
    pub signed_pre_key_pub: [u8; 32],
    pub signed_pre_key_sig: [u8; 64],
    pub one_time_pre_key_id: i32,
    pub one_time_pre_key_pub: Option<[u8; 32]>,
}

pub fn verify_prekey_bundle_proof(
    raw: &[u8],
    trust: &TrustAnchors,
) -> Result<VerifiedPrekeyBundle> {
    let wire: PrekeyBundleProofWire =
        serde_json::from_slice(raw).map_err(|e| DeviceProofError::Json(e.to_string()))?;
    if wire.schema != SCHEMA_V1 {
        return Err(DeviceProofError::UnsupportedSchema(wire.schema));
    }

    verify_receipt_signature(&wire.receipt)?;
    validate_checkpoint_for_entries(&wire.checkpoint, &wire.key_transparency_entries)?;
    verify_consistency_proof_for_checkpoint(&wire.consistency_proof, &wire.checkpoint)?;

    let receipt = &wire.receipt;
    let checkpoint = &wire.checkpoint;
    if receipt.peer_user_id != checkpoint.user_id
        || receipt.peer_device_id != checkpoint.device_id
        || receipt.key_transparency_to_sequence != checkpoint.to_sequence
        || receipt.key_transparency_root_hash != checkpoint.root_hash
        || receipt.key_transparency_latest_hash != checkpoint.latest_entry_hash
        || receipt.key_transparency_checkpoint_sig != checkpoint.signature
    {
        return Err(DeviceProofError::Tampered("receipt/checkpoint mismatch"));
    }

    let active = latest_active_entry(&wire.key_transparency_entries, EVENT_PREKEYS_UPLOADED)?
        .ok_or(DeviceProofError::NoActivePrekeyEntry)?;
    if active.user_id != receipt.peer_user_id
        || active.device_id != receipt.peer_device_id
        || active.identity_key != receipt.identity_key
        || active.signed_pre_key_id != receipt.signed_pre_key_id
        || active.signed_pre_key_pub != receipt.signed_pre_key_pub
        || active.signed_pre_key_sig != receipt.signed_pre_key_sig
    {
        return Err(DeviceProofError::Tampered(
            "receipt/key-transparency mismatch",
        ));
    }

    let fingerprint = prekey_bundle_fingerprint(receipt, checkpoint)?;
    if fingerprint != receipt.bundle_fingerprint {
        return Err(DeviceProofError::Tampered("bundle fingerprint mismatch"));
    }

    require_trusted(&receipt.signing_public_key, trust.signing_public_keys)?;
    require_trusted(&checkpoint.signing_public_key, trust.signing_public_keys)?;
    validate_witness_set(
        checkpoint,
        &wire.witness_signatures,
        trust.witness_public_keys,
        trust.min_witness_signatures,
    )?;

    let signing_entry =
        latest_active_entry(&wire.key_transparency_entries, EVENT_DEVICE_SIGNING_KEY_SET)?
            .ok_or(DeviceProofError::NoTrustedDeviceSigningKey)?;
    let device_signing_key = arr32(&signing_entry.device_signing_key, "device signing key")?;

    let identity_key = arr32(&receipt.identity_key, "identity key")?;
    let signed_pre_key_pub = arr32(&receipt.signed_pre_key_pub, "signed prekey pub")?;
    let signed_pre_key_sig = arr64(&receipt.signed_pre_key_sig, "signed prekey sig")?;
    let one_time_pre_key_pub =
        if receipt.one_time_pre_key_id > 0 && !receipt.one_time_pre_key_pub.is_empty() {
            Some(arr32(&receipt.one_time_pre_key_pub, "one-time prekey pub")?)
        } else {
            None
        };

    Ok(VerifiedPrekeyBundle {
        user_id: receipt.peer_user_id,
        device_id: receipt.peer_device_id,
        identity_key,
        device_signing_key,
        signed_pre_key_id: receipt.signed_pre_key_id,
        signed_pre_key_pub,
        signed_pre_key_sig,
        one_time_pre_key_id: receipt.one_time_pre_key_id,
        one_time_pre_key_pub,
    })
}

// --- wire format -----------------------------------------------------------

fn de_bytes<'de, D>(d: D) -> core::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(d)?;
    match opt {
        None => Ok(Vec::new()),
        Some(s) => BASE64.decode(s).map_err(serde::de::Error::custom),
    }
}

// Go's `encoding/json` marshals a nil slice as `null`, not `[]` (e.g. when no
// key-transparency witnesses are configured). serde's Vec<T> only accepts a
// JSON array, so unwrap the Option ourselves.
fn de_vec_or_null<'de, D, T>(d: D) -> core::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let opt: Option<Vec<T>> = Deserialize::deserialize(d)?;
    Ok(opt.unwrap_or_default())
}

#[derive(Deserialize)]
struct PrekeyBundleProofWire {
    schema: String,
    receipt: PrekeyBundleReceiptWire,
    #[serde(deserialize_with = "de_vec_or_null")]
    key_transparency_entries: Vec<KeyTransparencyEntryWire>,
    checkpoint: KeyTransparencyCheckpointWire,
    consistency_proof: KeyTransparencyConsistencyProofWire,
    #[serde(deserialize_with = "de_vec_or_null")]
    witness_signatures: Vec<KeyTransparencyWitnessSignatureWire>,
}

#[derive(Deserialize)]
struct PrekeyBundleReceiptWire {
    #[serde(rename = "ReceiptID")]
    receipt_id: String,
    #[serde(rename = "RequesterUserID")]
    requester_user_id: i64,
    #[serde(rename = "RequesterDeviceID")]
    requester_device_id: i64,
    #[serde(rename = "PeerUserID")]
    peer_user_id: i64,
    #[serde(rename = "PeerDeviceID")]
    peer_device_id: i64,
    #[serde(rename = "IdentityKey", deserialize_with = "de_bytes")]
    identity_key: Vec<u8>,
    #[serde(rename = "SignedPreKeyID")]
    signed_pre_key_id: i32,
    #[serde(rename = "SignedPreKeyPub", deserialize_with = "de_bytes")]
    signed_pre_key_pub: Vec<u8>,
    #[serde(rename = "SignedPreKeySig", deserialize_with = "de_bytes")]
    signed_pre_key_sig: Vec<u8>,
    #[serde(rename = "OneTimePreKeyID")]
    one_time_pre_key_id: i32,
    #[serde(rename = "OneTimePreKeyPub", deserialize_with = "de_bytes")]
    one_time_pre_key_pub: Vec<u8>,
    #[serde(rename = "RemainingOneTime")]
    remaining_one_time: i32,
    #[serde(rename = "KeyTransparencyToSequence")]
    key_transparency_to_sequence: i64,
    #[serde(rename = "KeyTransparencyRootHash", deserialize_with = "de_bytes")]
    key_transparency_root_hash: Vec<u8>,
    #[serde(rename = "KeyTransparencyLatestHash", deserialize_with = "de_bytes")]
    key_transparency_latest_hash: Vec<u8>,
    #[serde(rename = "KeyTransparencyCheckpointSig", deserialize_with = "de_bytes")]
    key_transparency_checkpoint_sig: Vec<u8>,
    #[serde(rename = "BundleFingerprint", deserialize_with = "de_bytes")]
    bundle_fingerprint: Vec<u8>,
    #[serde(rename = "IssuedAt")]
    issued_at: String,
    #[serde(rename = "SignatureScheme")]
    signature_scheme: String,
    #[serde(rename = "SigningPublicKey", deserialize_with = "de_bytes")]
    signing_public_key: Vec<u8>,
    #[serde(rename = "Signature", deserialize_with = "de_bytes")]
    signature: Vec<u8>,
}

#[derive(Deserialize, Clone)]
struct KeyTransparencyEntryWire {
    #[serde(rename = "UserID")]
    user_id: i64,
    #[serde(rename = "DeviceID")]
    device_id: i64,
    #[serde(rename = "Sequence")]
    sequence: i64,
    #[serde(rename = "Event")]
    event: String,
    #[serde(rename = "IdentityKey", deserialize_with = "de_bytes")]
    identity_key: Vec<u8>,
    #[serde(rename = "SignedPreKeyID")]
    signed_pre_key_id: i32,
    #[serde(rename = "SignedPreKeyPub", deserialize_with = "de_bytes")]
    signed_pre_key_pub: Vec<u8>,
    #[serde(rename = "SignedPreKeySig", deserialize_with = "de_bytes")]
    signed_pre_key_sig: Vec<u8>,
    #[serde(rename = "DeviceSigningKey", deserialize_with = "de_bytes")]
    device_signing_key: Vec<u8>,
    #[serde(rename = "PrevHash", deserialize_with = "de_bytes")]
    prev_hash: Vec<u8>,
    #[serde(rename = "EntryHash", deserialize_with = "de_bytes")]
    entry_hash: Vec<u8>,
    #[serde(rename = "CreatedAt")]
    created_at: String,
}

#[derive(Deserialize, Clone)]
struct KeyTransparencyCheckpointWire {
    #[serde(rename = "UserID")]
    user_id: i64,
    #[serde(rename = "DeviceID")]
    device_id: i64,
    #[serde(rename = "FromSequence")]
    from_sequence: i64,
    #[serde(rename = "ToSequence")]
    to_sequence: i64,
    #[serde(rename = "EntryCount")]
    entry_count: i32,
    #[serde(rename = "RootHash", deserialize_with = "de_bytes")]
    root_hash: Vec<u8>,
    #[serde(rename = "LatestEntryHash", deserialize_with = "de_bytes")]
    latest_entry_hash: Vec<u8>,
    #[serde(rename = "GeneratedAt")]
    generated_at: String,
    #[serde(rename = "SignatureScheme")]
    signature_scheme: String,
    #[serde(rename = "SigningPublicKey", deserialize_with = "de_bytes")]
    signing_public_key: Vec<u8>,
    #[serde(rename = "Signature", deserialize_with = "de_bytes")]
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct KeyTransparencyConsistencyProofWire {
    #[serde(rename = "UserID")]
    user_id: i64,
    #[serde(rename = "DeviceID")]
    device_id: i64,
    #[serde(rename = "FromSequence")]
    from_sequence: i64,
    #[serde(rename = "ToSequence")]
    to_sequence: i64,
    #[serde(rename = "FromRootHash", deserialize_with = "de_bytes")]
    from_root_hash: Vec<u8>,
    #[serde(rename = "ToRootHash", deserialize_with = "de_bytes")]
    to_root_hash: Vec<u8>,
    #[serde(rename = "SuffixEntryHashes")]
    suffix_entry_hashes: Vec<SuffixHash>,
}

#[derive(Deserialize)]
struct SuffixHash(#[serde(deserialize_with = "de_bytes")] Vec<u8>);

#[derive(Deserialize)]
struct KeyTransparencyWitnessSignatureWire {
    #[serde(rename = "UserID")]
    user_id: i64,
    #[serde(rename = "DeviceID")]
    device_id: i64,
    #[serde(rename = "ToSequence")]
    to_sequence: i64,
    #[serde(rename = "RootHash", deserialize_with = "de_bytes")]
    root_hash: Vec<u8>,
    #[serde(rename = "CheckpointSignatureHash", deserialize_with = "de_bytes")]
    checkpoint_signature_hash: Vec<u8>,
    #[serde(rename = "WitnessID")]
    witness_id: String,
    #[serde(rename = "WitnessPublicKey", deserialize_with = "de_bytes")]
    witness_public_key: Vec<u8>,
    #[serde(rename = "SignedAt")]
    signed_at: String,
    #[serde(rename = "SignatureScheme")]
    signature_scheme: String,
    #[serde(rename = "Signature", deserialize_with = "de_bytes")]
    signature: Vec<u8>,
}

// --- time --------------------------------------------------------------

fn unix_millis(rfc3339: &str) -> Result<i64> {
    let dt = time::OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339)
        .map_err(|_| DeviceProofError::BadField("timestamp"))?;
    Ok((dt.unix_timestamp_nanos() / 1_000_000) as i64)
}

// --- fixed-size helpers --------------------------------------------------

fn arr32(v: &[u8], field: &'static str) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| DeviceProofError::BadField(field))
}

fn arr64(v: &[u8], field: &'static str) -> Result<[u8; 64]> {
    v.try_into().map_err(|_| DeviceProofError::BadField(field))
}

// --- hashing (mirrors session-gateway/internal/store hashInt64/hashInt32/hashString/hashBytes) --

struct Hasher(Vec<u8>);

impl Hasher {
    fn new() -> Self {
        Hasher(Vec::with_capacity(256))
    }

    fn raw(&mut self, domain: &str) -> &mut Self {
        self.0.extend_from_slice(domain.as_bytes());
        self
    }

    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        wire::append_u64_le(&mut self.0, v.len() as u64);
        self.0.extend_from_slice(v);
        self
    }

    fn string(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    fn i64(&mut self, v: i64) -> &mut Self {
        wire::append_u64_le(&mut self.0, v as u64);
        self
    }

    fn i32(&mut self, v: i32) -> &mut Self {
        wire::append_u32_le(&mut self.0, v as u32);
        self
    }

    fn finish(&self) -> [u8; 32] {
        crypto::sha256(&self.0)
    }
}

// --- key transparency entry hash chain -----------------------------------

fn entry_hash(e: &KeyTransparencyEntryWire) -> Result<[u8; 32]> {
    let created_at = unix_millis(&e.created_at)?;
    let mut h = Hasher::new();
    h.raw("notegram-key-transparency-entry-v1")
        .i64(e.user_id)
        .i64(e.device_id)
        .i64(e.sequence)
        .string(&e.event)
        .bytes(&e.identity_key)
        .i32(e.signed_pre_key_id)
        .bytes(&e.signed_pre_key_pub)
        .bytes(&e.signed_pre_key_sig);
    if e.event == EVENT_DEVICE_SIGNING_KEY_SET {
        h.bytes(&e.device_signing_key);
    }
    h.bytes(&e.prev_hash).i64(created_at);
    Ok(h.finish())
}

fn validate_entry_payload(e: &KeyTransparencyEntryWire) -> Result<()> {
    match e.event.as_str() {
        EVENT_PREKEYS_UPLOADED => {
            if e.identity_key.len() != 32
                || e.signed_pre_key_id <= 0
                || e.signed_pre_key_pub.len() != 32
                || e.signed_pre_key_sig.len() != 64
                || !e.device_signing_key.is_empty()
            {
                return Err(DeviceProofError::ChainBroken(
                    "prekeys.uploaded.v1 payload shape",
                ));
            }
        }
        EVENT_DEVICE_SIGNING_KEY_SET => {
            if !e.identity_key.is_empty()
                || e.signed_pre_key_id != 0
                || !e.signed_pre_key_pub.is_empty()
                || !e.signed_pre_key_sig.is_empty()
                || e.device_signing_key.len() != 32
            {
                return Err(DeviceProofError::ChainBroken(
                    "device_signing_key.set.v1 payload shape",
                ));
            }
        }
        EVENT_DEVICE_MATERIAL_DELETED => {
            if !e.identity_key.is_empty()
                || e.signed_pre_key_id != 0
                || !e.signed_pre_key_pub.is_empty()
                || !e.signed_pre_key_sig.is_empty()
                || !e.device_signing_key.is_empty()
            {
                return Err(DeviceProofError::ChainBroken(
                    "device_material.deleted.v1 payload shape",
                ));
            }
        }
        _ => {
            return Err(DeviceProofError::ChainBroken(
                "unsupported key transparency event",
            ))
        }
    }
    Ok(())
}

fn validate_entries(entries: &[KeyTransparencyEntryWire]) -> Result<()> {
    for (i, e) in entries.iter().enumerate() {
        if e.user_id == 0 || e.device_id == 0 {
            return Err(DeviceProofError::BadField("entry subject"));
        }
        if e.sequence <= 0 {
            return Err(DeviceProofError::BadField("entry sequence"));
        }
        if e.event.is_empty() {
            return Err(DeviceProofError::BadField("entry event"));
        }
        validate_entry_payload(e)?;
        if e.entry_hash.len() != 32 {
            return Err(DeviceProofError::BadField("entry hash length"));
        }
        match e.sequence {
            1 if !e.prev_hash.is_empty() => {
                return Err(DeviceProofError::Tampered("genesis entry has prev hash"))
            }
            s if s > 1 && e.prev_hash.len() != 32 => {
                return Err(DeviceProofError::BadField("entry prev hash length"))
            }
            _ => {}
        }
        if entry_hash(e)?.as_slice() != e.entry_hash.as_slice() {
            return Err(DeviceProofError::Tampered("entry hash mismatch"));
        }
        if i == 0 {
            continue;
        }
        let prev = &entries[i - 1];
        if e.user_id != prev.user_id || e.device_id != prev.device_id {
            return Err(DeviceProofError::ChainBroken("entry subject changed"));
        }
        if e.sequence != prev.sequence + 1 {
            return Err(DeviceProofError::ChainBroken("entry sequence gap"));
        }
        if e.prev_hash != prev.entry_hash {
            return Err(DeviceProofError::Tampered("entry prev hash mismatch"));
        }
    }
    Ok(())
}

fn empty_root_hash(user_id: i64, device_id: i64) -> [u8; 32] {
    Hasher::new()
        .raw("notegram-key-transparency-root-empty-v2")
        .i64(user_id)
        .i64(device_id)
        .finish()
}

fn root_step_hash(
    user_id: i64,
    device_id: i64,
    sequence: i64,
    prev_root: &[u8],
    entry_hash: &[u8],
) -> Result<[u8; 32]> {
    if prev_root.len() != 32 || entry_hash.len() != 32 || sequence <= 0 {
        return Err(DeviceProofError::BadField("root step inputs"));
    }
    Ok(Hasher::new()
        .raw("notegram-key-transparency-root-step-v2")
        .i64(user_id)
        .i64(device_id)
        .i64(sequence)
        .bytes(prev_root)
        .bytes(entry_hash)
        .finish())
}

fn root_hash(
    user_id: i64,
    device_id: i64,
    entries: &[KeyTransparencyEntryWire],
) -> Result<[u8; 32]> {
    validate_entries(entries)?;
    if let Some(first) = entries.first() {
        if first.user_id != user_id || first.device_id != device_id || first.sequence != 1 {
            return Err(DeviceProofError::ChainBroken(
                "root hash subject/genesis mismatch",
            ));
        }
    }
    let mut root = empty_root_hash(user_id, device_id);
    for e in entries {
        root = root_step_hash(user_id, device_id, e.sequence, &root, &e.entry_hash)?;
    }
    Ok(root)
}

// --- checkpoint ------------------------------------------------------------

fn checkpoint_signing_payload(c: &KeyTransparencyCheckpointWire) -> Result<Vec<u8>> {
    if c.user_id == 0 || c.device_id == 0 || c.root_hash.len() != 32 {
        return Err(DeviceProofError::BadField("checkpoint subject/root"));
    }
    if c.entry_count == 0 {
        if c.from_sequence != 0 || c.to_sequence != 0 || !c.latest_entry_hash.is_empty() {
            return Err(DeviceProofError::BadField(
                "empty checkpoint has non-empty range",
            ));
        }
    } else {
        if c.from_sequence <= 0
            || c.to_sequence < c.from_sequence
            || c.latest_entry_hash.len() != 32
        {
            return Err(DeviceProofError::BadField("checkpoint range/latest hash"));
        }
    }
    if c.signature_scheme != CHECKPOINT_SIGNATURE_SCHEME_V2 {
        return Err(DeviceProofError::BadField("checkpoint signature scheme"));
    }
    if c.signing_public_key.len() != 32 {
        return Err(DeviceProofError::BadField("checkpoint signing public key"));
    }
    let generated_at = unix_millis(&c.generated_at)?;
    let mut h = Hasher::new();
    h.raw("notegram-key-transparency-signed-checkpoint-v1")
        .string(&c.signature_scheme)
        .i64(c.user_id)
        .i64(c.device_id)
        .i64(c.from_sequence)
        .i64(c.to_sequence)
        .i32(c.entry_count)
        .bytes(&c.root_hash)
        .bytes(&c.latest_entry_hash)
        .i64(generated_at)
        .bytes(&c.signing_public_key);
    Ok(h.finish().to_vec())
}

fn verify_checkpoint_signature(c: &KeyTransparencyCheckpointWire) -> Result<()> {
    if c.signature.len() != 64 {
        return Err(DeviceProofError::BadField("checkpoint signature length"));
    }
    let payload = checkpoint_signing_payload(c)?;
    let pk = arr32(&c.signing_public_key, "checkpoint signing public key")?;
    let sig = arr64(&c.signature, "checkpoint signature")?;
    if !crypto::ed25519_verify(&pk, &payload, &sig) {
        return Err(DeviceProofError::Tampered(
            "checkpoint signature verification failed",
        ));
    }
    Ok(())
}

fn checkpoint_heads_equal(
    a: &KeyTransparencyCheckpointWire,
    b: &KeyTransparencyCheckpointWire,
) -> bool {
    a.user_id == b.user_id
        && a.device_id == b.device_id
        && a.from_sequence == b.from_sequence
        && a.to_sequence == b.to_sequence
        && a.entry_count == b.entry_count
        && a.signature_scheme == b.signature_scheme
        && a.root_hash == b.root_hash
        && a.latest_entry_hash == b.latest_entry_hash
        && a.signing_public_key == b.signing_public_key
}

fn validate_checkpoint_for_entries(
    c: &KeyTransparencyCheckpointWire,
    entries: &[KeyTransparencyEntryWire],
) -> Result<()> {
    verify_checkpoint_signature(c)?;
    let root = root_hash(c.user_id, c.device_id, entries)?;
    let (from_sequence, to_sequence, latest_entry_hash) = match entries.last() {
        Some(latest) => (
            entries.first().map(|e| e.sequence).unwrap_or(0),
            latest.sequence,
            latest.entry_hash.clone(),
        ),
        None => (0, 0, Vec::new()),
    };
    let expected = KeyTransparencyCheckpointWire {
        user_id: c.user_id,
        device_id: c.device_id,
        from_sequence,
        to_sequence,
        entry_count: entries.len() as i32,
        root_hash: root.to_vec(),
        latest_entry_hash,
        generated_at: c.generated_at.clone(),
        signature_scheme: c.signature_scheme.clone(),
        signing_public_key: c.signing_public_key.clone(),
        signature: Vec::new(),
    };
    if !checkpoint_heads_equal(c, &expected) {
        return Err(DeviceProofError::Tampered(
            "checkpoint does not match transparency entries",
        ));
    }
    Ok(())
}

// --- consistency proof ------------------------------------------------------

fn verify_consistency_proof(p: &KeyTransparencyConsistencyProofWire) -> Result<()> {
    if p.user_id == 0 || p.device_id == 0 {
        return Err(DeviceProofError::BadField("consistency proof subject"));
    }
    if p.from_sequence < 0 || p.to_sequence < p.from_sequence {
        return Err(DeviceProofError::BadField("consistency proof range"));
    }
    if p.from_root_hash.len() != 32 || p.to_root_hash.len() != 32 {
        return Err(DeviceProofError::BadField(
            "consistency proof root hash length",
        ));
    }
    if p.suffix_entry_hashes.len() as i64 != p.to_sequence - p.from_sequence {
        return Err(DeviceProofError::BadField("consistency proof suffix count"));
    }
    let mut root = p.from_root_hash.clone();
    for (i, suffix) in p.suffix_entry_hashes.iter().enumerate() {
        root = root_step_hash(
            p.user_id,
            p.device_id,
            p.from_sequence + i as i64 + 1,
            &root,
            &suffix.0,
        )?
        .to_vec();
    }
    if root != p.to_root_hash {
        return Err(DeviceProofError::Tampered(
            "consistency proof root mismatch",
        ));
    }
    Ok(())
}

fn verify_consistency_proof_for_checkpoint(
    p: &KeyTransparencyConsistencyProofWire,
    c: &KeyTransparencyCheckpointWire,
) -> Result<()> {
    verify_checkpoint_signature(c)?;
    verify_consistency_proof(p)?;
    if p.user_id != c.user_id || p.device_id != c.device_id {
        return Err(DeviceProofError::BadField(
            "consistency proof subject vs checkpoint",
        ));
    }
    if p.to_sequence != c.to_sequence || p.to_root_hash != c.root_hash {
        return Err(DeviceProofError::Tampered(
            "consistency proof head vs checkpoint",
        ));
    }
    Ok(())
}

// --- witness signatures ------------------------------------------------------

fn checkpoint_signature_hash(c: &KeyTransparencyCheckpointWire) -> Result<[u8; 32]> {
    verify_checkpoint_signature(c)?;
    let payload = checkpoint_signing_payload(c)?;
    Ok(Hasher::new()
        .raw("notegram-key-transparency-checkpoint-signature-hash-v1")
        .bytes(&payload)
        .bytes(&c.signature)
        .finish())
}

fn witness_signing_payload(s: &KeyTransparencyWitnessSignatureWire) -> Result<Vec<u8>> {
    if s.user_id == 0 || s.device_id == 0 || s.to_sequence < 0 {
        return Err(DeviceProofError::BadField("witness signature subject"));
    }
    if s.root_hash.len() != 32 || s.checkpoint_signature_hash.len() != 32 {
        return Err(DeviceProofError::BadField("witness signature hash length"));
    }
    if s.witness_id.is_empty() || s.witness_public_key.len() != 32 {
        return Err(DeviceProofError::BadField("witness id/public key"));
    }
    if s.witness_id != format!("ed25519:{}", hex_encode(&s.witness_public_key)) {
        return Err(DeviceProofError::BadField(
            "witness id does not match public key",
        ));
    }
    if s.signature_scheme != WITNESS_SIGNATURE_SCHEME_V1 {
        return Err(DeviceProofError::BadField("witness signature scheme"));
    }
    let signed_at = unix_millis(&s.signed_at)?;
    let mut h = Hasher::new();
    h.raw("notegram-key-transparency-witness-signature-v1")
        .string(&s.signature_scheme)
        .i64(s.user_id)
        .i64(s.device_id)
        .i64(s.to_sequence)
        .bytes(&s.root_hash)
        .bytes(&s.checkpoint_signature_hash)
        .string(&s.witness_id)
        .bytes(&s.witness_public_key)
        .i64(signed_at);
    Ok(h.finish().to_vec())
}

fn verify_witness_signature(s: &KeyTransparencyWitnessSignatureWire) -> Result<()> {
    if s.signature.len() != 64 {
        return Err(DeviceProofError::BadField("witness signature length"));
    }
    let payload = witness_signing_payload(s)?;
    let pk = arr32(&s.witness_public_key, "witness public key")?;
    let sig = arr64(&s.signature, "witness signature")?;
    if !crypto::ed25519_verify(&pk, &payload, &sig) {
        return Err(DeviceProofError::Tampered(
            "witness signature verification failed",
        ));
    }
    Ok(())
}

fn verify_witness_signature_for_checkpoint(
    s: &KeyTransparencyWitnessSignatureWire,
    c: &KeyTransparencyCheckpointWire,
) -> Result<()> {
    let checkpoint_hash = checkpoint_signature_hash(c)?;
    verify_witness_signature(s)?;
    if s.user_id != c.user_id
        || s.device_id != c.device_id
        || s.to_sequence != c.to_sequence
        || s.root_hash != c.root_hash
        || s.checkpoint_signature_hash != checkpoint_hash
    {
        return Err(DeviceProofError::Tampered(
            "witness signature does not match checkpoint",
        ));
    }
    Ok(())
}

fn validate_witness_set(
    checkpoint: &KeyTransparencyCheckpointWire,
    signatures: &[KeyTransparencyWitnessSignatureWire],
    trusted: &[[u8; 32]],
    min_signatures: usize,
) -> Result<()> {
    if min_signatures > 0 && trusted.is_empty() {
        return Err(DeviceProofError::BadField(
            "witness threshold requires trusted public keys",
        ));
    }
    if min_signatures > trusted.len() {
        return Err(DeviceProofError::BadField(
            "witness threshold exceeds trusted key count",
        ));
    }
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for s in signatures {
        verify_witness_signature_for_checkpoint(s, checkpoint)?;
        let Ok(key) = arr32(&s.witness_public_key, "witness public key") else {
            continue;
        };
        if !trusted.is_empty() && !trusted.contains(&key) {
            continue;
        }
        if !seen.contains(&key) {
            seen.push(key);
        }
    }
    if seen.len() < min_signatures {
        return Err(DeviceProofError::WitnessThresholdNotMet);
    }
    Ok(())
}

// --- prekey bundle receipt ---------------------------------------------------

fn receipt_signing_payload(r: &PrekeyBundleReceiptWire) -> Result<Vec<u8>> {
    if r.receipt_id.is_empty() {
        return Err(DeviceProofError::BadField("receipt id"));
    }
    if r.requester_user_id == 0
        || r.requester_device_id == 0
        || r.peer_user_id == 0
        || r.peer_device_id == 0
    {
        return Err(DeviceProofError::BadField("receipt subject"));
    }
    if r.bundle_fingerprint.len() != 32 {
        return Err(DeviceProofError::BadField(
            "receipt bundle fingerprint length",
        ));
    }
    if r.key_transparency_to_sequence <= 0 {
        return Err(DeviceProofError::BadField("receipt kt sequence"));
    }
    if r.key_transparency_root_hash.len() != 32 || r.key_transparency_latest_hash.len() != 32 {
        return Err(DeviceProofError::BadField("receipt kt hash length"));
    }
    if r.key_transparency_checkpoint_sig.len() != 64 {
        return Err(DeviceProofError::BadField(
            "receipt kt checkpoint sig length",
        ));
    }
    if r.signature_scheme != RECEIPT_SIGNATURE_SCHEME_V1 {
        return Err(DeviceProofError::BadField("receipt signature scheme"));
    }
    if r.signing_public_key.len() != 32 {
        return Err(DeviceProofError::BadField("receipt signing public key"));
    }
    let issued_at = unix_millis(&r.issued_at)?;
    let mut h = Hasher::new();
    h.string("notegram-prekey-bundle-receipt-signature-v1")
        .string(&r.receipt_id)
        .i64(r.requester_user_id)
        .i64(r.requester_device_id)
        .i64(r.peer_user_id)
        .i64(r.peer_device_id)
        .bytes(&r.identity_key)
        .i32(r.signed_pre_key_id)
        .bytes(&r.signed_pre_key_pub)
        .bytes(&r.signed_pre_key_sig)
        .i32(r.one_time_pre_key_id)
        .bytes(&r.one_time_pre_key_pub)
        .i32(r.remaining_one_time)
        .i64(r.key_transparency_to_sequence)
        .bytes(&r.key_transparency_root_hash)
        .bytes(&r.key_transparency_latest_hash)
        .bytes(&r.key_transparency_checkpoint_sig)
        .bytes(&r.bundle_fingerprint)
        .i64(issued_at)
        .string(&r.signature_scheme)
        .bytes(&r.signing_public_key);
    Ok(h.finish().to_vec())
}

fn verify_receipt_signature(r: &PrekeyBundleReceiptWire) -> Result<()> {
    if r.signature.len() != 64 {
        return Err(DeviceProofError::BadField("receipt signature length"));
    }
    let payload = receipt_signing_payload(r)?;
    let pk = arr32(&r.signing_public_key, "receipt signing public key")?;
    let sig = arr64(&r.signature, "receipt signature")?;
    if !crypto::ed25519_verify(&pk, &payload, &sig) {
        return Err(DeviceProofError::Tampered(
            "receipt signature verification failed",
        ));
    }
    Ok(())
}

fn prekey_bundle_fingerprint(
    r: &PrekeyBundleReceiptWire,
    c: &KeyTransparencyCheckpointWire,
) -> Result<Vec<u8>> {
    if r.peer_user_id == 0
        || r.peer_device_id == 0
        || r.identity_key.len() != 32
        || r.signed_pre_key_id <= 0
        || r.signed_pre_key_pub.len() != 32
        || r.signed_pre_key_sig.len() != 64
    {
        return Err(DeviceProofError::BadField("fingerprint bundle inputs"));
    }
    verify_checkpoint_signature(c)?;
    let mut h = Hasher::new();
    h.string("notegram-prekey-bundle-fingerprint-v1")
        .i64(r.peer_user_id)
        .i64(r.peer_device_id)
        .bytes(&r.identity_key)
        .i32(r.signed_pre_key_id)
        .bytes(&r.signed_pre_key_pub)
        .bytes(&r.signed_pre_key_sig)
        .i32(r.one_time_pre_key_id)
        .bytes(&r.one_time_pre_key_pub)
        .i64(c.to_sequence)
        .bytes(&c.root_hash)
        .bytes(&c.latest_entry_hash)
        .bytes(&c.signature);
    Ok(h.finish().to_vec())
}

// --- trust -------------------------------------------------------------------

fn require_trusted(public_key: &[u8], trusted: &[[u8; 32]]) -> Result<()> {
    let key = arr32(public_key, "signing public key")?;
    if trusted.is_empty() {
        return Err(DeviceProofError::UntrustedSigningKey);
    }
    if trusted.contains(&key) {
        Ok(())
    } else {
        Err(DeviceProofError::UntrustedSigningKey)
    }
}

fn hex_encode(v: &[u8]) -> String {
    let mut out = String::with_capacity(v.len() * 2);
    for b in v {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// --- latest-active entry lookup ----------------------------------------------

fn latest_active_entry<'a>(
    entries: &'a [KeyTransparencyEntryWire],
    event: &str,
) -> Result<Option<&'a KeyTransparencyEntryWire>> {
    validate_entries(entries)?;
    match entries.last() {
        None => return Ok(None),
        Some(last) if last.event == EVENT_DEVICE_MATERIAL_DELETED => return Ok(None),
        _ => {}
    }
    Ok(entries.iter().rev().find(|e| e.event == event))
}
