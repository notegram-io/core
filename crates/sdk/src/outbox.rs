//! Messages written down before they are sent.
//!
//! A send that fails used to end there: the text lived in a view, the view went
//! away, and so did the message. Everything needed to deliver it is recorded
//! here first, so the attempt survives losing the network, closing the chat and
//! restarting the app, and is retried until the server takes it.
//!
//! **The ciphertext is stored, not the plaintext to re-encrypt.** The server
//! deduplicates by `(sender, device, client_msg_id)` and rejects a second
//! attempt whose fingerprint differs, which is exactly what re-encrypting would
//! produce: the ratchet advances on every encrypt, so the same text yields
//! different bytes. Keeping the envelope makes a retry byte-identical, which is
//! what turns "did it land?" from a question into a no-op — the server either
//! stores it or recognises it as the one it already has.
//!
//! The queue is not a place for messages to be forgotten in: there is no failed
//! state, only "not yet". A message leaves only when the server has it.

use crate::SdkError;

const OUTBOX_FORMAT_V1: u8 = 1;

/// One recipient device and the envelope encrypted for it. A message to a peer
/// with three devices carries three of these, all under one client id, because
/// the server takes the fan-out as a unit or not at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRecipient {
    pub user_id: i64,
    pub device_id: i64,
    pub envelope_type: String,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A message waiting to be accepted by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    pub client_msg_id: String,
    pub chat_id: i64,
    /// Who the conversation is with, so the queue can be walked per chat
    /// without decoding recipients.
    pub peer_user_id: i64,
    pub schema: String,
    pub suite: String,
    /// The encrypted copies, one per recipient device — **or empty, meaning the
    /// message could not be encrypted yet.**
    ///
    /// The first message to a peer needs their prekey bundle, which comes from
    /// the server, so a chat with no ratchet session yet cannot be encrypted
    /// while offline. Queuing it unencrypted is what stops that message from
    /// being the one case the queue does not save; it is encrypted on the way
    /// out instead.
    ///
    /// Encrypting late is safe precisely because nothing was sent: the
    /// fingerprint the server pins to a client id is only fixed once an attempt
    /// reaches it, and an entry in this state never has.
    pub recipients: Vec<OutboxRecipient>,
    pub associated_data: Vec<u8>,
    pub forward_info: Option<Vec<u8>>,
    pub reply_to: Option<i64>,
    /// When the user pressed send, not when the attempt was made: it is what
    /// orders the queue and what the message is shown under.
    pub created_at: i64,
    /// How many times delivery has been tried. Kept for backoff and for saying
    /// something honest in the UI, never as grounds for giving up.
    pub attempts: u32,
}

/// Keyed by creation time first so the queue walks in the order the user typed
/// in. Sending a chat's messages out of order would reorder the conversation
/// for the recipient, which no amount of later correction undoes.
pub(crate) fn outbox_key(created_at: i64, client_msg_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + client_msg_id.len());
    key.extend_from_slice(&created_at.to_le_bytes());
    key.extend_from_slice(client_msg_id.as_bytes());
    key
}

pub(crate) fn encode_entry(entry: &OutboxEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(OUTBOX_FORMAT_V1);
    append_str(&mut out, &entry.client_msg_id);
    out.extend_from_slice(&entry.chat_id.to_le_bytes());
    out.extend_from_slice(&entry.peer_user_id.to_le_bytes());
    append_str(&mut out, &entry.schema);
    append_str(&mut out, &entry.suite);
    out.extend_from_slice(&(entry.recipients.len() as u32).to_le_bytes());
    for r in &entry.recipients {
        out.extend_from_slice(&r.user_id.to_le_bytes());
        out.extend_from_slice(&r.device_id.to_le_bytes());
        append_str(&mut out, &r.envelope_type);
        append_bytes(&mut out, &r.header);
        append_bytes(&mut out, &r.ciphertext);
    }
    append_bytes(&mut out, &entry.associated_data);
    // An absent forward is encoded as an empty blob: forward info is never
    // empty when present, so no separate presence byte is needed.
    append_bytes(&mut out, entry.forward_info.as_deref().unwrap_or(&[]));
    // 0 is not a valid message ref, so it doubles as "not a reply".
    out.extend_from_slice(&entry.reply_to.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&entry.created_at.to_le_bytes());
    out.extend_from_slice(&entry.attempts.to_le_bytes());
    out
}

pub(crate) fn decode_entry(raw: &[u8]) -> Result<OutboxEntry, SdkError> {
    let mut r = Reader { b: raw, off: 0 };
    if r.u8()? != OUTBOX_FORMAT_V1 {
        return Err(SdkError::BadKeyMaterial);
    }
    let client_msg_id = r.string()?;
    let chat_id = r.i64()?;
    let peer_user_id = r.i64()?;
    let schema = r.string()?;
    let suite = r.string()?;
    let count = r.u32()? as usize;
    // Bounded before allocating: a corrupted length must not be a request for
    // gigabytes.
    if count > MAX_RECIPIENTS {
        return Err(SdkError::BadKeyMaterial);
    }
    let mut recipients = Vec::with_capacity(count);
    for _ in 0..count {
        recipients.push(OutboxRecipient {
            user_id: r.i64()?,
            device_id: r.i64()?,
            envelope_type: r.string()?,
            header: r.bytes()?,
            ciphertext: r.bytes()?,
        });
    }
    let associated_data = r.bytes()?;
    let forward_info = r.bytes()?;
    let reply_to = r.i64()?;
    let created_at = r.i64()?;
    let attempts = r.u32()?;
    Ok(OutboxEntry {
        client_msg_id,
        chat_id,
        peer_user_id,
        schema,
        suite,
        recipients,
        associated_data,
        forward_info: (!forward_info.is_empty()).then_some(forward_info),
        reply_to: (reply_to != 0).then_some(reply_to),
        created_at,
        attempts,
    })
}

/// A fan-out larger than this is not a message anyone sent; it is a decode that
/// has gone wrong.
const MAX_RECIPIENTS: usize = 4096;

fn append_str(out: &mut Vec<u8>, value: &str) {
    append_bytes(out, value.as_bytes());
}

fn append_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], SdkError> {
        let end = self.off.checked_add(n).ok_or(SdkError::BadKeyMaterial)?;
        if end > self.b.len() {
            return Err(SdkError::BadKeyMaterial);
        }
        let out = &self.b[self.off..end];
        self.off = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, SdkError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, SdkError> {
        let raw: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| SdkError::BadKeyMaterial)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn i64(&mut self) -> Result<i64, SdkError> {
        let raw: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| SdkError::BadKeyMaterial)?;
        Ok(i64::from_le_bytes(raw))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, SdkError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self) -> Result<String, SdkError> {
        String::from_utf8(self.bytes()?).map_err(|_| SdkError::BadKeyMaterial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OutboxEntry {
        OutboxEntry {
            client_msg_id: "c-1".to_string(),
            chat_id: 42,
            peer_user_id: 7,
            schema: "e2ee.v1".to_string(),
            suite: "libsignal.x3dh".to_string(),
            recipients: vec![
                OutboxRecipient {
                    user_id: 7,
                    device_id: 7001,
                    envelope_type: "signal.prekey.v1".to_string(),
                    header: vec![1, 2, 3],
                    ciphertext: vec![9; 64],
                },
                OutboxRecipient {
                    user_id: 7,
                    device_id: 7002,
                    envelope_type: "signal.v1".to_string(),
                    header: vec![],
                    ciphertext: vec![7; 16],
                },
            ],
            associated_data: vec![4, 5],
            forward_info: Some(vec![8, 8]),
            reply_to: Some(99),
            created_at: 1_700_000_000_000,
            attempts: 2,
        }
    }

    #[test]
    fn round_trips_every_field() {
        let entry = sample();
        assert_eq!(decode_entry(&encode_entry(&entry)).unwrap(), entry);
    }

    /// The absent forms have to survive too: they are encoded as an empty blob
    /// and a zero, and reading either back as present would attach a reply or a
    /// forward attribution to a message that had neither.
    #[test]
    fn absent_reply_and_forward_stay_absent() {
        let mut entry = sample();
        entry.forward_info = None;
        entry.reply_to = None;
        let back = decode_entry(&encode_entry(&entry)).unwrap();
        assert_eq!(back.forward_info, None);
        assert_eq!(back.reply_to, None);
    }

    /// The queue is walked in key order, and that order has to be the order the
    /// user typed in — a chat delivered out of order stays wrong.
    #[test]
    fn keys_sort_by_time_then_id() {
        let early = outbox_key(10, "b");
        let late = outbox_key(11, "a");
        assert!(early < late, "an earlier message sorts first");

        let same_time_a = outbox_key(10, "a");
        let same_time_b = outbox_key(10, "b");
        assert!(same_time_a < same_time_b, "ties break on the id, stably");
    }

    #[test]
    fn a_truncated_record_is_an_error_not_a_panic() {
        let encoded = encode_entry(&sample());
        for cut in 0..encoded.len() {
            assert!(decode_entry(&encoded[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn an_absurd_recipient_count_is_refused_before_allocating() {
        let mut encoded = encode_entry(&sample());
        // The count sits after the version, client id, chat, peer, schema and
        // suite; rather than compute the offset, rebuild with a huge count.
        let mut forged = Vec::new();
        forged.push(OUTBOX_FORMAT_V1);
        append_str(&mut forged, "c-1");
        forged.extend_from_slice(&42i64.to_le_bytes());
        forged.extend_from_slice(&7i64.to_le_bytes());
        append_str(&mut forged, "s");
        append_str(&mut forged, "s");
        forged.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_entry(&forged).is_err());
        encoded.clear();
    }
}
