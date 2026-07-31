//! Local message history.
//!
//! Decrypted messages are kept client-side only: the server stores ciphertext
//! and drops it on ack, so this is the sole durable copy of a conversation.
//! Records live in the encrypted store like every other secret.

use crate::SdkError;

/// One message in a conversation, as shown in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub chat_id: i64,
    /// The other side of the conversation, regardless of direction, so a chat
    /// can be listed without inspecting each message.
    pub peer_user_id: i64,
    pub outgoing: bool,
    pub client_msg_id: String,
    pub text: String,
    pub created_at: i64,
}

/// Store key: `chat_id | created_at | client_msg_id`, all big-endian so the
/// backend's byte-ordered listing is already grouped by chat and chronological
/// within it. The id tail keeps two messages in the same millisecond distinct
/// and makes writes idempotent — a redelivered message overwrites its own row
/// instead of duplicating.
pub(crate) fn message_key(chat_id: i64, created_at: i64, client_msg_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(16 + client_msg_id.len());
    key.extend_from_slice(&chat_id.to_be_bytes());
    key.extend_from_slice(&created_at.to_be_bytes());
    key.extend_from_slice(client_msg_id.as_bytes());
    key
}

pub(crate) fn chat_key_prefix(chat_id: i64) -> [u8; 8] {
    chat_id.to_be_bytes()
}

pub(crate) fn encode_message(msg: &StoredMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + msg.client_msg_id.len() + msg.text.len());
    out.push(MESSAGE_FORMAT_V1);
    out.extend_from_slice(&msg.chat_id.to_le_bytes());
    out.extend_from_slice(&msg.peer_user_id.to_le_bytes());
    out.push(u8::from(msg.outgoing));
    out.extend_from_slice(&msg.created_at.to_le_bytes());
    append_str(&mut out, &msg.client_msg_id);
    append_str(&mut out, &msg.text);
    out
}

pub(crate) fn decode_message(raw: &[u8]) -> Result<StoredMessage, SdkError> {
    let mut r = Reader { b: raw, off: 0 };
    if r.u8()? != MESSAGE_FORMAT_V1 {
        return Err(SdkError::BadKeyMaterial);
    }
    let chat_id = r.i64()?;
    let peer_user_id = r.i64()?;
    let outgoing = r.u8()? != 0;
    let created_at = r.i64()?;
    let client_msg_id = r.string()?;
    let text = r.string()?;
    Ok(StoredMessage {
        chat_id,
        peer_user_id,
        outgoing,
        client_msg_id,
        text,
        created_at,
    })
}

const MESSAGE_FORMAT_V1: u8 = 1;

fn append_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
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

    fn i64(&mut self) -> Result<i64, SdkError> {
        let raw: [u8; 8] = self.take(8)?.try_into().map_err(|_| SdkError::BadKeyMaterial)?;
        Ok(i64::from_le_bytes(raw))
    }

    fn string(&mut self) -> Result<String, SdkError> {
        let raw: [u8; 4] = self.take(4)?.try_into().map_err(|_| SdkError::BadKeyMaterial)?;
        let len = u32::from_le_bytes(raw) as usize;
        let bytes = self.take(len)?.to_vec();
        String::from_utf8(bytes).map_err(|_| SdkError::BadKeyMaterial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoredMessage {
        StoredMessage {
            chat_id: 42,
            peer_user_id: 7,
            outgoing: true,
            client_msg_id: "abc-123".into(),
            text: "привет 👋".into(),
            created_at: 1_700_000_000_000,
        }
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let msg = sample();
        assert_eq!(decode_message(&encode_message(&msg)).unwrap(), msg);
    }

    #[test]
    fn rejects_truncated_and_unknown_format() {
        let encoded = encode_message(&sample());
        assert!(decode_message(&encoded[..encoded.len() - 3]).is_err());
        let mut wrong = encoded.clone();
        wrong[0] = 99;
        assert!(decode_message(&wrong).is_err());
    }

    #[test]
    fn keys_sort_by_chat_then_time() {
        let a = message_key(1, 100, "m1");
        let b = message_key(1, 200, "m2");
        let c = message_key(2, 50, "m3");
        assert!(a < b, "same chat orders by time");
        assert!(b < c, "chat id dominates the ordering");
        assert!(a.starts_with(&chat_key_prefix(1)));
    }

    #[test]
    fn negative_chat_ids_still_group_together() {
        // Big-endian on a two's-complement i64 puts negatives first, but all
        // rows of one chat must still share a contiguous prefix.
        let a = message_key(-5, 10, "m1");
        let b = message_key(-5, 20, "m2");
        assert!(a < b);
        assert!(a.starts_with(&chat_key_prefix(-5)));
        assert!(b.starts_with(&chat_key_prefix(-5)));
    }
}
