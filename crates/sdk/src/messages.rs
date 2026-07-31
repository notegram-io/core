//! Local message history.
//!
//! Decrypted messages are kept client-side only: the server stores ciphertext
//! and drops it on ack, so this is the sole durable copy of a conversation.
//! Records live in the encrypted store like every other secret.

use crate::SdkError;

/// Delivery state of an outgoing message. Incoming messages are always `Sent`,
/// since the concept does not apply to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    /// Accepted by the server; the recipient has not fetched it yet.
    Sent,
    /// The recipient's device fetched and acked it.
    Delivered,
    /// The recipient opened the conversation.
    Read,
}

impl MessageStatus {
    fn code(self) -> u8 {
        match self {
            MessageStatus::Sent => 0,
            MessageStatus::Delivered => 1,
            MessageStatus::Read => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(MessageStatus::Sent),
            1 => Some(MessageStatus::Delivered),
            2 => Some(MessageStatus::Read),
            _ => None,
        }
    }

    /// Status only ever moves forward: a late delivery notice must not undo a
    /// read receipt that already arrived.
    fn rank(self) -> u8 {
        self.code()
    }
}

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
    pub status: MessageStatus,
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

/// Whether `next` is a forward move from `current`. Delivery notices can
/// arrive after a read receipt, and applying them blindly would visibly
/// downgrade a message in the UI.
pub(crate) fn status_advances(current: MessageStatus, next: MessageStatus) -> bool {
    next.rank() > current.rank()
}

pub(crate) fn chat_key_prefix(chat_id: i64) -> [u8; 8] {
    chat_id.to_be_bytes()
}

pub(crate) fn encode_message(msg: &StoredMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + msg.client_msg_id.len() + msg.text.len());
    out.push(MESSAGE_FORMAT_V2);
    out.extend_from_slice(&msg.chat_id.to_le_bytes());
    out.extend_from_slice(&msg.peer_user_id.to_le_bytes());
    out.push(u8::from(msg.outgoing));
    out.extend_from_slice(&msg.created_at.to_le_bytes());
    append_str(&mut out, &msg.client_msg_id);
    append_str(&mut out, &msg.text);
    out.push(msg.status.code());
    out
}

pub(crate) fn decode_message(raw: &[u8]) -> Result<StoredMessage, SdkError> {
    let mut r = Reader { b: raw, off: 0 };
    // v1 rows predate delivery status and are still on disk; they read back as
    // Sent rather than being discarded.
    let version = r.u8()?;
    if version != MESSAGE_FORMAT_V1 && version != MESSAGE_FORMAT_V2 {
        return Err(SdkError::BadKeyMaterial);
    }
    let chat_id = r.i64()?;
    let peer_user_id = r.i64()?;
    let outgoing = r.u8()? != 0;
    let created_at = r.i64()?;
    let client_msg_id = r.string()?;
    let text = r.string()?;
    let status = if version >= MESSAGE_FORMAT_V2 {
        MessageStatus::from_code(r.u8()?).ok_or(SdkError::BadKeyMaterial)?
    } else {
        MessageStatus::Sent
    };
    Ok(StoredMessage {
        chat_id,
        peer_user_id,
        outgoing,
        client_msg_id,
        text,
        created_at,
        status,
    })
}

const MESSAGE_FORMAT_V1: u8 = 1;
const MESSAGE_FORMAT_V2: u8 = 2;

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
            status: MessageStatus::Sent,
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
    #[test]
    fn status_survives_a_roundtrip_and_only_moves_forward() {
        let mut msg = sample();
        msg.status = MessageStatus::Delivered;
        assert_eq!(decode_message(&encode_message(&msg)).unwrap().status, MessageStatus::Delivered);

        assert!(status_advances(MessageStatus::Sent, MessageStatus::Delivered));
        assert!(status_advances(MessageStatus::Delivered, MessageStatus::Read));
        // A delivery notice can land after a read receipt; applying it would
        // visibly downgrade the message.
        assert!(!status_advances(MessageStatus::Read, MessageStatus::Delivered));
        assert!(!status_advances(MessageStatus::Delivered, MessageStatus::Delivered));
    }

    #[test]
    fn rows_written_before_status_existed_still_load() {
        // v1 layout: no trailing status byte.
        let msg = sample();
        let mut v1 = encode_message(&msg);
        v1.pop();
        v1[0] = MESSAGE_FORMAT_V1;

        let decoded = decode_message(&v1).expect("v1 rows must remain readable");
        assert_eq!(decoded.text, msg.text);
        assert_eq!(decoded.status, MessageStatus::Sent);
    }

}
