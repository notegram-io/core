//! What a decrypted message actually contains.
//!
//! The payload inside the ciphertext is typed, so a read receipt can travel as
//! an ordinary encrypted message: the server sees a message go by — which it
//! could see anyway — but not that it is a receipt, nor which messages it
//! covers. Nothing about read state ever reaches the server in the clear, which
//! is why receipts are not modelled the way delivery notices are.

use tl::generated::{MessageBodyReadReceipt, MessageBodyText};
use tl::TlObject;

/// A decrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageBody {
    Text(String),
    /// Everything the sender wrote in this chat up to and including this
    /// timestamp has been read. A watermark rather than a per-message id, so one
    /// receipt covers a backlog and receipts are idempotent.
    ReadReceipt {
        up_to_created_at: i64,
    },
}

impl MessageBody {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            MessageBody::Text(text) => tl::encode_to_vec(&MessageBodyText { text: text.clone() })
                .expect("message body encodes"),
            MessageBody::ReadReceipt { up_to_created_at } => {
                tl::encode_to_vec(&MessageBodyReadReceipt {
                    up_to_created_at: *up_to_created_at,
                })
                .expect("message body encodes")
            }
        }
    }

    /// Reads a payload back. Anything that is not a known body type is treated
    /// as plain text: messages predate this envelope and are still in local
    /// history and in transit, and dropping them would lose real conversation.
    pub fn decode(raw: &[u8]) -> Self {
        match ctor_of(raw) {
            Some(MessageBodyText::CTOR) => {
                match tl::decode_from::<MessageBodyText>(raw, tl::Limits::default()) {
                    Ok(body) => MessageBody::Text(body.text),
                    Err(_) => MessageBody::Text(lossy_text(raw)),
                }
            }
            Some(MessageBodyReadReceipt::CTOR) => {
                match tl::decode_from::<MessageBodyReadReceipt>(raw, tl::Limits::default()) {
                    Ok(body) => MessageBody::ReadReceipt {
                        up_to_created_at: body.up_to_created_at,
                    },
                    Err(_) => MessageBody::Text(lossy_text(raw)),
                }
            }
            _ => MessageBody::Text(lossy_text(raw)),
        }
    }
}

fn ctor_of(raw: &[u8]) -> Option<u32> {
    (raw.len() >= 4).then(|| wire::u32_le(&raw[0..4]))
}

fn lossy_text(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_receipts_survive_a_roundtrip() {
        let text = MessageBody::Text("привет 👋".into());
        assert_eq!(MessageBody::decode(&text.encode()), text);

        let receipt = MessageBody::ReadReceipt {
            up_to_created_at: 1_700_000_000_000,
        };
        assert_eq!(MessageBody::decode(&receipt.encode()), receipt);
    }

    #[test]
    fn a_receipt_is_not_mistaken_for_text() {
        // The two bodies must stay distinguishable byte-wise, or a receipt would
        // render as a garbled message in the transcript.
        let receipt = MessageBody::ReadReceipt {
            up_to_created_at: 42,
        };
        assert!(matches!(
            MessageBody::decode(&receipt.encode()),
            MessageBody::ReadReceipt { .. }
        ));
    }

    #[test]
    fn payloads_written_before_bodies_were_typed_read_as_text() {
        // Older senders put raw UTF-8 in the ciphertext.
        assert_eq!(
            MessageBody::decode("plain old message".as_bytes()),
            MessageBody::Text("plain old message".into())
        );
        // Including short ones that cannot even hold a constructor id.
        assert_eq!(MessageBody::decode(b"hi"), MessageBody::Text("hi".into()));
    }
}
