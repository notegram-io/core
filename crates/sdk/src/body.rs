//! What a decrypted message actually contains.
//!
//! The payload inside the ciphertext is typed, so a read receipt can travel as
//! an ordinary encrypted message: the server sees a message go by — which it
//! could see anyway — but not that it is a receipt, nor which messages it
//! covers. Nothing about read state ever reaches the server in the clear, which
//! is why receipts are not modelled the way delivery notices are.

use tl::generated::{
    MessageBodyDeleted, MessageBodyEdit, MessageBodyForwarded, MessageBodyReadReceipt,
    MessageBodyText,
};
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
    /// A message relayed from somewhere else, carrying who wrote it first.
    ///
    /// The attribution is asserted by whoever forwards, and cannot be anything
    /// else: they could equally retype the text and claim the same origin. It
    /// is provenance as a courtesy, not as proof, and the UI should not present
    /// it as verified.
    Forwarded {
        text: String,
        origin_username: String,
        origin_created_at: i64,
    },
    /// New text for a message the sender wrote earlier, named by the client id
    /// they chose for it.
    ///
    /// Only ever applicable to that sender's own messages — a recipient that
    /// applied it to anything else would let a peer rewrite words it did not
    /// write. Enforced where it is applied, not here.
    Edit {
        target_client_msg_id: String,
        text: String,
        edited_at: i64,
    },
    /// Messages the sender has withdrawn. A list, so a selection costs one
    /// message rather than one each.
    Deleted {
        target_client_msg_ids: Vec<String>,
        deleted_at: i64,
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
            MessageBody::Forwarded {
                text,
                origin_username,
                origin_created_at,
            } => tl::encode_to_vec(&MessageBodyForwarded {
                text: text.clone(),
                origin_username: origin_username.clone(),
                origin_created_at: *origin_created_at,
            })
            .expect("message body encodes"),
            MessageBody::Edit {
                target_client_msg_id,
                text,
                edited_at,
            } => tl::encode_to_vec(&MessageBodyEdit {
                target_client_msg_id: target_client_msg_id.clone(),
                text: text.clone(),
                edited_at: *edited_at,
            })
            .expect("message body encodes"),
            MessageBody::Deleted {
                target_client_msg_ids,
                deleted_at,
            } => tl::encode_to_vec(&MessageBodyDeleted {
                target_client_msg_i_ds: target_client_msg_ids.clone(),
                deleted_at: *deleted_at,
            })
            .expect("message body encodes"),
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
            Some(MessageBodyForwarded::CTOR) => {
                match tl::decode_from::<MessageBodyForwarded>(raw, tl::Limits::default()) {
                    Ok(body) => MessageBody::Forwarded {
                        text: body.text,
                        origin_username: body.origin_username,
                        origin_created_at: body.origin_created_at,
                    },
                    Err(_) => MessageBody::Text(lossy_text(raw)),
                }
            }
            Some(MessageBodyEdit::CTOR) => {
                match tl::decode_from::<MessageBodyEdit>(raw, tl::Limits::default()) {
                    Ok(body) => MessageBody::Edit {
                        target_client_msg_id: body.target_client_msg_id,
                        text: body.text,
                        edited_at: body.edited_at,
                    },
                    Err(_) => MessageBody::Text(lossy_text(raw)),
                }
            }
            Some(MessageBodyDeleted::CTOR) => {
                match tl::decode_from::<MessageBodyDeleted>(raw, tl::Limits::default()) {
                    Ok(body) => MessageBody::Deleted {
                        target_client_msg_ids: body.target_client_msg_i_ds,
                        deleted_at: body.deleted_at,
                    },
                    Err(_) => MessageBody::Text(lossy_text(raw)),
                }
            }
            _ => MessageBody::Text(lossy_text(raw)),
        }
    }

    /// The words to show, whatever kind of body this is. A forward reads as an
    /// ordinary message with a header above it, so callers that only care about
    /// the transcript do not have to match on the variant.
    pub fn text(&self) -> &str {
        match self {
            MessageBody::Text(text) => text,
            MessageBody::Forwarded { text, .. } => text,
            MessageBody::Edit { text, .. } => text,
            // Neither carries anything to show: a receipt is not part of the
            // conversation, and a deletion is the absence of one.
            MessageBody::ReadReceipt { .. } => "",
            MessageBody::Deleted { .. } => "",
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
