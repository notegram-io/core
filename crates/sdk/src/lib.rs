#![forbid(unsafe_code)]

mod body;
mod client;
mod identity;
mod messages;
mod session;

#[cfg(feature = "uniffi")]
mod ffi;

#[cfg(feature = "uniffi")]
mod net_ffi;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub use body::MessageBody;
pub use client::{
    IncomingMessage, NotegramClient, OneTimePreKeyPub, OutgoingEnvelope, PreKeyBundleUpload,
    RecipientPreKeyBundle,
};
pub use identity::{Identity, PublicIdentity};
pub use messages::{message_ref, MessageStatus, StoredMessage};
pub use session::{InboundPreKeys, PeerAddress, PreKeyBundle};

#[derive(Debug, PartialEq, Eq)]
pub enum SdkError {
    Store(store::StoreError),

    Session(ratchet::RatchetError),

    NoSession,

    BadPrekeySignature,

    BadKeyMaterial,

    NoIdentity,

    /// The authenticated associated data does not describe the message the
    /// server claimed to be delivering.
    MisattributedMessage,
}

impl core::fmt::Display for SdkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SdkError::Store(e) => write!(f, "sdk: {e}"),
            SdkError::Session(e) => write!(f, "sdk: {e}"),
            SdkError::NoSession => write!(f, "sdk: no session for peer"),
            SdkError::BadPrekeySignature => write!(f, "sdk: signed prekey signature invalid"),
            SdkError::BadKeyMaterial => write!(f, "sdk: malformed key material"),
            SdkError::NoIdentity => write!(f, "sdk: no local identity"),
            SdkError::MisattributedMessage => {
                write!(
                    f,
                    "sdk: associated data does not match the delivered message"
                )
            }
        }
    }
}

impl std::error::Error for SdkError {}

impl From<store::StoreError> for SdkError {
    fn from(e: store::StoreError) -> Self {
        SdkError::Store(e)
    }
}

impl From<ratchet::RatchetError> for SdkError {
    fn from(e: ratchet::RatchetError) -> Self {
        SdkError::Session(e)
    }
}

pub type Result<T> = core::result::Result<T, SdkError>;
