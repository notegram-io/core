#![forbid(unsafe_code)]

mod backend;
mod seal;
mod store;

#[cfg(feature = "sqlite")]
mod sqlite;

pub use backend::{Backend, MemoryBackend};
pub use seal::{RecordCipher, MASTER_KEY_LEN};
pub use store::{Namespace, SecureStore};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteBackend;

#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    Decrypt,

    BadRecord,

    BadMasterKey,

    Backend(String),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoreError::Decrypt => write!(f, "store: sealed record failed to open"),
            StoreError::BadRecord => write!(f, "store: malformed sealed record"),
            StoreError::BadMasterKey => write!(f, "store: master key must be 32 bytes"),
            StoreError::Backend(e) => write!(f, "store: backend error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type Result<T> = core::result::Result<T, StoreError>;
