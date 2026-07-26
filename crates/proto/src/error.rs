use std::fmt;

#[derive(Debug)]
pub enum ProtoError {
    BadHeader,

    UnsupportedVersion(u8),

    FrameTooLarge,

    ShortBuffer,

    Decrypt,

    MissingAuthKey,

    BadContainer,

    Tl(tl::TlError),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::BadHeader => write!(f, "proto: bad outer header"),
            ProtoError::UnsupportedVersion(v) => write!(f, "proto: unsupported secure version {v}"),
            ProtoError::FrameTooLarge => write!(f, "proto: frame too large"),
            ProtoError::ShortBuffer => write!(f, "proto: short buffer"),
            ProtoError::Decrypt => write!(f, "proto: decrypt/authentication failed"),
            ProtoError::MissingAuthKey => write!(f, "proto: missing auth key"),
            ProtoError::BadContainer => write!(f, "proto: malformed inner-frame container"),
            ProtoError::Tl(e) => write!(f, "proto: {e}"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<tl::TlError> for ProtoError {
    fn from(e: tl::TlError) -> Self {
        ProtoError::Tl(e)
    }
}

pub type Result<T> = std::result::Result<T, ProtoError>;
