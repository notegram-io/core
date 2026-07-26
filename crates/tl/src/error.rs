use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlError {
    ShortBuffer,

    InvalidData,

    LimitExceeded,

    InvalidVector,

    InvalidPadding,

    UnexpectedCtor { expected: u32, got: u32 },

    NestingExceeded,

    InvalidUtf8,
}

impl fmt::Display for TlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlError::ShortBuffer => write!(f, "tl: short buffer"),
            TlError::InvalidData => write!(f, "tl: invalid data"),
            TlError::LimitExceeded => write!(f, "tl: limit exceeded"),
            TlError::InvalidVector => write!(f, "tl: invalid vector"),
            TlError::InvalidPadding => write!(f, "tl: invalid padding"),
            TlError::UnexpectedCtor { expected, got } => {
                write!(f, "tl: expected ctor {expected:#010x}, got {got:#010x}")
            }
            TlError::NestingExceeded => write!(f, "tl: nesting exceeded"),
            TlError::InvalidUtf8 => write!(f, "tl: invalid utf-8 in string"),
        }
    }
}

impl std::error::Error for TlError {}

pub type Result<T> = std::result::Result<T, TlError>;
