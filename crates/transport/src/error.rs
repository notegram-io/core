use std::fmt;
use std::io;

use proto::ProtoError;

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),

    Proto(ProtoError),

    FrameTooLarge,

    UnexpectedDirection { expected: u8, got: u8 },

    Closed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport: io: {e}"),
            TransportError::Proto(e) => write!(f, "transport: {e}"),
            TransportError::FrameTooLarge => write!(f, "transport: inbound frame too large"),
            TransportError::UnexpectedDirection { expected, got } => {
                write!(f, "transport: unexpected direction {got} (want {expected})")
            }
            TransportError::Closed => write!(f, "transport: connection closed"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        TransportError::Io(e)
    }
}

impl From<ProtoError> for TransportError {
    fn from(e: ProtoError) -> Self {
        TransportError::Proto(e)
    }
}

pub type Result<T> = std::result::Result<T, TransportError>;
