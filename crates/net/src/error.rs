use std::fmt;

use proto::HandshakeError;
use transport::TransportError;

#[derive(Debug)]
pub enum NetError {
    Io(std::io::Error),
    Closed,
    FrameTooLarge,
    BadFrame,
    Admission(&'static str),
    Transport(TransportError),
    Encode,
    Decode,

    Handshake(HandshakeError),

    Rpc { code: i32, message: String },

    NoResponse,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "net: io: {e}"),
            NetError::Closed => write!(f, "net: connection closed"),
            NetError::FrameTooLarge => write!(f, "net: frame too large"),
            NetError::BadFrame => write!(f, "net: malformed frame"),
            NetError::Admission(w) => write!(f, "net: admission: {w}"),
            NetError::Transport(e) => write!(f, "net: {e}"),
            NetError::Encode => write!(f, "net: request encode failed"),
            NetError::Decode => write!(f, "net: response decode failed"),
            NetError::Handshake(e) => write!(f, "net: {e}"),
            NetError::Rpc { code, message } => write!(f, "net: rpc error {code}: {message}"),
            NetError::NoResponse => write!(f, "net: no matching response"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NetError::Closed
        } else {
            NetError::Io(e)
        }
    }
}

impl From<TransportError> for NetError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Closed => NetError::Closed,
            TransportError::FrameTooLarge => NetError::FrameTooLarge,
            other => NetError::Transport(other),
        }
    }
}

pub type Result<T> = core::result::Result<T, NetError>;
