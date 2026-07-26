mod container;
mod error;
pub mod handshake;
mod outer;
mod secure;

pub use container::{pack_container, unpack_container};
pub use error::{ProtoError, Result};
pub use handshake::{ClientFinishing, ClientHandshake, EstablishedSecure, HandshakeError};
pub use outer::{OuterHeader, DIR_C2S, DIR_S2C, OUTER_HEADER_SIZE, SECURE_VERSION_2};
pub use secure::{derive_msg_key, open_frame, open_outer, seal_frame, SealParams};
