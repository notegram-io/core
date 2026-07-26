mod codec;
mod error;
mod flags;
mod object;

pub mod generated;

pub use codec::{Decoder, Encoder, Limits, BOOL_FALSE_CTOR, BOOL_TRUE_CTOR, VECTOR_CTOR};
pub use error::{Result, TlError};
pub use flags::{Flags, MAX_FLAG_BITS};
pub use object::{decode_from, encode_to_vec, TlObject};
