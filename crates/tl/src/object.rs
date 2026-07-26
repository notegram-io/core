use crate::codec::{Decoder, Encoder, Limits};
use crate::error::Result;

pub trait TlObject: Sized {
    const CTOR: u32;

    fn encode(&self, e: &mut Encoder) -> Result<()>;

    fn decode(d: &mut Decoder) -> Result<Self>;
}

pub fn encode_to_vec<T: TlObject>(obj: &T) -> Result<Vec<u8>> {
    let mut e = Encoder::new();
    obj.encode(&mut e)?;
    Ok(e.into_bytes())
}

pub fn decode_from<T: TlObject>(bytes: &[u8], limits: Limits) -> Result<T> {
    let mut d = Decoder::new(bytes, limits)?;
    T::decode(&mut d)
}
