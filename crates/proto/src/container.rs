use crate::error::{ProtoError, Result};

pub fn pack_container(frames: &[&[u8]]) -> Vec<u8> {
    let total: usize = frames.iter().map(|f| 4 + f.len()).sum();
    let mut out = Vec::with_capacity(total);
    for f in frames {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

pub fn unpack_container(container: &[u8], max_frame: usize) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < container.len() {
        if container.len() - i < 4 {
            return Err(ProtoError::BadContainer);
        }
        let n = wire::u32_le(&container[i..i + 4]) as usize;
        i += 4;
        if max_frame != 0 && n > max_frame {
            return Err(ProtoError::FrameTooLarge);
        }
        if container.len() - i < n {
            return Err(ProtoError::BadContainer);
        }
        out.push(container[i..i + n].to_vec());
        i += n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let frames: [&[u8]; 3] = [b"first", b"", b"third-frame"];
        let packed = pack_container(&frames);
        let got = unpack_container(&packed, 1 << 20).unwrap();
        assert_eq!(
            got,
            vec![b"first".to_vec(), Vec::new(), b"third-frame".to_vec()]
        );
    }

    #[test]
    fn empty_container() {
        assert!(unpack_container(&[], 0).unwrap().is_empty());
    }

    #[test]
    fn truncated_is_rejected() {
        let bad = [10, 0, 0, 0, 1, 2];
        assert!(matches!(
            unpack_container(&bad, 0),
            Err(ProtoError::BadContainer)
        ));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let packed = pack_container(&[b"abcdef"]);
        assert!(matches!(
            unpack_container(&packed, 3),
            Err(ProtoError::FrameTooLarge)
        ));
    }
}
