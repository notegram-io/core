#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags(pub u32);

pub const MAX_FLAG_BITS: u32 = 32;

impl Flags {
    #[inline]
    pub fn has(self, bit: u32) -> bool {
        bit < MAX_FLAG_BITS && (self.0 & (1 << bit)) != 0
    }

    #[inline]
    #[must_use]
    pub fn set(self, bit: u32, value: bool) -> Flags {
        if bit >= MAX_FLAG_BITS {
            return self;
        }
        let mask = 1u32 << bit;
        Flags(if value { self.0 | mask } else { self.0 & !mask })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_has() {
        let f = Flags(0).set(0, true).set(3, true);
        assert!(f.has(0));
        assert!(f.has(3));
        assert!(!f.has(1));
        assert_eq!(f.0, 0b1001);
        assert!(!f.set(0, false).has(0));
    }

    #[test]
    fn out_of_range_is_noop() {
        assert_eq!(Flags(0xFFFF_FFFF).set(32, false), Flags(0xFFFF_FFFF));
        assert!(!Flags(0xFFFF_FFFF).has(32));
    }
}
