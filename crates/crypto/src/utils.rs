use core::fmt;
use std::str::FromStr;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitSize(pub usize);

impl BitSize {
    /// Returns the minimum number of bytes necessary to hold a number of `self`
    /// number of bits.
    pub fn byte_size(self) -> usize {
        (self.0 + 7) / 8
    }
}

impl fmt::Display for BitSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for BitSize {
    type Err = <usize as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        usize::from_str(s).map(Self)
    }
}

pub type ByteSize = usize;
