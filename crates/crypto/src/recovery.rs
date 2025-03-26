use crate::{AlgorithmInstance, Error};

pub trait RecoveryKey: Sized {
    fn recover(
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error>;
}
