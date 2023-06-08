use crate::{Algorithm, UnsupportedAlgorithm};

pub trait Signer {
    fn sign(&self, algorithm: Algorithm, bytes: &[u8]) -> Result<Vec<u8>, UnsupportedAlgorithm>;
}
