use super::r#type::KeyType;
use crate::{AlgorithmInstance, Error};

/// Key metadata.
#[derive(Default)]
pub struct KeyMetadata {
    /// Identifier.
    pub id: Option<Vec<u8>>,

    /// Type.
    pub r#type: Option<KeyType>,

    /// Signature algorithm.
    pub algorithm: Option<AlgorithmInstance>,
}

impl KeyMetadata {
    pub fn new(
        id: Option<Vec<u8>>,
        r#type: Option<KeyType>,
        algorithm: Option<AlgorithmInstance>,
    ) -> Self {
        Self {
            id,
            r#type,
            algorithm,
        }
    }

    pub fn into_id_and_algorithm(
        self,
        algorithm: Option<AlgorithmInstance>,
    ) -> Result<(Option<Vec<u8>>, AlgorithmInstance), Error> {
        let algorithm = infer_algorithm(algorithm, || self.algorithm, || self.r#type)
            .ok_or(Error::AlgorithmMissing)?;
        Ok((self.id, algorithm))
    }
}

/// Infer the appropriate signature algorithm to use given the following hints.
pub fn infer_algorithm(
    user_algorithm: Option<AlgorithmInstance>,
    key_algorithm: impl FnOnce() -> Option<AlgorithmInstance>,
    key_type: impl FnOnce() -> Option<KeyType>,
) -> Option<AlgorithmInstance> {
    user_algorithm
        .or_else(key_algorithm)
        .or_else(|| key_type().and_then(|t| t.default_algorithm_params()))
}
