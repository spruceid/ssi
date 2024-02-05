use crate::{Provable, Verifiable};

/// Serializable claims.
pub trait SerializeClaims: Provable {
    fn serialize_with_proof<S>(
        &self,
        proof: &Self::Proof,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

impl<C: SerializeClaims> serde::Serialize for Verifiable<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.claims.serialize_with_proof(&self.proof, serializer)
    }
}
