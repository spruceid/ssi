use crate::{Proof, Verifiable};

/// Serializable claims.
pub trait SerializeVerifiableClaims<T> {
    fn serialize_verifiable_claims<S>(&self, claims: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

impl<C, P: Proof> serde::Serialize for Verifiable<C, P>
where
    P::Prepared: SerializeVerifiableClaims<C>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.proof
            .serialize_verifiable_claims(&self.claims, serializer)
    }
}

/// Serialize claims with a slice of proofs.
pub trait SerializeVerifiableClaimsFromSlice<T>: Sized {
    fn serialize_verifiable_claims_from_slice<S>(
        proofs: &[Self],
        claims: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

impl<T, P: SerializeVerifiableClaimsFromSlice<T>> SerializeVerifiableClaims<T> for Vec<P> {
    fn serialize_verifiable_claims<S>(&self, claims: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        P::serialize_verifiable_claims_from_slice(self, claims, serializer)
    }
}
