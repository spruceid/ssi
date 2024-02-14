use ssi_claims_core::serde::{SerializeVerifiableClaims, SerializeVerifiableClaimsFromSlice};
use std::fmt;
use std::ops::{Deref, DerefMut};

use super::Proof;
use crate::CryptographicSuite;

/// Prepared Data-Integrity Proof.
pub struct PreparedProof<T: CryptographicSuite> {
    /// Compact proof.
    proof: Proof<T>,

    /// Hashed credential/presentation value.
    hash: T::Hashed,
}

impl<T: CryptographicSuite> PreparedProof<T> {
    pub fn new(proof: Proof<T>, hash: T::Hashed) -> Self {
        Self { proof, hash }
    }

    pub fn proof(&self) -> &Proof<T> {
        &self.proof
    }

    pub fn hash(&self) -> &T::Hashed {
        &self.hash
    }
}

impl<T: CryptographicSuite> Deref for PreparedProof<T> {
    type Target = Proof<T>;

    fn deref(&self) -> &Self::Target {
        &self.proof
    }
}

impl<T: CryptographicSuite> DerefMut for PreparedProof<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.proof
    }
}

impl<S: CryptographicSuite> ssi_claims_core::UnprepareProof for PreparedProof<S> {
    type Unprepared = Proof<S>;

    fn unprepare(self) -> Self::Unprepared {
        self.proof
    }
}

impl<T: CryptographicSuite> serde::Serialize for PreparedProof<T>
where
    T::VerificationMethod: serde::Serialize,
    T::Options: serde::Serialize,
    T::Signature: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.proof.serialize(serializer)
    }
}

impl<T: CryptographicSuite> fmt::Debug for PreparedProof<T>
where
    T: fmt::Debug,
    T::VerificationMethod: fmt::Debug,
    T::Options: fmt::Debug,
    T::Signature: fmt::Debug,
    T::Hashed: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProof { proof: ")?;
        self.proof.fmt(f)?;
        f.write_str(", hash: ")?;
        self.hash.fmt(f)?;
        f.write_str(" }")
    }
}

impl<T: CryptographicSuite> Clone for PreparedProof<T>
where
    T: Clone,
    T::VerificationMethod: Clone,
    T::Options: Clone,
    T::Signature: Clone,
    T::Hashed: Clone,
{
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            hash: self.hash.clone(),
        }
    }
}

impl<T: serde::Serialize, S: CryptographicSuite> SerializeVerifiableClaims<T> for PreparedProof<S>
where
    S::VerificationMethod: serde::Serialize,
    S::Options: serde::Serialize,
    S::Signature: serde::Serialize,
{
    fn serialize_verifiable_claims<U>(&self, claims: &T, serializer: U) -> Result<U::Ok, U::Error>
    where
        U: serde::Serializer,
    {
        use serde::Serialize;

        #[derive(serde::Serialize)]
        struct WithClaims<'a, T, P> {
            #[serde(flatten)]
            claims: &'a T,

            proof: &'a P,
        }

        WithClaims {
            claims,
            proof: self,
        }
        .serialize(serializer)
    }
}

impl<T: serde::Serialize, S: CryptographicSuite> SerializeVerifiableClaimsFromSlice<T>
    for PreparedProof<S>
where
    S::VerificationMethod: serde::Serialize,
    S::Options: serde::Serialize,
    S::Signature: serde::Serialize,
{
    fn serialize_verifiable_claims_from_slice<U>(
        proofs: &[Self],
        claims: &T,
        serializer: U,
    ) -> Result<U::Ok, U::Error>
    where
        U: serde::Serializer,
    {
        use serde::Serialize;

        #[derive(serde::Serialize)]
        struct WithClaims<'a, T, P> {
            #[serde(flatten)]
            claims: &'a T,

            proof: &'a [P],
        }

        WithClaims {
            claims,
            proof: proofs,
        }
        .serialize(serializer)
    }
}
