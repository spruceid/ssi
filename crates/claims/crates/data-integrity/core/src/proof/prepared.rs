use educe::Educe;
use serde::Serialize;
use ssi_claims_core::serde::SerializeVerifiableClaims;
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_core::one_or_many::OneOrManyRef;
use std::fmt;
use std::ops::{Deref, DerefMut};

use super::Proof;
use crate::suite::{
    CloneCryptographicSuite, CryptographicSuiteVerification, DebugCryptographicSuite,
    SerializeCryptographicSuite,
};
use crate::{CryptographicSuite, Proofs};

/// Prepared Data-Integrity Proof.
pub struct PreparedProof<T: CryptographicSuite> {
    /// Compact proof.
    proof: Proof<T>,

    /// Hashed credential/presentation value.
    hash: T::PreparedClaims,
}

impl<T: CryptographicSuite> PreparedProof<T> {
    pub fn new(proof: Proof<T>, hash: T::PreparedClaims) -> Self {
        Self { proof, hash }
    }

    pub fn proof(&self) -> &Proof<T> {
        &self.proof
    }

    pub fn hash(&self) -> &T::PreparedClaims {
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

impl<T, S: CryptographicSuite, V> ssi_claims_core::ValidateProof<V, T> for PreparedProof<S>
where
    S: CryptographicSuiteVerification<V>,
{
    async fn validate_proof<'a>(
        &'a self,
        _claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        self.proof()
            .suite()
            .verify_proof(verifier, self.hash(), self.proof().borrowed())
            .await
    }
}

impl<S: CryptographicSuite> ssi_claims_core::UnprepareProof for PreparedProof<S> {
    type Unprepared = Proof<S>;

    fn unprepare(self) -> Self::Unprepared {
        self.proof
    }
}

impl<T: SerializeCryptographicSuite> serde::Serialize for PreparedProof<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.proof.serialize(serializer)
    }
}

impl<T: DebugCryptographicSuite> fmt::Debug for PreparedProof<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedProof { proof: ")?;
        self.proof.fmt(f)?;
        f.write_str(", hash: ")?;
        T::fmt_prepared_claims(&self.hash, f)?;
        f.write_str(" }")
    }
}

impl<T: CloneCryptographicSuite> Clone for PreparedProof<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            hash: T::clone_prepared_claims(&self.hash),
        }
    }
}

impl<T: Serialize, S: SerializeCryptographicSuite> SerializeVerifiableClaims<T>
    for PreparedProof<S>
{
    fn serialize_verifiable_claims<U>(&self, claims: &T, serializer: U) -> Result<U::Ok, U::Error>
    where
        U: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(bound = "T: Serialize, S: SerializeCryptographicSuite")]
        struct WithClaims<'a, T, S: CryptographicSuite> {
            #[serde(flatten)]
            claims: &'a T,

            proof: &'a Proof<S>,
        }

        WithClaims {
            claims,
            proof: &self.proof,
        }
        .serialize(serializer)
    }
}

#[derive(Educe)]
#[educe(Debug(bound("S: DebugCryptographicSuite")))]
#[educe(Clone(bound("S: CloneCryptographicSuite")))]
#[educe(Default)]
pub struct PreparedProofs<S: CryptographicSuite>(pub(crate) Vec<PreparedProof<S>>);

impl<S: CryptographicSuite> Deref for PreparedProofs<S> {
    type Target = Vec<PreparedProof<S>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: CryptographicSuite> DerefMut for PreparedProofs<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<S: CryptographicSuite> From<PreparedProof<S>> for PreparedProofs<S> {
    fn from(value: PreparedProof<S>) -> Self {
        Self(vec![value])
    }
}

impl<S: CryptographicSuite> ssi_claims_core::UnprepareProof for PreparedProofs<S> {
    type Unprepared = Proofs<S>;

    fn unprepare(self) -> Self::Unprepared {
        Proofs(self.0.unprepare())
    }
}

impl<T, S: CryptographicSuiteVerification<V>, V> ssi_claims_core::ValidateProof<V, T>
    for PreparedProofs<S>
{
    async fn validate_proof<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        self.0.validate_proof(claims, verifier).await
    }
}

impl<T: SerializeCryptographicSuite> serde::Serialize for PreparedProofs<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OneOrManyRef::from_slice(&self.0).serialize(serializer)
    }
}

impl<T: Serialize, S: SerializeCryptographicSuite> SerializeVerifiableClaims<T>
    for PreparedProofs<S>
{
    fn serialize_verifiable_claims<U>(&self, claims: &T, serializer: U) -> Result<U::Ok, U::Error>
    where
        U: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(bound = "T: Serialize, S: SerializeCryptographicSuite")]
        struct WithClaims<'a, T, S: CryptographicSuite> {
            #[serde(flatten)]
            claims: &'a T,

            proof: OneOrManyRef<'a, PreparedProof<S>>,
        }

        WithClaims {
            claims,
            proof: OneOrManyRef::from_slice(&self.0),
        }
        .serialize(serializer)
    }
}
