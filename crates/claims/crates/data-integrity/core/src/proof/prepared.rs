use educe::Educe;
use ssi_claims_core::serde::SerializeVerifiableClaims;
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_core::one_or_many::OneOrManyRef;
use ssi_verification_methods_core::VerificationMethodResolver;
use std::fmt::{self, Debug};
use std::ops::{Deref, DerefMut};

use super::Proof;
use crate::{CryptographicSuite, Proofs};

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

impl<T, S: CryptographicSuite, V: VerificationMethodResolver<Method = S::VerificationMethod>>
    ssi_claims_core::ValidateProof<T, V> for PreparedProof<S>
{
    async fn validate_proof<'a>(
        &'a self,
        _claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        let suite = self.proof().suite();
        suite
            .verify_proof(self.hash(), verifier, self.proof().borrowed())
            .await
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

#[derive(Educe)]
#[educe(Debug(bound("S: Debug, S::Hashed: Debug, S::VerificationMethod: Debug, S::Options: Debug, S::Signature: Debug")))]
#[educe(Clone(bound("S: Clone, S::Hashed: Clone, S::VerificationMethod: Clone, S::Options: Clone, S::Signature: Clone")))]
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

impl<T, S: CryptographicSuite, V: VerificationMethodResolver<Method = S::VerificationMethod>>
    ssi_claims_core::ValidateProof<T, V> for PreparedProofs<S>
{
    async fn validate_proof<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        self.0.validate_proof(claims, verifier).await
    }
}

impl<T: CryptographicSuite> serde::Serialize for PreparedProofs<T>
where
    T::VerificationMethod: serde::Serialize,
    T::Options: serde::Serialize,
    T::Signature: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OneOrManyRef::from_slice(&self.0).serialize(serializer)
    }
}

impl<T: serde::Serialize, S> SerializeVerifiableClaims<T> for PreparedProofs<S>
where
    S: CryptographicSuite,
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

            proof: OneOrManyRef<'a, P>,
        }

        WithClaims {
            claims,
            proof: OneOrManyRef::from_slice(&self.0),
        }
        .serialize(serializer)
    }
}
