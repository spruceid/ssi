// //! Verifiable Credential Data Integrity 1.0 core implementation.
// //!
// //! See: <https://www.w3.org/TR/vc-data-integrity/>
// use std::ops::{Deref, DerefMut};

// pub mod canonicalization;
// mod de;
// mod decode;
// mod document;
// pub mod hashing;
// mod options;
// pub mod signing;
pub mod primitives;
mod proof;
mod suite;

use std::ops::{Deref, DerefMut};

use educe::Educe;
use serde::Serialize;
use ssi_claims_core::{Parameters, ValidateClaims, VerifiableClaims, Verification};
use ssi_crypto::{Error, Signer};
use ssi_verification_methods::{VerificationMethodIssuer, VerificationMethodVerifier};
// pub use decode::*;
// use educe::Educe;
// pub use options::ProofOptions;
// pub use proof::value_or_array;
// pub use proof::*;
// use serde::Serialize;
// use ssi_claims_core::{
//     ProofValidationError, ValidateClaims, ValidateProof, VerifiableClaims, Verification, VerificationParameters,
// };
// use ssi_crypto::Verifier;
pub use proof::*;
pub use suite::*;
// use suite::{CryptographicSuiteSelect, SelectionError};

// pub use document::*;
// #[doc(hidden)]
// pub use ssi_rdf;

/// Data-Integrity-secured document.
#[derive(Educe, Serialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[educe(Debug(bound("T: std::fmt::Debug, S: std::fmt::Debug")))]
#[educe(Clone(bound("T: Clone, S: Clone")))]
pub struct DataIntegrity<T, S: CryptographicSuite> {
    #[serde(flatten)]
    pub claims: T,

    #[serde(rename = "proof", skip_serializing_if = "<[Proof<S>]>::is_empty")]
    pub proofs: Proofs<S>,
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Create new Data-Integrity-secured claims by providing the proofs.
    pub fn new(claims: T, proofs: Proofs<S>) -> Self {
        Self {
            claims,
            proofs: proofs.into(),
        }
    }

    /// Generates a verifiable document secured with this cryptographic suite.
    pub async fn sign_with(
        issuer: impl VerificationMethodIssuer,
        claims: T,
        configuration: Proof<S>,
        params: &Parameters,
    ) -> Result<Self, Error>
    where
        S: CryptographicSuiteFor<T>,
    {
        let key = issuer
            .require_key(Some(configuration.verification_method.id().as_bytes()))
            .await?;

        let prepared =
            S::prepare(&claims, configuration.as_ref(), key.key_metadata(), params).await?;
        let proof = S::generate_proof(key, prepared, configuration, params).await?;
        Ok(DataIntegrity::new(claims, Proofs::new(proof)))
    }

    pub async fn sign(
        issuer: impl VerificationMethodIssuer,
        claims: T,
        configuration: Proof<S>,
    ) -> Result<Self, Error>
    where
        S: CryptographicSuiteFor<T>,
    {
        let params = Parameters::default();
        Self::sign_with(issuer, claims, configuration, &params).await
    }

    /// Select a subset of claims to disclose.
    pub async fn select_with(
        &self,
        options: S::SelectionOptions,
        params: &Parameters,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, S>, Error>
    where
        S: CryptographicSuiteSelect<T>,
    {
        match self.proofs.split_first() {
            Some((proof, [])) => {
                proof
                    .r#type
                    .select(&self.claims, proof.as_ref(), options, params)
                    .await
            }
            Some(_) => Err(Error::SignatureTooMany),
            None => Err(Error::SignatureMissing),
        }
    }

    /// Select a subset of claims to disclose.
    pub async fn select(
        &self,
        options: S::SelectionOptions,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, S>, Error>
    where
        S: CryptographicSuiteSelect<T>,
    {
        let params = Parameters::default();
        Self::select_with(&self, options, &params).await
    }

    /// Verify the claims and proofs.
    ///
    /// The `params` argument provides all the verification parameters required
    /// to validate the claims and proof.
    ///
    /// # What verification parameters should I use?
    ///
    /// It really depends on the claims type `T` and cryptosuite type `S`,
    /// but the `ssi::claims::VerificationParameters` type is a good starting
    /// point that should work most of the time.
    ///
    /// # Passing the parameters by reference
    ///
    /// If the validation traits are implemented for `P`, they will be
    /// implemented for `&P` as well. This means the parameters can be passed
    /// by move *or* by reference.
    pub async fn verify_with(
        &self,
        verifier: impl VerificationMethodVerifier,
        params: &Parameters,
    ) -> Result<Verification, Error>
    where
        T: ValidateClaims<Proofs<S>>,
        S: CryptographicSuiteFor<T>,
    {
        VerifiableClaims::verify_with(self, verifier, params).await
    }

    pub async fn verify(
        &self,
        verifier: impl VerificationMethodVerifier,
    ) -> Result<Verification, Error>
    where
        T: ValidateClaims<Proofs<S>>,
        S: CryptographicSuiteFor<T>,
    {
        VerifiableClaims::verify(self, verifier).await
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> DataIntegrity<U, S> {
        DataIntegrity {
            claims: f(self.claims),
            proofs: self.proofs,
        }
    }
}

impl<T, S: CryptographicSuite> Deref for DataIntegrity<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}

impl<T, S: CryptographicSuite> DerefMut for DataIntegrity<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.claims
    }
}

impl<T, S: CryptographicSuite> VerifiableClaims for DataIntegrity<T, S> {
    type Claims = T;
    type Proof = Proofs<S>;

    fn claims(&self) -> &Self::Claims {
        &self.claims
    }

    fn proof(&self) -> &Self::Proof {
        &self.proofs
    }
}
