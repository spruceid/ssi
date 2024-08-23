//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use serde::{Deserialize, Serialize};
use ssi_claims_core::ResolverProvider;
use ssi_data_integrity_core::{
    suite::{
        ConfigurationAlgorithm, ConfigurationError, CryptographicSuiteSelect, InputProofOptions,
        SelectionError, SelectiveCryptographicSuite,
    },
    CryptosuiteStr, DataIntegrity, ProofConfiguration, ProofRef, StandardCryptographicSuite,
    TypeRef,
};
use ssi_di_sd_primitives::{HmacSha256Key, JsonPointerBuf};
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;
use ssi_verification_methods::{Multikey, VerificationMethodResolver};

use crate::try_from_type;

pub(crate) mod transformation;
pub use transformation::{Bbs2023Transformation, Bbs2023TransformationOptions, Transformed};

pub mod hashing;
pub use hashing::{Bbs2023Hashing, HashData};

mod signature;
pub use signature::*;

mod derive;
pub use derive::*;

mod verification;

#[cfg(test)]
mod tests;

/// The `bbs-2023` cryptographic suite.
#[derive(Debug, Clone, Copy)]
pub struct Bbs2023;

impl SelectiveCryptographicSuite for Bbs2023 {
    type SelectionOptions = DeriveOptions;
}

impl<T, P> CryptographicSuiteSelect<T, P> for Bbs2023
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
    P: JsonLdLoaderProvider + ResolverProvider,
    P::Resolver: VerificationMethodResolver<Method = Multikey>,
{
    async fn select(
        &self,
        document: &T,
        proof: ProofRef<'_, Self>,
        params: P,
        options: DeriveOptions,
    ) -> Result<DataIntegrity<json_syntax::Object, Self>, SelectionError> {
        let verification_method = params
            .resolver()
            .resolve_verification_method(None, Some(proof.verification_method))
            .await?;

        add_derived_proof(
            params.loader(),
            document,
            &verification_method,
            options,
            proof,
        )
        .await
        .map_err(SelectionError::proof_derivation)
    }
}

impl StandardCryptographicSuite for Bbs2023 {
    type Configuration = Bbs2023Configuration;

    type Transformation = Bbs2023Transformation;

    type Hashing = Bbs2023Hashing;

    type VerificationMethod = Multikey;

    type ProofOptions = ();

    type SignatureAlgorithm = Bbs2023SignatureAlgorithm;

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("bbs-2023").unwrap())
    }
}

try_from_type!(Bbs2023);

#[derive(Debug, Default, Clone)]
pub struct Bbs2023SignatureOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    pub feature_option: FeatureOption,

    pub commitment_with_proof: Option<Vec<u8>>,

    pub hmac_key: Option<HmacSha256Key>,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FeatureOption {
    #[default]
    Baseline,
    AnonymousHolderBinding,
    PseudonymIssuerPid,
    PseudonymHiddenPid,
}

/// Base Proof Configuration.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-configuration-bbs-2023>
pub struct Bbs2023Configuration;

impl ConfigurationAlgorithm<Bbs2023> for Bbs2023Configuration {
    /// Input type for the verification method.
    type InputVerificationMethod = Multikey;

    /// Input suite-specific proof options.
    type InputSuiteOptions = ();

    /// Input signature options.
    type InputSignatureOptions = Bbs2023SignatureOptions;

    type InputVerificationOptions = ();

    /// Document transformation options.
    type TransformationOptions = Bbs2023TransformationOptions;

    fn configure_signature(
        type_: &Bbs2023,
        options: InputProofOptions<Bbs2023>,
        signature_options: Bbs2023SignatureOptions,
    ) -> Result<(ProofConfiguration<Bbs2023>, Bbs2023TransformationOptions), ConfigurationError>
    {
        let proof_configuration = options.into_configuration(*type_)?;
        Ok((
            proof_configuration,
            Bbs2023TransformationOptions::BaseSignature(signature_options),
        ))
    }

    fn configure_verification(
        _suite: &Bbs2023,
        _verification_options: &ssi_data_integrity_core::suite::InputVerificationOptions<Bbs2023>,
    ) -> Result<Self::TransformationOptions, ConfigurationError> {
        Ok(Bbs2023TransformationOptions::DerivedVerification)
    }
}
