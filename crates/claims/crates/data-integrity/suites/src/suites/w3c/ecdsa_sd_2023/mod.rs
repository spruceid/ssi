use serde::Serialize;
use ssi_data_integrity_core::{
    suite::{CryptographicSuiteSelect, SelectionError, SelectiveCryptographicSuite},
    CryptosuiteStr, DataIntegrity, ProofRef, StandardCryptographicSuite, TypeRef,
};

use crate::try_from_type;

mod configuration;
pub use configuration::*;

mod transformation;
use ssi_json_ld::{Expandable, ExpandedDocument, JsonLdLoaderProvider, JsonLdNodeObject};
use ssi_rdf::LexicalInterpretation;
use ssi_verification_methods::Multikey;
pub use transformation::*;

mod hashing;
pub use hashing::*;

mod signature;
pub use signature::*;

mod derive;
pub use derive::*;

mod verification;

/// The `ecdsa-sd-2023` cryptographic suite.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023>
#[derive(Debug, Clone, Copy)]
pub struct EcdsaSd2023;

impl StandardCryptographicSuite for EcdsaSd2023 {
    type Configuration = ConfigurationAlgorithm;

    type Transformation = TransformationAlgorithm;

    type Hashing = HashingAlgorithm;

    type VerificationMethod = Multikey;

    type ProofOptions = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("ecdsa-sd-2023").unwrap())
    }
}

impl SelectiveCryptographicSuite for EcdsaSd2023 {
    type SelectionOptions = DeriveOptions;
}

impl<T, P> CryptographicSuiteSelect<T, P> for EcdsaSd2023
where
    T: Serialize + JsonLdNodeObject + Expandable,
    T::Expanded<LexicalInterpretation, ()>: Into<ExpandedDocument>,
    P: JsonLdLoaderProvider,
{
    async fn select(
        &self,
        unsecured_document: &T,
        proof: ProofRef<'_, Self>,
        params: P,
        options: Self::SelectionOptions,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, Self>, SelectionError> {
        derive::add_derived_proof(params.loader(), unsecured_document, options, proof)
            .await
            .map_err(SelectionError::proof_derivation)
    }
}

try_from_type!(EcdsaSd2023);
