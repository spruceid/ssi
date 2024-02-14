#[cfg(feature = "w3c")]
mod w3c;
use linked_data::{to_quads, LinkedDataPredicateObjects, LinkedDataSubject};
use rdf_types::{generator, interpretation, Quad};
use ssi_core::Referencable;
use ssi_data_integrity_core::{CryptographicSuite, ExpandedConfiguration, ProofConfigurationRef};
use ssi_rdf::urdna2015;
#[cfg(feature = "w3c")]
pub use w3c::*;

#[cfg(feature = "dif")]
mod dif;
#[cfg(feature = "dif")]
pub use dif::*;

mod unspecified;
pub use unspecified::*;

/// SHA256-based input hashing algorithm used by many cryptographic suites.
fn sha256_hash<'a, T: CryptographicSuite>(
    data: &[u8],
    suite: &T,
    proof_configuration: ExpandedConfiguration<'a, T::VerificationMethod, T::Options>,
) -> [u8; 64]
where
    <T::VerificationMethod as Referencable>::Reference<'a>:
        LinkedDataPredicateObjects<interpretation::WithGenerator<generator::Blank>>,
    <T::Options as Referencable>::Reference<'a>:
        LinkedDataSubject<interpretation::WithGenerator<generator::Blank>>,
{
    let generator = rdf_types::generator::Blank::new();
    let proof_config_quads = proof_configuration.quads();
    let proof_config_normalized_quads =
        urdna2015::normalize(proof_config_quads.iter().map(Quad::as_quad_ref)).into_nquads();
    let proof_config_hash: [u8; 32] =
        ssi_crypto::hashes::sha256::sha256(proof_config_normalized_quads.as_bytes());

    let transformed_document_hash = ssi_crypto::hashes::sha256::sha256(data);

    let mut hash_data = [0u8; 64];
    hash_data[..32].copy_from_slice(&proof_config_hash);
    hash_data[32..].copy_from_slice(&transformed_document_hash);

    hash_data
}

/// `CryptographicSuiteInput` trait implementation for RDF dataset inputs
/// normalized using URDNA2015.
///
/// Many cryptographic suites take RDF datasets as input, then normalized with
/// the URDNA2015 canonicalization algorithm. This macro is used to
/// automatically write the `CryptographicSuiteInput` trait implementation.
#[macro_export]
macro_rules! impl_rdf_input_urdna2015 {
    ($ty:ident) => {
        impl<V: rdf_types::Vocabulary, I: rdf_types::Interpretation, E, T>
            $crate::ssi_data_integrity_core::CryptographicSuiteInput<T, E> for $ty
        where
            E: $crate::ssi_rdf::AnyLdEnvironment<Vocabulary = V, Interpretation = I>,
            I: rdf_types::interpretation::InterpretationMut<V>
                + rdf_types::interpretation::ReverseIriInterpretation<Iri = V::Iri>
                + rdf_types::interpretation::ReverseBlankIdInterpretation<BlankId = V::BlankId>
                + rdf_types::ReverseLiteralInterpretation<Literal = V::Literal>,
            V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
            T: $crate::ssi_rdf::Expandable<E>,
            T::Expanded: linked_data::LinkedData<I, V>,
        {
            // type Transform<'t> = ::std::future::Ready<Result<Self::Transformed, $crate::suite::TransformError>> where Self: 't, T: 't, E: 't;

            /// Transformation algorithm.
            async fn transform<'t, 'c: 't>(
                &'t self,
                data: &'t T,
                context: &'t mut E,
                _options: $crate::ssi_data_integrity_core::ExpandedConfigurationRef<
                    'c,
                    <$ty as $crate::ssi_data_integrity_core::CryptographicSuite>::VerificationMethod,
                    <$ty as $crate::ssi_data_integrity_core::CryptographicSuite>::Options,
                >,
            ) -> Result<Self::Transformed, $crate::ssi_data_integrity_core::suite::TransformError> {
                let expanded = data
                    .expand(context)
                    .await
                    .map_err(|_| $crate::ssi_data_integrity_core::suite::TransformError::ExpansionFailed)?;
                context.into_canonical_form(&expanded).map_err(Into::into)
            }
        }
    };
}
