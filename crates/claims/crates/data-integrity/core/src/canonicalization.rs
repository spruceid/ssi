use digest::Digest;
use std::marker::PhantomData;

use rdf_types::{generator, Quad};
use serde::Serialize;
use ssi_json_ld::{
    syntax::Value, JsonLdLoaderProvider, JsonLdNodeObject, JsonLdProcessor, RemoteDocument,
};
use ssi_rdf::{urdna2015, LexicalQuad};

use crate::{
    hashing::ConcatOutputSize,
    suite::{
        standard::{self, HashingAlgorithm, TransformationAlgorithm, TransformationError},
        TransformationOptions,
    },
    CryptographicSuite, ProofConfigurationRef, SerializeCryptographicSuite,
    StandardCryptographicSuite,
};

/// Canonical claims and configuration.
pub struct CanonicalClaimsAndConfiguration {
    pub claims: Vec<String>,
    pub configuration: Vec<String>,
}

/// RDF Canonicalization transformation algorithm.
pub struct CanonicalizeClaimsAndConfiguration;

impl<S: CryptographicSuite> standard::TransformationAlgorithm<S>
    for CanonicalizeClaimsAndConfiguration
{
    type Output = CanonicalClaimsAndConfiguration;
}

impl<S, T, C> standard::TypedTransformationAlgorithm<S, T, C> for CanonicalizeClaimsAndConfiguration
where
    S: SerializeCryptographicSuite,
    T: JsonLdNodeObject + Serialize,
    C: JsonLdLoaderProvider,
{
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, S>,
        _verification_method: &S::VerificationMethod,
        _transformation_options: TransformationOptions<S>,
    ) -> Result<Self::Output, TransformationError> {
        // Serialize via json-ld `to_rdf`, which keeps the datatype IRI the
        // context coerces a literal to (e.g. OpenBadge's
        // `https://www.w3.org/2001/XMLSchema#boolean`). The previous
        // `linked_data::to_lexical_quads` path rewrote such datatypes to the
        // canonical `http://…` form and broke verification of those credentials.
        // Expansion stays strict: undefined terms are an error, not dropped.
        let value: Value = json_syntax::to_value(data)
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?;

        let mut generator = generator::Blank::new();
        let quads: Vec<LexicalQuad> = RemoteDocument::new(None, None, value)
            .to_rdf_using(
                &mut generator,
                context.loader(),
                ssi_json_ld::strict_options(),
            )
            .await
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?
            .cloned_quads()
            .map(|quad| quad.map_predicate(|p| p.into_iri().unwrap()))
            .collect();

        let claims =
            urdna2015::normalize(quads.iter().map(Quad::as_lexical_quad_ref)).into_nquads_lines();

        Ok(CanonicalClaimsAndConfiguration {
            claims,
            configuration: proof_configuration
                .expand(context, data)
                .await
                .map_err(TransformationError::ProofConfigurationExpansion)?
                .nquads_lines(),
        })
    }
}

pub struct HashCanonicalClaimsAndConfiguration<H>(PhantomData<H>);

impl<H, S> HashingAlgorithm<S> for HashCanonicalClaimsAndConfiguration<H>
where
    H: Digest,
    H::OutputSize: ConcatOutputSize,
    S: StandardCryptographicSuite,
    S::Transformation: TransformationAlgorithm<S, Output = CanonicalClaimsAndConfiguration>,
{
    type Output = <H::OutputSize as ConcatOutputSize>::ConcatOutput;

    fn hash(
        input: standard::TransformedData<S>,
        _proof_configuration: ProofConfigurationRef<S>,
        _verification_method: &S::VerificationMethod,
    ) -> Result<Self::Output, standard::HashingError> {
        let proof_configuration_hash = input
            .configuration
            .iter()
            .fold(H::new(), |h, line| h.chain_update(line.as_bytes()))
            .finalize();

        let claims_hash = input
            .claims
            .iter()
            .fold(H::new(), |h, line| h.chain_update(line.as_bytes()))
            .finalize();

        Ok(<H::OutputSize as ConcatOutputSize>::concat(
            proof_configuration_hash,
            claims_hash,
        ))
    }
}

pub struct ConcatCanonicalClaimsAndConfiguration;

impl<S> HashingAlgorithm<S> for ConcatCanonicalClaimsAndConfiguration
where
    S: StandardCryptographicSuite,
    S::Transformation: TransformationAlgorithm<S, Output = CanonicalClaimsAndConfiguration>,
{
    type Output = String;

    fn hash(
        input: standard::TransformedData<S>,
        _proof_configuration: ProofConfigurationRef<S>,
        _verification_method: &S::VerificationMethod,
    ) -> Result<Self::Output, standard::HashingError> {
        let mut result = String::new();

        for line in &input.configuration {
            result.push_str(line);
        }

        result.push('\n');

        for line in &input.claims {
            result.push_str(line);
        }

        Ok(result)
    }
}
