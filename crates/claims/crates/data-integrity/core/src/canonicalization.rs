use digest::Digest;
use std::marker::PhantomData;

use rdf_types::{generator, Quad};
use serde::Serialize;
use ssi_json_ld::{
    syntax::Value, Expandable, JsonLdLoaderProvider, JsonLdNodeObject, JsonLdProcessor,
    RemoteDocument,
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
    T: JsonLdNodeObject + Expandable + Serialize,
    C: JsonLdLoaderProvider,
{
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, S>,
        _verification_method: &S::VerificationMethod,
        _transformation_options: TransformationOptions<S>,
    ) -> Result<Self::Output, TransformationError> {
        // Serialize to RDF with `to_rdf`, which keeps the context's `@type`
        // coercion on literals. `canonical_form_of` rewrites coerced datatypes to
        // the canonical `http://…`, which no longer match what the issuer signed.
        // Then apply RDFC-1.0 (urdna2015).
        let value: Value = json_syntax::to_value(data)
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?;

        let mut generator = generator::Blank::new();
        let quads: Vec<LexicalQuad> = RemoteDocument::new(None, None, value)
            .to_rdf(&mut generator, context.loader())
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
