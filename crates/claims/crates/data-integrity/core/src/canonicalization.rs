use digest::Digest;
use std::marker::PhantomData;

use linked_data::LinkedData;
use rdf_types::{
    interpretation::{
        ReverseBlankIdInterpretation, ReverseIriInterpretation, ReverseLiteralInterpretation,
    },
    InterpretationMut, Vocabulary,
};
use ssi_json_ld::JsonLdNodeObject;
use ssi_rdf::{AnyLdEnvironment, Expandable};

use crate::{
    hashing::ConcatOutputSize,
    suite::standard::{self, HashingAlgorithm, TransformationAlgorithm, TransformationError},
    ConfigurationExpandingEnvironment, CryptographicSuite, ProofConfigurationRef,
    SerializeCryptographicSuite, StandardCryptographicSuite,
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

impl<S, T, C, I, V> standard::TypedTransformationAlgorithm<S, T, C>
    for CanonicalizeClaimsAndConfiguration
where
    S: SerializeCryptographicSuite,
    T: Expandable<C> + JsonLdNodeObject,
    T::Expanded: LinkedData<I, V>,
    C: AnyLdEnvironment<Vocabulary = V, Interpretation = I> + ConfigurationExpandingEnvironment,
    V: Vocabulary,
    I: InterpretationMut<V>
        + ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
{
    async fn transform(
        context: &mut C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Output, TransformationError> {
        let expanded = data
            .expand(context)
            .await
            .map_err(|e| TransformationError::JsonLdExpansion(e.to_string()))?;

        Ok(CanonicalClaimsAndConfiguration {
            claims: context
                .canonical_form_of(&expanded)
                .map_err(TransformationError::JsonLdDeserialization)?,
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
