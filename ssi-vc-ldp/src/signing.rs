use rdf_types::{
    interpretation::TraversableInterpretation, BlankIdVocabularyMut, ReverseTermInterpretation,
    ReverseTermInterpretationMut,
};
use ssi_crypto::{SignatureError, Signer};
use ssi_rdf::DatasetWithEntryPoint;
use ssi_vc::Verifiable;
use std::hash::Hash;

use crate::{
    suite::{CryptographicSuiteInput, HashError, SigningParameters},
    CryptographicSuite, DataIntegrity,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing credential")]
    MissingCredentialId,

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),

    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(#[from] SignatureError),
}

impl<C: Sync, S: CryptographicSuite> DataIntegrity<C, S> {
    /// Sign the given Linked Data credential with a Data Integrity
    /// cryptographic suite.
    pub fn sign_ld<'a, V, I>(
        vocabulary: &'a mut V,
        interpretation: &'a mut I,
        signer: &impl Signer<S::VerificationMethod>,
        credential: C,
        suite: S,
        params: S::SigningParameters,
    ) -> Result<Verifiable<Self>, Error>
    where
        V: BlankIdVocabularyMut,
        I: TraversableInterpretation + ReverseTermInterpretationMut<BlankId = V::BlankId>,
        I::Resource: Eq + Hash,
        C: treeldr_rust_prelude::rdf::Quads<V, I>,
        S: CryptographicSuiteInput<DatasetWithEntryPoint<'a, V, I>>,
    {
        // Convert the `credential` to an RDF dataset.
        let (entry_point, quads) = credential.rdf_quads(vocabulary, interpretation, None);
        let dataset = quads.collect();

        // Assign a term to all resources.
        let mut generator =
            rdf_types::generator::Blank::new_with_prefix("_ssi-vc-ldp_".to_string());
        interpretation.assign_terms(|interpretation, id| {
            if interpretation.has_term(id) {
                None
            } else {
                Some(rdf_types::Term::Id(rdf_types::Id::Blank(
                    vocabulary.insert_owned_blank_id(generator.next_blank_id()),
                )))
            }
        });

        // Prepare the dataset for the crypto suite.
        let data = DatasetWithEntryPoint {
            vocabulary,
            interpretation,
            dataset,
            entry_point: entry_point.ok_or(Error::MissingCredentialId)?,
        };

        // Apply the crypto suite.
        let transformed = suite.transform(data, params.transformation_parameters());
        let hash = suite.hash(transformed, params.hash_parameters())?;
        let proof = suite.generate_proof(&hash, signer, params.into_proof_parameters())?;

        Ok(Verifiable::new(
            Self::new(credential, hash),
            proof.into_typed(suite),
        ))
    }
}
