use iref::Iri;
use linked_data::{LinkedData, LinkedDataPredicateObjects, LinkedDataSubject};
use rdf_types::Quad;
use serde::{Deserialize, Serialize};
use ssi_verification_methods::{ProofPurpose, Referencable, ReferenceOrOwned, ReferenceOrOwnedRef};
use static_iref::iri;

use crate::{CryptographicSuite, UntypedProof};

pub const DC_CREATED_IRI: &Iri = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: &Iri = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofConfiguration<M, O = ()> {
    /// Date a creation of the proof.
    pub created: xsd_types::DateTime,

    /// Verification method.
    pub verification_method: ReferenceOrOwned<M>,

    /// Purpose of the proof.
    pub proof_purpose: ProofPurpose,

    /// Additional proof options required by the cryptographic suite.
    ///
    /// For instance, tezos cryptosuites requires the public key associated with
    /// the verification method, which is a blockchain account id.
    pub options: O,
}

impl<M, O> ProofConfiguration<M, O> {
    pub fn new(
        created: xsd_types::DateTime,
        verification_method: ReferenceOrOwned<M>,
        proof_purpose: ProofPurpose,
        options: O,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            options,
        }
    }

    pub fn into_proof<S>(self, signature: S) -> UntypedProof<M, O, S> {
        UntypedProof::from_configuration(self, signature)
    }

    pub fn borrowed(&self) -> ProofConfigurationRef<M, O>
    where
        M: Referencable,
        O: Referencable,
    {
        ProofConfigurationRef {
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
            options: self.options.as_reference(),
        }
    }
}

#[derive(LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(prefix("dc" = "http://purl.org/dc/terms/"))]
pub struct ProofConfigurationWithSuiteRef<'a, 'b, M: Referencable, O: 'a + Referencable> {
    #[ld(type)]
    pub type_: &'b Iri,

    #[ld("sec:cryptosuite")]
    pub cryptosuite: Option<&'b str>,

    #[ld("dc:created")]
    pub created: &'a xsd_types::DateTime,

    #[ld("sec:verificationMethod")]
    pub verification_method: ReferenceOrOwnedRef<'a, M>,

    #[ld("sec:proofPurpose")]
    pub proof_purpose: ProofPurpose,

    #[ld(flatten)]
    pub options: O::Reference<'a>,
}

#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    bound(serialize = "M::Reference<'a>: Serialize, O::Reference<'a>: Serialize")
)]
pub struct ProofConfigurationRef<'a, M: Referencable, O: 'a + Referencable = ()> {
    pub created: &'a xsd_types::DateTime,
    pub verification_method: ReferenceOrOwnedRef<'a, M>,
    pub proof_purpose: ProofPurpose,
    pub options: O::Reference<'a>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProofConfigurationCastError {
    #[error("invalid verification method")]
    VerificationMethod,

    #[error("invalid options")]
    Options,
}

impl<'a, M: Referencable, O: Referencable> ProofConfigurationRef<'a, M, O> {
    pub fn new(
        created: &'a xsd_types::DateTime,
        verification_method: ReferenceOrOwnedRef<'a, M>,
        proof_purpose: ProofPurpose,
        options: O::Reference<'a>,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
            options,
        }
    }

    pub fn try_map_verification_method<N: 'a + Referencable, P: 'a + Referencable, E>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> Result<(ReferenceOrOwnedRef<'a, N>, P::Reference<'a>), E>,
    ) -> Result<ProofConfigurationRef<'a, N, P>, E> {
        let (verification_method, options) = f(self.verification_method, self.options)?;

        Ok(ProofConfigurationRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
            options,
        ))
    }

    pub fn map_verification_method<N: 'a + Referencable, P: 'a + Referencable>(
        self,
        f: impl FnOnce(
            ReferenceOrOwnedRef<'a, M>,
            O::Reference<'a>,
        ) -> (ReferenceOrOwnedRef<'a, N>, P::Reference<'a>),
    ) -> ProofConfigurationRef<'a, N, P> {
        let (verification_method, options) = f(self.verification_method, self.options);
        ProofConfigurationRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
            options,
        )
    }

    pub fn try_cast_verification_method<N: 'a + Referencable, P: 'a + Referencable>(
        self,
    ) -> Result<ProofConfigurationRef<'a, N, P>, ProofConfigurationCastError>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>>,
        O::Reference<'a>: TryInto<P::Reference<'a>>,
    {
        self.try_map_verification_method(|m, options| {
            let m = m
                .try_cast()
                .map_err(|_| ProofConfigurationCastError::VerificationMethod)?;
            let options = options
                .try_into()
                .map_err(|_| ProofConfigurationCastError::Options)?;
            Ok((m, options))
        })
    }

    pub fn with_suite<'b, T: CryptographicSuite>(
        &self,
        suite: &'b T,
    ) -> ProofConfigurationWithSuiteRef<'a, 'b, M, O> {
        ProofConfigurationWithSuiteRef {
            type_: suite.iri(),
            cryptosuite: suite.cryptographic_suite(),
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
            options: self.options,
        }
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads<T: CryptographicSuite>(&self, suite: &T) -> Vec<Quad>
    where
        M::Reference<'a>: LinkedDataPredicateObjects,
        O::Reference<'a>: LinkedDataSubject,
    {
        let generator =
            rdf_types::generator::Blank::new_with_prefix("proofConfiguration:".to_string());
        let quads = linked_data::to_quads(generator, &self.with_suite(suite)).unwrap();
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_quad_ref)).collect()
    }
}

impl<'a, M: Referencable, O: 'a + Referencable> Clone for ProofConfigurationRef<'a, M, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, M: Referencable, O: 'a + Referencable> Copy for ProofConfigurationRef<'a, M, O> {}
