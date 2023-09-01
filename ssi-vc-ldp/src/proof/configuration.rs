use iref::Iri;
use linked_data::{LinkedData, LinkedDataPredicateObjects};
use rdf_types::Quad;
use serde::{Deserialize, Serialize};
use ssi_verification_methods::{ProofPurpose, Referencable, ReferenceOrOwned, ReferenceOrOwnedRef};
use static_iref::iri;

use crate::{CryptographicSuite, UntypedProof};

pub const DC_CREATED_IRI: &Iri = iri!("http://purl.org/dc/terms/created");

pub const XSD_DATETIME_IRI: &Iri = iri!("http://www.w3.org/2001/XMLSchema#dateTime");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofConfiguration<M> {
    pub created: xsd_types::DateTime,
    pub verification_method: ReferenceOrOwned<M>,
    pub proof_purpose: ProofPurpose,
}

impl<M> ProofConfiguration<M> {
    pub fn new(
        created: xsd_types::DateTime,
        verification_method: ReferenceOrOwned<M>,
        proof_purpose: ProofPurpose,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
        }
    }

    pub fn into_proof<S>(self, signature: S) -> UntypedProof<M, S> {
        UntypedProof::from_options(self, signature)
    }

    pub fn borrowed(&self) -> ProofConfigurationRef<M>
    where
        M: Referencable,
    {
        ProofConfigurationRef {
            created: &self.created,
            verification_method: self.verification_method.borrowed(),
            proof_purpose: self.proof_purpose,
        }
    }
}

#[derive(LinkedData)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct ProofConfigurationWithSuiteRef<'a, 'b, M: Referencable> {
    #[ld(type)]
    pub type_: &'b Iri,

    #[ld("sec:cryptosuite")]
    pub cryptosuite: Option<&'b str>,

    #[ld("sec:created")]
    pub created: &'a xsd_types::DateTime,

    #[ld("sec:verificationMethod")]
    pub verification_method: ReferenceOrOwnedRef<'a, M>,

    #[ld("sec:proofPurpose")]
    pub proof_purpose: ProofPurpose,
}

#[derive(Serialize)]
#[serde(
    rename_all = "camelCase",
    bound(serialize = "M::Reference<'a>: Serialize")
)]
pub struct ProofConfigurationRef<'a, M: Referencable> {
    pub created: &'a xsd_types::DateTime,
    pub verification_method: ReferenceOrOwnedRef<'a, M>,
    pub proof_purpose: ProofPurpose,
}

impl<'a, M: Referencable> ProofConfigurationRef<'a, M> {
    pub fn new(
        created: &'a xsd_types::DateTime,
        verification_method: ReferenceOrOwnedRef<'a, M>,
        proof_purpose: ProofPurpose,
    ) -> Self {
        Self {
            created,
            verification_method,
            proof_purpose,
        }
    }

    pub fn try_map_verification_method<N: 'a + Referencable, E>(
        self,
        f: impl FnOnce(ReferenceOrOwnedRef<'a, M>) -> Result<ReferenceOrOwnedRef<'a, N>, E>,
    ) -> Result<ProofConfigurationRef<'a, N>, E> {
        let verification_method = f(self.verification_method)?;

        Ok(ProofConfigurationRef::new(
            self.created,
            verification_method,
            self.proof_purpose,
        ))
    }

    pub fn map_verification_method<N: 'a + Referencable>(
        self,
        f: impl FnOnce(ReferenceOrOwnedRef<'a, M>) -> ReferenceOrOwnedRef<'a, N>,
    ) -> ProofConfigurationRef<'a, N> {
        let verification_method = f(self.verification_method);

        ProofConfigurationRef::new(self.created, verification_method, self.proof_purpose)
    }

    pub fn try_cast_verification_method<N: 'a + Referencable>(
        self,
    ) -> Result<ProofConfigurationRef<'a, N>, <M::Reference<'a> as TryInto<N::Reference<'a>>>::Error>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>>,
    {
        self.try_map_verification_method(|m| Ok(m.try_cast()?))
    }

    pub fn with_suite<'b, T: CryptographicSuite>(
        &self,
        suite: &'b T,
    ) -> ProofConfigurationWithSuiteRef<'a, 'b, M> {
        ProofConfigurationWithSuiteRef {
            type_: suite.iri(),
            cryptosuite: suite.cryptographic_suite(),
            created: self.created,
            verification_method: self.verification_method,
            proof_purpose: self.proof_purpose,
        }
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads<T: CryptographicSuite>(&self, suite: &T) -> Vec<Quad>
    where
        M::Reference<'a>: LinkedDataPredicateObjects,
    {
        let generator =
            rdf_types::generator::Blank::new_with_prefix("proofConfiguration:".to_string());
        let quads = linked_data::to_quads(generator, &self.with_suite(suite)).unwrap();
        ssi_rdf::urdna2015::normalize(quads.iter().map(Quad::as_quad_ref)).collect()
    }
}

impl<'a, M: Referencable> Clone for ProofConfigurationRef<'a, M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, M: Referencable> Copy for ProofConfigurationRef<'a, M> {}
