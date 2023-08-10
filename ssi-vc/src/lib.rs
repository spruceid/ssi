//! Verifiable Credentials Data Model v1.1 implementation.
//!
//! This library provides Rust types for the Verifiable Credentials Data Model.
//! Proof mechanism are defined as extensions of this data model.
//! The `ssi` library collection provides two proof mechanisms:
//!   - JSON Web Token, defined by the `ssi-jwt` library.
//!   - Data Integrity Proofs, defined by the `ssi-ldp` library.
use std::hash::Hash;

use iref::Iri;
use ssi_verification_methods::{VerificationError, Verifier};
use treeldr_rust_macros::tldr;
use treeldr_rust_prelude::{locspan::Meta, rdf_types::VocabularyMut};

pub mod datatype;
mod verification;
pub mod vocab;

pub use verification::*;

pub const CREDENTIALS_V1_CONTEXT_IRI: Iri<'static> =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");

#[tldr("ssi-vc/src/schema/cred.ttl", "ssi-vc/src/schema/sec.ttl")]
pub mod schema {
    #[prefix("http://www.w3.org/2002/07/owl#")]
    pub use ssi_security::schema::owl;

    #[prefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#")]
    pub use ssi_security::schema::rdf;

    #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
    pub use ssi_security::schema::rdfs;

    #[prefix("http://www.w3.org/2001/XMLSchema#")]
    pub use ssi_security::schema::xsd;

    #[prefix("https://treeldr.org/")]
    pub use ssi_security::schema::tldr;

    #[prefix("https://w3id.org/security#")]
    pub use ssi_security::schema::sec;

    #[prefix("https://www.w3.org/2018/credentials#")]
    pub mod cred {}
}

pub use schema::cred::*;

/// Verifiable credential.
pub struct Verifiable<C: VerifiableWith> {
    /// Credential.
    credential: C,

    /// Credential proof.
    proof: C::Proof,
}

impl<C: VerifiableWith> Verifiable<C> {
    pub fn new(credential: C, proof: C::Proof) -> Self {
        Self { credential, proof }
    }

    pub fn credential(&self) -> &C {
        &self.credential
    }

    pub fn proof(&self) -> &C::Proof {
        &self.proof
    }

    pub fn map<D: VerifiableWith>(
        self,
        f: impl FnOnce(C, C::Proof) -> (D, D::Proof),
    ) -> Verifiable<D> {
        let (credential, proof) = f(self.credential, self.proof);

        Verifiable { credential, proof }
    }
}

impl<C: VerifiableWith> Verifiable<C> {
    pub async fn verify(
        &self,
        verifiers: &impl Verifier<C::Method>,
    ) -> Result<ProofValidity, VerificationError> {
        self.credential.verify_with(verifiers, &self.proof).await
    }
}

impl<V: VocabularyMut, I, C: VerifiableWith + treeldr_rust_prelude::IntoJsonLdObjectMeta<V, I>>
    treeldr_rust_prelude::IntoJsonLdObjectMeta<V, I> for Verifiable<C>
where
    V::Iri: Eq + Hash,
    V::BlankId: Eq + Hash,
    C::Proof: treeldr_rust_prelude::IntoJsonLdObjectMeta<V, I>,
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: (),
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, ()> {
        let mut json_ld =
            self.credential
                .into_json_ld_object_meta(vocabulary, interpretation, meta);
        let proof = self
            .proof
            .into_json_ld_object_meta(vocabulary, interpretation, ());

        if let Some(node) = json_ld.as_node_mut() {
            node.type_entry_or_default((), ()).push(Meta(
                json_ld::Id::iri(vocabulary.insert(vocab::VERIFIABLE_CREDENTIAL)),
                (),
            ));

            node.properties_mut().insert(
                Meta(
                    json_ld::Id::Valid(json_ld::ValidId::Iri(vocabulary.insert(vocab::PROOF))),
                    (),
                ),
                proof,
            )
        }

        json_ld
    }
}
