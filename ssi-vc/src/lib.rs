//! Verifiable Credentials Data Model v1.1 implementation.
//!
//! This library provides Rust types for the Verifiable Credentials Data Model.
//! Proof mechanism are defined as extensions of this data model.
//! The `ssi` library collection provides two proof mechanisms:
//!   - JSON Web Token, defined by the `ssi-jwt` library.
//!   - Data Integrity Proofs, defined by the `ssi-ldp` library.
use std::hash::Hash;

use iref::Iri;
use ssi_crypto::VerifierProvider;
use treeldr_rust_macros::tldr;
use treeldr_rust_prelude::{
    locspan::Meta,
    rdf_types::{IntoId, Namespace, VocabularyMut},
};

pub mod datatype;
pub mod decode;
mod verification;

pub use decode::Decoder;
pub use verification::*;

#[tldr("ssi-vc/src/schema.ttl")]
pub mod schema {
    #[prefix("https://treeldr.org/")]
    pub mod tldr {}

    #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
    pub mod rdfs {}

    #[prefix("http://www.w3.org/2001/XMLSchema#")]
    pub mod xsd {}

    #[prefix("https://www.w3.org/2018/credentials#")]
    pub mod cred {}
}

pub use schema::cred::*;

pub trait AttachProof<P>: Sized {
    fn with_proof(self, proof: P) -> Verifiable<Self, P> {
        Verifiable::new(self, proof)
    }
}

impl<C, P> AttachProof<P> for C {}

/// Verifiable credential.
pub struct Verifiable<C, P> {
    /// Credential.
    credential: C,

    /// Credential proof.
    proof: P,
}

const VERIFIABLE_CREDENTIAL_IRI: Iri<'static> =
    static_iref::iri!("https://www.w3.org/2018/credentials#VerifiableCredential");
const PROOF_IRI: Iri<'static> = static_iref::iri!("https://w3id.org/security#proof");
const PROOF_VALUE_IRI: Iri<'static> = static_iref::iri!("https://w3id.org/security#proofValue");

impl<C, P> Verifiable<C, P> {
    pub fn new(credential: C, proof: P) -> Self {
        Self { credential, proof }
    }

    pub fn credential(&self) -> &C {
        &self.credential
    }

    pub fn proof(&self) -> &P {
        &self.proof
    }

    pub fn map<D>(self, f: impl FnOnce(C) -> D) -> Verifiable<D, P> {
        Verifiable {
            credential: f(self.credential),
            proof: self.proof,
        }
    }
}

impl<C: VerifiableWith<P>, P> Verifiable<C, P> {
    pub fn verify(
        &self,
        context: &mut impl verification::Context<C, P>,
        verifiers: &impl VerifierProvider<C::Method>,
        parameters: C::Parameters,
    ) -> Result<ProofValidity, C::Error> {
        self.credential
            .verify_with(context, verifiers, &self.proof, parameters)
    }
}

impl<
        N: VocabularyMut,
        C: treeldr_rust_prelude::IntoJsonLdObjectMeta<N>,
        P: treeldr_rust_prelude::IntoJsonLdObjectMeta<N>,
    > treeldr_rust_prelude::IntoJsonLdObjectMeta<N> for Verifiable<C, P>
where
    N: Namespace,
    N::Id: IntoId<Iri = N::Iri, BlankId = N::BlankId>,
    N::Iri: Eq + Hash,
    N::BlankId: Eq + Hash,
{
    fn into_json_ld_object_meta(
        self,
        namespace: &mut N,
        meta: (),
    ) -> json_ld::IndexedObject<N::Iri, N::BlankId, ()> {
        let mut json_ld = self.credential.into_json_ld_object_meta(namespace, meta);
        let proof = self.proof.into_json_ld_object_meta(namespace, ());

        if let Some(node) = json_ld.as_node_mut() {
            node.type_entry_or_default((), ()).push(Meta(
                json_ld::Id::iri(namespace.insert(VERIFIABLE_CREDENTIAL_IRI)),
                (),
            ));

            node.properties_mut().insert(
                Meta(
                    json_ld::Id::Valid(json_ld::ValidId::Iri(namespace.insert(PROOF_IRI))),
                    (),
                ),
                proof,
            )
        }

        json_ld
    }
}
