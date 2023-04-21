//! Verifiable Credentials Data Model v1.1 implementation.
//!
//! This library provides Rust types for the Verifiable Credentials Data Model.
//! Proof mechanism are defined as extensions of this data model.
//! The `ssi` library collection provides two proof mechanisms:
//!   - JSON Web Token, defined by the `ssi-jwt` library.
//!   - Data Integrity Proofs, defined by the `ssi-ldp` library.
use treeldr_rust_macros::tldr;

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
use treeldr_rust_prelude::locspan::Meta;

pub trait AttachProof<P>: Sized {
    fn with_proof(self, proof: P) -> Verifiable<Self, P> {
        Verifiable::new(self, proof)
    }
}

impl<C, P> AttachProof<P> for C {}

/// Linked Data Credential with proof.
pub struct Verifiable<C, P> {
    credential: C,
    proof: P,
}

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
}

impl<N, C: treeldr_rust_prelude::IntoJsonLd<N>, P: treeldr_rust_prelude::IntoJsonLd<N>>
    treeldr_rust_prelude::IntoJsonLd<N> for Verifiable<C, P>
{
    fn into_json_ld(self, namespace: &N) -> json_ld::syntax::Value<()> {
        let mut json_ld = self.credential.into_json_ld(namespace);
        let proof = self.proof.into_json_ld(namespace);
        json_ld
            .as_object_mut()
            .unwrap()
            .insert(Meta("proof".into(), ()), Meta(proof, ()));
        json_ld
    }
}
