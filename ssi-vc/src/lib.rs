//! Verifiable Credentials Data Model v1.1 implementation.
//!
//! This library provides Rust types for the Verifiable Credentials Data Model.
//! Proof mechanism are defined as extensions of this data model.
//! The `ssi` library collection provides two proof mechanisms:
//!   - JSON Web Token, defined by the `ssi-jwt` library.
//!   - Data Integrity Proofs, defined by the `ssi-ldp` library.
use iref::Iri;
use linked_data::LinkedData;
use ssi_verification_methods::{VerificationError, Verifier};

pub mod datatype;
mod verification;
pub mod vocab;

pub use verification::*;

pub const CREDENTIALS_V1_CONTEXT_IRI: &Iri =
    static_iref::iri!("https://www.w3.org/2018/credentials/v1");

// #[tldr("ssi-vc/src/schema/cred.ttl", "ssi-vc/src/schema/sec.ttl")]
// pub mod schema {
//     #[prefix("http://www.w3.org/2002/07/owl#")]
//     pub use ssi_security::schema::owl;

//     #[prefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#")]
//     pub use ssi_security::schema::rdf;

//     #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
//     pub use ssi_security::schema::rdfs;

//     #[prefix("http://www.w3.org/2001/XMLSchema#")]
//     pub use ssi_security::schema::xsd;

//     #[prefix("https://treeldr.org/")]
//     pub use ssi_security::schema::tldr;

//     #[prefix("https://w3id.org/security#")]
//     pub use ssi_security::schema::sec;

//     #[prefix("https://www.w3.org/2018/credentials#")]
//     pub mod cred {}
// }

// pub use schema::cred::*;

/// Verifiable credential.
#[derive(LinkedData)]
pub struct Verifiable<C: VerifiableWith> {
    /// Credential.
    #[ld(flatten)]
    credential: C,

    /// Credential proof.
    #[ld("sec:proof")]
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
