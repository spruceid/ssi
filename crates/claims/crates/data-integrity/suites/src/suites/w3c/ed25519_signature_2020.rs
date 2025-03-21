//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use k256::sha2::Sha256;
use lazy_static::lazy_static;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::{Base58Btc, MultibaseSigning},
    suite::AddProofContext,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Ed25519VerificationKey2020;
use static_iref::{iri, iri_ref};

use crate::try_from_type;

lazy_static! {
    static ref PROOF_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
        ssi_json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://w3id.org/security/suites/ed25519-2020/v1").to_owned(),
        )
    };
}

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2020;

impl Ed25519Signature2020 {
    pub const NAME: &'static str = "Ed25519Signature2020";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Ed25519Signature2020");
}

#[derive(Default)]
pub struct Ed25519Signature2020v1Context;

impl From<Ed25519Signature2020v1Context> for ssi_json_ld::syntax::Context {
    fn from(_: Ed25519Signature2020v1Context) -> Self {
        ssi_json_ld::syntax::Context::One(PROOF_CONTEXT.clone())
    }
}

impl StandardCryptographicSuite for Ed25519Signature2020 {
    type Configuration = AddProofContext<Ed25519Signature2020v1Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Ed25519VerificationKey2020;

    type SignatureAlgorithm = MultibaseSigning<ssi_crypto::algorithm::EdDSA, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(Ed25519Signature2020);
