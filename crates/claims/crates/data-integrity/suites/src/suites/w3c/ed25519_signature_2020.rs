//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::{Base58Btc, MultibaseSigning},
    suite::NoConfiguration,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Ed25519VerificationKey2020;
use static_iref::iri;

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

impl StandardCryptographicSuite for Ed25519Signature2020 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Ed25519VerificationKey2020;

    type SignatureAlgorithm = MultibaseSigning<ssi_jwk::algorithm::EdDSA, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}
