//! EdDSA Cryptosuite v2022 implementation.
//!
//! This is the successor of the EdDSA Cryptosuite v2020.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/>
use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::{Base58Btc, MultibaseSigning},
    suite::NoConfiguration,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Multikey;
use static_iref::iri;

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct EdDsa2022;

impl EdDsa2022 {
    pub const NAME: &'static str = "DataIntegrityProof";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#DataIntegrityProof");
}

impl StandardCryptographicSuite for EdDsa2022 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Multikey;

    type SignatureAlgorithm = MultibaseSigning<ssi_jwk::algorithm::EdDSA, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof("eddsa-2022")
    }
}
