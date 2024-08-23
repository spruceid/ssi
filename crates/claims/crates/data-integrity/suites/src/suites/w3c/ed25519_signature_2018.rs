use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsSigning,
    suite::NoConfiguration,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Ed25519VerificationKey2018;
use static_iref::iri;

use crate::try_from_type;

/// Ed25519 Signature 2018.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2018;

impl Ed25519Signature2018 {
    pub const NAME: &'static str = "Ed25519Signature2018";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Ed25519Signature2018");
}

impl StandardCryptographicSuite for Ed25519Signature2018 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Ed25519VerificationKey2018;

    type SignatureAlgorithm = DetachedJwsSigning<ssi_crypto::algorithm::EdDSA>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(Ed25519Signature2018);
