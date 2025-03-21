use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsSigning,
    suite::NoConfiguration,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::EcdsaSecp256k1VerificationKey2019;
use static_iref::iri;

use crate::try_from_type;

/// Ecdsa Secp256k1 Signature 2019.
///
/// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaSecp256k1Signature2019;

impl EcdsaSecp256k1Signature2019 {
    pub const NAME: &'static str = "EcdsaSecp256k1Signature2019";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EcdsaSecp256k1Signature2019");
}

impl StandardCryptographicSuite for EcdsaSecp256k1Signature2019 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = EcdsaSecp256k1VerificationKey2019;

    type SignatureAlgorithm = DetachedJwsSigning<ssi_crypto::algorithm::ES256K>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EcdsaSecp256k1Signature2019);
