use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsSigning,
    suite::NoConfiguration,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::EcdsaSecp256r1VerificationKey2019;
use static_iref::iri;

use crate::try_from_type;

/// ECDSA Cryptosuite v2019 `EcdsaSecp256r1Signature2019`.
///
/// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaSecp256r1Signature2019;

impl EcdsaSecp256r1Signature2019 {
    pub const NAME: &'static str = "EcdsaSecp256r1Signature2019";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EcdsaSecp256r1Signature2019");
}

impl StandardCryptographicSuite for EcdsaSecp256r1Signature2019 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = EcdsaSecp256r1VerificationKey2019;

    type SignatureAlgorithm = DetachedJwsSigning<ssi_crypto::algorithm::ES256>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EcdsaSecp256r1Signature2019);
