use iref::Iri;
use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsSigning,
    suite::AddProofContext,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::EcdsaSecp256k1RecoveryMethod2020;
use static_iref::iri;

use crate::try_from_type;

/// `EcdsaSecp256k1RecoverySignature2020`.
///
/// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaSecp256k1RecoverySignature2020;

impl EcdsaSecp256k1RecoverySignature2020 {
    pub const NAME: &'static str = "EcdsaSecp256k1RecoverySignature2020";

    pub const IRI: &'static Iri = iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoverySignature2020");
}

impl StandardCryptographicSuite for EcdsaSecp256k1RecoverySignature2020 {
    type Configuration = AddProofContext<Secp256k1Recovery2020v2Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = EcdsaSecp256k1RecoveryMethod2020;

    type SignatureAlgorithm = DetachedJwsSigning<ssi_crypto::algorithm::ES256KR>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EcdsaSecp256k1RecoverySignature2020);

#[derive(Default)]
pub struct Secp256k1Recovery2020v2Context;

impl From<Secp256k1Recovery2020v2Context> for ssi_json_ld::syntax::Context {
    fn from(_: Secp256k1Recovery2020v2Context) -> Self {
        iri!("https://w3id.org/security/suites/secp256k1recovery-2020/v2").into()
    }
}
