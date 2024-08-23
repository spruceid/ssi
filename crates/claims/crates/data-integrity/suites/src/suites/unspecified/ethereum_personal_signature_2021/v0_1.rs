use super::{EthereumWalletSigning, VerificationMethod, EPSIG_CONTEXT};
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, ConcatCanonicalClaimsAndConfiguration},
    suite::AddProofContext,
    StandardCryptographicSuite, TypeRef,
};
use static_iref::iri;

use crate::try_from_type;

#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumPersonalSignature2021v0_1;

impl EthereumPersonalSignature2021v0_1 {
    pub const NAME: &'static str = "EthereumPersonalSignature2021";

    pub const IRI: &'static iref::Iri =
        iri!("https://demo.spruceid.com/ld/epsig/EthereumPersonalSignature2021");
}

impl StandardCryptographicSuite for EthereumPersonalSignature2021v0_1 {
    type Configuration = AddProofContext<EthereumPersonalSignature2021v0_1Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = ConcatCanonicalClaimsAndConfiguration;

    type VerificationMethod = VerificationMethod;

    type SignatureAlgorithm = EthereumWalletSigning;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EthereumPersonalSignature2021v0_1);

#[derive(Default)]
pub struct EthereumPersonalSignature2021v0_1Context;

impl From<EthereumPersonalSignature2021v0_1Context> for ssi_json_ld::syntax::Context {
    fn from(_: EthereumPersonalSignature2021v0_1Context) -> Self {
        ssi_json_ld::syntax::Context::One(EPSIG_CONTEXT.clone())
    }
}
