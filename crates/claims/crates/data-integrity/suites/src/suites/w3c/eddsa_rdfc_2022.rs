use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::{Base58Btc, MultibaseSigning},
    suite::NoConfiguration,
    CryptosuiteStr, StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Multikey;
use static_iref::iri;

use crate::try_from_type;

/// The `eddsa-rdfc-2022` cryptosuite.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#eddsa-rdfc-2022>
#[derive(Debug, Default, Clone, Copy)]
pub struct EdDsaRdfc2022;

impl EdDsaRdfc2022 {
    pub const NAME: &'static str = "DataIntegrityProof";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#DataIntegrityProof");
}

impl StandardCryptographicSuite for EdDsaRdfc2022 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Multikey;

    type SignatureAlgorithm = MultibaseSigning<ssi_crypto::algorithm::EdDSA, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("eddsa-rdfc-2022").unwrap())
    }
}

try_from_type!(EdDsaRdfc2022);
