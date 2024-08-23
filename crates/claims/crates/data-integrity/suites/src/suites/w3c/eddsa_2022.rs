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

/// The `eddsa-2022` cryptosuite, a draft version of the `eddsa-rdfc-2022`
/// cryptosuite.
///
/// This is only provided for compatibility with applications based on the
/// EDDSA cryptosuite draft.
///
/// See: <https://www.w3.org/TR/2023/WD-vc-di-eddsa-20230714/#eddsa-2022>
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

    type SignatureAlgorithm = MultibaseSigning<ssi_crypto::algorithm::EdDSA, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("eddsa-2022").unwrap())
    }
}

try_from_type!(EdDsa2022);
