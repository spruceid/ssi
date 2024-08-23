//! `ecdsa-rdfc-2019` cryptosuite implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019>
use ssi_crypto::algorithm::ES256OrES384;
use ssi_data_integrity_core::{
    canonicalization::{
        CanonicalClaimsAndConfiguration, CanonicalizeClaimsAndConfiguration,
        HashCanonicalClaimsAndConfiguration,
    },
    signing::{Base58Btc, MultibaseSigning},
    suite::{
        standard::{HashingAlgorithm, HashingError},
        NoConfiguration,
    },
    CryptosuiteStr, ProofConfigurationRef, StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::{multikey::DecodedMultikey, Multikey};
use static_iref::iri;

use crate::try_from_type;

/// The `ecdsa-rdfc-2019` cryptosuite.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019>
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaRdfc2019;

impl EcdsaRdfc2019 {
    pub const NAME: &'static str = "DataIntegrityProof";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#DataIntegrityProof");
}

impl StandardCryptographicSuite for EcdsaRdfc2019 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = EcdsaRdfc2019HashingAlgorithm;

    type VerificationMethod = Multikey;

    type SignatureAlgorithm = MultibaseSigning<ES256OrES384, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("ecdsa-rdfc-2019").unwrap())
    }
}

try_from_type!(EcdsaRdfc2019);

pub struct EcdsaRdfc2019HashingAlgorithm;

impl HashingAlgorithm<EcdsaRdfc2019> for EcdsaRdfc2019HashingAlgorithm {
    type Output = EcdsaRdfc2019Hash;

    fn hash(
        input: CanonicalClaimsAndConfiguration,
        proof_configuration: ProofConfigurationRef<EcdsaRdfc2019>,
        verification_method: &Multikey,
    ) -> Result<Self::Output, HashingError> {
        match verification_method
            .public_key
            .decode()
            .map_err(|_| HashingError::InvalidKey)?
        {
            #[cfg(feature = "secp256r1")]
            DecodedMultikey::P256(_) => {
                HashCanonicalClaimsAndConfiguration::<k256::sha2::Sha256>::hash(
                    input,
                    proof_configuration,
                    verification_method,
                )
                .map(EcdsaRdfc2019Hash::Sha256)
            }
            #[cfg(feature = "secp384r1")]
            DecodedMultikey::P384(_) => {
                HashCanonicalClaimsAndConfiguration::<k256::sha2::Sha384>::hash(
                    input,
                    proof_configuration,
                    verification_method,
                )
                .map(EcdsaRdfc2019Hash::Sha384)
            }
            _ => Err(HashingError::InvalidKey),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EcdsaRdfc2019Hash {
    Sha256([u8; 64]),
    Sha384([u8; 96]),
}

impl AsRef<[u8]> for EcdsaRdfc2019Hash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha256(b) => b.as_ref(),
            Self::Sha384(b) => b.as_ref(),
        }
    }
}
