//! `ecdsa-rdfc-2019` cryptosuite implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-rdfc-2019>
use k256::sha2::{Sha256, Sha384};
use ssi_data_integrity_core::{
    canonicalization::{
        CanonicalClaimsAndConfiguration, CanonicalizeClaimsAndConfiguration,
        HashCanonicalClaimsAndConfiguration,
    },
    signing::{AlgorithmSelection, AlgorithmSelectionError, Base58Btc, MultibaseSigning},
    suite::{
        standard::{HashingAlgorithm, HashingError},
        NoConfiguration,
    },
    ProofConfigurationRef, StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Multikey;
use static_iref::iri;

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

    type SignatureAlgorithm = MultibaseSigning<P256OrP384, Base58Btc>;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof("ecdsa-rdfc-2019")
    }
}

pub struct EcdsaRdfc2019HashingAlgorithm;

impl HashingAlgorithm<EcdsaRdfc2019> for EcdsaRdfc2019HashingAlgorithm {
    type Output = EcdsaRdfc2019Hash;

    fn hash(
        input: CanonicalClaimsAndConfiguration,
        proof_configuration: ProofConfigurationRef<EcdsaRdfc2019>,
        verification_method: &Multikey,
    ) -> Result<Self::Output, HashingError> {
        match verification_method.public_key.codec() {
            ssi_multicodec::P256_PUB => HashCanonicalClaimsAndConfiguration::<Sha256>::hash(
                input,
                proof_configuration,
                verification_method,
            )
            .map(EcdsaRdfc2019Hash::Sha256),
            ssi_multicodec::P384_PUB => HashCanonicalClaimsAndConfiguration::<Sha384>::hash(
                input,
                proof_configuration,
                verification_method,
            )
            .map(EcdsaRdfc2019Hash::Sha384),
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

pub enum P256OrP384 {
    P256,
    P384,
}

impl<O> AlgorithmSelection<Multikey, O> for P256OrP384 {
    fn select_algorithm(
        verification_method: &Multikey,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        match verification_method.public_key.codec() {
            ssi_multicodec::P256_PUB => Ok(Self::P256),
            ssi_multicodec::P384_PUB => Ok(Self::P384),
            _ => Err(AlgorithmSelectionError::InvalidKey),
        }
    }
}

impl From<P256OrP384> for ssi_jwk::Algorithm {
    fn from(value: P256OrP384) -> Self {
        match value {
            P256OrP384::P256 => Self::ES256,
            P256OrP384::P384 => Self::ES384,
        }
    }
}
