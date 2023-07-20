//! Cryptographic suites.
use async_trait::async_trait;
use iref::Iri;
use ssi_crypto::{SignatureError, Signer, VerificationError, Verifier};
use ssi_vc::ProofValidity;

use crate::Proof;

mod dif;
mod unspecified;

#[cfg(feature = "w3c")]
mod w3c;

pub use dif::*;
pub use unspecified::*;

#[cfg(feature = "w3c")]
pub use w3c::*;

pub struct TransformationOptions<T> {
    pub type_: T,
}

/// Cryptographic suite.
#[async_trait]
pub trait CryptographicSuite: Sync + Sized {
    /// Transformation algorithm parameters.
    type TransformationParameters;

    /// Transformation algorithm result.
    type Transformed;

    /// Hashing algorithm parameters.
    type HashParameters;

    /// Hashing algorithm result.
    type Hashed: Sync;

    /// Proof generation algorithm parameters.
    type ProofParameters;

    type SigningParameters: SigningParameters<
        Self::TransformationParameters,
        Self::HashParameters,
        Self::ProofParameters,
    >;

    /// Combination of transformation parameters and hash parameters that can
    /// be used to verify a credential.
    type VerificationParameters: VerificationParameters<
        Self::TransformationParameters,
        Self::HashParameters,
    >;

    type VerificationMethod: Sync;

    fn iri(&self) -> Iri;

    fn cryptographic_suite(&self) -> Option<&str>;

    /// Hashing algorithm.
    fn hash(&self, data: Self::Transformed, params: Self::HashParameters) -> Self::Hashed;

    fn generate_proof(
        &self,
        data: &Self::Hashed,
        signer: &impl Signer<Self::VerificationMethod>,
        params: Self::ProofParameters,
    ) -> Result<Proof<Self>, SignatureError>;

    async fn verify_proof(
        &self,
        data: &Self::Hashed,
        verifier: &impl Verifier<Self::VerificationMethod>,
        proof: &Proof<Self>,
    ) -> Result<ProofValidity, VerificationError>;
}

pub trait CryptographicSuiteInput<T>: CryptographicSuite {
    /// Transformation algorithm.
    fn transform(&self, data: T, params: Self::TransformationParameters) -> Self::Transformed;
}

pub trait SigningParameters<T, H, P> {
    fn transformation_parameters(&self) -> T;

    fn hash_parameters(&self) -> H;

    fn into_proof_parameters(self) -> P;
}

pub trait VerificationParameters<T, H> {
    fn transformation_parameters(&self) -> T;

    fn into_hash_parameters(self) -> H;
}

/// Built-in Data Integrity cryptographic suites types.
pub enum SuiteType {
    /// W3C RSA Signature Suite 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-rsa2018/>
    #[cfg(all(feature = "w3c", feature = "rsa"))]
    RsaSignature2018,

    /// W3C Ed25519 Signature 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    Ed25519Signature2018,

    /// W3C Ed25519 Signature 2020.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    Ed25519Signature2020,

    /// W3C EdDSA Cryptosuite v2022.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    EdDsa2022,

    /// W3C Ecdsa Secp256k1 Signature 2019.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
    #[cfg(all(feature = "w3c", feature = "secp256k1"))]
    EcdsaSecp256k1Signature2019,

    /// DIF Ecdsa Secp256k1 Recovery Signature 2019.
    ///
    /// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
    #[cfg(all(feature = "w3c", feature = "secp256k1"))]
    EcdsaSecp256k1RecoverySignature2020,

    /// W3C Ecdsa Secp256r1 Signature 2019.
    ///
    /// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
    #[cfg(all(feature = "w3c", feature = "secp256r1"))]
    EcdsaSecp256r1Signature2019,

    /// W3C JSON Web Signature 2020.
    ///
    /// See: <https://w3c-ccg.github.io/lds-jws2020/>
    #[cfg(feature = "w3c")]
    JsonWebSignature2020,

    /// W3C Ethereum EIP712 Signature 2021.
    ///
    /// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
    #[cfg(all(feature = "w3c", feature = "eip"))]
    EthereumEip712Signature2021,

    /// Unspecified Ethereum Personal Signature 2021.
    #[cfg(feature = "eip")]
    EthereumPersonalSignature2021,

    /// Unspecified Eip712 Signature 2021.
    #[cfg(feature = "eip")]
    Eip712Signature2021,

    /// Unspecified Ed25519 BLAKE2B Digest Size 20 Base58 Check Encoded Signature 2021.
    #[cfg(feature = "tezos")]
    Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified P256 BLAKE2B Digest Size 20 Base58 Check Encoded Signature 2021.
    #[cfg(feature = "tezos")]
    P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,

    /// Unspecified Tezos Signature 2021.
    #[cfg(feature = "tezos")]
    TezosSignature2021,

    /// Unspecified Tezos Jcs Signature 2021.
    #[cfg(feature = "tezos")]
    TezosJcsSignature2021,

    /// Unspecified Solana Signature 2021.
    #[cfg(feature = "solana")]
    SolanaSignature2021,

    /// Unspecified Aleo Signature 2021.
    #[cfg(feature = "aleo")]
    AleoSignature2021,

    /// Unknown suite type.
    Unknown(String),
}

pub enum Suite {
    /// W3C Ed25519 Signature 2018.
    ///
    /// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    Ed25519Signature2018,

    /// W3C Ed25519 Signature 2020.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    Ed25519Signature2020,

    /// W3C EdDSA Cryptosuite v2022.
    ///
    /// See: <https://w3c.github.io/vc-di-eddsa/>
    #[cfg(all(feature = "w3c", feature = "ed25519"))]
    EdDsa2022,
}
