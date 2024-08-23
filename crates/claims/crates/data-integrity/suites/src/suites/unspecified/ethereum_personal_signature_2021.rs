use serde::{Deserialize, Serialize};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, ConcatCanonicalClaimsAndConfiguration},
    suite::{
        standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm},
        AddProofContext,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_jwk::JWK;
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020::DigestFunction,
    ecdsa_secp_256k1_verification_key_2019,
    protocol::{EthereumWallet, WithProtocol},
    verification_method_union, AnyMethod, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, InvalidVerificationMethod, MessageSigner,
};
use static_iref::iri;

use crate::try_from_type;

mod v0_1;
pub use v0_1::*;

lazy_static::lazy_static! {
    pub static ref EPSIG_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
        let context_str = ssi_contexts::EPSIG_V0_1;
        serde_json::from_str(context_str).unwrap()
    };
}

/// Ethereum Personal Signature 2021.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumPersonalSignature2021;

impl EthereumPersonalSignature2021 {
    pub const NAME: &'static str = "EthereumPersonalSignature2021";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EthereumPersonalSignature2021");
}

impl StandardCryptographicSuite for EthereumPersonalSignature2021 {
    type Configuration = AddProofContext<EthereumPersonalSignature2021Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = ConcatCanonicalClaimsAndConfiguration;

    type VerificationMethod = VerificationMethod;

    type SignatureAlgorithm = EthereumWalletSigning;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EthereumPersonalSignature2021);

#[derive(Default)]
pub struct EthereumPersonalSignature2021Context;

impl From<EthereumPersonalSignature2021Context> for ssi_json_ld::syntax::Context {
    fn from(_: EthereumPersonalSignature2021Context) -> Self {
        ssi_json_ld::syntax::Context::One(EPSIG_CONTEXT.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    /// Hex-encoded (with `0x` prefix) signature.
    pub proof_value: String,
}

impl Signature {
    pub fn new(proof_value: String) -> Self {
        Self { proof_value }
    }

    pub fn decode(&self) -> Result<Vec<u8>, ProofValidationError> {
        EthereumWallet::decode_signature(self.proof_value.as_bytes())
            .map_err(|_| ProofValidationError::InvalidSignature)
    }
}

impl AsRef<str> for Signature {
    fn as_ref(&self) -> &str {
        &self.proof_value
    }
}

impl ssi_data_integrity_core::signing::AlterSignature for Signature {
    fn alter(&mut self) {
        self.proof_value.push_str("ff")
    }
}

pub struct EthereumWalletSigning;

impl SignatureAndVerificationAlgorithm for EthereumWalletSigning {
    type Signature = Signature;
}

impl<S, T> SignatureAlgorithm<S, T> for EthereumWalletSigning
where
    S: CryptographicSuite<VerificationMethod = VerificationMethod>,
    S::PreparedClaims: AsRef<[u8]>,
    T: MessageSigner<WithProtocol<ssi_crypto::algorithm::AnyESKeccakK, EthereumWallet>>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        _proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        let proof_value_bytes = signer
            .sign(
                WithProtocol(verification_method.algorithm(), EthereumWallet),
                prepared_claims.as_ref(),
            )
            .await?;
        match String::from_utf8(proof_value_bytes) {
            Ok(proof_value) => Ok(Signature::new(proof_value)),
            Err(_) => Err(SignatureError::InvalidSignature),
        }
    }
}

impl<S> VerificationAlgorithm<S> for EthereumWalletSigning
where
    S: CryptographicSuite<VerificationMethod = VerificationMethod, Signature = Signature>,
    S::PreparedClaims: AsRef<[u8]>,
{
    fn verify(
        method: &S::VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let message = EthereumWallet::prepare_message(prepared_claims.as_ref());
        let signature_bytes = proof.signature.decode()?;
        method.verify_bytes(&message, &signature_bytes)
    }
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

impl VerificationMethod {
    pub fn algorithm(&self) -> ssi_crypto::algorithm::AnyESKeccakK {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => {
                ssi_crypto::algorithm::AnyESKeccakK::ESKeccakK
            }
            Self::EcdsaSecp256k1RecoveryMethod2020(_) => {
                ssi_crypto::algorithm::AnyESKeccakK::ESKeccakKR
            }
        }
    }

    pub fn check_jwk(&self, jwk: &JWK) -> Result<bool, ProofValidationError> {
        match self {
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => Ok(m.public_key.matches(jwk)?),
            Self::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(m.public_key.to_jwk().equals_public(jwk))
            }
        }
    }

    pub fn verify_bytes(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(m) => m.verify_bytes(
                message,
                signature,
                ecdsa_secp_256k1_verification_key_2019::DigestFunction::Keccack,
            ),
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => {
                m.verify_bytes(message, signature, DigestFunction::Keccack)
            }
        }
    }
}

impl TryFrom<AnyMethod> for VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            other => Err(InvalidVerificationMethod::UnsupportedMethodType(
                other.type_().name().to_owned(),
            )),
        }
    }
}

impl From<VerificationMethod> for AnyMethod {
    fn from(value: VerificationMethod) -> Self {
        match value {
            VerificationMethod::EcdsaSecp256k1VerificationKey2019(m) => {
                Self::EcdsaSecp256k1VerificationKey2019(m)
            }
            VerificationMethod::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Self::EcdsaSecp256k1RecoveryMethod2020(m)
            }
        }
    }
}
