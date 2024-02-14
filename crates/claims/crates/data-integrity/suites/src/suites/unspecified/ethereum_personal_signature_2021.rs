use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::{protocol::EthereumWallet, MessageSigner};
use ssi_data_integrity_core::{
    suite::HashError, CryptographicSuite, ExpandedConfiguration, ProofConfigurationRef,
};
use ssi_jwk::JWK;
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020::DigestFunction, ecdsa_secp_256k1_verification_key_2019,
    verification_method_union, AnyMethod, AnyMethodRef, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, InvalidSignature, InvalidVerificationMethod, SignatureError,
    VerificationError,
};
use static_iref::iri;

mod v0_1;
pub use v0_1::*;

use crate::{impl_rdf_input_urdna2015, AnySignature, AnySignatureRef};

/// Ethereum Personal Signature 2021.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
pub struct EthereumPersonalSignature2021;

impl EthereumPersonalSignature2021 {
    pub const NAME: &'static str = "EthereumPersonalSignature2021";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EthereumPersonalSignature2021");
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

impl<'a> VerificationMethodRef<'a> {
    pub fn algorithm(&self) -> ssi_jwk::algorithm::AnyESKeccakK {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => {
                ssi_jwk::algorithm::AnyESKeccakK::ESKeccakK
            }
            Self::EcdsaSecp256k1RecoveryMethod2020(_) => {
                ssi_jwk::algorithm::AnyESKeccakK::ESKeccakKR
            }
        }
    }

    pub fn verify_bytes(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerificationError> {
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
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
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

impl<'a> TryFrom<AnyMethodRef<'a>> for VerificationMethodRef<'a> {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethodRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(Self::EcdsaSecp256k1VerificationKey2019(m))
            }
            AnyMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Ok(Self::EcdsaSecp256k1RecoveryMethod2020(m))
            }
            _ => Err(InvalidVerificationMethod::UnsupportedMethodType),
        }
    }
}

impl<'a> From<VerificationMethodRef<'a>> for AnyMethodRef<'a> {
    fn from(value: VerificationMethodRef<'a>) -> Self {
        match value {
            VerificationMethodRef::EcdsaSecp256k1VerificationKey2019(m) => {
                Self::EcdsaSecp256k1VerificationKey2019(m)
            }
            VerificationMethodRef::EcdsaSecp256k1RecoveryMethod2020(m) => {
                Self::EcdsaSecp256k1RecoveryMethod2020(m)
            }
        }
    }
}

impl_rdf_input_urdna2015!(EthereumPersonalSignature2021);

impl CryptographicSuite for EthereumPersonalSignature2021 {
    type Transformed = String;

    type Hashed = String;

    type VerificationMethod = VerificationMethod;

    type Signature = Signature;

    type SignatureProtocol = EthereumWallet;

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

    type Options = ();

    fn name(&self) -> &str {
        Self::NAME
    }

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads().into_nquads();
        let message = format!("{proof_quads}\n{data}");
        Ok(message)
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    /// Hex-encoded (with `0x` prefix) signature.
    pub proof_value: String,
}

impl Signature {
    pub fn new(proof_value: String) -> Self {
        Self { proof_value }
    }
}

impl Referencable for Signature {
    type Reference<'a> = SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        SignatureRef {
            proof_value: &self.proof_value,
        }
    }

    covariance_rule!();
}

impl From<Signature> for AnySignature {
    fn from(value: Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl TryFrom<AnySignature> for Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    pub proof_value: &'a str,
}

impl<'a> SignatureRef<'a> {
    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        EthereumWallet::decode_signature(self.proof_value.as_bytes())
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

impl<'a> From<SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?,
        })
    }
}

pub struct SignatureAlgorithm;

// impl SignatureAlgorithm {
//     /// Sign as an Ethereum wallet.
//     pub fn wallet_sign(
//         message: &[u8],
//         secret_key: &k256::SecretKey,
//     ) -> Result<String, MessageSignatureError> {
//         use k256::ecdsa::signature::Signer;
//         let prefixed_message = ssi_crypto::hashes::keccak::prefix_personal_message(message);
//         let signing_key = k256::ecdsa::SigningKey::from(secret_key);
//         let sig: k256::ecdsa::recoverable::Signature = signing_key
//             .try_sign(&prefixed_message)
//             .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))?;
//         let sig_bytes = &mut sig.as_ref().to_vec();

//         // Recovery ID starts at 27 instead of 0.
//         sig_bytes[64] += 27;
//         Ok(ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes))
//     }
// }

impl ssi_verification_methods::SignatureAlgorithm<VerificationMethod> for SignatureAlgorithm {
    type Options = ();

    type Signature = Signature;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

    type Protocol = EthereumWallet;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <() as Referencable>::Reference<'_>,
        method: <VerificationMethod as Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        let proof_value_bytes = signer
            .sign(method.algorithm().into(), EthereumWallet, bytes)
            .await?;
        match String::from_utf8(proof_value_bytes) {
            Ok(proof_value) => Ok(Signature::new(proof_value)),
            Err(_) => Err(SignatureError::InvalidSignature),
        }
    }

    fn verify(
        &self,
        _options: (),
        signature: SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let message = EthereumWallet::prepare_message(bytes);
        let signature_bytes = signature.decode()?;
        method.verify_bytes(&message, &signature_bytes)
    }
}

impl<'a> VerificationMethodRef<'a> {
    pub fn check_jwk(&self, jwk: &JWK) -> Result<bool, VerificationError> {
        match self {
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => Ok(m.public_key.matches(jwk)?),
            Self::EcdsaSecp256k1VerificationKey2019(m) => {
                Ok(m.public_key.to_jwk().equals_public(jwk))
            }
        }
    }
}

// #[pin_project]
// pub struct EthereumWalletSign<
//     'a,
//     S: 'a + MessageSigner<ssi_jwk::algorithm::AnyESKeccakK, EthereumWallet>,
// > {
//     #[pin]
//     inner: S::Sign<'a>,
// }

// impl<'a, S: 'a + MessageSigner<ssi_jwk::algorithm::AnyESKeccakK, EthereumWallet>>
//     EthereumWalletSign<'a, S>
// {
//     pub fn new(inner: S::Sign<'a>) -> Self {
//         Self { inner }
//     }
// }

// impl<'a, S: 'a + MessageSigner<ssi_jwk::algorithm::AnyESKeccakK, EthereumWallet>> Future
//     for EthereumWalletSign<'a, S>
// {
//     type Output = Result<Signature, SignatureError>;

//     fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
//         let this = self.project();
//         this.inner.poll(cx).map(|r| {
//             let proof_value = r?;
//             match String::from_utf8(proof_value) {
//                 Ok(proof_value) => Ok(Signature::new(proof_value)),
//                 Err(_) => Err(SignatureError::InvalidSignature),
//             }
//         })
//     }
// }
