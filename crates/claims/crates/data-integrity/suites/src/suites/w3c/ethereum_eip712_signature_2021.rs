//! Ethereum EIP712 Signature 2021 implementation.
//!
//! See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
use lazy_static::lazy_static;
use serde::Serialize;
use ssi_claims_core::{MessageSignatureError, ProofValidationError, ProofValidity, SignatureError};
use ssi_crypto::algorithm::{AlgorithmError, AnyESKeccakK};
use ssi_data_integrity_core::{
    suite::{
        standard::{
            SignatureAlgorithm, SignatureAndVerificationAlgorithm, TransformationAlgorithm,
            TransformationError, TypedTransformationAlgorithm, VerificationAlgorithm,
        },
        AddProofContext, TransformationOptions,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef, SerializeCryptographicSuite,
    StandardCryptographicSuite, TypeRef,
};
use ssi_eip712::{Eip712TypesLoaderProvider, TypesLoader, Value};
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020, ecdsa_secp_256k1_verification_key_2019,
    verification_method_union, AnyMethod, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, InvalidVerificationMethod, JsonWebKey2020, MessageSigner,
};
use static_iref::{iri, iri_ref};

pub mod v0_1;
pub use v0_1::EthereumEip712Signature2021v0_1;

use crate::{
    eip712::{Eip712Hashing, Eip712Signature, Input, TypesOrURI},
    try_from_type,
};

lazy_static! {
    static ref PROOF_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
        ssi_json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://w3id.org/security/suites/eip712sig-2021/v1").to_owned(),
        )
    };
}

#[derive(Default)]
pub struct Eip712Sig2021v1Context;

impl From<Eip712Sig2021v1Context> for ssi_json_ld::syntax::Context {
    fn from(_: Eip712Sig2021v1Context) -> Self {
        ssi_json_ld::syntax::Context::One(PROOF_CONTEXT.clone())
    }
}

/// Ethereum EIP-712 Signature 2021.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
///
/// # Input
///
/// This suites accepts a [EIP `TypedData`][1] object, with or without a `types`
/// property, represented by the [`Input`] type.
///
/// [1]: <https://eips.ethereum.org/EIPS/eip-712>
///
/// # Transformation algorithm
///
/// If no `types` property is bound to the input `TypedData`, one is generated
/// according to the [Types Generation algorithm][2].
///
/// [2]: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#types-generation>
///
/// # Hashing algorithm
///
/// The transformed input is hashed using the `Keccak-256` algorithm.
///
/// # Signature algorithm
///
/// The hashed input is signed using the `ECDSA K-256` signature algorithm.
///
/// # Verification methods
///
/// The following verification methods can be used to sign/verify a credential
/// with this suite:
/// - [`EcdsaSecp256k1VerificationKey2019`],
/// - [`EcdsaSecp256k1RecoveryMethod2020`],
/// - [`JsonWebKey2020`]
///
/// # Linked-Data support
///
/// This suite is not a Linked-Data cryptographic suite.
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEip712Signature2021;

// https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021

impl EthereumEip712Signature2021 {
    pub const NAME: &'static str = "EthereumEip712Signature2021";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EthereumEip712Signature2021");
}

impl StandardCryptographicSuite for EthereumEip712Signature2021 {
    type Configuration = AddProofContext<Eip712Sig2021v1Context>;

    type Transformation = EthereumEip712Transformation;

    type Hashing = Eip712Hashing;

    type VerificationMethod = VerificationMethod;

    type SignatureAlgorithm = EthereumEip712SignatureAlgorithm;

    type ProofOptions = Options;

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EthereumEip712Signature2021);

#[derive(
    Debug,
    serde::Serialize,
    serde::Deserialize,
    Clone,
    PartialEq,
    Eq,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct Eip712Options {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:message-schema")]
    #[serde(alias = "messageSchema")]
    pub types: Option<crate::eip712::TypesOrURI>,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primary-type")]
    pub primary_type: Option<ssi_eip712::StructName>,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: Option<ssi_eip712::Value>,
}

#[derive(
    Debug,
    Default,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
pub struct Options {
    #[ld("eip712:eip712-domain")]
    pub eip712: Option<Eip712Options>,
}

pub trait AnyEip712Options {
    fn types(&self) -> Option<&TypesOrURI>;

    fn primary_type(&self) -> Option<&str>;

    fn domain(&self) -> Option<&Value>;
}

impl AnyEip712Options for Options {
    fn types(&self) -> Option<&TypesOrURI> {
        self.eip712.as_ref()?.types.as_ref()
    }

    fn primary_type(&self) -> Option<&str> {
        self.eip712.as_ref()?.primary_type.as_deref()
    }

    fn domain(&self) -> Option<&Value> {
        self.eip712.as_ref()?.domain.as_ref()
    }
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020,
        JsonWebKey2020
    }
}

impl VerificationMethod {
    pub fn algorithm(&self) -> Result<AnyESKeccakK, AlgorithmError> {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => Ok(AnyESKeccakK::ESKeccakK),
            Self::EcdsaSecp256k1RecoveryMethod2020(_) => Ok(AnyESKeccakK::ESKeccakKR),
            Self::JsonWebKey2020(m) => match m.public_key.algorithm {
                Some(ssi_jwk::Algorithm::ES256K) => Ok(AnyESKeccakK::ESKeccakK),
                Some(ssi_jwk::Algorithm::ES256KR) => Ok(AnyESKeccakK::ESKeccakKR),
                Some(other) => Err(AlgorithmError::Unsupported(other.into())),
                None => Err(AlgorithmError::Missing),
            },
        }
    }

    pub fn verify_bytes(
        &self,
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(m) => m.verify_bytes(
                bytes,
                signature,
                ecdsa_secp_256k1_verification_key_2019::DigestFunction::Keccack,
            ),
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => m.verify_bytes(
                bytes,
                signature,
                ecdsa_secp_256k1_recovery_method_2020::DigestFunction::Keccack,
            ),
            Self::JsonWebKey2020(m) => m.verify_bytes(bytes, signature, None),
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
            AnyMethod::JsonWebKey2020(m) => Ok(Self::JsonWebKey2020(m)),
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
            VerificationMethod::JsonWebKey2020(m) => Self::JsonWebKey2020(m),
        }
    }
}

pub struct EthereumEip712Transformation;

impl<S: CryptographicSuite> TransformationAlgorithm<S> for EthereumEip712Transformation {
    type Output = ssi_eip712::TypedData;
}

impl<S, T, C> TypedTransformationAlgorithm<S, T, C> for EthereumEip712Transformation
where
    S: SerializeCryptographicSuite,
    S::ProofOptions: AnyEip712Options,
    T: Serialize,
    C: Eip712TypesLoaderProvider,
{
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<'_, S>,
        _verification_method: &S::VerificationMethod,
        _transformation_options: TransformationOptions<S>,
    ) -> Result<Self::Output, ssi_data_integrity_core::suite::standard::TransformationError> {
        let types = match proof_configuration.options.types() {
            Some(TypesOrURI::Object(types)) => Some(types.clone()),
            Some(TypesOrURI::URI(uri)) => Some(
                context
                    .eip712_types()
                    .fetch_types(uri)
                    .await
                    .map_err(TransformationError::internal)?,
            ),
            None => None,
        };

        let primary_type = proof_configuration
            .options
            .primary_type()
            .map(ToOwned::to_owned);
        let domain = proof_configuration.options.domain().cloned();

        let message = ssi_eip712::to_struct(data).map_err(|_| TransformationError::InvalidInput)?;

        let input = Input {
            types,
            primary_type,
            domain,
            message,
        };

        input
            .try_into_typed_data(&proof_configuration.without_proof_options())
            .map_err(|_| TransformationError::InvalidInput)
    }
}

pub struct EthereumEip712SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for EthereumEip712SignatureAlgorithm {
    type Signature = Eip712Signature;
}

impl<S, T> SignatureAlgorithm<S, T> for EthereumEip712SignatureAlgorithm
where
    S: CryptographicSuite<VerificationMethod = VerificationMethod>,
    S::PreparedClaims: AsRef<[u8]>,
    T: MessageSigner<ssi_crypto::algorithm::AnyESKeccakK>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        _proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        // ssi_jwk::algorithm::AnyESKeccakK
        match verification_method.algorithm() {
            Ok(algorithm) => {
                Eip712Signature::sign(prepared_claims.as_ref(), signer, algorithm).await
            }
            Err(e) => Err(MessageSignatureError::into(e.into())),
        }
    }
}

impl<S> VerificationAlgorithm<S> for EthereumEip712SignatureAlgorithm
where
    S: CryptographicSuite<VerificationMethod = VerificationMethod, Signature = Eip712Signature>,
    S::PreparedClaims: AsRef<[u8]>,
{
    fn verify(
        method: &<S as CryptographicSuite>::VerificationMethod,
        prepared_claims: <S as CryptographicSuite>::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature_bytes = proof.signature.decode()?;
        method
            .verify_bytes(prepared_claims.as_ref(), &signature_bytes)
            .map(Into::into)
    }
}
