//! Ethereum EIP712 Signature 2021 implementation.
//!
//! See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
use lazy_static::lazy_static;
use pin_project::pin_project;
use ssi_core::Referencable;
use ssi_crypto::{MessageSignatureError, MessageSigner};
use ssi_jwk::algorithm::{AlgorithmError, AnyESKeccakK};
use ssi_vc_data_integrity_core::{
    suite::{CryptographicSuiteOptions, HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, ExpandedConfiguration, ExpandedConfigurationRef,
    ProofConfigurationRef,
};
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020, ecdsa_secp_256k1_verification_key_2019,
    verification_method_union, AnyMethod, AnyMethodRef, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, InvalidVerificationMethod, JsonWebKey2020, SignatureError,
    VerificationError,
};
use static_iref::{iri, iri_ref};
use std::{future::Future, pin::Pin, task};

pub mod v0_1;
pub use v0_1::EthereumEip712Signature2021v0_1;

use crate::eip712::{
    Eip712Signature, Eip712SignatureRef, Input, TypesFetchError, TypesOrURI, TypesProvider,
};

lazy_static! {
    static ref PROOF_CONTEXT: json_ld::syntax::Context = {
        json_ld::syntax::Context::One(json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://w3id.org/security/suites/eip712sig-2021/v1").to_owned(),
        ))
    };
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

impl<'a> Eip712Options {
    pub fn as_ref(&self) -> Eip712OptionsRef {
        Eip712OptionsRef {
            types: self.types.as_ref(),
            primary_type: self.primary_type.as_ref(),
            domain: self.domain.as_ref(),
        }
    }
}

#[derive(
    Debug,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct Eip712OptionsRef<'a> {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:message-schema")]
    #[serde(alias = "messageSchema")]
    pub types: Option<&'a crate::eip712::TypesOrURI>,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primary-type")]
    pub primary_type: Option<&'a ssi_eip712::StructName>,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: Option<&'a ssi_eip712::Value>,
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

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            eip712: self.eip712.as_ref().map(Eip712Options::as_ref),
        }
    }

    fn apply_covariance<'big: 'small, 'small>(r: Self::Reference<'big>) -> Self::Reference<'small>
    where
        Self: 'big,
    {
        r
    }
}

impl<T: CryptographicSuite> CryptographicSuiteOptions<T> for Options {}

#[derive(Debug, Default, Clone, Copy, serde::Serialize, linked_data::Serialize)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct OptionsRef<'a> {
    #[ld("eip712:eip712-domain")]
    pub eip712: Option<Eip712OptionsRef<'a>>,
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020,
        JsonWebKey2020
    }
}

impl<'a> VerificationMethodRef<'a> {
    pub fn algorithm(&self) -> Result<AnyESKeccakK, AlgorithmError> {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => Ok(AnyESKeccakK::ESKeccakK),
            Self::EcdsaSecp256k1RecoveryMethod2020(_) => Ok(AnyESKeccakK::ESKeccakKR),
            Self::JsonWebKey2020(m) => match m.public_key.algorithm {
                Some(ssi_jwk::Algorithm::ES256K) => Ok(AnyESKeccakK::ESKeccakK),
                Some(ssi_jwk::Algorithm::ES256KR) => Ok(AnyESKeccakK::ESKeccakKR),
                Some(other) => Err(AlgorithmError::Unsupported(other)),
                None => Err(AlgorithmError::Missing),
            },
        }
    }

    pub fn verify_bytes(&self, bytes: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
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
            VerificationMethod::JsonWebKey2020(m) => Self::JsonWebKey2020(m),
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
            AnyMethodRef::JsonWebKey2020(m) => Ok(Self::JsonWebKey2020(m)),
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
            VerificationMethodRef::JsonWebKey2020(m) => Self::JsonWebKey2020(m),
        }
    }
}

impl CryptographicSuite for EthereumEip712Signature2021 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 66];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

    type Options = Options;

    fn name(&self) -> &str {
        Self::NAME
    }

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    // fn generate_signature_metadata(&self, data: &Self::Transformed, options: &Self::Options) -> Self::SignatureMetadata {
    //     SignatureMetadata {
    //         eip712: options.embed.then(|| Eip712Metadata {
    //             types_or_uri: TypesOrURI::Object(data.types.clone()),
    //             primary_type: data.primary_type.clone(),
    //             domain: data.domain.clone()
    //         })
    //     }
    // }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: ssi_eip712::TypedData,
        _proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        data.encode()
            .map_err(|e| HashError::InvalidMessage(Box::new(e)))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

impl<T: serde::Serialize, C: TypesProvider> CryptographicSuiteInput<T, C>
    for EthereumEip712Signature2021
where
    for<'a> <Self::VerificationMethod as Referencable>::Reference<'a>: serde::Serialize,
    for<'a> <Self::Options as Referencable>::Reference<'a>: serde::Serialize,
{
    // type Transform<'a> = Transform<'a, C> where Self: 'a, T: 'a, C: 'a;

    async fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: &'a mut C,
        params: ExpandedConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Transformed, TransformError>
    where
        C: 'a,
    {
        Transform::new(
            data,
            context,
            params,
            &PROOF_CONTEXT,
            "EthereumEip712Signature2021",
        )
        .await
    }
}

#[pin_project(project = FetchTypesProj)]
enum FetchTypes<C: TypesProvider> {
    Ready(Option<ssi_eip712::Types>),
    Pending(#[pin] C::Fetch),
}

impl<C: TypesProvider> Future for FetchTypes<C> {
    type Output = Result<Option<ssi_eip712::Types>, TypesFetchError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            FetchTypesProj::Ready(t) => task::Poll::Ready(Ok(t.take())),
            FetchTypesProj::Pending(f) => f.poll(cx).map(|r| r.map(Some)),
        }
    }
}

#[pin_project]
pub struct Transform<'a, C: TypesProvider> {
    params: ExpandedConfigurationRef<'a, VerificationMethod>,

    #[pin]
    types: FetchTypes<C>,
    primary_type: Option<String>,
    domain: Option<ssi_eip712::Value>,
    message: Option<Result<ssi_eip712::Struct, TransformError>>,
    proof_context: &'static json_ld::syntax::Context,
    proof_type: &'static str,
}

impl<'a, C: TypesProvider> Transform<'a, C> {
    pub fn new<'c: 'a, T: serde::Serialize>(
        data: &'a T,
        context: &'a mut C,
        params: ExpandedConfigurationRef<'c, VerificationMethod, Options>,
        proof_context: &'static json_ld::syntax::Context,
        proof_type: &'static str,
    ) -> Self {
        let (types, primary_type, domain) = match &params.options.eip712 {
            Some(eip712) => {
                let types = match eip712.types {
                    Some(TypesOrURI::Object(types)) => FetchTypes::Ready(Some(types.clone())),
                    Some(TypesOrURI::URI(uri)) => FetchTypes::Pending(context.fetch_types(uri)),
                    None => FetchTypes::Ready(None),
                };

                (types, eip712.primary_type.cloned(), eip712.domain.cloned())
            }
            None => (FetchTypes::Ready(None), None, None),
        };

        Self {
            params: params.without_options().shorten_lifetime(),
            types,
            primary_type,
            domain,
            message: Some(ssi_eip712::to_struct(data).map_err(|_| TransformError::InvalidData)),
            proof_context,
            proof_type,
        }
    }
}

impl<'a, C: TypesProvider> Future for Transform<'a, C> {
    type Output = Result<ssi_eip712::TypedData, TransformError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        if this.message.as_ref().is_some_and(|r| r.is_err()) {
            task::Poll::Ready(Err(this.message.take().unwrap().err().unwrap()))
        } else {
            match this.types.poll(cx) {
                task::Poll::Pending => task::Poll::Pending,
                task::Poll::Ready(Err(e)) => {
                    task::Poll::Ready(Err(TransformError::Internal(e.to_string())))
                }
                task::Poll::Ready(Ok(types)) => {
                    let input = Input {
                        types,
                        primary_type: this.primary_type.take(),
                        domain: this.domain.take(),
                        message: this.message.take().unwrap().ok().unwrap(),
                    };

                    task::Poll::Ready(
                        input
                            .try_into_typed_data(this.proof_context, this.proof_type, **this.params)
                            .map_err(|_| TransformError::InvalidData),
                    )
                }
            }
        }
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<VerificationMethod> for SignatureAlgorithm {
    type Options = Options;

    type Signature = Eip712Signature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <VerificationMethod as Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        match method.algorithm() {
            Ok(algorithm) => Eip712Signature::sign(bytes, signer, algorithm).await,
            Err(e) => Err(MessageSignatureError::into(e.into())),
        }
    }

    fn verify(
        &self,
        _options: OptionsRef,
        signature: Eip712SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let signature_bytes = signature.decode()?;
        method.verify_bytes(bytes, &signature_bytes)
    }
}
