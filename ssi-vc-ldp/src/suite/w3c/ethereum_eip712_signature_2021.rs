//! Ethereum EIP712 Signature 2021 implementation.
//!
//! See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
use std::{future::Future, task, pin::Pin};
use lazy_static::lazy_static;
use locspan::Meta;
use pin_project::pin_project;
use ssi_crypto::{MessageSigner, MessageSignatureError};
use ssi_jwk::algorithm::{AnyES256K, AlgorithmError};
use ssi_verification_methods::{
    verification_method_union, EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    JsonWebKey2020, Referencable, VerificationError,
};
use static_iref::{iri, iri_ref};

use crate::{
    suite::{HashError, TransformError, CryptographicSuiteOptions},
    CryptographicSuite, CryptographicSuiteInput, ProofConfigurationRef, eip712::{Input, Eip712Signature, Eip712SignatureRef, TypesOrURI, TypesProvider, TypesFetchError, Eip712Sign},
};

mod v0_1;
pub use v0_1::EthereumEip712Signature2021v0_1;

lazy_static! {
    static ref PROOF_CONTEXT: json_ld::syntax::Context = {
        json_ld::syntax::Context::One(Meta::none(
            json_ld::syntax::ContextEntry::IriRef(iri_ref!("https://w3id.org/security/suites/eip712sig-2021/v1").to_owned())
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
    pub const IRI: &iref::Iri = iri!("https://w3id.org/security#EthereumEip712Signature2021");
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, linked_data::Serialize, linked_data::Deserialize)]
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

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
pub struct Options {
    #[ld("eip712:eip712-domain")]
    pub eip712: Option<Eip712Options>
}

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            eip712: self.eip712.as_ref()
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
    pub eip712: Option<&'a Eip712Options>
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020,
        JsonWebKey2020
    }
}

impl<'a> VerificationMethodRef<'a> {
    pub fn algorithm(&self) -> Result<AnyES256K, AlgorithmError> {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(_) => Ok(AnyES256K::ES256K),
            Self::EcdsaSecp256k1RecoveryMethod2020(_) => Ok(AnyES256K::ES256KR),
            Self::JsonWebKey2020(m) => match m.public_key.algorithm {
                Some(ssi_jwk::Algorithm::ES256K) => Ok(AnyES256K::ES256K),
                Some(ssi_jwk::Algorithm::ES256KR) => Ok(AnyES256K::ES256KR),
                Some(other) => Err(AlgorithmError::Unsupported(other)),
                None => Err(AlgorithmError::Missing)
            }
        }
    }

    pub fn verify_bytes(&self, bytes: &[u8], signature: &[u8]) -> Result<bool, VerificationError> {
        match self {
            Self::EcdsaSecp256k1VerificationKey2019(m) => m.verify_bytes(bytes, signature),
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => m.verify_bytes(bytes, signature),
            Self::JsonWebKey2020(m) => m.verify_bytes(bytes, signature)
        }
    }
}

impl CryptographicSuite for EthereumEip712Signature2021 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 32];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyES256K;

    type Options = Options;

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
        _proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        data.hash()
            .map_err(|e| HashError::InvalidMessage(Box::new(e)))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

impl<T: serde::Serialize, C: TypesProvider> CryptographicSuiteInput<T, C> for EthereumEip712Signature2021
where
    for<'a> <Self::VerificationMethod as Referencable>::Reference<'a>: serde::Serialize,
    for<'a> <Self::Options as Referencable>::Reference<'a>: serde::Serialize
{
    type Transform<'a> = Transform<'a, C> where Self: 'a, T: 'a, C: 'a;
        
    fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: C,
        params: ProofConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Self::Transform<'a> where C: 'a {
        eprintln!("TRANSFORM v1.0");
        Transform::new(data, context, params, &PROOF_CONTEXT, "EthereumEip712Signature2021")
    }
}

#[pin_project(project = FetchTypesProj)]
enum FetchTypes<C: TypesProvider> {
    Ready(Option<ssi_eip712::Types>),
    Pending(#[pin] C::Fetch)
}

impl<C: TypesProvider> Future for FetchTypes<C> {
    type Output = Result<Option<ssi_eip712::Types>, TypesFetchError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            FetchTypesProj::Ready(t) => task::Poll::Ready(Ok(t.take())),
            FetchTypesProj::Pending(f) => f.poll(cx).map(|r| r.map(Some))
        }
    }
}

#[pin_project]
pub struct Transform<'a, C: TypesProvider> {
    params: ProofConfigurationRef<'a, VerificationMethod>,

    #[pin]
    types: FetchTypes<C>,
    primary_type: Option<String>,
    domain: Option<ssi_eip712::Value>,
    message: Option<Result<ssi_eip712::Struct, TransformError>>,
    proof_context: &'static json_ld::syntax::Context,
    proof_type: &'static str
}

impl<'a, C: TypesProvider> Transform<'a, C> {
    pub fn new<'c: 'a, T: serde::Serialize>(
        data: &'a T,
        context: C,
        params: ProofConfigurationRef<'c, VerificationMethod, Options>,
        proof_context: &'static json_ld::syntax::Context,
        proof_type: &'static str
    ) -> Self {
        let (types, primary_type, domain) = match params.options.eip712 {
            Some(eip712) => {
                let types = match &eip712.types {
                    Some(TypesOrURI::Object(types)) => {
                        FetchTypes::Ready(Some(types.clone()))
                    }
                    Some(TypesOrURI::URI(uri)) => {
                        FetchTypes::Pending(context.fetch_types(uri))
                    }
                    None => FetchTypes::Ready(None)
                };

                (types, eip712.primary_type.clone(), eip712.domain.clone())
            }
            None => (FetchTypes::Ready(None), None, None)
        };

        eprintln!("primary type: {primary_type:?}");

        Self {
            params: params.without_options().shorten_lifetime(),
            types,
            primary_type,
            domain,
            message: Some(ssi_eip712::to_struct(data).map_err(|_| TransformError::InvalidData)),
            proof_context,
            proof_type
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
                task::Poll::Ready(Err(e)) => task::Poll::Ready(Err(TransformError::Internal(e.to_string()))),
                task::Poll::Ready(Ok(types)) => {
                    let input = Input {
                        types,
                        primary_type: this.primary_type.take(),
                        domain: this.domain.take(),
                        message: this.message.take().unwrap().ok().unwrap()
                    };

                    task::Poll::Ready(input.try_into_typed_data(this.proof_context, this.proof_type, *this.params).map_err(|_| TransformError::InvalidData))
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

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyES256K;

    type Sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>> =
        Eip712Sign<'a, S>;

    fn sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: OptionsRef<'a>,
        method: VerificationMethodRef,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        match method.algorithm() {
            Ok(algorithm) => Eip712Sign::new(bytes, signer, algorithm),
            Err(e) => Eip712Sign::err(MessageSignatureError::into(e.into()))
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
