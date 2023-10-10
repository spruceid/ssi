//! Ethereum EIP712 Signature 2021 implementation.
//!
//! See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/>
use std::{future::{self, Future}, task, pin::Pin};
use iref::Uri;
use linked_data::LinkedData;
use pin_project::pin_project;
use ssi_crypto::MessageSigner;
use ssi_verification_methods::{
    verification_method_union, EcdsaSecp256k1RecoveryMethod2020, EcdsaSecp256k1VerificationKey2019,
    JsonWebKey2020, Referencable, SignatureError,
};
use static_iref::iri;

use crate::{
    suite::{HashError, TransformError, CryptographicSuiteOptions},
    CryptographicSuite, CryptographicSuiteInput, ProofConfigurationRef, eip712::{Input, Eip712Signature, Eip712SignatureRef, TypesOrURI, TypesProvider, TypesFetchError},
};

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
pub struct EthereumEip712Signature2021; // TODO add LD support

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq, LinkedData)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct Eip712Options {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:types")]
    #[serde(alias = "messageSchema")]
    pub types: Option<crate::eip712::TypesOrURI>,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primaryType")]
    pub primary_type: Option<ssi_eip712::StructName>,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: Option<ssi_eip712::Value>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize, LinkedData)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
pub struct Options {
    #[ld("eip712:eip712")]
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

#[derive(Debug, Default, Clone, Copy, serde::Serialize, LinkedData)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct OptionsRef<'a> {
    #[ld("eip712:eip712")]
    pub eip712: Option<&'a Eip712Options>
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020,
        JsonWebKey2020
    }
}

impl CryptographicSuite for EthereumEip712Signature2021 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 32];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = Options;

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#EthereumEip712Signature2021")
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

        Transform {
            params: params.without_options().shorten_lifetime(),
            types,
            primary_type,
            domain,
            message: Some(ssi_eip712::to_struct(data).map_err(|_| TransformError::InvalidData))
        }
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
    message: Option<Result<ssi_eip712::Struct, TransformError>>
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

                    task::Poll::Ready(input.try_into_typed_data(*this.params).map_err(|_| TransformError::InvalidData))
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

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        options: OptionsRef<'a>,
        method: VerificationMethodRef,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        options: OptionsRef,
        signature: Eip712SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
