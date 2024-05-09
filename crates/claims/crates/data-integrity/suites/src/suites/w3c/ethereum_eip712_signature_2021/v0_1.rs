use lazy_static::lazy_static;
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_core::Referencable;
use ssi_crypto::{MessageSignatureError, MessageSigner};
use ssi_data_integrity_core::{
    suite::{CryptographicSuiteOptions, HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, ExpandedConfiguration, ExpandedConfigurationRef,
};
use ssi_verification_methods::SignatureError;
use static_iref::{iri, iri_ref};

use crate::eip712::{Eip712Signature, TypesProvider};

use super::{Transform, VerificationMethod};

lazy_static! {
    static ref PROOF_CONTEXT: json_ld::syntax::ContextEntry = {
        json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://demo.spruceid.com/ld/eip712sig-2021/v0.1.jsonld").to_owned(),
        )
    };
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
#[ld(prefix("eip712" = "https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct Eip712Options {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:message-schema")]
    pub message_schema: Option<crate::eip712::TypesOrURI>,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primary-type")]
    pub primary_type: Option<ssi_eip712::StructName>,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: Option<ssi_eip712::Value>,
}

impl Eip712Options {
    pub fn as_ref(&self) -> Eip712OptionsRef {
        Eip712OptionsRef {
            message_schema: self.message_schema.as_ref(),
            primary_type: self.primary_type.as_ref(),
            domain: self.domain.as_ref(),
        }
    }
}

impl From<super::Eip712Options> for Eip712Options {
    fn from(value: super::Eip712Options) -> Self {
        Self {
            message_schema: value.types.clone(),
            primary_type: value.primary_type.clone(),
            domain: value.domain.clone(),
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
#[ld(prefix("eip712" = "https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
pub struct Eip712OptionsRef<'a> {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:message-schema")]
    pub message_schema: Option<&'a crate::eip712::TypesOrURI>,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primary-type")]
    pub primary_type: Option<&'a ssi_eip712::StructName>,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: Option<&'a ssi_eip712::Value>,
}

impl<'a> From<Eip712OptionsRef<'a>> for super::Eip712OptionsRef<'a> {
    fn from(value: Eip712OptionsRef<'a>) -> Self {
        Self {
            types: value.message_schema,
            primary_type: value.primary_type,
            domain: value.domain,
        }
    }
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
#[ld(prefix("eip712" = "https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#"))]
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

impl<'a> From<OptionsRef<'a>> for super::OptionsRef<'a> {
    fn from(value: OptionsRef<'a>) -> Self {
        Self {
            eip712: value.eip712.map(Eip712OptionsRef::into),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEip712Signature2021v0_1;

impl EthereumEip712Signature2021v0_1 {
    pub const NAME: &'static str = "EthereumEip712Signature2021";

    pub const IRI: &'static iref::Iri = iri!("https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021");
}

impl CryptographicSuite for EthereumEip712Signature2021v0_1 {
    type Transformed = ssi_eip712::TypedData;

    type Hashed = [u8; 66];

    type VerificationMethod = VerificationMethod;

    type Signature = Eip712Signature;

    type SignatureProtocol = ();

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

    /// Hashing algorithm.
    fn hash(
        &self,
        data: ssi_eip712::TypedData,
        _proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        data.encode()
            .map_err(|e| HashError::InvalidMessage(e.to_string()))
    }

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        Some(json_ld::syntax::Context::One(PROOF_CONTEXT.clone()))
    }

    async fn sign_hash(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        match method.algorithm() {
            Ok(algorithm) => Eip712Signature::sign(bytes, signer, algorithm).await,
            Err(e) => Err(MessageSignatureError::into(e.into())),
        }
    }

    fn verify_hash(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as Referencable>::Reference<'_>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature_bytes = signature.decode()?;
        method.verify_bytes(bytes, &signature_bytes).map(Into::into)
    }
}

impl<T: serde::Serialize, C: TypesProvider> CryptographicSuiteInput<T, C>
    for EthereumEip712Signature2021v0_1
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
            params.map_options(OptionsRef::into),
            // &PROOF_CONTEXT,
            "EthereumEip712Signature2021",
        )
        .await
    }
}
