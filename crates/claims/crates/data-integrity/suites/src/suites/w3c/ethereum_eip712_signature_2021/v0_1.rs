use lazy_static::lazy_static;
use ssi_data_integrity_core::{suite::AddProofContext, StandardCryptographicSuite, TypeRef};
use ssi_eip712::Value;
use static_iref::{iri, iri_ref};

use crate::{
    eip712::{Eip712Hashing, TypesOrURI},
    try_from_type,
};

use super::{
    AnyEip712Options, EthereumEip712SignatureAlgorithm, EthereumEip712Transformation,
    VerificationMethod,
};

lazy_static! {
    static ref PROOF_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
        ssi_json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://demo.spruceid.com/ld/eip712sig-2021/v0.1.jsonld").to_owned(),
        )
    };
}

#[derive(Default)]
pub struct Eip712Sig2021v0_1Context;

impl From<Eip712Sig2021v0_1Context> for ssi_json_ld::syntax::Context {
    fn from(_: Eip712Sig2021v0_1Context) -> Self {
        ssi_json_ld::syntax::Context::One(PROOF_CONTEXT.clone())
    }
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

impl From<super::Eip712Options> for Eip712Options {
    fn from(value: super::Eip712Options) -> Self {
        Self {
            message_schema: value.types,
            primary_type: value.primary_type,
            domain: value.domain,
        }
    }
}

impl From<Eip712Options> for super::Eip712Options {
    fn from(value: Eip712Options) -> Self {
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

impl AnyEip712Options for Options {
    fn types(&self) -> Option<&TypesOrURI> {
        self.eip712.as_ref()?.message_schema.as_ref()
    }

    fn primary_type(&self) -> Option<&str> {
        self.eip712.as_ref()?.primary_type.as_deref()
    }

    fn domain(&self) -> Option<&Value> {
        self.eip712.as_ref()?.domain.as_ref()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumEip712Signature2021v0_1;

impl EthereumEip712Signature2021v0_1 {
    pub const NAME: &'static str = "EthereumEip712Signature2021";

    pub const IRI: &'static iref::Iri = iri!("https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021");
}

impl StandardCryptographicSuite for EthereumEip712Signature2021v0_1 {
    type Configuration = AddProofContext<Eip712Sig2021v0_1Context>;

    type Transformation = EthereumEip712Transformation;

    type Hashing = Eip712Hashing;

    type VerificationMethod = VerificationMethod;

    type SignatureAlgorithm = EthereumEip712SignatureAlgorithm;

    type ProofOptions = Options;

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(EthereumEip712Signature2021v0_1);
