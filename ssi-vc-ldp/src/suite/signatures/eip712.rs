use ssi_verification_methods::{covariance_rule, Referencable};

/// Common signature format for EIP-712-based cryptographic suites.
#[derive(Debug, Clone)]
pub struct Eip712Signature {
    /// Proof value
    pub proof_value: String,

    /// Meta-information about the signature generation process.
    pub eip712: Option<Eip712Metadata>,
}

impl Referencable for Eip712Signature {
    type Reference<'a> = Eip712SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        Eip712SignatureRef {
            proof_value: &self.proof_value,
            eip712: self.eip712.as_ref(),
        }
    }

    covariance_rule!();
}

/// Reference to [`Eip712Signature`].
#[derive(Debug, Clone, Copy)]
pub struct Eip712SignatureRef<'a> {
    /// Proof value
    pub proof_value: &'a str,

    /// Meta-information about the signature generation process.
    pub eip712: Option<&'a Eip712Metadata>,
}

/// Meta-information about the signature generation process.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021>
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Eip712Metadata {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[serde(rename = "types", alias = "messageSchema")]
    pub types_or_uri: TypesOrURI,

    /// Value of the `primaryType` property of the `TypedData` object.
    pub primary_type: ssi_eip712::StructName,

    /// Value of the `domain` property of the `TypedData` object.
    pub domain: ssi_eip712::Value,
}

/// Object containing EIP-712 types, or a URI for such.
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
#[serde(untagged)]
pub enum TypesOrURI {
    URI(String),
    Object(ssi_eip712::Types),
}
