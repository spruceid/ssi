use iref::UriBuf;
use linked_data::{LinkedData, LinkedDataGraph};
use rdf_types::{Interpretation, Vocabulary};
use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_crypto::algorithm::AnyESKeccakK;
use ssi_verification_methods::MessageSigner;

/// Common signature format for EIP-712-based cryptographic suites.
///
/// See: <https://eips.ethereum.org/EIPS/eip-712>
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Signature {
    /// Hex encoded output of the EIP712 signature function according to
    /// [EIP712](https://eips.ethereum.org/EIPS/eip-712).
    pub proof_value: String,
}

impl Eip712Signature {
    pub fn from_bytes(mut signature_bytes: Vec<u8>) -> Self {
        signature_bytes[64] += 27;
        Self {
            proof_value: format!("0x{}", hex::encode(signature_bytes)),
        }
    }

    pub fn decode(&self) -> Result<Vec<u8>, ProofValidationError> {
        if self.proof_value.len() >= 4 && &self.proof_value[0..2] == "0x" {
            let mut bytes = hex::decode(&self.proof_value[2..])
                .map_err(|_| ProofValidationError::InvalidSignature)?;
            bytes[64] -= 27;
            Ok(bytes)
        } else {
            Err(ProofValidationError::InvalidSignature)
        }
    }

    pub async fn sign<S: MessageSigner<AnyESKeccakK>>(
        bytes: &[u8],
        signer: S,
        algorithm: AnyESKeccakK,
    ) -> Result<Self, SignatureError> {
        let signature = signer.sign(algorithm, bytes).await?;
        Ok(Eip712Signature::from_bytes(signature))
    }
}

impl AsRef<str> for Eip712Signature {
    fn as_ref(&self) -> &str {
        &self.proof_value
    }
}

impl ssi_data_integrity_core::signing::AlterSignature for Eip712Signature {
    fn alter(&mut self) {
        self.proof_value.push_str("ff")
    }
}

/// Meta-information about the signature generation process.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021>
#[derive(
    Debug,
    serde::Serialize,
    serde::Deserialize,
    Clone,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Eip712Metadata {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:message-schema")]
    #[serde(rename = "types", alias = "messageSchema")]
    pub types_or_uri: TypesOrURI,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primary-type")]
    pub primary_type: ssi_eip712::StructName,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: ssi_eip712::Value,
}

/// Object containing EIP-712 types, or a URI for such.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TypesOrURI {
    URI(UriBuf),
    Object(ssi_eip712::Types),
}

linked_data::json_literal!(TypesOrURI);

impl<V: Vocabulary, I: Interpretation> LinkedDataGraph<I, V> for TypesOrURI {
    fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<I, V>,
    {
        visitor.subject(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedData<I, V> for TypesOrURI {
    fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        visitor.default_graph(self)?;
        visitor.end()
    }
}
