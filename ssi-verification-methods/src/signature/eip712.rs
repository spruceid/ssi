use async_trait::async_trait;
use ssi_crypto::VerificationError;

use crate::{EcdsaSecp256k1VerificationKey2019, VerificationMethodRef, EcdsaSecp256k1RecoveryMethod2020, JsonWebKey2020};

pub struct Eip712Signature {
	/// Proof value 
	proof_value: String,

	/// Meta-information about the signature generation process.
	eip712: Option<Eip712Metadata>
}

impl ssi_crypto::Referencable for Eip712Signature {
	type Reference<'a> = Eip712SignatureRef<'a> where Self: 'a;

	fn as_reference(&self) -> Self::Reference<'_> {
		Eip712SignatureRef {
			proof_value: &self.proof_value,
			eip712: self.eip712.as_ref()
		}
	}
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

pub struct Eip712SignatureRef<'a> {
	proof_value: &'a str,

	eip712: Option<&'a Eip712Metadata>
}

#[async_trait]
impl<'a> VerificationMethodRef<'a, EcdsaSecp256k1VerificationKey2019, Eip712Signature>
    for &'a EcdsaSecp256k1VerificationKey2019
{
    /// Verifies the given signature.
    async fn verify<'s: 'async_trait>(
        self,
        controllers: &impl crate::ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        data: &[u8],
        signature: Eip712SignatureRef<'s>,
    ) -> Result<bool, VerificationError> {
		let Some(hex_signature) = signature.proof_value.strip_prefix("0x") else {
			return Err(VerificationError::InvalidSignature)
		};

		let signature_bytes = hex::decode(&hex_signature).map_err(|_| VerificationError::InvalidSignature)?;

        self.verify_bytes(data, &signature_bytes)
    }
}

#[async_trait]
impl<'a> VerificationMethodRef<'a, EcdsaSecp256k1RecoveryMethod2020, Eip712Signature>
    for &'a EcdsaSecp256k1RecoveryMethod2020
{
    /// Verifies the given signature.
    async fn verify<'s: 'async_trait>(
        self,
        controllers: &impl crate::ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        data: &[u8],
        signature: Eip712SignatureRef<'s>,
    ) -> Result<bool, VerificationError> {
		let Some(hex_signature) = signature.proof_value.strip_prefix("0x") else {
			return Err(VerificationError::InvalidSignature)
		};

		let signature_bytes = hex::decode(&hex_signature).map_err(|_| VerificationError::InvalidSignature)?;

        self.verify_bytes(data, &signature_bytes)
    }
}

#[async_trait]
impl<'a> VerificationMethodRef<'a, JsonWebKey2020, Eip712Signature>
    for &'a JsonWebKey2020
{
    /// Verifies the given signature.
    async fn verify<'s: 'async_trait>(
        self,
        controllers: &impl crate::ControllerProvider,
        proof_purpose: ssi_crypto::ProofPurpose,
        data: &[u8],
        signature: Eip712SignatureRef<'s>,
    ) -> Result<bool, VerificationError> {
		let Some(hex_signature) = signature.proof_value.strip_prefix("0x") else {
			return Err(VerificationError::InvalidSignature)
		};

		let signature_bytes = hex::decode(&hex_signature).map_err(|_| VerificationError::InvalidSignature)?;

        self.verify_bytes(data, &signature_bytes)
    }
}