use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::MessageSigner;
use ssi_jwk::Algorithm;
use ssi_jws::{CompactJWSStr, CompactJWSString, JWS};
use ssi_verification_methods::{SignatureError, VerificationError};

/// Common signature format where the proof value is multibase-encoded.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct MultibaseSignature {
    /// Multibase encoded signature.
    #[serde(rename = "proofValue")]
    #[ld("sec:proofValue")]
    pub proof_value: String,
}

impl MultibaseSignature {
    pub fn new_base58btc(signature: Vec<u8>) -> Self {
        Self {
            proof_value: multibase::encode(multibase::Base::Base58Btc, signature),
        }
    }

    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        multibase::decode(&self.proof_value)
            .map(|(_, data)| data)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

impl Referencable for MultibaseSignature {
    type Reference<'a> = MultibaseSignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        MultibaseSignatureRef {
            proof_value: &self.proof_value,
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy)]
pub struct MultibaseSignatureRef<'a> {
    /// Multibase encoded signature.
    pub proof_value: &'a str,
}

impl<'a> MultibaseSignatureRef<'a> {
    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        multibase::decode(self.proof_value)
            .map(|(_, data)| data)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct JwsSignature {
    #[ld("sec:jws")]
    pub jws: CompactJWSString,
}

impl JwsSignature {
    pub fn new(jws: CompactJWSString) -> Self {
        Self { jws }
    }

    pub async fn sign_detached<A: Clone + Into<ssi_jwk::Algorithm>, S: MessageSigner<A>>(
        payload: &[u8],
        signer: S,
        key_id: Option<String>,
        algorithm: A,
    ) -> Result<Self, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(algorithm.clone().into(), key_id);
        let signing_bytes = header.encode_signing_bytes(payload);
        let signature = signer.sign(algorithm, (), &signing_bytes).await?;
        let jws = ssi_jws::CompactJWSString::encode_detached(header, &signature);
        Ok(JwsSignature::new(jws))
    }
}

impl Referencable for JwsSignature {
    type Reference<'a> = JwsSignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        JwsSignatureRef { jws: &self.jws }
    }

    covariance_rule!();
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, linked_data::Serialize, linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct JwsSignatureRef<'a> {
    #[ld("sec:jws")]
    pub jws: &'a CompactJWSStr,
}

impl<'a> JwsSignatureRef<'a> {
    /// Decodes the signature for the given message.
    ///
    /// Returns the signing bytes, the signature bytes and the signature algorithm.
    pub fn decode(
        &self,
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Algorithm), VerificationError> {
        let JWS {
            header, signature, ..
        } = self
            .jws
            .decode()
            .map_err(|_| VerificationError::InvalidSignature)?;
        let signing_bytes = header.encode_signing_bytes(message);
        Ok((signing_bytes, signature, header.algorithm))
    }
}
