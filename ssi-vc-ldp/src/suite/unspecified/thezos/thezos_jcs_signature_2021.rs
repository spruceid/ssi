use serde::Serialize;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::TezosMethod2021;
use static_iref::iri;

use crate::{
    suite::HashError, verification, CryptographicSuite, CryptographicSuiteInput,
    ProofConfiguration, ProofOptions,
};

/// Tezos signature suite based on JCS.
///
/// This is not a Linked-Data suite. The credential is processed as a
/// simple JSON document, normalized using the [JSON Canonicalization Scheme
/// (JCS)][1].
///
/// # Transformation algorithm
///
/// The input credential is serialized into JSON.
///
/// # Hashing algorithm
///
/// The proof configuration is serialized into JSON and added to the JSON
/// credential under the `proof` field. The result is then normalized using the
/// [JSON Canonicalization Scheme (JCS)][1] and prefixed by the string:
/// `Tezos Signed Message: ` (terminated by a space character) to form a
/// message.
///
/// The output is a bytes string composed of the byte 0x5, followed by the byte
/// 0x1, followed by the 4 bytes encoding the message lenght in big endian,
/// followd by the message.
///
/// [1]: <https://tools.ietf.org/html/rfc8785>
///
/// # Verification method
///
/// The [`TezosMethod2021`] verification method is used.
pub struct TezosJcsSignature2021;

pub enum TransformError {
    JsonSerialization(serde_json::Error),
    ExpectedJsonObject,
}

impl<T: Serialize> CryptographicSuiteInput<T> for TezosJcsSignature2021 {
    type TransformError = TransformError;

    /// Transformation algorithm.
    fn transform(&self, data: T, _options: ()) -> Result<Self::Transformed, TransformError> {
        let json = serde_json::to_value(data).map_err(TransformError::JsonSerialization)?;
        match json {
            serde_json::Value::Object(obj) => Ok(obj),
            _ => Err(TransformError::ExpectedJsonObject),
        }
    }
}

#[async_trait::async_trait]
impl CryptographicSuite for TezosJcsSignature2021 {
    type TransformationParameters = ();
    type Transformed = serde_json::Map<String, serde_json::Value>;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = Vec<u8>;

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<TezosMethod2021>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#TezosJcsSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        mut data: serde_json::Map<String, serde_json::Value>,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let json_proof_configuration = serde_json::to_value(proof_configuration).unwrap();
        data.insert("proof".to_string(), json_proof_configuration);
        let msg = serde_jcs::to_string(&data).unwrap();
        match ssi_tzkey::encode_tezos_signed_message(&msg) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }
}
