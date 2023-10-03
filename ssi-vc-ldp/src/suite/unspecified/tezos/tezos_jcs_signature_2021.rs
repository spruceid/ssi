use std::future;

use serde::Serialize;
use ssi_crypto::MessageSigner;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{SignatureError, TezosMethod2021};
use static_iref::iri;

use crate::{
    suite::{HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, ProofConfiguration, ProofConfigurationRef,
};

pub use super::tezos_signature_2021::{PublicKey, PublicKeyRef, Signature, SignatureRef};

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

impl<T: Serialize> CryptographicSuiteInput<T> for TezosJcsSignature2021 {
    /// Transformation algorithm.
    fn transform(
        &self,
        data: &T,
        context: (),
        _options: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Transformed, TransformError> {
        let json = serde_json::to_value(data).map_err(TransformError::JsonSerialization)?;
        match json {
            serde_json::Value::Object(obj) => Ok(obj),
            _ => Err(TransformError::ExpectedJsonObject),
        }
    }
}

impl CryptographicSuite for TezosJcsSignature2021 {
    type Transformed = serde_json::Map<String, serde_json::Value>;
    type Hashed = Vec<u8>;

    type VerificationMethod = TezosMethod2021;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#TezosJcsSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        mut data: serde_json::Map<String, serde_json::Value>,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        let json_proof_configuration = serde_json::to_value(proof_configuration).unwrap();
        data.insert("proof".to_string(), json_proof_configuration);
        let msg = serde_jcs::to_string(&data).unwrap();
        match ssi_tzkey::encode_tezos_signed_message(&msg) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<TezosMethod2021> for SignatureAlgorithm {
    type Options = ();

    type Signature = Signature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        options: (),
        method: &TezosMethod2021,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        options: (),
        signature: SignatureRef,
        method: &TezosMethod2021,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
