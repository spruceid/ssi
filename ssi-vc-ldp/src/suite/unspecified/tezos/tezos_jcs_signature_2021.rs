use iref::Iri;
use lazy_static::lazy_static;
use serde::Serialize;
use ssi_crypto::MessageSigner;
use ssi_jwk::algorithm::AnyBlake2b;
use ssi_security::{Multibase, MultibaseBuf};
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{
    covariance_rule, Referencable, SignatureError, TezosMethod2021, VerificationError,
};
use static_iref::iri;

use crate::{
    suite::{CryptographicSuiteOptions, HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, ProofConfigurationRef,
};

use super::{decode_jwk_from_multibase, TezosSign, TezosWallet};
pub use super::{Signature, SignatureRef};

pub const TZ_JCS_PROOF_CONTEXT_STR: &str = include_str!("tzjcsvm-2021-v1.jsonld");

lazy_static! {
    pub static ref TZ_JCS_PROOF_CONTEXT: serde_json::Value =
        { serde_json::from_str(TZ_JCS_PROOF_CONTEXT_STR).unwrap() };
}

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
/// credential under the `proof` field with `type` set to
/// `TezosJcsSignature2021` and its associated `@context` definition. The result
/// is then normalized using the [JSON Canonicalization Scheme (JCS)][1] and
/// prefixed by the string: `Tezos Signed Message: ` (terminated by a space
/// character) to form a message.
///
/// The output is a bytes string composed of the byte 0x5, followed by the byte
/// 0x1, followed by the 4 bytes encoding the message length in big endian,
/// followed by the message.
///
/// [1]: <https://tools.ietf.org/html/rfc8785>
///
/// # Verification method
///
/// The [`TezosMethod2021`] verification method is used.
pub struct TezosJcsSignature2021;

impl TezosJcsSignature2021 {
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#TezosJcsSignature2021");
}

impl<C, T: Serialize> CryptographicSuiteInput<T, C> for TezosJcsSignature2021 {
    type Transform<'a> = std::future::Ready<Result<Self::Transformed, TransformError>> where Self: 'a, T: 'a, C: 'a;

    /// Transformation algorithm.
    fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: C,
        _options: ProofConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Self::Transform<'a>
    where
        C: 'a,
    {
        std::future::ready(transform(data, context))
    }
}

fn transform<C, T: Serialize>(
    data: &T,
    _context: C,
) -> Result<serde_json::Map<String, serde_json::Value>, TransformError> {
    let json = serde_json::to_value(data).map_err(TransformError::JsonSerialization)?;
    match json {
        serde_json::Value::Object(obj) => Ok(obj),
        _ => Err(TransformError::ExpectedJsonObject),
    }
}

impl CryptographicSuite for TezosJcsSignature2021 {
    type Transformed = serde_json::Map<String, serde_json::Value>;
    type Hashed = Vec<u8>;

    type VerificationMethod = TezosMethod2021;

    type Signature = Signature;

    type SignatureProtocol = TezosWallet;

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = AnyBlake2b;

    type Options = Options;

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        mut data: serde_json::Map<String, serde_json::Value>,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        #[derive(Serialize)]
        #[serde(bound(serialize = "M::Reference<'a>: Serialize, O::Reference<'a>: Serialize"))]
        struct ProofConfigurationWithContext<'a, M: Referencable, O: Referencable> {
            #[serde(rename = "@context")]
            context: &'static serde_json::Value,

            #[serde(rename = "type")]
            type_: &'static str,

            #[serde(flatten)]
            proof_configuration: ProofConfigurationRef<'a, M, O>,
        }

        let json_proof_configuration = serde_json::to_value(ProofConfigurationWithContext {
            context: &TZ_JCS_PROOF_CONTEXT,
            type_: "TezosJcsSignature2021",
            proof_configuration,
        })
        .unwrap();

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
    type Options = Options;

    type Signature = Signature;

    type Protocol = TezosWallet;

    type MessageSignatureAlgorithm = AnyBlake2b;

    type Sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>> =
        TezosSign<'a, S>;

    fn sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: OptionsRef<'a>,
        method: &TezosMethod2021,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        let public_key_jwk = options
            .public_key_multibase
            .map(|k| decode_jwk_from_multibase(k).map_err(|_| SignatureError::InvalidPublicKey))
            .transpose();

        match public_key_jwk {
            Ok(key) => TezosSign::new(method.public_key.as_jwk().or(key.as_ref()), bytes, signer),
            Err(e) => TezosSign::err(e),
        }
    }

    fn verify(
        &self,
        options: OptionsRef,
        signature: SignatureRef,
        method: &TezosMethod2021,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let public_key_jwk = options
            .public_key_multibase
            .map(|k| decode_jwk_from_multibase(k).map_err(|_| VerificationError::InvalidKey))
            .transpose()?;

        let (algorithm, signature_bytes) = signature.decode()?;
        method.verify_bytes(public_key_jwk.as_ref(), bytes, algorithm, &signature_bytes)
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
pub struct Options {
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    #[ld("sec:publicKeyMultibase")]
    pub public_key_multibase: Option<MultibaseBuf>,
}

impl Options {
    pub fn new(public_key_multibase: Option<MultibaseBuf>) -> Self {
        Self {
            public_key_multibase,
        }
    }
}

impl<T> CryptographicSuiteOptions<T> for Options {}

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            public_key_multibase: self.public_key_multibase.as_deref(),
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy, serde::Serialize, linked_data::Serialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct OptionsRef<'a> {
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    #[ld("sec:publicKeyMultibase")]
    pub public_key_multibase: Option<&'a Multibase>,
}
