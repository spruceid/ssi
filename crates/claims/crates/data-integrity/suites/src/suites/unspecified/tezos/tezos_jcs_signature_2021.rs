use iref::Iri;
use json_syntax::Print;
use lazy_static::lazy_static;
use serde::Serialize;
use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::MessageSigner;
use ssi_data_integrity_core::{
    suite::{CryptographicSuiteOptions, HashError, TransformError},
    CryptographicSuite, CryptographicSuiteInput, ExpandedConfiguration, ExpandedConfigurationRef,
};
use ssi_jwk::algorithm::AnyBlake2b;
use ssi_security::{Multibase, MultibaseBuf};
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{SignatureError, TezosMethod2021, VerificationError};
use static_iref::iri;

use super::{decode_jwk_from_multibase, TezosWallet};
pub use super::{Signature, SignatureRef, TZJCSVM_CONTEXT};

pub const TZ_JCS_PROOF_CONTEXT_STR: &str = include_str!("tzjcsvm-2021-v1.jsonld");

lazy_static! {
    pub static ref TZ_JCS_PROOF_CONTEXT: serde_json::Value =
        serde_json::from_str(TZ_JCS_PROOF_CONTEXT_STR).unwrap();
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
    pub const NAME: &'static str = "TezosJcsSignature2021";

    pub const IRI: &'static Iri = iri!("https://w3id.org/security#TezosJcsSignature2021");
}

impl<C, T: Serialize> CryptographicSuiteInput<T, C> for TezosJcsSignature2021 {
    // type Transform<'a> = std::future::Ready<Result<Self::Transformed, TransformError>> where Self: 'a, T: 'a, C: 'a;

    /// Transformation algorithm.
    async fn transform<'a, 'c: 'a>(
        &'a self,
        data: &'a T,
        context: &'a mut C,
        _options: ExpandedConfigurationRef<'c, Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Transformed, TransformError>
    where
        C: 'a,
    {
        transform(data, context)
    }
}

fn transform<C, T: Serialize>(
    data: &T,
    _context: C,
) -> Result<json_syntax::Object, TransformError> {
    let json = json_syntax::to_value(data).map_err(TransformError::JsonSerialization)?;
    match json {
        json_syntax::Value::Object(obj) => Ok(obj),
        _ => Err(TransformError::ExpectedJsonObject),
    }
}

impl CryptographicSuite for TezosJcsSignature2021 {
    type Transformed = json_syntax::Object;
    type Hashed = Vec<u8>;

    type VerificationMethod = TezosMethod2021;

    type Signature = Signature;

    type SignatureProtocol = TezosWallet;

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = AnyBlake2b;

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

    fn hash(
        &self,
        mut data: json_syntax::Object,
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        #[derive(Serialize)]
        #[serde(bound(serialize = "M::Reference<'a>: Serialize, O::Reference<'a>: Serialize"))]
        struct ProofConfigurationWithContext<'a, M: Referencable, O: Referencable> {
            #[serde(rename = "@context")]
            context: &'static serde_json::Value,

            #[serde(rename = "type")]
            type_: &'static str,

            #[serde(flatten)]
            proof_configuration: ExpandedConfiguration<'a, M, O>,
        }

        let json_proof_configuration = json_syntax::to_value(ProofConfigurationWithContext {
            context: &TZ_JCS_PROOF_CONTEXT,
            type_: "TezosJcsSignature2021",
            proof_configuration,
        })
        .unwrap();

        data.insert("proof".into(), json_proof_configuration);
        data.canonicalize();
        let msg = json_syntax::Value::Object(data).compact_print().to_string();

        eprintln!("unencoded message: {msg}");

        match ssi_tzkey::encode_tezos_signed_message(&msg) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        Some(json_ld::syntax::Context::One(TZJCSVM_CONTEXT.clone()))
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<TezosMethod2021> for SignatureAlgorithm {
    type Options = Options;

    type Signature = Signature;

    type Protocol = TezosWallet;

    type MessageSignatureAlgorithm = AnyBlake2b;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: <Self::Options as Referencable>::Reference<'_>,
        method: <TezosMethod2021 as Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        let public_key_jwk = options
            .public_key_multibase
            .map(|k| decode_jwk_from_multibase(k).map_err(|_| SignatureError::InvalidPublicKey))
            .transpose();

        match public_key_jwk {
            Ok(key) => {
                Signature::sign(method.public_key.as_jwk().or(key.as_ref()), bytes, signer).await
            }
            Err(e) => Err(e),
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
