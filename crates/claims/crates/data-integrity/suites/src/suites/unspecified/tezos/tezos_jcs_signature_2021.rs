use iref::Iri;
use json_syntax::Print;
use lazy_static::lazy_static;
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_crypto::algorithm::AnyBlake2b;
use ssi_data_integrity_core::{
    suite::{
        standard::{
            HashingAlgorithm, HashingError, JsonObjectTransformation, SignatureAlgorithm,
            SignatureAndVerificationAlgorithm, VerificationAlgorithm,
        },
        AddProofContext,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_security::MultibaseBuf;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{protocol::WithProtocol, MessageSigner, TezosMethod2021};
use static_iref::iri;

use crate::{try_from_type, TezosJcsVmV1Context, TezosWallet};

use super::decode_jwk_from_multibase;
pub use super::{Signature, TZJCSVM_CONTEXT};

pub const TZ_JCS_PROOF_CONTEXT_STR: &str = include_str!("tzjcsvm-2021-v1.jsonld");

lazy_static! {
    pub static ref TZ_JCS_PROOF_CONTEXT: ssi_json_ld::syntax::Context =
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
#[derive(Debug, Default, Clone, Copy)]
pub struct TezosJcsSignature2021;

impl TezosJcsSignature2021 {
    pub const NAME: &'static str = "TezosJcsSignature2021";

    pub const IRI: &'static Iri = iri!("https://w3id.org/security#TezosJcsSignature2021");
}

impl StandardCryptographicSuite for TezosJcsSignature2021 {
    type Configuration = AddProofContext<TezosJcsVmV1Context>;

    type Transformation = JsonObjectTransformation;

    type Hashing = TezosJcsHashingAlgorithm;

    type VerificationMethod = TezosMethod2021;

    type SignatureAlgorithm = TezosJcsSignatureAlgorithm;

    type ProofOptions = Options;

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(TezosJcsSignature2021);

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

pub struct TezosJcsHashingAlgorithm;

impl HashingAlgorithm<TezosJcsSignature2021> for TezosJcsHashingAlgorithm {
    type Output = Vec<u8>;

    fn hash(
        mut object: json_syntax::Object,
        proof_configuration: ProofConfigurationRef<TezosJcsSignature2021>,
        _verification_method: &TezosMethod2021,
    ) -> Result<Self::Output, HashingError> {
        let json_proof_configuration = json_syntax::to_value(ProofConfigurationRef {
            context: Some(&TZ_JCS_PROOF_CONTEXT),
            ..proof_configuration
        })
        .unwrap();

        object.insert("proof".into(), json_proof_configuration);
        object.canonicalize();

        let msg = json_syntax::Value::Object(object)
            .compact_print()
            .to_string();

        match ssi_tzkey::encode_tezos_signed_message(&msg) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashingError::TooLong),
        }
    }
}

pub struct TezosJcsSignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for TezosJcsSignatureAlgorithm {
    type Signature = Signature;
}

impl<T> SignatureAlgorithm<TezosJcsSignature2021, T> for TezosJcsSignatureAlgorithm
where
    T: MessageSigner<WithProtocol<AnyBlake2b, TezosWallet>>,
{
    async fn sign(
        verification_method: &<TezosJcsSignature2021 as CryptographicSuite>::VerificationMethod,
        signer: T,
        prepared_claims: Vec<u8>,
        proof_configuration: ProofConfigurationRef<'_, TezosJcsSignature2021>,
    ) -> Result<Self::Signature, SignatureError> {
        let public_key_jwk = proof_configuration
            .options
            .public_key_multibase
            .as_ref()
            .map(|k| decode_jwk_from_multibase(k).map_err(|_| SignatureError::InvalidPublicKey))
            .transpose();

        match public_key_jwk {
            Ok(key) => {
                Signature::sign(
                    verification_method.public_key.as_jwk().or(key.as_ref()),
                    &prepared_claims,
                    signer,
                )
                .await
            }
            Err(e) => Err(e),
        }
    }
}

impl VerificationAlgorithm<TezosJcsSignature2021> for TezosJcsSignatureAlgorithm {
    fn verify(
        method: &TezosMethod2021,
        prepared_claims: Vec<u8>,
        proof: ProofRef<TezosJcsSignature2021>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let public_key_jwk = proof
            .options
            .public_key_multibase
            .as_ref()
            .map(|k| decode_jwk_from_multibase(k).map_err(|_| ProofValidationError::InvalidKey))
            .transpose()?;

        let (algorithm, signature_bytes) = proof.signature.decode()?;
        method
            .verify_bytes(
                public_key_jwk.as_ref(),
                &prepared_claims,
                algorithm,
                &signature_bytes,
            )
            .map(Into::into)
    }
}
