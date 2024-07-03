use std::{borrow::Cow, path::Path};

use hashbrown::HashMap;
use iref::UriBuf;
use serde::{de::DeserializeOwned, Deserialize};
use ssi_claims_core::SignatureError;
use ssi_data_integrity_core::{CryptographicSuite, DataIntegrityDocument, ProofOptions};
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{Multibase, MultibaseBuf};
use ssi_verification_methods::{
    MessageSignatureError, MessageSigner, ReferenceOrOwnedRef, ResolutionOptions,
    VerificationMethodResolutionError, VerificationMethodResolver,
};

fn load_json(path: impl AsRef<Path>) -> serde_json::Value {
    let buffer = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&buffer).unwrap()
}

fn load_unsecured_vc(path: impl AsRef<Path>) -> DataIntegrityDocument {
    let buffer = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&buffer).unwrap()
}

// fn load_secured_vc<S: DeserializeCryptographicSuiteOwned>(path: impl AsRef<Path>) -> DataIntegrity<DataIntegrityDocument, S> {
// 	let buffer = std::fs::read_to_string(path).unwrap();
// 	serde_json::from_str(&buffer).unwrap()
// }

fn load_options<M, T>(path: impl AsRef<Path>) -> ProofOptions<M, T>
where
    M: DeserializeOwned,
    T: DeserializeOwned,
{
    let buffer = std::fs::read_to_string(path).unwrap();
    let mut options: ProofOptions<M, T> = serde_json::from_str(&buffer).unwrap();
    options.context = None;
    options
}

#[derive(Deserialize)]
struct MultikeyPair {
    #[serde(rename = "publicKeyMultibase")]
    public: MultibaseBuf,

    #[serde(rename = "privateKeyMultibase")]
    private: MultibaseBuf,
}

impl MultikeyPair {
    fn load(path: impl AsRef<Path>) -> Self {
        let buffer = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&buffer).unwrap()
    }
}

#[derive(Default)]
struct MultikeyRing {
    map: HashMap<MultibaseBuf, MultibaseBuf>,
}

impl MultikeyRing {
    fn insert(&mut self, key_pair: MultikeyPair) {
        self.map.insert(key_pair.public, key_pair.private);
    }
}

#[cfg(feature = "w3c")]
impl VerificationMethodResolver for MultikeyRing {
    type Method = ssi_verification_methods::Multikey;

    async fn resolve_verification_method_with(
        &self,
        _issuer: Option<&iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
        _options: ResolutionOptions,
    ) -> Result<Cow<Self::Method>, VerificationMethodResolutionError> {
        match method {
            Some(ReferenceOrOwnedRef::Owned(method)) => Ok(Cow::Owned(method.clone())),
            Some(ReferenceOrOwnedRef::Reference(id)) => match id.fragment() {
                Some(fragment) => {
                    let public_key = MultibaseBuf::new(fragment.to_owned().into_string());
                    let fragment_start = id.len() - fragment.len() - 1;
                    let controller = &id[..fragment_start];
                    Ok(Cow::Owned(ssi_verification_methods::Multikey {
                        id: id.to_owned(),
                        controller: UriBuf::new(controller.to_owned().into_bytes()).unwrap(),
                        public_key: ssi_verification_methods::multikey::PublicKey::decode(
                            public_key,
                        )
                        .unwrap(),
                    }))
                }
                None => Err(VerificationMethodResolutionError::UnknownKey),
            },
            None => Err(VerificationMethodResolutionError::UnknownKey),
        }
    }
}

#[cfg(feature = "w3c")]
impl ssi_verification_methods::Signer<ssi_verification_methods::Multikey> for MultikeyRing {
    type MessageSigner = PrivateKey;

    async fn for_method(
        &self,
        method: Cow<'_, ssi_verification_methods::Multikey>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        method
            .id
            .fragment()
            .and_then(|id| self.map.get(id.as_str()))
            .map(MultibaseBuf::as_multibase)
            .map(PrivateKey::from_multibase)
            .transpose()
            .map_err(SignatureError::other)
    }
}

enum PrivateKey {
    #[cfg(feature = "secp256r1")]
    P256(p256::SecretKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::SecretKey),
}

#[cfg(all(feature = "w3c", any(feature = "secp256r1", feature = "secp384r1")))]
impl MessageSigner<ssi_data_integrity_suites::ecdsa_rdfc_2019::ES256OrES384> for PrivateKey {
    async fn sign(
        self,
        algorithm: ssi_data_integrity_suites::ecdsa_rdfc_2019::ES256OrES384,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match algorithm {
            #[cfg(feature = "secp256r1")]
            ssi_data_integrity_suites::ecdsa_rdfc_2019::ES256OrES384::ES256 => {
                #[allow(irrefutable_let_patterns)]
                if let Self::P256(secret_key) = self {
                    use p256::ecdsa::{signature::Signer, Signature};
                    let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                    let sig: Signature = signing_key.try_sign(message).unwrap(); // Uses SHA-256 by default.
                    Ok(sig.to_bytes().to_vec())
                } else {
                    Err(MessageSignatureError::InvalidSecretKey)
                }
            }
            #[cfg(feature = "secp384r1")]
            ssi_data_integrity_suites::ecdsa_rdfc_2019::ES256OrES384::ES384 => {
                #[allow(irrefutable_let_patterns)]
                if let Self::P384(secret_key) = self {
                    use p384::ecdsa::{signature::Signer, Signature};
                    let signing_key = p384::ecdsa::SigningKey::from(secret_key);
                    let sig: Signature = signing_key.try_sign(message).unwrap(); // Uses SHA-256 by default.
                    Ok(sig.to_bytes().to_vec())
                } else {
                    Err(MessageSignatureError::InvalidSecretKey)
                }
            }
            #[allow(unreachable_patterns)]
            a => Err(MessageSignatureError::UnsupportedAlgorithm(a.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum PrivateKeyDecodeError {
    #[error("multibase: {0}")]
    Multibase(#[from] multibase::Error),

    #[error("multicodec: {0}")]
    Multicodec(#[from] ssi_multicodec::Error),

    #[error("unsupported codec 0x{0:2x}")]
    Unsupported(u64),

    #[cfg(feature = "secp256r1")]
    #[error("P-256: {0}")]
    P256(p256::elliptic_curve::Error),

    #[cfg(feature = "secp384r1")]
    #[error("P-384: {0}")]
    P384(p384::elliptic_curve::Error),
}

impl PrivateKey {
    fn from_multibase(multibase: &Multibase) -> Result<Self, PrivateKeyDecodeError> {
        let (_, decoded) = multibase.decode()?;
        let multi_encoded = MultiEncodedBuf::new(decoded)?;
        let (codec, data) = multi_encoded.parts();

        match codec {
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PRIV => p256::SecretKey::from_slice(data)
                .map(Self::P256)
                .map_err(PrivateKeyDecodeError::P256),

            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PRIV => p384::SecretKey::from_slice(data)
                .map(Self::P384)
                .map_err(PrivateKeyDecodeError::P384),

            c => Err(PrivateKeyDecodeError::Unsupported(c)),
        }
    }
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
#[async_std::test]
async fn test_ecdsa_rdfc_2019() {
    use ssi_claims_core::VerificationParameters;
    use ssi_data_integrity_suites::EcdsaRdfc2019;
    let input = load_unsecured_vc("tests/ecdsa_rdfc_2019/input.jsonld");
    let expected_output = load_json("tests/ecdsa_rdfc_2019/output.jsonld");
    let options = load_options("tests/ecdsa_rdfc_2019/options.json");
    let key_pair = MultikeyPair::load("tests/ecdsa_rdfc_2019/keys.json");

    let mut keys = MultikeyRing::default();
    keys.insert(key_pair);

    let vc = EcdsaRdfc2019
        .sign(input, &keys, &keys, options)
        .await
        .unwrap();

    let output = serde_json::to_value(&vc).unwrap();

    eprintln!(
        "output   = {}",
        serde_json::to_string_pretty(&output).unwrap()
    );
    eprintln!(
        "expected = {}",
        serde_json::to_string_pretty(&expected_output).unwrap()
    );

    assert_eq!(output, expected_output);

    let params = VerificationParameters::from_resolver(&keys);
    assert!(vc.verify(params).await.unwrap().is_ok());
}
