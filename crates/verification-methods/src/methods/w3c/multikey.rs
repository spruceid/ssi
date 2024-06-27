use iref::{Iri, IriBuf, UriBuf};
use multibase::Base;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, ProofValidationError, ProofValidity, SignatureError};
use ssi_jwk::JWK;
use ssi_multicodec::{Codec, MultiCodec, MultiEncodedBuf};
use ssi_security::MultibaseBuf;
use ssi_verification_methods_core::{
    MaybeJwkVerificationMethod, MessageSignatureError, SigningMethod, VerificationMethodSet,
    VerifyBytes,
};
use static_iref::iri;
use std::{borrow::Cow, hash::Hash};

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
};

/// Multikey type name.
pub const MULTIKEY_TYPE: &str = "Multikey";

/// Multikey verification method.
///
/// See: <https://www.w3.org/TR/vc-data-integrity/#multikey>
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[serde(tag = "type", rename = "Multikey")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:Multikey")]
pub struct Multikey {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public key encoded according to [MULTICODEC] and formatted according to
    /// [MULTIBASE].
    ///
    /// [MULTICODEC]: <https://github.com/multiformats/multicodec>
    /// [MULTIBASE]: <https://github.com/multiformats/multibase>
    #[serde(rename = "publicKeyMultibase")]
    #[ld("sec:publicKeyMultibase")]
    pub public_key: MultibaseBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Multicodec(#[from] ssi_multicodec::Error),
}

impl From<InvalidPublicKey> for ProofValidationError {
    fn from(_value: InvalidPublicKey) -> Self {
        ProofValidationError::InvalidKey
    }
}

impl From<InvalidPublicKey> for MessageSignatureError {
    fn from(_value: InvalidPublicKey) -> Self {
        MessageSignatureError::InvalidPublicKey
    }
}

impl From<InvalidPublicKey> for SignatureError {
    fn from(_value: InvalidPublicKey) -> Self {
        SignatureError::InvalidPublicKey
    }
}

impl Multikey {
    pub const NAME: &'static str = MULTIKEY_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#Multikey");

    pub fn public_key_jwk(&self) -> Option<JWK> {
        self.decode().ok()?.to_jwk()
    }

    pub fn decode(&self) -> Result<DecodedMultikey, InvalidPublicKey> {
        let pk_multi_encoded = MultiEncodedBuf::new(self.public_key.decode()?.1)?;
        pk_multi_encoded.decode().map_err(Into::into)
    }

    #[cfg(feature = "ed25519")]
    pub fn generate_ed25519_key_pair(
        id: IriBuf,
        controller: UriBuf,
        csprng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> (Self, ed25519_dalek::SigningKey) {
        let key = ed25519_dalek::SigningKey::generate(csprng);
        (
            Self::from_public_key(id, controller, &key.verifying_key()),
            key,
        )
    }

    pub fn from_public_key<K: MultiCodec>(id: IriBuf, controller: UriBuf, public_key: &K) -> Self {
        Self {
            id,
            controller,
            public_key: MultibaseBuf::encode(Base::Base58Btc, MultiEncodedBuf::encode(public_key)),
        }
    }
}

pub enum SecretKeyRef<'a> {
    #[cfg(feature = "ed25519")]
    Ed25519(&'a ed25519_dalek::SigningKey),
    Jwk(&'a JWK),
}

#[cfg(feature = "ed25519")]
impl<'a> From<&'a ed25519_dalek::SigningKey> for SecretKeyRef<'a> {
    fn from(value: &'a ed25519_dalek::SigningKey) -> Self {
        Self::Ed25519(value)
    }
}

impl<'a> From<&'a JWK> for SecretKeyRef<'a> {
    fn from(value: &'a JWK) -> Self {
        Self::Jwk(value)
    }
}

impl VerificationMethod for Multikey {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for Multikey {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl<A: Into<ssi_jwk::Algorithm>> VerifyBytes<A> for Multikey {
    fn verify_bytes(
        &self,
        algorithm: A,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        let key = self
            .public_key_jwk()
            .ok_or(ProofValidationError::UnknownKey)?;
        Ok(
            ssi_jws::verify_bytes(algorithm.into(), signing_bytes, &key, signature)
                .map_err(|_| InvalidProof::Signature),
        )
    }
}

#[cfg(feature = "ed25519")]
impl VerifyBytes<ssi_jwk::algorithm::EdDSA> for Multikey {
    fn verify_bytes(
        &self,
        _algorithm: ssi_jwk::algorithm::EdDSA,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        #[allow(unreachable_patterns)]
        match self.decode()? {
            DecodedMultikey::Ed25519(public_key) => {
                use ed25519_dalek::Verifier;
                let signature = ed25519_dalek::Signature::try_from(signature)
                    .map_err(|_| ProofValidationError::InvalidSignature)?;
                Ok(public_key
                    .verify(signing_bytes, &signature)
                    .map_err(|_| InvalidProof::Signature))
            }
            _ => Err(ProofValidationError::InvalidKey),
        }
    }
}

impl SigningMethod<JWK, ssi_jwk::Algorithm> for Multikey {
    fn sign_bytes(
        &self,
        secret: &JWK,
        algorithm: ssi_jwk::Algorithm,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm, bytes, secret)
            .map_err(MessageSignatureError::signature_failed)
    }
}

#[cfg(feature = "ed25519")]
impl SigningMethod<ed25519_dalek::SigningKey, ssi_jwk::algorithm::EdDSA> for Multikey {
    fn sign_bytes(
        &self,
        secret: &ed25519_dalek::SigningKey,
        _algorithm: ssi_jwk::algorithm::EdDSA,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        use ed25519_dalek::Signer;
        let signature = secret.sign(bytes);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TypedVerificationMethod for Multikey {
    fn expected_type() -> Option<ExpectedType> {
        Some(MULTIKEY_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == MULTIKEY_TYPE
    }

    fn type_(&self) -> &str {
        MULTIKEY_TYPE
    }
}

impl MaybeJwkVerificationMethod for Multikey {
    fn try_to_jwk(&self) -> Option<Cow<JWK>> {
        self.public_key_jwk().map(Cow::Owned)
    }
}

impl TryFrom<GenericVerificationMethod> for Multikey {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key: m
                .properties
                .get("publicKeyMultibase")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyMultibase"))?
                .as_str()
                .ok_or_else(|| {
                    InvalidVerificationMethod::invalid_property(
                        "publicKeyMultibase is not a string",
                    )
                })?
                .parse()
                .map_err(|e| {
                    InvalidVerificationMethod::invalid_property(&format!(
                        "publicKeyMultibase parsing failed because: {e}"
                    ))
                })?,
        })
    }
}

#[non_exhaustive]
pub enum DecodedMultikey {
    #[cfg(feature = "ed25519")]
    Ed25519(ed25519_dalek::VerifyingKey),

    #[cfg(feature = "secp256k1")]
    Secp256k1(k256::PublicKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::PublicKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::PublicKey),

    #[cfg(feature = "bls12-381")]
    Bls12_381(zkryptium::bbsplus::keys::BBSplusPublicKey),
}

impl DecodedMultikey {
    pub fn to_jwk(&self) -> Option<JWK> {
        #[allow(unreachable_patterns)]
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => Some((*key).into()),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => Some((*key).into()),
            #[cfg(feature = "secp256r1")]
            Self::P256(key) => Some((*key).into()),
            #[cfg(feature = "secp384r1")]
            Self::P384(key) => Some((*key).into()),
            _ => None,
        }
    }
}

impl MultiCodec for DecodedMultikey {
    fn from_codec_and_bytes(codec: u64, bytes: &[u8]) -> Result<Self, ssi_multicodec::Error> {
        match codec {
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PUB => Codec::from_bytes(bytes).map(Self::Ed25519),
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => Codec::from_bytes(bytes).map(Self::Secp256k1),
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => Codec::from_bytes(bytes).map(Self::P256),
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => Codec::from_bytes(bytes).map(Self::P384),
            #[cfg(feature = "bls12-381")]
            ssi_multicodec::BLS12_381_G2_PUB => Codec::from_bytes(bytes).map(Self::Bls12_381),
            _ => Err(ssi_multicodec::Error::UnexpectedCodec(codec)),
        }
    }

    fn to_codec_and_bytes(&self) -> (u64, Cow<[u8]>) {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Ed25519(k) => k.to_codec_and_bytes(),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(k) => k.to_codec_and_bytes(),
            #[cfg(feature = "secp256r1")]
            Self::P256(k) => k.to_codec_and_bytes(),
            #[cfg(feature = "secp384r1")]
            Self::P384(k) => k.to_codec_and_bytes(),
            #[cfg(feature = "bls12-381")]
            Self::Bls12_381(k) => k.to_codec_and_bytes(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(), // references are always considered inhabited.
        }
    }
}
