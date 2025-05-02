use iref::{Iri, IriBuf, UriBuf};
use multibase::Base;
use rdf_types::{
    dataset::PatternMatchingDataset,
    interpretation::{ReverseIriInterpretation, ReverseLiteralInterpretation},
    vocabulary::{IriVocabularyMut, LiteralVocabulary},
    Interpretation, Vocabulary,
};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{
    InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity, SignatureError,
};
use ssi_crypto::algorithm::SignatureAlgorithmType;
use ssi_jwk::JWK;
use ssi_multicodec::{MultiCodec, MultiEncodedBuf};
use ssi_security::MultibaseBuf;
use ssi_verification_methods_core::{
    MaybeJwkVerificationMethod, SigningMethod, VerificationMethodSet, VerifyBytes,
};
use static_iref::iri;
use std::{borrow::Cow, hash::Hash, str::FromStr, sync::OnceLock};

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
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, thiserror::Error)]
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
        self.public_key.decode().ok()?.to_jwk()
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
            public_key: PublicKey::new(public_key),
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

impl<A: SignatureAlgorithmType> SigningMethod<JWK, A> for Multikey
where
    A::Instance: Into<ssi_crypto::AlgorithmInstance>,
{
    fn sign_bytes(
        &self,
        secret: &JWK,
        algorithm: A::Instance,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(algorithm.into().try_into()?, bytes, secret)
            .map_err(MessageSignatureError::signature_failed)
    }

    #[allow(unused_variables)]
    fn sign_bytes_multi(
        &self,
        secret: &JWK,
        algorithm: A::Instance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match algorithm.into() {
            #[cfg(feature = "bbs")]
            ssi_crypto::AlgorithmInstance::Bbs(bbs_algorithm) => {
                let secret: ssi_bbs::BBSplusSecretKey = secret
                    .try_into()
                    .map_err(|_| MessageSignatureError::InvalidSecretKey)?;
                self.sign_bytes_multi(&secret, bbs_algorithm, messages)
            }
            other => Err(MessageSignatureError::UnsupportedAlgorithm(
                other.algorithm().to_string(),
            )),
        }
    }
}

#[cfg(feature = "ed25519")]
impl SigningMethod<ed25519_dalek::SigningKey, ssi_crypto::algorithm::EdDSA> for Multikey {
    fn sign_bytes(
        &self,
        secret: &ed25519_dalek::SigningKey,
        _algorithm: ssi_crypto::algorithm::EdDSA,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        use ed25519_dalek::Signer;
        let signature = secret.sign(bytes);
        Ok(signature.to_bytes().to_vec())
    }
}

#[cfg(feature = "bbs")]
impl SigningMethod<ssi_bbs::BBSplusSecretKey, ssi_crypto::algorithm::Bbs> for Multikey {
    fn sign_bytes(
        &self,
        secret: &ssi_bbs::BBSplusSecretKey,
        algorithm: ssi_crypto::algorithm::BbsInstance,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        self.sign_bytes_multi(secret, algorithm, &[bytes.to_vec()])
    }

    fn sign_bytes_multi(
        &self,
        secret: &ssi_bbs::BBSplusSecretKey,
        algorithm: ssi_crypto::algorithm::BbsInstance,
        messages: &[Vec<u8>],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        #[allow(irrefutable_let_patterns)]
        let DecodedMultikey::Bls12_381(pk) = self.public_key.decode()?
        else {
            return Err(MessageSignatureError::InvalidPublicKey);
        };

        ssi_bbs::sign(*algorithm.0, secret, pk, messages)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey {
    pub encoded: MultibaseBuf,

    #[serde(skip)]
    decoded: OnceLock<Result<DecodedMultikey, InvalidPublicKey>>,
}

impl PublicKey {
    pub fn new(public_key: &impl MultiCodec) -> Self {
        Self::from_multibase(MultibaseBuf::encode(
            Base::Base58Btc,
            MultiEncodedBuf::encode(public_key),
        ))
    }

    pub fn from_multibase(encoded: MultibaseBuf) -> Self {
        Self {
            encoded,
            decoded: OnceLock::new(),
        }
    }

    pub fn decode(&self) -> Result<&DecodedMultikey, InvalidPublicKey> {
        self.decoded
            .get_or_init(|| {
                let pk_multi_encoded = MultiEncodedBuf::new(self.encoded.decode()?.1)?;
                pk_multi_encoded.decode().map_err(Into::into)
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

impl From<MultibaseBuf> for PublicKey {
    fn from(value: MultibaseBuf) -> Self {
        Self::from_multibase(value)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.encoded.cmp(&other.encoded)
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state)
    }
}

impl FromStr for PublicKey {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MultibaseBuf::from_str(s).map(Self::from_multibase)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V> for PublicKey
where
    V: IriVocabularyMut,
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        self.encoded.interpretation(vocabulary, interpretation)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataPredicateObjects<I, V> for PublicKey
where
    V: IriVocabularyMut,
{
    fn visit_objects<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        self.encoded.visit_objects(visitor)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataSubject<I, V> for PublicKey {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        self.encoded.visit_subject(visitor)
    }
}

impl<V: Vocabulary, I> linked_data::LinkedDataDeserializeSubject<I, V> for PublicKey
where
    V: LiteralVocabulary,
    I: ReverseIriInterpretation<Iri = V::Iri> + ReverseLiteralInterpretation<Literal = V::Literal>,
{
    fn deserialize_subject_in<D>(
        vocabulary: &V,
        interpretation: &I,
        dataset: &D,
        graph: Option<&I::Resource>,
        resource: &<I as Interpretation>::Resource,
        context: linked_data::Context<I>,
    ) -> Result<Self, linked_data::FromLinkedDataError>
    where
        D: PatternMatchingDataset<Resource = I::Resource>,
    {
        Ok(Self::from_multibase(MultibaseBuf::deserialize_subject_in(
            vocabulary,
            interpretation,
            dataset,
            graph,
            resource,
            context,
        )?))
    }
}

#[derive(Debug, Clone)]
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

    #[cfg(feature = "bbs")]
    Bls12_381(ssi_bbs::BBSplusPublicKey),
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
            #[cfg(feature = "bbs")]
            Self::Bls12_381(key) => Some(key.into()),
            _ => None,
        }
    }
}

impl MultiCodec for DecodedMultikey {
    #[allow(unused_variables)]
    fn from_codec_and_bytes(codec: u64, bytes: &[u8]) -> Result<Self, ssi_multicodec::Error> {
        match codec {
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PUB => {
                ssi_multicodec::Codec::from_bytes(bytes).map(Self::Ed25519)
            }
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => {
                ssi_multicodec::Codec::from_bytes(bytes).map(Self::Secp256k1)
            }
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => ssi_multicodec::Codec::from_bytes(bytes).map(Self::P256),
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => ssi_multicodec::Codec::from_bytes(bytes).map(Self::P384),
            #[cfg(feature = "bbs")]
            ssi_multicodec::BLS12_381_G2_PUB => {
                ssi_multicodec::Codec::from_bytes(bytes).map(Self::Bls12_381)
            }
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
            #[cfg(feature = "bbs")]
            Self::Bls12_381(k) => k.to_codec_and_bytes(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(), // references are always considered inhabited.
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultikeyPair {
    #[serde(rename = "publicKeyMultibase")]
    pub public: MultibaseBuf,

    #[serde(rename = "secretKeyMultibase")]
    pub secret: MultibaseBuf,
}

impl MultikeyPair {
    pub fn public_jwk(&self) -> Result<JWK, ToJWKError> {
        let (_, decoded) = self.public.decode()?;
        let multi_encoded = MultiEncodedBuf::new(decoded)?;
        JWK::from_multicodec(&multi_encoded).map_err(Into::into)
    }

    pub fn secret_jwk(&self) -> Result<JWK, ToJWKError> {
        let (_, decoded) = self.secret.decode()?;
        let multi_encoded = MultiEncodedBuf::new(decoded)?;
        JWK::from_multicodec(&multi_encoded).map_err(Into::into)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToJWKError {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    MultiCodec(#[from] ssi_multicodec::Error),

    #[error(transparent)]
    JWK(#[from] ssi_jwk::FromMulticodecError),
}
