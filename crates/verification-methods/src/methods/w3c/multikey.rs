use std::{borrow::Cow, hash::Hash, str::FromStr};

use ed25519_dalek::Signer;
use iref::{Iri, IriBuf, UriBuf};
use rand_core::{CryptoRng, RngCore};
use rdf_types::{Interpretation, Vocabulary};
use serde::{Deserialize, Serialize};
use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{Multibase, MultibaseBuf};
use ssi_verification_methods_core::{JwkVerificationMethod, VerificationError};
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
};

// /// IRI of the Multikey type.
// pub const MULTIKEY_IRI: &Iri = iri!("https://w3id.org/security#Multikey");

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

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Multicodec(#[from] ssi_multicodec::Error),

    #[error("invalid key type")]
    InvalidKeyType,

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::SignatureError),
}

impl Multikey {
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#Multikey");

    pub fn public_key_jwk(&self) -> JWK {
        self.public_key.to_jwk()
    }

    pub fn generate_key_pair(
        id: IriBuf,
        controller: UriBuf,
        csprng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, ed25519_dalek::SigningKey) {
        let key = ed25519_dalek::SigningKey::generate(csprng);
        (
            Self::from_public_key(id, controller, key.verifying_key()),
            key,
        )
    }

    pub fn from_public_key(
        id: IriBuf,
        controller: UriBuf,
        public_key: ed25519_dalek::VerifyingKey,
    ) -> Self {
        Self {
            id,
            controller,
            public_key: PublicKey::encode(public_key),
        }
    }

    pub fn sign_bytes<'a>(
        &self,
        secret_key: impl Into<SecretKeyRef<'a>>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        match secret_key.into() {
            SecretKeyRef::Ed25519(key_pair) => {
                let signature = key_pair.sign(signing_bytes);
                Ok(signature.to_bytes().to_vec())
            }
            SecretKeyRef::Jwk(secret_key) => {
                let algorithm = ssi_jwk::Algorithm::EdDSA;
                let key_algorithm = secret_key.algorithm.unwrap_or(algorithm);
                if !algorithm.is_compatible_with(key_algorithm) {
                    return Err(MessageSignatureError::InvalidSecretKey);
                }

                ssi_jws::sign_bytes(algorithm, signing_bytes, secret_key)
                    .map_err(|_| MessageSignatureError::InvalidSecretKey)
            }
        }
    }

    pub fn verify_bytes(
        &self,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, VerificationError> {
        let signature = ed25519_dalek::Signature::try_from(signature)
            .map_err(|_| VerificationError::InvalidSignature)?;
        Ok(self.public_key.verify(signing_bytes, &signature))
    }
}

pub enum SecretKeyRef<'a> {
    Ed25519(&'a ed25519_dalek::SigningKey),
    Jwk(&'a JWK),
}

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

impl Referencable for Multikey {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for Multikey {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }

    fn ref_id(r: Self::Reference<'_>) -> &Iri {
        r.id.as_iri()
    }

    fn ref_controller(r: Self::Reference<'_>) -> Option<&Iri> {
        Some(r.controller.as_iri())
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

    fn ref_type(_r: Self::Reference<'_>) -> &str {
        MULTIKEY_TYPE
    }
}

impl JwkVerificationMethod for Multikey {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Owned(self.public_key_jwk())
    }

    fn ref_to_jwk(r: Self::Reference<'_>) -> Cow<'_, JWK> {
        <Self as JwkVerificationMethod>::to_jwk(r)
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
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyMultibase"))?
                .parse()
                .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyMultibase"))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Multibase-encoded public key.
    encoded: MultibaseBuf,

    /// Decoded public key.
    decoded: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    pub fn encode(decoded: ed25519_dalek::VerifyingKey) -> Self {
        let multi_encoded =
            MultiEncodedBuf::encode(ssi_multicodec::ED25519_PUB, decoded.as_bytes());

        Self {
            encoded: MultibaseBuf::encode(multibase::Base::Base58Btc, multi_encoded.as_bytes()),
            decoded,
        }
    }

    pub fn decode(encoded: MultibaseBuf) -> Result<Self, InvalidPublicKey> {
        let pk_multi_encoded = MultiEncodedBuf::new(encoded.decode()?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::ED25519_PUB {
            let decoded = ed25519_dalek::VerifyingKey::try_from(pk_data)?;
            Ok(Self { encoded, decoded })
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn encoded(&self) -> &Multibase {
        &self.encoded
    }

    pub fn decoded(&self) -> &ed25519_dalek::VerifyingKey {
        &self.decoded
    }

    pub fn to_jwk(&self) -> JWK {
        self.decoded.into()
    }

    pub fn verify(&self, data: &[u8], signature: &ed25519_dalek::Signature) -> bool {
        use ed25519_dalek::Verifier;
        self.decoded.verify(data, signature).is_ok()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.encoded.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        use serde::de::Error;
        let encoded = MultibaseBuf::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl FromStr for PublicKey {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(MultibaseBuf::new(s.to_owned()))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.decoded.eq(&other.decoded)
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state)
    }
}

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataResource<I, V> for PublicKey
where
    MultibaseBuf: linked_data::LinkedDataResource<I, V>,
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        self.encoded.interpretation(vocabulary, interpretation)
    }
}

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataSubject<I, V> for PublicKey
where
    MultibaseBuf: linked_data::LinkedDataSubject<I, V>,
{
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        self.encoded.visit_subject(serializer)
    }
}

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataPredicateObjects<I, V> for PublicKey
where
    MultibaseBuf: linked_data::LinkedDataPredicateObjects<I, V>,
{
    fn visit_objects<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        self.encoded.visit_objects(visitor)
    }
}
