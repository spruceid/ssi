use std::{borrow::Cow, hash::Hash, str::FromStr};

use iref::{Iri, IriBuf, UriBuf};
use rdf_types::{Interpretation, Vocabulary};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, ProofValidationError, ProofValidity};
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{Multibase, MultibaseBuf};
use ssi_verification_methods_core::{
    JwkVerificationMethod, MessageSignatureError, SigningMethod, VerificationMethodSet, VerifyBytes,
};
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

    #[error("unsupported key type: `{0}`")]
    UnsupportedKeyType(String),

    #[error(transparent)]
    Jwk(#[from] ssi_jwk::Error),
}

impl Multikey {
    pub const NAME: &'static str = MULTIKEY_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#Multikey");

    pub fn public_key_jwk(&self) -> JWK {
        self.public_key.to_jwk()
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
        let key = self.public_key_jwk();
        Ok(
            ssi_jws::verify_bytes(algorithm.into(), signing_bytes, &key, signature)
                .map_err(|_| InvalidProof::Signature),
        )
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

impl JwkVerificationMethod for Multikey {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Owned(self.public_key_jwk())
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

#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Multibase-encoded public key.
    encoded: MultibaseBuf,

    codec: u64,

    /// Decoded public key.
    decoded: JWK,
}

impl PublicKey {
    pub fn decode(encoded: MultibaseBuf) -> Result<Self, InvalidPublicKey> {
        let pk_multi_encoded = MultiEncodedBuf::new(encoded.decode()?.1)?;

        let (codec, pk_data) = pk_multi_encoded.parts();
        let decoded = match codec {
            #[cfg(feature = "ed25519")]
            ssi_multicodec::ED25519_PUB => ssi_jwk::ed25519_parse(pk_data)?,
            #[cfg(feature = "secp256k1")]
            ssi_multicodec::SECP256K1_PUB => ssi_jwk::secp256k1_parse(pk_data)?,
            #[cfg(feature = "secp256r1")]
            ssi_multicodec::P256_PUB => ssi_jwk::p256_parse(pk_data)?,
            #[cfg(feature = "secp384r1")]
            ssi_multicodec::P384_PUB => ssi_jwk::p384_parse(pk_data)?,
            c => return Err(InvalidPublicKey::UnsupportedKeyType(format!("{c:#x}")))?,
        };
        Ok(Self {
            encoded,
            codec,
            decoded,
        })
    }

    pub fn codec(&self) -> u64 {
        self.codec
    }

    pub fn encoded(&self) -> &Multibase {
        &self.encoded
    }

    pub fn to_jwk(&self) -> JWK {
        self.decoded.clone()
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
