use std::{borrow::Cow, hash::Hash, str::FromStr};

use hex::FromHexError;
use iref::{Iri, IriBuf, UriBuf};
use rdf_types::{Interpretation, Vocabulary};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_jwk::JWK;
use ssi_verification_methods_core::{JwkVerificationMethod, VerificationMethodSet, VerifyBytes};
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
};

pub const ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE: &str = "EcdsaSecp256k1VerificationKey2019";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestFunction {
    Sha256,
    Keccack,
}

impl DigestFunction {
    pub fn into_crypto_algorithm(self) -> ssi_jwk::Algorithm {
        match self {
            Self::Sha256 => ssi_jwk::Algorithm::ES256K,
            Self::Keccack => ssi_jwk::Algorithm::ESKeccakK,
        }
    }
}

/// Key for [Ecdsa Secp256k1 Signature 2019][1].
///
/// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/#key-format>
///
/// [1]: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
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
#[serde(tag = "type", rename = "EcdsaSecp256k1VerificationKey2019")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:EcdsaSecp256k1VerificationKey2019")]
pub struct EcdsaSecp256k1VerificationKey2019 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Key controller.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public key.
    #[serde(flatten)]
    #[ld(flatten)]
    pub public_key: PublicKey,
}

impl EcdsaSecp256k1VerificationKey2019 {
    pub const NAME: &'static str = ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE;
    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019");

    pub fn public_key_jwk(&self) -> Cow<JWK> {
        self.public_key.to_jwk()
    }

    pub fn sign_bytes(
        &self,
        secret_key: &JWK,
        digest_function: DigestFunction,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let algorithm = digest_function.into_crypto_algorithm();
        let key_algorithm = secret_key.algorithm.unwrap_or(algorithm);
        if !algorithm.is_compatible_with(key_algorithm) {
            return Err(MessageSignatureError::InvalidSecretKey);
        }

        // let header = ssi_jws::Header::new_unencoded(algorithm, None);
        // let signing_bytes = header.encode_signing_bytes(data);
        ssi_jws::sign_bytes(algorithm, signing_bytes, secret_key)
            .map_err(|_| MessageSignatureError::InvalidSecretKey)
        // Ok(JwsBuf::from_signing_bytes_and_signature(signing_bytes, signature).unwrap())
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature: &[u8],
        digest_function: DigestFunction,
    ) -> Result<ProofValidity, ProofValidationError> {
        let public_key = self.public_key.to_jwk();
        let algorithm = digest_function.into_crypto_algorithm();
        if !algorithm.is_compatible_with(public_key.algorithm.unwrap_or(algorithm)) {
            return Err(ProofValidationError::InvalidKey);
        }

        Ok(
            ssi_jws::verify_bytes(ssi_jwk::Algorithm::ES256K, data, &public_key, signature)
                .map_err(|_| InvalidProof::Signature),
        )
    }
}

impl VerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for EcdsaSecp256k1VerificationKey2019 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    fn expected_type() -> Option<ExpectedType> {
        Some(
            ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
                .to_string()
                .into(),
        )
    }

    fn type_match(ty: &str) -> bool {
        ty == ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256K1_VERIFICATION_KEY_2019_TYPE
    }
}

impl JwkVerificationMethod for EcdsaSecp256k1VerificationKey2019 {
    fn to_jwk(&self) -> Cow<JWK> {
        self.public_key_jwk()
    }
}

impl VerifyBytes<ssi_crypto::algorithm::ES256K> for EcdsaSecp256k1VerificationKey2019 {
    fn verify_bytes(
        &self,
        _: ssi_crypto::algorithm::ES256K,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        self.verify_bytes(signing_bytes, signature, DigestFunction::Sha256)
    }
}

impl TryFrom<GenericVerificationMethod> for EcdsaSecp256k1VerificationKey2019 {
    type Error = InvalidVerificationMethod;

    fn try_from(mut m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        let public_key = match (
            m.properties.remove("publicKeyJwk"),
            m.properties.get("publicKeyHex"),
        ) {
            (Some(k), None) => PublicKey::Jwk(
                serde_json::from_value(k)
                    .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyJwk"))?,
            ),
            (None, Some(k)) => PublicKey::Hex(Box::new(
                k.as_str()
                    .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyHex"))?
                    .parse()
                    .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyHex"))?,
            )),
            (Some(_), Some(_)) => return Err(InvalidVerificationMethod::AmbiguousPublicKey),
            (None, None) => {
                return Err(InvalidVerificationMethod::missing_property("publicKeyJwk"))
            }
        };

        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key,
        })
    }
}

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
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub enum PublicKey {
    #[serde(rename = "publicKeyJwk")]
    #[ld("sec:publicKeyJwk")]
    Jwk(Box<JWK>),

    #[serde(rename = "publicKeyHex")]
    #[ld("sec:publicKeyHex")]
    Hex(Box<PublicKeyHex>),
}

impl PublicKey {
    pub fn to_jwk(&self) -> Cow<JWK> {
        match self {
            Self::Jwk(jwk) => Cow::Borrowed(jwk),
            Self::Hex(hex) => Cow::Owned(hex.to_jwk()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PublicKeyHex {
    encoded: String,
    decoded: k256::PublicKey,
}

impl PublicKeyHex {
    pub fn decode(encoded: String) -> Result<Self, InvalidPublicKey> {
        let bytes = hex::decode(&encoded)?;
        let decoded = k256::PublicKey::from_sec1_bytes(&bytes)?;

        Ok(Self { encoded, decoded })
    }

    pub fn to_jwk(&self) -> JWK {
        self.decoded.into()
    }
}

impl PartialEq for PublicKeyHex {
    fn eq(&self, other: &Self) -> bool {
        self.decoded.eq(&other.decoded)
    }
}

impl Eq for PublicKeyHex {}

impl Hash for PublicKeyHex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state)
    }
}

impl Serialize for PublicKeyHex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.encoded.serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for PublicKeyHex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        use serde::de::Error;
        let encoded = String::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl FromStr for PublicKeyHex {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s.to_owned())
    }
}

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataResource<I, V> for PublicKeyHex
where
    String: linked_data::LinkedDataResource<I, V>,
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        self.encoded.interpretation(vocabulary, interpretation)
    }
}

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataSubject<I, V> for PublicKeyHex
where
    String: linked_data::LinkedDataSubject<I, V>,
{
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        self.encoded.visit_subject(serializer)
    }
}

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataPredicateObjects<I, V>
    for PublicKeyHex
where
    String: linked_data::LinkedDataPredicateObjects<I, V>,
{
    fn visit_objects<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        self.encoded.visit_objects(visitor)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] FromHexError),

    #[error("invalid key bytes: {0}")]
    K256(#[from] k256::elliptic_curve::Error),
}

impl From<InvalidPublicKey> for ProofValidationError {
    fn from(_value: InvalidPublicKey) -> Self {
        Self::InvalidKey
    }
}
