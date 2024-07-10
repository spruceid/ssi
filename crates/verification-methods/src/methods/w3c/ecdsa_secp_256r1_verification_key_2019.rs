use iref::{Iri, IriBuf, UriBuf};
use rdf_types::{Interpretation, Vocabulary};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use ssi_security::{Multibase, MultibaseBuf};
use ssi_verification_methods_core::{JwkVerificationMethod, VerificationMethodSet, VerifyBytes};
use static_iref::iri;
use std::{borrow::Cow, hash::Hash, str::FromStr};

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, TypedVerificationMethod,
    VerificationMethod,
};

pub const ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE: &str = "EcdsaSecp256r1VerificationKey2019";

// pub const ECDSA_SECP_256R1_VERIFICATION_KEY_2019_IRI: &Iri =
//     iri!("https://w3id.org/security#EcdsaSecp256r1VerificationKey2019");

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Multicodec(#[from] ssi_multicodec::Error),

    #[error("invalid key type")]
    InvalidKeyType,

    #[error(transparent)]
    P256(#[from] p256::elliptic_curve::Error),
}

/// Key for [Ecdsa Secp256r1 Signature 2019][1].
///
/// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1verificationkey2019>
///
/// [1]: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
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
#[serde(tag = "type", rename = "EcdsaSecp256r1VerificationKey2019")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:EcdsaSecp256r1VerificationKey2019")]
pub struct EcdsaSecp256r1VerificationKey2019 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Key controller.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public key.
    #[serde(rename = "publicKeyMultibase")]
    #[ld("sec:publicKeyMultibase")]
    pub public_key: PublicKey,
}

pub enum SecretKeyRef<'a> {
    P256(&'a p256::SecretKey),
    Jwk(&'a JWK),
}

impl<'a> From<&'a p256::SecretKey> for SecretKeyRef<'a> {
    fn from(value: &'a p256::SecretKey) -> Self {
        Self::P256(value)
    }
}

impl<'a> From<&'a JWK> for SecretKeyRef<'a> {
    fn from(value: &'a JWK) -> Self {
        Self::Jwk(value)
    }
}

impl EcdsaSecp256r1VerificationKey2019 {
    pub const NAME: &'static str = ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE;
    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#EcdsaSecp256r1VerificationKey2019");

    pub fn public_key_jwk(&self) -> JWK {
        self.public_key.to_jwk()
    }

    pub fn sign_bytes<'a>(
        &self,
        secret_key: impl Into<SecretKeyRef<'a>>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        use p256::ecdsa::signature::Signer;

        match secret_key.into() {
            SecretKeyRef::P256(secret_key) => {
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                let signature: p256::ecdsa::Signature =
                    signing_key.try_sign(signing_bytes).unwrap();
                Ok(signature.to_bytes().to_vec())
            }
            SecretKeyRef::Jwk(secret_key) => {
                let algorithm = ssi_jwk::Algorithm::ES256;
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
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature = p256::ecdsa::Signature::try_from(signature_bytes)
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        Ok(self.public_key.verify(data, &signature))
    }
}

impl VerificationMethod for EcdsaSecp256r1VerificationKey2019 {
    /// Returns the identifier of the key.
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    /// Returns an URI to the key controller.
    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for EcdsaSecp256r1VerificationKey2019 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for EcdsaSecp256r1VerificationKey2019 {
    fn expected_type() -> Option<ExpectedType> {
        Some(
            ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE
                .to_string()
                .into(),
        )
    }

    fn type_match(ty: &str) -> bool {
        ty == ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE
    }

    /// Returns the type of the key.
    fn type_(&self) -> &str {
        ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE
    }
}

impl JwkVerificationMethod for EcdsaSecp256r1VerificationKey2019 {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Owned(self.public_key_jwk())
    }
}

impl VerifyBytes<ssi_crypto::algorithm::ES256> for EcdsaSecp256r1VerificationKey2019 {
    fn verify_bytes(
        &self,
        _: ssi_crypto::algorithm::ES256,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        self.verify_bytes(signing_bytes, signature)
    }
}

impl TryFrom<GenericVerificationMethod> for EcdsaSecp256r1VerificationKey2019 {
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

/// Public key of an Ed25519 Verification Key 2020 verification method.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Public key encoded according to [MULTICODEC] and formatted according to
    /// [MULTIBASE].
    ///
    /// The multicodec encoding of an P256 public key is the
    /// two-byte prefix 0x1200 followed by the public key data. The value is
    /// then encoded using base58-btc (z) as the prefix.
    encoded: MultibaseBuf,

    /// Decoded public key.
    decoded: p256::PublicKey,
}

impl PublicKey {
    pub fn decode(encoded: MultibaseBuf) -> Result<Self, InvalidPublicKey> {
        let pk_multi_encoded = MultiEncodedBuf::new(encoded.decode()?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::P256_PUB {
            let decoded = p256::PublicKey::from_sec1_bytes(pk_data)?;
            Ok(Self { encoded, decoded })
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn encoded(&self) -> &Multibase {
        &self.encoded
    }

    pub fn decoded(&self) -> &p256::PublicKey {
        &self.decoded
    }

    pub fn to_jwk(&self) -> JWK {
        self.decoded.into()
    }

    pub fn verify(&self, data: &[u8], signature: &p256::ecdsa::Signature) -> ProofValidity {
        use p256::ecdsa::signature::Verifier;
        let verifying_key = p256::ecdsa::VerifyingKey::from(self.decoded);
        verifying_key
            .verify(data, signature)
            .map_err(|_| InvalidProof::Signature)
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
