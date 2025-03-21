use std::{borrow::Cow, hash::Hash, str::FromStr};

use ed25519_dalek::{Signer, Verifier};
use iref::{Iri, IriBuf, UriBuf};
use rdf_types::{Interpretation, Vocabulary};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{
    InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity, SignatureError,
};
use ssi_jwk::JWK;
use ssi_jws::JwsString;
use ssi_verification_methods_core::{JwkVerificationMethod, VerificationMethodSet, VerifyBytes};
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, SigningMethod,
    TypedVerificationMethod, VerificationMethod,
};

/// Ed25519 Verification Key 2018 type name.
pub const ED25519_VERIFICATION_KEY_2018_TYPE: &str = "Ed25519VerificationKey2018";

/// Deprecated verification method for the `Ed25519Signature2018` suite.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/#the-ed25519-key-format>
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
#[serde(tag = "type", rename = "Ed25519VerificationKey2018")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:Ed25519VerificationKey2018")]
pub struct Ed25519VerificationKey2018 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Public key encoded in base58 using the same alphabet as Bitcoin
    /// addresses and IPFS hashes.
    #[serde(rename = "publicKeyBase58")]
    #[ld("sec:publicKeyBase58")]
    pub public_key: PublicKey,
}

impl Ed25519VerificationKey2018 {
    pub const NAME: &'static str = ED25519_VERIFICATION_KEY_2018_TYPE;
    pub const IRI: &'static Iri = iri!("https://w3id.org/security#Ed25519VerificationKey2018");

    pub fn public_key_jwk(&self) -> JWK {
        self.public_key.to_jwk()
    }

    pub fn sign(
        &self,
        data: &[u8],
        secret_key: &ed25519_dalek::SigningKey,
    ) -> Result<JwsString, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(ssi_jwk::Algorithm::EdDSA, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = secret_key.sign(&signing_bytes);

        Ok(ssi_jws::JwsString::from_signing_bytes_and_signature(
            // TODO base64 encode signature?
            signing_bytes,
            signature.to_bytes(),
        )
        .unwrap())
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        let signature = ed25519_dalek::Signature::try_from(signature_bytes)
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        Ok(self.public_key.verify(data, &signature))
    }
}

impl VerificationMethod for Ed25519VerificationKey2018 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for Ed25519VerificationKey2018 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
    }
}

impl TypedVerificationMethod for Ed25519VerificationKey2018 {
    fn expected_type() -> Option<ExpectedType> {
        Some(ED25519_VERIFICATION_KEY_2018_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == ED25519_VERIFICATION_KEY_2018_TYPE
    }

    fn type_(&self) -> &str {
        ED25519_VERIFICATION_KEY_2018_TYPE
    }
}

impl JwkVerificationMethod for Ed25519VerificationKey2018 {
    fn to_jwk(&self) -> Cow<JWK> {
        Cow::Owned(self.public_key_jwk())
    }
}

impl TryFrom<GenericVerificationMethod> for Ed25519VerificationKey2018 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key: m
                .properties
                .get("publicKeyBase58")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyBase58"))?
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyBase58"))?
                .parse()
                .map_err(|_| InvalidVerificationMethod::invalid_property("publicKeyBase58"))?,
        })
    }
}

impl SigningMethod<JWK, ssi_crypto::algorithm::EdDSA> for Ed25519VerificationKey2018 {
    fn sign_bytes(
        &self,
        secret: &JWK,
        _algorithm: ssi_crypto::algorithm::EdDSA,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(ssi_jwk::Algorithm::EdDSA, bytes, secret)
            .map_err(MessageSignatureError::signature_failed)
    }
}

impl VerifyBytes<ssi_crypto::algorithm::EdDSA> for Ed25519VerificationKey2018 {
    fn verify_bytes(
        &self,
        _: ssi_crypto::algorithm::EdDSA,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        self.verify_bytes(signing_bytes, signature)
    }
}

/// Public key of an Ed25519 Verification Key 2018 verification method.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Base58-BTC encoded public key.
    encoded: String,

    /// Decoded public key.
    decoded: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    pub fn decode(encoded: String) -> Result<Self, InvalidPublicKey> {
        let pk_bytes = multibase::Base::Base58Btc.decode(&encoded)?;
        let decoded = ed25519_dalek::VerifyingKey::try_from(pk_bytes.as_slice())?;
        Ok(Self { encoded, decoded })
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn decoded(&self) -> &ed25519_dalek::VerifyingKey {
        &self.decoded
    }

    pub fn to_jwk(&self) -> JWK {
        self.decoded.into()
    }

    pub fn verify(&self, data: &[u8], signature: &ed25519_dalek::Signature) -> ProofValidity {
        self.decoded
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
        let encoded = String::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl FromStr for PublicKey {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s.to_owned())
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

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataSubject<I, V> for PublicKey
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

impl<I: Interpretation, V: Vocabulary> linked_data::LinkedDataPredicateObjects<I, V> for PublicKey
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
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::SignatureError),
}
