use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_core::{Referencable, covariance_rule};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;
use static_iref::iri;
use std::hash::Hash;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    TypedVerificationMethod, VerificationError, VerificationMethod,
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

    /// Public key encoded according to [MULTICODEC] and formatted according to
    /// [MULTIBASE].
    ///
    /// The multicodec encoding of an Ed25519 public key is the
    /// two-byte prefix 0xed01 followed by the 32-byte public key data. The 34
    /// byte value is then encoded using base58-btc (z) as the prefix. Any other
    /// encoding MUST NOT be allowed.
    #[serde(rename = "publicKeyMultibase")]
    #[ld("sec:publicKeyMultibase")]
    pub public_key_multibase: String,
}

pub enum SecretKeyRef<'a> {
    P256(&'a p256::SecretKey),
    JWK(&'a JWK),
}

impl<'a> From<&'a p256::SecretKey> for SecretKeyRef<'a> {
    fn from(value: &'a p256::SecretKey) -> Self {
        Self::P256(value)
    }
}

impl<'a> From<&'a JWK> for SecretKeyRef<'a> {
    fn from(value: &'a JWK) -> Self {
        Self::JWK(value)
    }
}

impl EcdsaSecp256r1VerificationKey2019 {
    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#EcdsaSecp256r1VerificationKey2019");

    pub fn decode_public_key(&self) -> Result<p256::PublicKey, InvalidPublicKey> {
        let pk_multi_encoded =
            MultiEncodedBuf::new(multibase::decode(&self.public_key_multibase)?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::P256_PUB {
            let pk = p256::PublicKey::from_sec1_bytes(pk_data)?;
            Ok(pk)
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn sign_bytes<'a>(
        &self,
        secret_key: impl Into<SecretKeyRef<'a>>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        use p256::ecdsa::signature::{Signature, Signer};

        match secret_key.into() {
            SecretKeyRef::P256(secret_key) => {
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                Ok(signing_key
                    .try_sign(signing_bytes)
                    .unwrap()
                    .as_bytes()
                    .to_vec())
            }
            SecretKeyRef::JWK(secret_key) => {
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
    ) -> Result<bool, VerificationError> {
        use p256::ecdsa::signature::Verifier;

        let public_key = self
            .decode_public_key()
            .map_err(|_| VerificationError::InvalidKey)?;
        let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);

        let signature = p256::ecdsa::Signature::try_from(signature_bytes)
            .map_err(|_| VerificationError::InvalidSignature)?;

        Ok(verifying_key.verify(data, &signature).is_ok())
    }
}

impl Referencable for EcdsaSecp256r1VerificationKey2019 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
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

    fn ref_id<'a>(r: Self::Reference<'a>) -> &'a Iri {
        r.id.as_iri()
    }

    fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a Iri> {
        Some(r.controller.as_iri())
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

    fn ref_type<'a>(_r: Self::Reference<'a>) -> &'a str {
        ECDSA_SECP_256R1_VERIFICATION_KEY_2019_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for EcdsaSecp256r1VerificationKey2019 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key_multibase: m
                .properties
                .get("publicKeyMultibase")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyMultibase"))?
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyMultibase"))?
                .to_owned(),
        })
    }
}
