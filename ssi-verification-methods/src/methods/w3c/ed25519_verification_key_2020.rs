use std::hash::Hash;

use ed25519_dalek::{Signer, Verifier};
use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use rand_core_0_5::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::JWK;
use ssi_multicodec::MultiEncodedBuf;

use crate::{
    covariance_rule, ExpectedType, Referencable, SigningMethod, TypedVerificationMethod,
    VerificationError, VerificationMethod, GenericVerificationMethod, InvalidVerificationMethod,
};

/// Ed25519 Verification Key 2020 type name.
pub const ED25519_VERIFICATION_KEY_2020_TYPE: &str = "Ed25519VerificationKey2020";

/// Deprecated verification method for the `Ed25519Signature2020` suite.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#ed25519verificationkey2020>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(tag = "type", rename = "Ed25519VerificationKey2020")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:Ed25519VerificationKey2020")]
pub struct Ed25519VerificationKey2020 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
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

impl Ed25519VerificationKey2020 {
    pub fn generate_key_pair(
        id: IriBuf,
        controller: UriBuf,
        csprng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, ed25519_dalek::SecretKey) {
        let key = ed25519_dalek::Keypair::generate(csprng);
        (
            Self::from_public_key(id, controller, key.public),
            key.secret,
        )
    }

    pub fn from_public_key(
        id: IriBuf,
        controller: UriBuf,
        public_key: ed25519_dalek::PublicKey,
    ) -> Self {
        let bytes = public_key.to_bytes();
        let multi_encoded = MultiEncodedBuf::encode(ssi_multicodec::ED25519_PUB, &bytes);

        Self {
            id,
            controller,
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                multi_encoded.as_bytes(),
            ),
        }
    }

    pub fn decode_public_key(&self) -> Result<ed25519_dalek::PublicKey, InvalidPublicKey> {
        let pk_multi_encoded =
            MultiEncodedBuf::new(multibase::decode(&self.public_key_multibase)?.1)?;

        let (pk_codec, pk_data) = pk_multi_encoded.parts();
        if pk_codec == ssi_multicodec::ED25519_PUB {
            let pk = ed25519_dalek::PublicKey::from_bytes(pk_data)?;
            Ok(pk)
        } else {
            Err(InvalidPublicKey::InvalidKeyType)
        }
    }

    pub fn sign_bytes(&self, data: &[u8], key_pair: &ed25519_dalek::Keypair) -> Vec<u8> {
        let signature = key_pair.sign(data);
        signature.to_bytes().to_vec()
    }

    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let pk = self
            .decode_public_key()
            .map_err(|_| VerificationError::InvalidKey)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
            .map_err(|_| VerificationError::InvalidSignature)?;
        Ok(pk.verify(data, &signature).is_ok())
    }
}

impl Referencable for Ed25519VerificationKey2020 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for Ed25519VerificationKey2020 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for Ed25519VerificationKey2020 {
    fn expected_type() -> Option<ExpectedType> {
        Some(ED25519_VERIFICATION_KEY_2020_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == ED25519_VERIFICATION_KEY_2020_TYPE
    }

    fn type_(&self) -> &str {
        ED25519_VERIFICATION_KEY_2020_TYPE
    }
}

impl SigningMethod<ed25519_dalek::Keypair> for Ed25519VerificationKey2020 {
    fn sign_ref(
        this: &Self,
        secret: &ed25519_dalek::Keypair,
        protocol: (),
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        Ok(this.sign_bytes(message, secret))
    }
}

impl SigningMethod<JWK> for Ed25519VerificationKey2020 {
    fn sign_ref(
        this: &Self,
        secret: &JWK,
        protocol: (),
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        todo!()
    }
}

impl TryFrom<GenericVerificationMethod> for Ed25519VerificationKey2020 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key_multibase: m.properties
                .get("publicKeyMultibase")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyMultibase"))?
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyMultibase"))?
                .to_owned()
        })
    }
}