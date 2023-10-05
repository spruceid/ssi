use std::hash::Hash;

use ed25519_dalek::{Signer, Verifier};
use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_jws::CompactJWSString;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SignatureError, TypedVerificationMethod, VerificationError, VerificationMethod,
};

/// Ed25519 Verification Key 2018 type name.
pub const ED25519_VERIFICATION_KEY_2018_TYPE: &str = "Ed25519VerificationKey2018";

/// Deprecated verification method for the `Ed25519Signature2018` suite.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/#the-ed25519-key-format>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
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
    pub public_key_base58: String,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidPublicKey {
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::SignatureError),
}

impl Ed25519VerificationKey2018 {
    pub fn decode_public_key(&self) -> Result<ed25519_dalek::PublicKey, InvalidPublicKey> {
        let pk_bytes = multibase::Base::Base58Btc.decode(&self.public_key_base58)?;
        let pk = ed25519_dalek::PublicKey::from_bytes(&pk_bytes)?;
        Ok(pk)
    }

    pub fn sign(
        &self,
        data: &[u8],
        key_pair: &ed25519_dalek::Keypair,
    ) -> Result<CompactJWSString, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(ssi_jwk::Algorithm::EdDSA, None);
        let signing_bytes = header.encode_signing_bytes(data);
        let signature = key_pair.sign(&signing_bytes);

        Ok(ssi_jws::CompactJWSString::from_signing_bytes_and_signature(
            signing_bytes,
            signature.to_bytes(),
        )
        .unwrap())
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

impl Referencable for Ed25519VerificationKey2018 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for Ed25519VerificationKey2018 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
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

impl TryFrom<GenericVerificationMethod> for Ed25519VerificationKey2018 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            public_key_base58: m
                .properties
                .get("publicKeyBase58")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("publicKeyBase58"))?
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("publicKeyBase58"))?
                .to_owned(),
        })
    }
}
