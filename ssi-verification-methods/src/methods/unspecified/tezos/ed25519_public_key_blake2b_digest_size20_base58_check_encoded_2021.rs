use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_crypto::MessageSignatureError;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{CompactJWSStr, Header};

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, SigningMethod, TypedVerificationMethod, VerificationError, VerificationMethod,
};

pub const ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE: &str =
    "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(
    tag = "type",
    rename = "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021")]
pub struct Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Blockchain account id.
    #[serde(rename = "blockchainAccountId")]
    #[ld("sec:blockchainAccountId")]
    pub blockchain_account_id: ssi_caips::caip10::BlockchainAccountId,
}

impl Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    pub fn matches_public_key(&self, public_key: &JWK) -> Result<bool, VerificationError> {
        use ssi_caips::caip10::BlockchainAccountIdVerifyError as VerifyError;
        match self.blockchain_account_id.verify(public_key) {
            Err(VerifyError::UnknownChainId(_) | VerifyError::HashError(_)) => {
                Err(VerificationError::InvalidKey)
            }
            Err(VerifyError::KeyMismatch(_, _)) => Ok(false),
            Ok(()) => Ok(true),
        }
    }
}

impl Referencable for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(
            ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE
                .to_string()
                .into(),
        )
    }

    fn type_match(ty: &str) -> bool {
        ty == ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE
    }

    fn type_(&self) -> &str {
        ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod>
    for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
{
    type Error = InvalidVerificationMethod;

    fn try_from(value: GenericVerificationMethod) -> Result<Self, Self::Error> {
        if value.type_ == ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE {
            Ok(Self {
                id: value.id,
                controller: value.controller,
                blockchain_account_id: value
                    .properties
                    .get("blockchainAccountId")
                    .ok_or_else(|| {
                        InvalidVerificationMethod::missing_property("blockchainAccountId")
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        InvalidVerificationMethod::invalid_property("blockchainAccountId")
                    })?
                    .parse()
                    .map_err(|_| {
                        InvalidVerificationMethod::invalid_property("blockchainAccountId")
                    })?,
            })
        } else {
            Err(InvalidVerificationMethod::InvalidTypeName(value.type_))
        }
    }
}

fn build_signing_bytes(bytes: &[u8], public_key: &JWK) -> (Header, Vec<u8>) {
    let header = ssi_jws::Header::new_unencoded(Algorithm::EdBlake2b, public_key.key_id.clone());
    let signing_bytes = header.encode_signing_bytes(bytes);
    (header, signing_bytes)
}

impl SigningMethod<JWK> for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    fn sign_ref(
        _this: &Self,
        key: &JWK,
        _protocol: (),
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(Algorithm::EdBlake2b, bytes, key)
            .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))
    }
}