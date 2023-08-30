use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;
use static_iref::iri;

use crate::{
    covariance_rule, ExpectedType, Referencable, TypedVerificationMethod, VerificationError,
    VerificationMethod,
};

pub const ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_IRI: &Iri =
    iri!("https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021");

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

    fn type_(&self) -> &str {
        ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE
    }
}
