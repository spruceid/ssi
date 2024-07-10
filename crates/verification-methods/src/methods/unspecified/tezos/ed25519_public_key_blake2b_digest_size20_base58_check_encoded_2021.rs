use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{InvalidProof, MessageSignatureError, ProofValidationError, ProofValidity};
use ssi_jwk::{Algorithm, JWK};
use ssi_verification_methods_core::{VerificationMethodSet, VerifyBytesWithRecoveryJwk};
use static_iref::iri;

use crate::{
    ExpectedType, GenericVerificationMethod, InvalidVerificationMethod, SigningMethod,
    TypedVerificationMethod, VerificationMethod,
};

pub const ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE: &str =
    "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021";

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
    pub const NAME: &'static str = "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021";
    pub const IRI: &'static Iri =
        iri!("https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021");

    pub fn matches_public_key(&self, public_key: &JWK) -> Result<bool, ProofValidationError> {
        use ssi_caips::caip10::BlockchainAccountIdVerifyError as VerifyError;
        match self.blockchain_account_id.verify(public_key) {
            Err(VerifyError::UnknownChainId(_) | VerifyError::HashError(_)) => {
                Err(ProofValidationError::InvalidKey)
            }
            Err(VerifyError::KeyMismatch(_, _)) => Ok(false),
            Ok(()) => Ok(true),
        }
    }
}

impl<A> VerifyBytesWithRecoveryJwk<A> for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
where
    A: Into<ssi_jwk::Algorithm>,
{
    fn verify_bytes_with_public_jwk(
        &self,
        public_jwk: &JWK,
        algorithm: A,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ProofValidity, ProofValidationError> {
        if self.matches_public_key(public_jwk)? {
            Ok(
                ssi_jws::verify_bytes(algorithm.into(), signing_bytes, public_jwk, signature)
                    .map_err(|_| InvalidProof::Signature),
            )
        } else {
            Ok(Err(InvalidProof::KeyMismatch))
        }
    }
}

impl VerificationMethod for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl VerificationMethodSet for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021 {
    type TypeSet = &'static str;

    fn type_set() -> Self::TypeSet {
        Self::NAME
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
            Err(InvalidVerificationMethod::invalid_type_name(
                &value.type_,
                ED25519_PUBLIC_KEY_BLAKE2B_DIGEST_SIZE20_BASE58_CHECK_ENCODED_2021_TYPE,
            ))
        }
    }
}

impl SigningMethod<JWK, ssi_crypto::algorithm::EdBlake2b>
    for Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
{
    fn sign_bytes(
        &self,
        key: &JWK,
        _algorithm: ssi_crypto::algorithm::EdBlake2b,
        bytes: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        ssi_jws::sign_bytes(Algorithm::EdBlake2b, bytes, key)
            .map_err(MessageSignatureError::signature_failed)
    }
}
