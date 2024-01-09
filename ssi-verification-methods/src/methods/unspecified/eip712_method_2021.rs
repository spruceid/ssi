use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

use crate::{
    covariance_rule, ExpectedType, GenericVerificationMethod, InvalidVerificationMethod,
    Referencable, TypedVerificationMethod, VerificationError, VerificationMethod,
};

// mod context;
// pub use context::*;

// pub const EIP712_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#Eip712Method2021");

pub const EIP712_METHOD_2021_TYPE: &str = "Eip712Method2021";

/// `Eip712Method2021`.
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
#[serde(tag = "type", rename = "Eip712Method2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:Eip712Method2021")]
pub struct Eip712Method2021 {
    /// Key identifier.
    #[ld(id)]
    pub id: IriBuf,

    /// Controller of the verification method.
    #[ld("sec:controller")]
    pub controller: UriBuf,

    /// Blockchain accound ID.
    #[serde(rename = "blockchainAccountId")]
    #[ld("sec:blockchainAccountId")]
    pub blockchain_account_id: ssi_caips::caip10::BlockchainAccountId,
}

impl Eip712Method2021 {
    pub fn verify_bytes(
        &self,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        // Interpret the signature.
        let signature = k256::ecdsa::Signature::try_from(&signature_bytes[..64])
            .map_err(|_| VerificationError::InvalidSignature)?;

        // Recover the signing key.
        let rec_id = k256::ecdsa::recoverable::Id::try_from(signature_bytes[64] % 27)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let sig = k256::ecdsa::recoverable::Signature::new(&signature, rec_id)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let recovered_key = sig
            .recover_verifying_key(data)
            .map_err(|_| VerificationError::InvalidSignature)?;

        // Check the signing key.
        let jwk = JWK {
            params: ssi_jwk::Params::EC(
                ssi_jwk::ECParams::try_from(
                    &k256::PublicKey::from_sec1_bytes(&recovered_key.to_bytes().as_slice())
                        .unwrap(),
                )
                .unwrap(),
            ),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        self.blockchain_account_id
            .verify(&jwk)
            .map_err(|_| VerificationError::InvalidKey)?;

        Ok(true)
    }
}

impl Referencable for Eip712Method2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for Eip712Method2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

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

impl TypedVerificationMethod for Eip712Method2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(EIP712_METHOD_2021_TYPE.to_string().into())
    }

    fn type_match(ty: &str) -> bool {
        ty == EIP712_METHOD_2021_TYPE
    }

    fn type_(&self) -> &str {
        EIP712_METHOD_2021_TYPE
    }

    fn ref_type<'a>(_r: Self::Reference<'a>) -> &'a str {
        EIP712_METHOD_2021_TYPE
    }
}

impl TryFrom<GenericVerificationMethod> for Eip712Method2021 {
    type Error = InvalidVerificationMethod;

    fn try_from(m: GenericVerificationMethod) -> Result<Self, Self::Error> {
        Ok(Self {
            id: m.id,
            controller: m.controller,
            blockchain_account_id: m
                .properties
                .get("blockchainAccountId")
                .ok_or_else(|| InvalidVerificationMethod::missing_property("blockchainAccountId"))?
                .as_str()
                .ok_or_else(|| InvalidVerificationMethod::invalid_property("blockchainAccountId"))?
                .parse()
                .map_err(|_| InvalidVerificationMethod::invalid_property("blockchainAccountId"))?,
        })
    }
}