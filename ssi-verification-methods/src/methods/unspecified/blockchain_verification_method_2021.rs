use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use static_iref::iri;

use crate::{
    covariance_rule, ExpectedType, Referencable, TypedVerificationMethod, VerificationMethod,
};

pub const BLOCKCHAIN_VERIFICATION_METHOD_2021_IRI: &Iri =
    iri!("https://w3id.org/security#BlockchainVerificationMethod2021");

pub const BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE: &str = "BlockchainVerificationMethod2021";

/// BlockchainVerificationMethod2021.
///
/// See: <https://w3id.org/security#BlockchainVerificationMethod2021>.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(tag = "type", rename = "BlockchainVerificationMethod2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:BlockchainVerificationMethod2021")]
pub struct BlockchainVerificationMethod2021 {
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

impl Referencable for BlockchainVerificationMethod2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for BlockchainVerificationMethod2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for BlockchainVerificationMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        BLOCKCHAIN_VERIFICATION_METHOD_2021_TYPE
    }
}
