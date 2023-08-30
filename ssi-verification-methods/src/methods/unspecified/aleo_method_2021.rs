use std::hash::Hash;

use iref::{Iri, IriBuf, UriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use static_iref::iri;

use crate::{
    covariance_rule, ExpectedType, Referencable, TypedVerificationMethod, VerificationMethod,
};

pub const ALEO_METHOD_2021_IRI: &Iri = iri!("https://w3id.org/security#AleoMethod2021");

pub const ALEO_METHOD_2021_TYPE: &str = "AleoMethod2021";

/// Aleo Method 2021.
///
/// Schnorr signature with [Edwards BLS12] curve
/// https://developer.aleo.org/aleo/concepts/accounts
///
/// The verification method object must have a [blockchainAccountId] property, identifying the
/// signer's Aleo
/// account address and network id for verification purposes. The chain id part of the account address
/// identifies an Aleo network as specified in the proposed [CAIP for Aleo Blockchain
/// Reference][caip-aleo-chain-ref]. Signatures use parameters defined per network. Currently only
/// network id "1" (CAIP-2 "aleo:1" / [Aleo Testnet I][testnet1]) is supported. The account
/// address format is documented in [Aleo
/// documentation](https://developer.aleo.org/aleo/concepts/accounts#account-address).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, LinkedData)]
#[serde(tag = "type", rename = "AleoMethod2021")]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[ld(type = "sec:AleoMethod2021")]
pub struct AleoMethod2021 {
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

impl Referencable for AleoMethod2021 {
    type Reference<'a> = &'a Self where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl VerificationMethod for AleoMethod2021 {
    fn id(&self) -> &Iri {
        self.id.as_iri()
    }

    fn controller(&self) -> Option<&Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for AleoMethod2021 {
    fn expected_type() -> Option<ExpectedType> {
        Some(ALEO_METHOD_2021_TYPE.to_string().into())
    }

    fn type_(&self) -> &str {
        ALEO_METHOD_2021_TYPE
    }
}
