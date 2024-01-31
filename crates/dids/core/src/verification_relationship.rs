/// A [verification relationship](https://w3c.github.io/did-core/#dfn-verification-relationship).
///
/// The relationship between a [verification method][VerificationMethod] and a DID
/// Subject (as described by a [DID Document][Document]) is considered analogous to a [proof
/// purpose](crate::vc::ProofPurpose).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
pub enum VerificationRelationship {
    AssertionMethod,
    Authentication,
    KeyAgreement,
    ContractAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

impl Default for VerificationRelationship {
    fn default() -> Self {
        Self::AssertionMethod
    }
}

impl FromStr for VerificationRelationship {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "contractAgreement" => Ok(Self::ContractAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            _ => Err(Error::UnsupportedVerificationRelationship),
        }
    }
}

impl TryFrom<String> for VerificationRelationship {
    type Error = Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<VerificationRelationship> for String {
    fn from(purpose: VerificationRelationship) -> String {
        match purpose {
            VerificationRelationship::Authentication => "authentication".to_string(),
            VerificationRelationship::AssertionMethod => "assertionMethod".to_string(),
            VerificationRelationship::KeyAgreement => "keyAgreement".to_string(),
            VerificationRelationship::ContractAgreement => "contractAgreement".to_string(),
            VerificationRelationship::CapabilityInvocation => "capabilityInvocation".to_string(),
            VerificationRelationship::CapabilityDelegation => "capabilityDelegation".to_string(),
        }
    }
}

impl VerificationRelationship {
    pub fn to_iri(&self) -> &Iri {
        match self {
            VerificationRelationship::Authentication => {
                iri!("https://w3id.org/security#authenticationMethod")
            }
            VerificationRelationship::AssertionMethod => {
                iri!("https://w3id.org/security#assertionMethod")
            }
            VerificationRelationship::KeyAgreement => {
                iri!("https://w3id.org/security#keyAgreementMethod")
            }
            VerificationRelationship::ContractAgreement => {
                iri!("https://w3id.org/security#contractAgreementMethod")
            }
            VerificationRelationship::CapabilityInvocation => {
                iri!("https://w3id.org/security#capabilityInvocationMethod")
            }
            VerificationRelationship::CapabilityDelegation => {
                iri!("https://w3id.org/security#capabilityDelegationMethod")
            }
        }
    }
}