use serde::{Deserialize, Serialize};
use ssi::claims::sd_jwt::{ConcealJwtClaims, SdAlg};
use ssi::json_pointer;
use ssi::prelude::*;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct CredentialClaims {
    name: Option<String>,
    email: Option<String>,
}

impl ssi::claims::jwt::ClaimSet for CredentialClaims {}
impl<E, P> ssi::claims::ValidateClaims<E, P> for CredentialClaims {}

#[async_std::test]
async fn issue_vc() {
    // implement code here - see issue.md
}
