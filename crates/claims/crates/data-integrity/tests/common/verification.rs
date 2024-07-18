#![allow(unused)]
use std::collections::HashMap;

use iref::IriBuf;
use serde::Deserialize;
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::AnyDataIntegrity;
use ssi_verification_methods::AnyMethod;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationTest {
    pub id: Option<IriBuf>,
    pub verification_methods: HashMap<IriBuf, AnyMethod>,
    pub input: AnyDataIntegrity,
}

impl VerificationTest {
    pub async fn run(self) {
        let params = VerificationParameters::from_resolver(self.verification_methods);
        let result = self.input.verify(params).await.unwrap();

        if let Err(e) = result {
            match self.id {
                Some(id) => panic!("<{}> verification failed: {e}", id),
                None => panic!("verification failed: {e}"),
            }
        }
    }
}
