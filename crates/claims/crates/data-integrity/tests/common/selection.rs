#![allow(unused)]
use std::collections::HashMap;

use iref::IriBuf;
use json_syntax::Print;
use serde::Deserialize;
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::{AnyDataIntegrity, AnySelectionOptions};
use ssi_verification_methods::AnyMethod;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectionTest {
    pub id: Option<IriBuf>,
    pub verification_methods: HashMap<IriBuf, AnyMethod>,
    pub options: AnySelectionOptions,
    pub input: AnyDataIntegrity,
    pub expected_output: json_syntax::Value,
}

impl SelectionTest {
    pub async fn run(mut self) {
        let params = VerificationParameters::from_resolver(self.verification_methods);

        let vc = self.input.select(params, self.options).await.unwrap();

        let mut json = json_syntax::to_value(vc).unwrap();
        json.canonicalize();

        self.expected_output.canonicalize();

        if json != self.expected_output {
            eprintln!("expected: {}", self.expected_output.pretty_print());
            eprintln!("found: {}", json.pretty_print());
            match self.id {
                Some(id) => panic!("test <{}> failed", id),
                None => panic!("test failed"),
            }
        }
    }
}
