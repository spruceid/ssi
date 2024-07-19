#![allow(unused)]
use std::collections::HashMap;

use iref::IriBuf;
use json_syntax::Print;
use serde::Deserialize;
use ssi_claims_core::SignatureEnvironment;
use ssi_data_integrity::{
    AnyDataIntegrity, AnySignatureOptions, AnySuite, CryptographicSuite, DataIntegrityDocument,
    ProofConfiguration,
};
use ssi_verification_methods::{multikey::MultikeyPair, AnyMethod, SingleSecretSigner};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureTest {
    pub id: Option<IriBuf>,
    pub key_pair: MultikeyPair,
    pub verification_methods: HashMap<IriBuf, AnyMethod>,
    pub configuration: ProofConfiguration<AnySuite>,
    #[serde(default)]
    pub options: AnySignatureOptions,
    pub input: DataIntegrityDocument,
    pub expected_output: json_syntax::Value,
}

impl SignatureTest {
    pub async fn run(mut self) {
        let (suite, options) = self.configuration.into_suite_and_options();

        let vc: AnyDataIntegrity = suite
            .sign_with(
                SignatureEnvironment::default(),
                self.input,
                &self.verification_methods,
                SingleSecretSigner::new(self.key_pair.secret_jwk().unwrap()).into_local(),
                options.cast(),
                self.options,
            )
            .await
            .unwrap();

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
