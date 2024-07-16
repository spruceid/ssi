use iref::IriBuf;
use json_syntax::Print;
use serde::Deserialize;
use ssi_claims_core::SignatureEnvironment;
use ssi_data_integrity::{
    AnyDataIntegrity, AnySignatureOptions, AnySuite, CryptographicSuite, DataIntegrityDocument,
    ProofConfiguration,
};
use ssi_verification_methods::{multikey::MultikeyPair, LocalSigner};

use super::MultikeyRing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureTest {
    pub id: IriBuf,
    pub key_pair: MultikeyPair,
    pub configuration: ProofConfiguration<AnySuite>,
    pub options: AnySignatureOptions,
    pub input: DataIntegrityDocument,
    pub expected_output: json_syntax::Value,
}

impl SignatureTest {
    pub async fn run(mut self) {
        let mut keys = MultikeyRing::default();
        keys.insert(self.key_pair);

        let (suite, options) = self.configuration.into_suite_and_options();

        let vc: AnyDataIntegrity = suite
            .sign_with(
                SignatureEnvironment::default(),
                self.input,
                &keys,
                LocalSigner(&keys),
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
            panic!("test <{}> failed", self.id);
        }
    }
}
