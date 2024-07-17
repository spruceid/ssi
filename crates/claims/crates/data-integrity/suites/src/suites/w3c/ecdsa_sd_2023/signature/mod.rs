use serde::{Deserialize, Serialize};
use ssi_claims_core::SignatureError;
use ssi_crypto::algorithm::ES256OrES384;
use ssi_data_integrity_core::{
    signing::AlterSignature,
    suite::standard::{self, SignatureAndVerificationAlgorithm},
    ProofConfigurationRef,
};
use ssi_security::MultibaseBuf;
use ssi_verification_methods::{MessageSigner, Multikey};

use crate::EcdsaSd2023;

use super::HashData;

mod base;
mod derived;

pub use base::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub proof_value: MultibaseBuf,
}

impl AsRef<str> for Signature {
    fn as_ref(&self) -> &str {
        self.proof_value.as_str()
    }
}

impl AlterSignature for Signature {
    fn alter(&mut self) {
        self.proof_value = MultibaseBuf::encode(multibase::Base::Base58Btc, [0])
    }
}

pub struct SignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for SignatureAlgorithm {
    type Signature = Signature;
}

impl<T> standard::SignatureAlgorithm<EcdsaSd2023, T> for SignatureAlgorithm
where
    T: MessageSigner<ES256OrES384>,
{
    async fn sign(
        _verification_method: &Multikey,
        signer: T,
        prepared_claims: HashData,
        _proof_configuration: ProofConfigurationRef<'_, EcdsaSd2023>,
    ) -> Result<Self::Signature, SignatureError> {
        match prepared_claims {
            HashData::Base(hash_data) => base::generate_proof(signer, *hash_data).await,
            HashData::Derived(_) => Err(SignatureError::other(
                "unable to sign derived claims without a base proof",
            )),
        }
    }
}
