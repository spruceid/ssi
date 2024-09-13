use ssi_core::JsonPointerBuf;
use ssi_data_integrity_core::{
    suite::{ConfigurationError, InputSignatureOptions, InputVerificationOptions},
    ProofConfiguration, ProofOptions,
};
use ssi_di_sd_primitives::HmacShaAnyKey;
use ssi_verification_methods::{multikey::MultikeyPair, Multikey};

use crate::EcdsaSd2023;

use super::TransformationOptions;

#[derive(Debug, Clone)]
pub struct SignatureOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    pub hmac_key: Option<HmacShaAnyKey>,

    pub key_pair: Option<MultikeyPair>,
}

pub struct ConfigurationAlgorithm;

impl ssi_data_integrity_core::suite::ConfigurationAlgorithm<EcdsaSd2023>
    for ConfigurationAlgorithm
{
    type InputVerificationMethod = Multikey;

    type InputSuiteOptions = ();

    type InputSignatureOptions = SignatureOptions;

    type InputVerificationOptions = ();

    type TransformationOptions = TransformationOptions;

    fn configure_signature(
        suite: &EcdsaSd2023,
        proof_options: ProofOptions<Self::InputVerificationMethod, Self::InputSuiteOptions>,
        signature_options: InputSignatureOptions<EcdsaSd2023>,
    ) -> Result<(ProofConfiguration<EcdsaSd2023>, Self::TransformationOptions), ConfigurationError>
    {
        let proof_configuration = proof_options.into_configuration(*suite)?;
        Ok((
            proof_configuration,
            TransformationOptions::Base(signature_options),
        ))
    }

    fn configure_verification(
        _suite: &EcdsaSd2023,
        _verification_options: &InputVerificationOptions<EcdsaSd2023>,
    ) -> Result<Self::TransformationOptions, ConfigurationError> {
        Ok(TransformationOptions::Derived)
    }
}
