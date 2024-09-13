use serde::Deserialize;
use ssi_core::JsonPointerBuf;
use ssi_di_sd_primitives::HmacShaAnyKey;
use ssi_verification_methods::multikey::MultikeyPair;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AnySignatureOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    #[serde(rename = "hmacKeyString")]
    pub hmac_key: Option<HmacShaAnyKey>,

    pub key_pair: Option<MultikeyPair>,

    #[cfg(all(feature = "w3c", feature = "bbs"))]
    #[serde(default)]
    pub feature_option: ssi_data_integrity_suites::bbs_2023::FeatureOption,

    #[cfg(all(feature = "w3c", feature = "bbs"))]
    pub commitment_with_proof: Option<Vec<u8>>,
}

impl From<AnySignatureOptions> for () {
    fn from(_value: AnySignatureOptions) -> Self {}
}

impl From<()> for AnySignatureOptions {
    fn from(_value: ()) -> Self {
        AnySignatureOptions::default()
    }
}

#[cfg(all(feature = "w3c", feature = "bbs"))]
impl TryFrom<AnySignatureOptions> for ssi_data_integrity_suites::bbs_2023::Bbs2023SignatureOptions {
    type Error = ssi_data_integrity_core::suite::ConfigurationError;

    fn try_from(o: AnySignatureOptions) -> Result<Self, Self::Error> {
        Ok(Self {
            mandatory_pointers: o.mandatory_pointers,
            feature_option: o.feature_option,
            commitment_with_proof: o.commitment_with_proof,
            hmac_key: o
                .hmac_key
                .map(HmacShaAnyKey::into_sha256)
                .transpose()
                .map_err(|_| {
                    ssi_data_integrity_core::suite::ConfigurationError::invalid_option("hmacKey")
                })?,
        })
    }
}

#[cfg(all(feature = "w3c", feature = "bbs"))]
impl From<ssi_data_integrity_suites::bbs_2023::Bbs2023SignatureOptions> for AnySignatureOptions {
    fn from(value: ssi_data_integrity_suites::bbs_2023::Bbs2023SignatureOptions) -> Self {
        Self {
            mandatory_pointers: value.mandatory_pointers,
            feature_option: value.feature_option,
            commitment_with_proof: value.commitment_with_proof,
            hmac_key: value.hmac_key.map(HmacShaAnyKey::Sha256),
            ..Default::default()
        }
    }
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
impl From<AnySignatureOptions> for ssi_data_integrity_suites::ecdsa_sd_2023::SignatureOptions {
    fn from(o: AnySignatureOptions) -> Self {
        Self {
            mandatory_pointers: o.mandatory_pointers,
            hmac_key: o.hmac_key,
            key_pair: o.key_pair,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
impl From<ssi_data_integrity_suites::ecdsa_sd_2023::SignatureOptions> for AnySignatureOptions {
    fn from(value: ssi_data_integrity_suites::ecdsa_sd_2023::SignatureOptions) -> Self {
        Self {
            mandatory_pointers: value.mandatory_pointers,
            hmac_key: value.hmac_key,
            key_pair: value.key_pair,
            ..Default::default()
        }
    }
}
