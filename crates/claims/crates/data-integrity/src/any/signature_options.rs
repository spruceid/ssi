use ssi_di_sd_primitives::JsonPointerBuf;

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct AnySignatureOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    #[cfg(all(feature = "w3c", feature = "bbs"))]
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
impl From<AnySignatureOptions> for ssi_data_integrity_suites::bbs_2023::Bbs2023SignatureOptions {
    fn from(o: AnySignatureOptions) -> Self {
        Self {
            mandatory_pointers: o.mandatory_pointers,
            feature_option: o.feature_option,
            commitment_with_proof: o.commitment_with_proof,
            hmac_key: None,
        }
    }
}

#[cfg(all(feature = "w3c", feature = "bbs"))]
impl From<ssi_data_integrity_suites::bbs_2023::Bbs2023SignatureOptions> for AnySignatureOptions {
    fn from(value: ssi_data_integrity_suites::bbs_2023::Bbs2023SignatureOptions) -> Self {
        Self {
            mandatory_pointers: value.mandatory_pointers,
            feature_option: value.feature_option,
            commitment_with_proof: value.commitment_with_proof,
        }
    }
}
