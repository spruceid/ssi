use ssi_data_integrity_core::Proof;
use ssi_di_sd_primitives::JsonPointerBuf;

use crate::{bbs_2023::DerivedFeatureOption, Bbs2023};

/// Creates data to be used to generate a derived proof.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata>
pub async fn create_disclosure_data<T>(
    loader: &impl ssi_json_ld::Loader,
    unsecured_document: &T,
    proof: &Proof<Bbs2023>,
    selective_pointers: &[JsonPointerBuf],
    presentation_header: Option<&[u8]>,
    transform_options: &DerivedFeatureOption,
) {
    // ...
}
