use super::Error;
use libipld::{
    multihash::{Code, MultihashDigest},
    Cid,
};
use ssi_dids::{Document, VerificationMethod, VerificationMethodMap};
use ssi_jwk::JWK;

/// Calculate the canonical CID of a UCAN
///
/// This function does not verify that the given string is a valid UCAN.
pub fn canonical_cid(jwt: &str) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(jwt.as_bytes()))
}

pub fn match_key_with_did_pkh(key: &JWK, doc: &Document) -> Result<(), Error> {
    doc.verification_method
        .iter()
        .flatten()
        .find_map(|vm| match vm {
            VerificationMethod::Map(vm) if vm.blockchain_account_id.is_some() => {
                Some(match_key_with_vm(key, vm))
            }
            _ => None,
        })
        .unwrap_or(Err(Error::VerificationMethodMismatch))
}

pub fn match_key_with_vm(key: &JWK, vm: &VerificationMethodMap) -> Result<(), Error> {
    use std::str::FromStr;
    Ok(ssi_caips::caip10::BlockchainAccountId::from_str(
        vm.blockchain_account_id
            .as_ref()
            .ok_or(Error::VerificationMethodMismatch)?,
    )?
    .verify(key)?)
}
