//! DID Methods.
//!
//! This library provides an interface for DIDs and
//! implementations for various DID methods.

// Re-export core definitions.
pub use ssi_dids_core::*;

// Re-export DID methods implementations.
pub use did_ethr as ethr;
pub use did_ion as ion;
pub use did_jwk as jwk;
pub use did_method_key as key;
pub use did_pkh as pkh;
pub use did_tz as tz;
pub use did_web as web;

pub use ethr::DIDEthr;
pub use ion::DIDION;
pub use jwk::DIDJWK;
pub use key::DIDKey;
pub use pkh::DIDPKH;
pub use tz::DIDTz;
pub use web::DIDWeb;

#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error(transparent)]
    Ethr(ssi_jwk::Error),

    #[error(transparent)]
    Key(key::GenerateError),

    #[error(transparent)]
    Pkh(pkh::GenerateError),

    #[error(transparent)]
    Tz(ssi_jwk::Error),

    #[error("unsupported method pattern `{0}`")]
    UnsupportedMethodPattern(String),
}

#[derive(Default, Clone)]
pub struct AnyDidMethod {
    ion: DIDION,
    tz: DIDTz,
}

impl AnyDidMethod {
    pub fn new(ion: DIDION, tz: DIDTz) -> Self {
        Self { ion, tz }
    }

    pub fn generate(
        &self,
        key: &ssi_jwk::JWK,
        method_pattern: &str,
    ) -> Result<DIDBuf, GenerateError> {
        match method_pattern
            .split_once(':')
            .map(|(m, p)| (m, Some(p)))
            .unwrap_or((method_pattern, None))
        {
            ("ethr", None) => ethr::DIDEthr::generate(key).map_err(GenerateError::Ethr),
            ("jwk", None) => Ok(jwk::DIDJWK::generate(key)),
            ("key", None) => key::DIDKey::generate(key).map_err(GenerateError::Key),
            ("pkh", Some(pkh_name)) => {
                pkh::DIDPKH::generate(key, pkh_name).map_err(GenerateError::Pkh)
            }
            ("tz", None) => self.tz.generate(key).map_err(GenerateError::Tz),
            _ => Err(GenerateError::UnsupportedMethodPattern(
                method_pattern.to_string(),
            )),
        }
    }
}

impl DIDResolver for AnyDidMethod {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match did.method_name() {
            "ethr" => {
                ethr::DIDEthr
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "ion" => {
                self.ion
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "jwk" => {
                DIDJWK
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "key" => {
                DIDKey
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "pkh" => {
                DIDPKH
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "tz" => {
                self.tz
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            "web" => {
                DIDWeb
                    .resolve_method_representation(did.method_specific_id(), options)
                    .await
            }
            m => Err(resolution::Error::MethodNotSupported(m.to_owned())),
        }
    }
}
