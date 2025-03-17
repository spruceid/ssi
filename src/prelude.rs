pub use crate::{
    claims::{
        data_integrity::{
            AnyDataIntegrity, AnySuite, CryptographicSuite, DataIntegrity, DataIntegrityDocument,
            ProofConfiguration, ProofOptions,
        },
        vc::syntax::{AnyJsonCredential, AnyJsonPresentation},
        JWTClaims, Jws, JwsBuf, JwsPayload, JwsSlice, JwsStr, JwsString, JwsVec, Parameters,
    },
    dids::{DidResolver, DIDJWK},
    verification_methods::{AnyJwkMethod, AnyMethod, SingleSecretSigner},
    xsd::DateTime,
    DefaultVerificationParameters, JWK,
};

#[cfg(feature = "example")]
pub use crate::dids::example::ExampleDIDResolver;
