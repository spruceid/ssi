pub use crate::{
    claims::{
        data_integrity::{
            AnyDataIntegrity, AnySuite, CryptographicSuite, DataIntegrity, ProofConfiguration,
            ProofOptions,
        },
        vc::syntax::{AnyJsonCredential, AnyJsonPresentation},
        CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, JWSPayload, JWTClaims,
    },
    dids::{DIDResolver, DIDJWK},
    verification_methods::{AnyJwkMethod, AnyMethod, SingleSecretSigner},
    xsd_types::DateTime,
    JWK,
};

#[cfg(feature = "example")]
pub use crate::dids::example::ExampleDIDResolver;
