pub use crate::{
    claims::{
        data_integrity::{
            AnyDataIntegrity, AnySuite, CryptographicSuite, DataIntegrity, DataIntegrityDocument,
            ProofConfiguration, ProofOptions,
        },
        vc::syntax::{AnyJsonCredential, AnyJsonPresentation},
        CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, JWSPayload, JWTClaims,
        VerificationParameters,
    },
    dids::{DIDResolver, DIDJWK},
    verification_methods::{AnyJwkMethod, AnyMethod, SingleSecretSigner},
    xsd_types::DateTime,
    DefaultVerificationParameters, JWK,
};

#[cfg(feature = "example")]
pub use crate::dids::example::ExampleDIDResolver;
