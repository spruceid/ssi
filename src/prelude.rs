pub use crate::{
    claims::{
        data_integrity::{
            AnyDataIntegrity, AnySuite, CryptographicSuite, DataIntegrity, ProofConfiguration,
            ProofOptions,
        },
        vc::{any_credential_from_json_slice, any_credential_from_json_str},
        CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, JWSPayload, JWTClaims,
        JsonCredential, JsonPresentation, SpecializedJsonCredential, VerifiableClaims,
        VerificationEnvironment,
    },
    dids::{DIDResolver, DIDJWK},
    verification_methods::{AnyJwkMethod, AnyMethod, SingleSecretSigner},
    xsd_types::DateTime,
    JWK,
};

#[cfg(feature = "example")]
pub use crate::dids::example::ExampleDIDResolver;
