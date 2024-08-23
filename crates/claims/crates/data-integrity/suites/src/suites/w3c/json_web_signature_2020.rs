use k256::sha2::Sha256;
use lazy_static::lazy_static;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsSigning,
    suite::AddProofContext,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::JsonWebKey2020;
use static_iref::{iri, iri_ref};

use crate::try_from_type;

lazy_static! {
    static ref W3ID_JWS2020_V1_CONTEXT: ssi_json_ld::syntax::ContextEntry = {
        ssi_json_ld::syntax::ContextEntry::IriRef(
            iri_ref!("https://w3id.org/security/suites/jws-2020/v1").to_owned(),
        )
    };
}

#[derive(Default)]
pub struct Jws2020v1Context;

impl From<Jws2020v1Context> for ssi_json_ld::syntax::Context {
    fn from(_: Jws2020v1Context) -> Self {
        ssi_json_ld::syntax::Context::One(W3ID_JWS2020_V1_CONTEXT.clone())
    }
}

/// JSON Web Signature 2020.
///
/// See: <https://w3c-ccg.github.io/lds-jws2020/>
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonWebSignature2020;

impl JsonWebSignature2020 {
    pub const NAME: &'static str = "JsonWebSignature2020";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#JsonWebSignature2020");
}

impl StandardCryptographicSuite for JsonWebSignature2020 {
    type Configuration = AddProofContext<Jws2020v1Context>;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = JsonWebKey2020;

    type SignatureAlgorithm = DetachedJwsSigning<ssi_jwk::Algorithm>; // TODO make sure to include the key id

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(JsonWebSignature2020);
