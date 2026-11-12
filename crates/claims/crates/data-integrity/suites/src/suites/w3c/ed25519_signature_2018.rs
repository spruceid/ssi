use k256::sha2::Sha256;
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::DetachedJwsSigning,
    suite::NoConfiguration,
    StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::Ed25519VerificationKey2018;
use static_iref::iri;

use crate::try_from_type;

/// Ed25519 Signature 2018.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2018;

impl Ed25519Signature2018 {
    pub const NAME: &'static str = "Ed25519Signature2018";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Ed25519Signature2018");
}

impl StandardCryptographicSuite for Ed25519Signature2018 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = Ed25519VerificationKey2018;

    type SignatureAlgorithm = DetachedJwsSigning<ssi_crypto::algorithm::EdDSA>;

    type ProofOptions = ();

    fn type_(&'_ self) -> TypeRef<'_> {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(Ed25519Signature2018);

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ssi_data_integrity_core::{
        signing::DetachedJwsSignature, suite::standard::VerificationAlgorithm, ProofConfiguration,
    };
    use ssi_jwk::{Algorithm, Params, JWK};
    use ssi_verification_methods::ReferenceOrOwned;

    use super::*;

    #[test]
    fn verifies_detached_jws_with_original_header_encoding() {
        let key = JWK::generate_ed25519().unwrap();
        let Params::OKP(params) = &key.params else {
            unreachable!()
        };
        let method = Ed25519VerificationKey2018 {
            id: "did:example:issuer#key".parse().unwrap(),
            controller: "did:example:issuer".parse().unwrap(),
            public_key: multibase::Base::Base58Btc
                .encode(&params.public_key.0)
                .parse()
                .unwrap(),
        };
        let claims = [42; 64];
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","b64":false,"crit":["b64"]}"#);
        let mut signing_bytes = format!("{header}.").into_bytes();
        signing_bytes.extend_from_slice(&claims);
        let signature = ssi_jws::sign_bytes(Algorithm::EdDSA, &signing_bytes, &key).unwrap();
        let jws = ssi_jws::JwsString::from_string(format!(
            "{header}..{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
        .unwrap();
        let proof = ProofConfiguration::from_method(
            Ed25519Signature2018,
            ReferenceOrOwned::Owned(method.clone()),
        )
        .into_proof(DetachedJwsSignature::new(jws));
        assert!(
            <DetachedJwsSigning<ssi_crypto::algorithm::EdDSA> as VerificationAlgorithm<
                Ed25519Signature2018,
            >>::verify(&method, claims, proof.borrowed())
            .unwrap()
            .is_ok()
        );
        assert!(
            <DetachedJwsSigning<ssi_crypto::algorithm::EdDSA> as VerificationAlgorithm<
                Ed25519Signature2018,
            >>::verify(&method, [43; 64], proof.borrowed())
            .unwrap()
            .is_err()
        );
    }
}
