use std::{borrow::Cow, marker::PhantomData};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_crypto::algorithm::{SignatureAlgorithmInstance, SignatureAlgorithmType};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{DecodedJws, JwsSignature, JwsString};
use ssi_verification_methods::{MessageSigner, VerifyBytes, VerifyBytesWithRecoveryJwk};

use crate::{
    suite::standard::{
        SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm,
    },
    CryptographicSuite, ProofConfigurationRef, ProofRef,
};

use super::AlgorithmSelection;

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct DetachedJwsSignature {
    #[ld("sec:jws")]
    pub jws: JwsString,
}

impl DetachedJwsSignature {
    pub fn new(jws: JwsString) -> Self {
        Self { jws }
    }

    /// Decodes the signature for the given message.
    ///
    /// Returns the signing bytes, the signature bytes and the signature algorithm.
    pub fn decode(
        &self,
        message: &[u8],
    ) -> Result<(Vec<u8>, JwsSignature, Algorithm), ProofValidationError> {
        let DecodedJws {
            signing_bytes: detached_signing_bytes,
            signature,
        } = self
            .jws
            .decode()
            .map_err(|_| ProofValidationError::InvalidSignature)?;
        // Verification must use the original protected header, not reserialize its JSON.
        let mut signing_bytes = self.jws.header().to_vec();
        signing_bytes.push(b'.');
        if detached_signing_bytes
            .header
            .base64urlencode_payload
            .unwrap_or(true)
        {
            signing_bytes.extend_from_slice(URL_SAFE_NO_PAD.encode(message).as_bytes());
        } else {
            signing_bytes.extend_from_slice(message);
        }
        Ok((
            signing_bytes,
            signature,
            detached_signing_bytes.header.algorithm,
        ))
    }

    pub async fn sign_detached<A: SignatureAlgorithmType + Into<Algorithm>, S: MessageSigner<A>>(
        payload: &[u8],
        signer: S,
        key_id: Option<String>,
        algorithm_instance: A::Instance,
    ) -> Result<Self, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(algorithm_instance.algorithm().into(), key_id);
        let signing_bytes = header.encode_signing_bytes(payload);
        let signature = signer.sign(algorithm_instance, &signing_bytes).await?;
        let jws = ssi_jws::JwsString::encode_detached(header, &signature);
        Ok(Self::new(jws))
    }
}

impl AsRef<str> for DetachedJwsSignature {
    fn as_ref(&self) -> &str {
        self.jws.as_str()
    }
}

impl super::AlterSignature for DetachedJwsSignature {
    fn alter(&mut self) {
        self.jws = JwsString::from_string(format!("ff{}", self.jws)).unwrap();
    }
}

pub struct DetachedJwsSigning<A>(PhantomData<A>);

impl<A> SignatureAndVerificationAlgorithm for DetachedJwsSigning<A> {
    type Signature = DetachedJwsSignature;
}

impl<A, S, T> SignatureAlgorithm<S, T> for DetachedJwsSigning<A>
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    A: SignatureAlgorithmType
        + AlgorithmSelection<S::VerificationMethod, S::ProofOptions>
        + Into<Algorithm>,
    T: MessageSigner<A>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        DetachedJwsSignature::sign_detached(
            prepared_claims.as_ref(),
            signer,
            None,
            A::select_algorithm(verification_method, proof_configuration.options)?,
        )
        .await
    }
}

impl<A, S> VerificationAlgorithm<S> for DetachedJwsSigning<A>
where
    S: CryptographicSuite<Signature = DetachedJwsSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    S::VerificationMethod: VerifyBytes<A>,
    A: TryFrom<Algorithm>,
{
    fn verify(
        method: &S::VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ssi_claims_core::ProofValidity, ProofValidationError> {
        let (signing_bytes, signature, algorithm) =
            proof.signature.decode(prepared_claims.as_ref())?;
        let algorithm = algorithm
            .try_into()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        method.verify_bytes(algorithm, &signing_bytes, &signature)
    }
}

pub struct DetachedJwsRecoverySigning<A>(PhantomData<A>);

impl<A> SignatureAndVerificationAlgorithm for DetachedJwsRecoverySigning<A> {
    type Signature = DetachedJwsSignature;
}

impl<A, S, T> SignatureAlgorithm<S, T> for DetachedJwsRecoverySigning<A>
where
    S: CryptographicSuite,
    S::PreparedClaims: AsRef<[u8]>,
    S::ProofOptions: RecoverPublicJwk,
    A: Clone + Into<Algorithm> + AlgorithmSelection<S::VerificationMethod, S::ProofOptions>,
    T: MessageSigner<A>,
{
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError> {
        DetachedJwsSignature::sign_detached(
            prepared_claims.as_ref(),
            signer,
            proof_configuration.options.public_jwk().key_id.clone(),
            A::select_algorithm(verification_method, proof_configuration.options)?,
        )
        .await
    }
}

impl<A, S> VerificationAlgorithm<S> for DetachedJwsRecoverySigning<A>
where
    S: CryptographicSuite<Signature = DetachedJwsSignature>,
    S::PreparedClaims: AsRef<[u8]>,
    S::ProofOptions: RecoverPublicJwk,
    S::VerificationMethod: VerifyBytesWithRecoveryJwk<A>,
    A: TryFrom<ssi_jwk::Algorithm>,
{
    fn verify(
        verification_method: &S::VerificationMethod,
        prepared_claims: S::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ssi_claims_core::ProofValidity, ProofValidationError> {
        let (signing_bytes, signature, algorithm) =
            proof.signature.decode(prepared_claims.as_ref())?;
        let found_algorithm = algorithm
            .try_into()
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        verification_method.verify_bytes_with_public_jwk(
            &proof.options.public_jwk(),
            found_algorithm,
            &signing_bytes,
            &signature,
        )
    }
}

pub trait RecoverPublicJwk {
    fn public_jwk(&'_ self) -> Cow<'_, JWK>;
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use super::*;

    fn sign(
        header: &str,
        message: &[u8],
        encoded_payload: bool,
        key: &JWK,
    ) -> DetachedJwsSignature {
        let encoded_header = URL_SAFE_NO_PAD.encode(header);
        let mut signing_bytes = format!("{encoded_header}.").into_bytes();
        if encoded_payload {
            signing_bytes.extend_from_slice(URL_SAFE_NO_PAD.encode(message).as_bytes());
        } else {
            signing_bytes.extend_from_slice(message);
        }
        let signature = ssi_jws::sign_bytes(Algorithm::EdDSA, &signing_bytes, key).unwrap();
        DetachedJwsSignature::new(
            JwsString::from_string(format!(
                "{encoded_header}..{}",
                URL_SAFE_NO_PAD.encode(signature)
            ))
            .unwrap(),
        )
    }

    #[test]
    fn preserves_original_header_when_decoding_detached_signatures() {
        let key = JWK::generate_ed25519().unwrap();
        for (header, encoded_payload) in [
            (r#"{"alg":"EdDSA","b64":false,"crit":["b64"]}"#, false),
            (r#"{"alg":"EdDSA","crit":["b64"],"b64":false}"#, false),
            (
                r#"{ "crit": ["b64"], "b64": false, "alg": "EdDSA" }"#,
                false,
            ),
            (r#"{"kid":"did:example:issuer#key","alg":"EdDSA"}"#, true),
            (r#"{"b64":true,"alg":"EdDSA"}"#, true),
        ] {
            for message in [b"".as_slice(), b"detached payload\x00\xff".as_slice()] {
                let detached = sign(header, message, encoded_payload, &key);
                let (signing_bytes, signature, algorithm) = detached.decode(message).unwrap();
                assert!(
                    ssi_jws::verify_bytes(algorithm, &signing_bytes, &key.to_public(), &signature)
                        .is_ok(),
                    "original header was not preserved: {header}"
                );
            }
        }
    }

    #[test]
    fn rejects_tampered_detached_payload_and_header() {
        let key = JWK::generate_ed25519().unwrap();
        let message = b"original payload";
        let header = r#"{"alg":"EdDSA","crit":["b64"],"b64":false}"#;
        let detached = sign(header, message, false, &key);
        let (bytes, signature, algorithm) = detached.decode(message).unwrap();
        let mut altered_signature = signature.as_ref().to_vec();
        altered_signature[0] ^= 1;
        assert!(
            ssi_jws::verify_bytes(algorithm, &bytes, &key.to_public(), &altered_signature).is_err()
        );
        let (bytes, signature, algorithm) = detached.decode(b"altered payload").unwrap();
        assert!(ssi_jws::verify_bytes(algorithm, &bytes, &key.to_public(), &signature).is_err());

        // Even a semantically equivalent header has different signed bytes.
        let altered_header =
            URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","b64":false,"crit":["b64"]}"#);
        let altered = DetachedJwsSignature::new(
            JwsString::from_string(format!(
                "{altered_header}..{}",
                URL_SAFE_NO_PAD.encode(signature)
            ))
            .unwrap(),
        );
        let (bytes, signature, algorithm) = altered.decode(message).unwrap();
        assert!(ssi_jws::verify_bytes(algorithm, &bytes, &key.to_public(), &signature).is_err());
    }

    #[test]
    fn rejects_malformed_detached_signatures() {
        for jws in ["bm90IGpzb24..", "e30..", "eyJhbGciOiJFZERTQSJ9..A"] {
            let detached =
                DetachedJwsSignature::new(JwsString::from_string(jws.to_owned()).unwrap());
            assert!(detached.decode(b"payload").is_err());
        }
    }
}
