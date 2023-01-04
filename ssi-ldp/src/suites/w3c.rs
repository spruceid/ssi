use super::super::*;
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_key, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Algorithm, Params as JWKParams, JWK};
use std::collections::HashMap as Map;

/// <https://w3c-ccg.github.io/lds-jws2020/>
pub struct JsonWebSignature2020;
impl JsonWebSignature2020 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let algorithm = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        Self::validate_key_and_algorithm(key, algorithm)?;
        let has_context = document_has_context(document, ssi_json_ld::W3ID_JWS2020_V1_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ssi_json_ld::W3ID_JWS2020_V1_CONTEXT])
            },
            ..Proof::new(ProofSuiteType::JsonWebSignature2020)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        sign_proof(document, proof, key, algorithm, context_loader).await
    }
    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let algorithm = public_key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        Self::validate_key_and_algorithm(public_key, algorithm)?;
        let has_context = document_has_context(document, ssi_json_ld::W3ID_JWS2020_V1_CONTEXT)?;
        let proof = Proof {
            context: if has_context {
                Value::Null
            } else {
                serde_json::json!([ssi_json_ld::W3ID_JWS2020_V1_CONTEXT])
            },
            ..Proof::new(ProofSuiteType::JsonWebSignature2020)
                .with_options(options)
                .with_properties(extra_proof_properties)
        };
        prepare_proof(document, proof, algorithm, context_loader).await
    }
    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        let jws = proof.jws.as_ref().ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let (header_b64, signature_b64) = ssi_jws::split_detached_jws(jws)?;
        let message = to_jws_payload(document, proof, context_loader).await?;
        let ssi_jws::DecodedJWS {
            header,
            signing_input,
            payload: _,
            signature,
        } = ssi_jws::decode_jws_parts(header_b64, &message, signature_b64)?;
        // Redundant early algorithm check before expensive key lookup and signature verification.
        Self::validate_algorithm(header.algorithm)?;
        let key = resolve_key(verification_method, resolver).await?;
        Self::validate_key_and_algorithm(&key, header.algorithm)?;
        Ok(ssi_jws::verify_bytes_warnable(
            header.algorithm,
            &signing_input,
            &key,
            &signature,
        )?)
    }

    fn validate_algorithm(algorithm: Algorithm) -> Result<(), Error> {
        match algorithm {
            Algorithm::EdDSA => (),
            Algorithm::ES256K => (),
            Algorithm::ES256 => (),
            Algorithm::ES384 => (),
            Algorithm::PS256 => (),
            _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
        }
        Ok(())
    }
    // https://w3c-ccg.github.io/lds-jws2020/#jose-conformance
    fn validate_key_and_algorithm(key: &JWK, algorithm: Algorithm) -> Result<(), Error> {
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != algorithm {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        match &key.params {
            JWKParams::RSA(_) => match algorithm {
                Algorithm::PS256 => (),
                _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
            },
            JWKParams::EC(ec_params) => {
                match &ec_params
                    .curve
                    .as_ref()
                    .ok_or(ssi_jwk::Error::MissingCurve)?[..]
                {
                    "secp256k1" => match algorithm {
                        Algorithm::ES256K => (),
                        _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                    },
                    "P-256" => match algorithm {
                        Algorithm::ES256 => (),
                        _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                    },
                    "P-384" => match algorithm {
                        Algorithm::ES384 => (),
                        _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                    },
                    _ => {
                        return Err(Error::UnsupportedCurve);
                    }
                }
            }
            JWKParams::OKP(okp_params) => match &okp_params.curve[..] {
                "Ed25519" => match algorithm {
                    Algorithm::EdDSA => (),
                    _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                },
                "Bls12381G2" => match algorithm {
                    Algorithm::BLS12381G2 => (),
                    _ => return Err(Error::JWS(ssi_jws::Error::UnsupportedAlgorithm)),
                },
                _ => {
                    return Err(Error::UnsupportedCurve);
                }
            },
            _ => return Err(Error::UnsupportedCurve),
        }
        Ok(())
    }
}
