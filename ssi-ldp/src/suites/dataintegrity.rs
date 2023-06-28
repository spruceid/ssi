use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_key, DIDResolver};
use ssi_json_ld::{ContextLoader, CREDENTIALS_V2_CONTEXT, W3ID_DATA_INTEGRITY_V1_CONTEXT};
use ssi_jwk::{Algorithm, Base64urlUInt, JWK};
use ssi_jws::VerificationWarnings;

use std::{collections::HashMap as Map, fmt};

use crate::{
    document_has_context, jcs_normalize, sha256_normalized, sha384_normalized, to_jws_payload,
    urdna2015_normalize, Error, LinkedDataDocument, LinkedDataProofOptions, Proof,
    ProofPreparation, ProofSuiteType, SigningInput,
};

pub struct DataIntegrityProof;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum DataIntegrityCryptoSuite {
    #[serde(rename = "eddsa-2022")]
    Eddsa2022,
    #[serde(rename = "json-eddsa-2022")]
    JcsEddsa2022,
    #[serde(rename = "ecdsa-2019")]
    Ecdsa2019,
    #[serde(rename = "jcs-ecdsa-2019")]
    JcsEcdsa2019,
}

impl DataIntegrityCryptoSuite {
    fn pick_from_jwk(jwk: &JWK) -> Result<Vec<Self>, Error> {
        match jwk.get_algorithm() {
            Some(Algorithm::EdDSA) => Ok(vec![Self::Eddsa2022, Self::JcsEddsa2022]),
            Some(Algorithm::ES256) | Some(Algorithm::ES384) => {
                Ok(vec![Self::Ecdsa2019, Self::JcsEcdsa2019])
            }
            Some(Algorithm::None) | None => Err(Error::MissingAlgorithm),
            Some(_) => Err(Error::UnsupportedCryptosuite),
        }
    }
}
impl TryFrom<&str> for DataIntegrityCryptoSuite {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "eddsa-2022" => Ok(Self::Eddsa2022),
            "json-eddsa-2022" => Ok(Self::JcsEddsa2022),
            "ecdsa-2022" => Ok(Self::Ecdsa2019),
            "jcs-ecdsa-2022" => Ok(Self::JcsEcdsa2019),
            _ => Err(Error::UnsupportedCryptosuite),
        }
    }
}

impl TryFrom<String> for DataIntegrityCryptoSuite {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl From<DataIntegrityCryptoSuite> for String {
    fn from(value: DataIntegrityCryptoSuite) -> Self {
        match value {
            DataIntegrityCryptoSuite::Eddsa2022 => "eddsa-2022".into(),
            DataIntegrityCryptoSuite::JcsEddsa2022 => "json-eddsa-2022".into(),
            DataIntegrityCryptoSuite::Ecdsa2019 => "ecdsa-2019".into(),
            DataIntegrityCryptoSuite::JcsEcdsa2019 => "jcs-ecdsa-2019".into(),
        }
    }
}

impl TryFrom<Value> for DataIntegrityCryptoSuite {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::String(s) => s.try_into(),
            _ => Err(Error::InvalidCryptosuiteType),
        }
    }
}

impl fmt::Display for DataIntegrityCryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from(self.clone()))
    }
}

impl DataIntegrityProof {
    async fn jws_payload(
        cryptosuite: &DataIntegrityCryptoSuite,
        jwa: &Algorithm,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        context_loader: &mut ContextLoader,
    ) -> Result<Vec<u8>, Error> {
        Ok(match (cryptosuite, jwa) {
            (DataIntegrityCryptoSuite::Eddsa2022, Algorithm::EdDSA)
            | (DataIntegrityCryptoSuite::Ecdsa2019, Algorithm::ES256) => {
                to_jws_payload(document, proof, context_loader).await?
            }
            (DataIntegrityCryptoSuite::JcsEddsa2022, Algorithm::EdDSA) => {
                let (doc_normalized, sigopts_normalized) = jcs_normalize(document, proof).await?;
                sha256_normalized(doc_normalized, sigopts_normalized)?
            }
            (DataIntegrityCryptoSuite::Ecdsa2019, Algorithm::ES384) => {
                let (doc_normalized, sigopts_normalized) =
                    urdna2015_normalize(document, proof, context_loader).await?;
                sha384_normalized(doc_normalized, sigopts_normalized)?
            }
            (DataIntegrityCryptoSuite::JcsEcdsa2019, Algorithm::ES256) => {
                let (doc_normalized, sigopts_normalized) = jcs_normalize(document, proof).await?;
                sha256_normalized(doc_normalized, sigopts_normalized)?
            }
            (DataIntegrityCryptoSuite::JcsEcdsa2019, Algorithm::ES384) => {
                let (doc_normalized, sigopts_normalized) = jcs_normalize(document, proof).await?;
                sha384_normalized(doc_normalized, sigopts_normalized)?
            }
            _ => Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch))?,
        })
    }

    async fn prepare_inner(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<(Algorithm, Proof, Vec<u8>), Error> {
        let cryptosuite = match &options.cryptosuite {
            None => DataIntegrityCryptoSuite::pick_from_jwk(key)?
                .first()
                .unwrap()
                .clone(),
            Some(c) => c.clone(),
        };
        let jwa = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != jwa {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        let mut proof = Proof::new(ProofSuiteType::DataIntegrityProof)
            .with_options(options)
            .with_properties(extra_proof_properties);
        proof.cryptosuite = Some(cryptosuite.clone());
        if !document_has_context(document, CREDENTIALS_V2_CONTEXT)?
            && !document_has_context(document, W3ID_DATA_INTEGRITY_V1_CONTEXT)?
        {
            proof.context = serde_json::json!([W3ID_DATA_INTEGRITY_V1_CONTEXT]);
        }
        let message =
            Self::jws_payload(&cryptosuite, &jwa, &proof, document, context_loader).await?;
        Ok((jwa, proof, message))
    }

    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let (jwa, mut proof, message) = Self::prepare_inner(
            document,
            options,
            context_loader,
            key,
            extra_proof_properties,
        )
        .await?;
        let sig = ssi_jws::sign_bytes(jwa, &message, key)?;
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, sig);
        proof.proof_value = Some(sig_multibase);
        Ok(proof)
    }

    pub(crate) async fn prepare(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        let (_jwa, proof, message) = Self::prepare_inner(
            document,
            options,
            context_loader,
            public_key,
            extra_proof_properties,
        )
        .await?;
        Ok(ProofPreparation {
            proof,
            jws_header: None,
            signing_input: SigningInput::Bytes(Base64urlUInt(message)),
        })
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        let cryptosuite = proof.cryptosuite.as_ref().ok_or(Error::MissingKey)?;

        let proof_value = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let key = resolve_key(verification_method, resolver).await?;
        let expected_cryptosuites = DataIntegrityCryptoSuite::pick_from_jwk(&key)?;
        let jwa = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if !expected_cryptosuites.contains(cryptosuite) {
            return Err(Error::UnexpectedCryptosuite(
                cryptosuite.to_string(),
                format!("{expected_cryptosuites:?}"),
            ));
        }

        // TODO must also match the VM relationship
        if proof.proof_purpose.is_none() {
            return Err(Error::MissingProofPurpose);
        };

        let message = Self::jws_payload(cryptosuite, &jwa, proof, document, context_loader).await?;
        let (base, sig) = multibase::decode(proof_value)?;
        if base != multibase::Base::Base58Btc {
            return Err(Error::ExpectedMultibaseZ);
        }
        Ok(ssi_jws::verify_bytes_warnable(jwa, &message, &key, &sig)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serde() {
        let res = serde_json::to_string(&DataIntegrityCryptoSuite::Eddsa2022).unwrap();
        assert_eq!(res, "\"eddsa-2022\"".to_string());
    }
}
