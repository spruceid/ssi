use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_key, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Algorithm, Base64urlUInt, JWK};
use ssi_jws::VerificationWarnings;

use std::{collections::HashMap as Map, fmt};

use crate::{
    document_has_context, to_jws_payload, Error, LinkedDataDocument, LinkedDataProofOptions, Proof,
    ProofPreparation, ProofSuiteType, SigningInput,
};

pub struct DataIntegrityProof;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum DataIntegrityCryptoSuite {
    #[serde(rename = "eddsa-2022")]
    Eddsa2022,
    #[serde(rename = "ecdsa-2019")]
    Ecdsa2019,
}

impl DataIntegrityCryptoSuite {
    fn pick_from_jwk(jwk: &JWK) -> Result<Self, Error> {
        match jwk.get_algorithm() {
            Some(Algorithm::EdDSA) => Ok(Self::Eddsa2022),
            Some(Algorithm::ES256) | Some(Algorithm::ES384) => Ok(Self::Ecdsa2019),
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
            DataIntegrityCryptoSuite::Ecdsa2019 => "ecdsa-2019".into(),
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
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        let cryptosuite = match &options.cryptosuite {
            None => DataIntegrityCryptoSuite::pick_from_jwk(key)?,
            Some(c) => c.clone(),
        };
        let jwa = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        let context_uri = ssi_json_ld::CREDENTIALS_V2_CONTEXT; // DataIntegrityProof is part of the v2 context
        if let Some(key_algorithm) = key.algorithm {
            if key_algorithm != jwa {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        let mut proof = Proof::new(ProofSuiteType::DataIntegrityProof)
            .with_options(options)
            .with_properties(extra_proof_properties);
        proof.cryptosuite = Some(cryptosuite);
        if !document_has_context(document, context_uri)? {
            proof.context = serde_json::json!([context_uri]);
        }
        let message = to_jws_payload(document, &proof, context_loader).await?;
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
        let cryptosuite = match &options.cryptosuite {
            None => DataIntegrityCryptoSuite::pick_from_jwk(public_key)?,
            Some(c) => c.clone(),
        };
        let jwa = public_key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        let context_uri = ssi_json_ld::CREDENTIALS_V2_CONTEXT; // DataIntegrityProof is part of the v2 context
        if let Some(key_algorithm) = public_key.algorithm {
            if key_algorithm != jwa {
                return Err(Error::JWS(ssi_jws::Error::AlgorithmMismatch));
            }
        }
        let mut proof = Proof::new(ProofSuiteType::DataIntegrityProof)
            .with_options(options)
            .with_properties(extra_proof_properties);
        proof.cryptosuite = Some(cryptosuite);
        if !document_has_context(document, context_uri)? {
            proof.context = serde_json::json!([context_uri]);
        }
        let message = to_jws_payload(document, &proof, context_loader).await?;
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
        let expected_cryptosuite = DataIntegrityCryptoSuite::pick_from_jwk(&key)?;
        let jwa = key.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        if &expected_cryptosuite != cryptosuite {
            return Err(Error::UnexpectedCryptosuite(
                cryptosuite.to_string(),
                expected_cryptosuite.into(),
            ));
        }

        let message = to_jws_payload(document, proof, context_loader).await?;
        let (_base, sig) = multibase::decode(proof_value)?;
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
