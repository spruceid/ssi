#[cfg(feature = "aleo")]
mod aleo;
pub mod dataintegrity;
#[cfg(feature = "eip")]
mod eip;
#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "solana")]
mod solana;
#[cfg(feature = "tezos")]
mod tezos;
#[cfg(feature = "w3c")]
mod w3c;

#[cfg(feature = "aleo")]
use aleo::*;
use dataintegrity::*;
#[cfg(feature = "eip")]
use eip::*;
#[cfg(feature = "secp256k1")]
use secp256k1::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(feature = "solana")]
use solana::*;
use ssi_core::uri::URI;
use ssi_dids::did_resolve::DIDResolver;
use ssi_json_ld::ContextLoader;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::VerificationWarnings;
#[cfg(feature = "tezos")]
use tezos::*;
#[cfg(feature = "w3c")]
use w3c::*;

use crate::{
    prepare, prepare_nojws, sign, sign_nojws, use_eip712sig, use_epsig, verify, verify_bbs_proof,
    verify_nojws, Error, LinkedDataDocument, LinkedDataProofOptions, Proof, ProofPreparation,
    ProofSuite,
};

use async_trait::async_trait;
use std::{collections::HashMap as Map, str::FromStr};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ProofSuiteType {
    #[cfg(feature = "rsa")]
    RsaSignature2018,
    #[cfg(feature = "ed25519")]
    Ed25519Signature2018,
    #[cfg(feature = "ed25519")]
    Ed25519Signature2020,
    DataIntegrityProof,
    #[cfg(feature = "tezos")]
    Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
    #[cfg(feature = "tezos")]
    P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
    #[cfg(feature = "secp256k1")]
    EcdsaSecp256k1Signature2019,
    #[cfg(feature = "secp256k1")]
    EcdsaSecp256k1RecoverySignature2020,
    #[cfg(feature = "eip")]
    Eip712Signature2021,
    #[cfg(feature = "eip")]
    EthereumPersonalSignature2021,
    #[cfg(feature = "eip")]
    EthereumEip712Signature2021,
    #[cfg(feature = "tezos")]
    TezosSignature2021,
    #[cfg(feature = "tezos")]
    TezosJcsSignature2021,
    #[cfg(feature = "solana")]
    SolanaSignature2021,
    #[cfg(feature = "aleo")]
    AleoSignature2021,
    #[cfg(feature = "w3c")]
    JsonWebSignature2020,
    #[cfg(feature = "secp256r1")]
    EcdsaSecp256r1Signature2019,
    CLSignature2019,
    #[cfg(feature = "test")]
    NonJwsProof,
    #[cfg(feature = "test")]
    #[serde(rename = "ex:AnonCredPresentationProofv1")]
    AnonCredPresentationProofv1,
    #[cfg(feature = "test")]
    #[serde(rename = "ex:AnonCredDerivedCredentialv1")]
    AnonCredDerivedCredentialv1,
    //#[cfg(feature = "bbsplus")]
    BbsBlsSignatureProof2020,
}

// #[derive(Debug, Error)]
// #[error(transparent)]
// pub struct ParseProofSuiteError(#[from] ErrorRepr);
impl FromStr for ProofSuiteType {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(json!(format!("{s}")))
    }
}

pub enum SignatureType {
    JWS,
    LD,
}

impl ProofSuiteType {
    pub fn signature_type(&self) -> SignatureType {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaSignature2018 => SignatureType::JWS,
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2018 => SignatureType::JWS,
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2020 => SignatureType::LD,
            Self::DataIntegrityProof => SignatureType::LD,
            #[cfg(feature = "tezos")]
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => SignatureType::JWS,
            #[cfg(feature = "tezos")]
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => SignatureType::JWS,
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1Signature2019 => SignatureType::JWS,
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoverySignature2020 => SignatureType::JWS,
            #[cfg(feature = "eip")]
            Self::Eip712Signature2021 => SignatureType::LD,
            #[cfg(feature = "eip")]
            Self::EthereumPersonalSignature2021 => SignatureType::LD,
            #[cfg(feature = "eip")]
            Self::EthereumEip712Signature2021 => SignatureType::LD,
            #[cfg(feature = "tezos")]
            Self::TezosSignature2021 => SignatureType::LD,
            #[cfg(feature = "tezos")]
            Self::TezosJcsSignature2021 => SignatureType::LD,
            #[cfg(feature = "solana")]
            Self::SolanaSignature2021 => SignatureType::LD,
            #[cfg(feature = "aleo")]
            Self::AleoSignature2021 => SignatureType::LD,
            #[cfg(feature = "w3c")]
            Self::JsonWebSignature2020 => SignatureType::JWS,
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1Signature2019 => SignatureType::JWS,
            Self::CLSignature2019 => todo!(),
            #[cfg(feature = "test")]
            Self::NonJwsProof
            | Self::AnonCredPresentationProofv1
            | Self::AnonCredDerivedCredentialv1 => todo!(),
            //#[cfg(feature = "bbsplus")]
            Self::BbsBlsSignatureProof2020 => SignatureType::JWS,
        }
    }

    // TODO not sure why this check isn't covered by JSON-LD
    pub(crate) fn associated_contexts(&self) -> &[&str] {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaSignature2018 => &["https://w3id.org/security#RsaSignature2018"],
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2018 => &["https://w3id.org/security#Ed25519Signature2018"],
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2020 => &["https://w3id.org/security#Ed25519Signature2020", "https://www.w3.org/ns/credentials/examples#Ed25519Signature2020"],
            Self::DataIntegrityProof => &["https://w3id.org/security#DataIntegrityProof"],
            #[cfg(feature = "tezos")]
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                &["https://w3id.org/security#Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021"]
            }
            #[cfg(feature = "tezos")]
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                &["https://w3id.org/security#P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021"]
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1Signature2019 => &["https://w3id.org/security#EcdsaSecp256k1Signature2019"],
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoverySignature2020 => {
                &["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoverySignature2020"]
            }
            #[cfg(feature = "eip")]
            Self::Eip712Signature2021 => &["https://w3id.org/security#Eip712Signature2021"],
            #[cfg(feature = "eip")]
            Self::EthereumPersonalSignature2021 => &["https://w3id.org/security#EthereumPersonalSignature2021", "https://demo.spruceid.com/ld/epsig/EthereumPersonalSignature2021"],
            #[cfg(feature = "eip")]
            Self::EthereumEip712Signature2021 => &[],
            #[cfg(feature = "tezos")]
            Self::TezosSignature2021 => &["https://w3id.org/security#TezosSignature2021"],
            #[cfg(feature = "tezos")]
            Self::TezosJcsSignature2021 => &["https://w3id.org/security#TezosJcsSignature2021"],
            #[cfg(feature = "solana")]
            Self::SolanaSignature2021 => &["https://w3id.org/security#SolanaSignature2021"],
            #[cfg(feature = "aleo")]
            Self::AleoSignature2021 => &["https://w3id.org/security#AleoSignature2021"],
            #[cfg(feature = "w3c")]
            Self::JsonWebSignature2020 => &["https://w3id.org/security#JsonWebSignature2020"],
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1Signature2019 => &["https://w3id.org/security#EcdsaSecp256r1Signature2019"],
            Self::CLSignature2019 => todo!(),
            #[cfg(feature = "test")]
            Self::NonJwsProof |
            Self::AnonCredPresentationProofv1 | Self::AnonCredDerivedCredentialv1 => todo!(),
            //#[cfg(feature = "bbsplus")]
            Self::BbsBlsSignatureProof2020 => &["https://w3id.org/security#BbsBlsSignatureProof2020"],
        }
    }

    pub(crate) fn pick(jwk: &JWK, verification_method: Option<&URI>) -> Result<Self, Error> {
        let algorithm = jwk.get_algorithm().ok_or(Error::MissingAlgorithm)?;
        Ok(match algorithm {
            #[cfg(feature = "rsa")]
            Algorithm::RS256 => Self::RsaSignature2018,
            #[cfg(feature = "w3c")]
            Algorithm::PS256 => Self::JsonWebSignature2020,
            #[cfg(feature = "w3c")]
            Algorithm::ES384 => Self::JsonWebSignature2020,
            #[cfg(feature = "aleo")]
            Algorithm::AleoTestnet1Signature => Self::AleoSignature2021,
            Algorithm::EdDSA | Algorithm::EdBlake2b => match verification_method {
                #[cfg(feature = "solana")]
                Some(URI::String(ref vm))
                    if (vm.starts_with("did:sol:") || vm.starts_with("did:pkh:sol:"))
                        && vm.ends_with("#SolanaMethod2021") =>
                {
                    Self::SolanaSignature2021
                }
                #[cfg(feature = "tezos")]
                Some(URI::String(ref vm))
                    if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
                {
                    if vm.ends_with("#TezosMethod2021") {
                        Self::TezosSignature2021
                    } else {
                        Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                    }
                }
                #[cfg(feature = "ed25519")]
                _ => Self::Ed25519Signature2018,
                #[cfg(not(feature = "ed25519"))]
                _ => {
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures(
                        "ed25519 or tezos or solana",
                    )))
                }
            },
            Algorithm::ES256 | Algorithm::ESBlake2b => match verification_method {
                #[cfg(feature = "tezos")]
                Some(URI::String(ref vm))
                    if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
                {
                    if vm.ends_with("#TezosMethod2021") {
                        Self::TezosSignature2021
                    } else {
                        Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
                    }
                }
                #[cfg(feature = "secp256r1")]
                _ => Self::EcdsaSecp256r1Signature2019,
                #[cfg(not(feature = "secp256r1"))]
                _ => {
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures(
                        "secp256r1 or tezos",
                    )))
                }
            },
            Algorithm::ES256K | Algorithm::ESBlake2bK => match verification_method {
                #[cfg(any(feature = "tezos", feature = "w3c"))]
                Some(URI::String(ref vm))
                    if vm.starts_with("did:tz:") || vm.starts_with("did:pkh:tz:") =>
                {
                    #[cfg(feature = "tezos")]
                    if vm.ends_with("#TezosMethod2021") {
                        return Ok(Self::TezosSignature2021);
                    }
                    #[cfg(feature = "w3c")]
                    return Ok(Self::EcdsaSecp256k1RecoverySignature2020);
                    #[cfg(not(feature = "w3c"))]
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures("w3c or tezos")));
                }
                #[cfg(feature = "secp256k1")]
                _ => Self::EcdsaSecp256k1Signature2019,
                #[cfg(not(feature = "secp256k1"))]
                _ => {
                    return Err(Error::JWS(ssi_jws::Error::MissingFeatures(
                        "secp256k1 or tezos or w3c",
                    )))
                }
            },
            Algorithm::ES256KR => {
                // #[allow(clippy::if_same_then_else)]
                #[cfg(feature = "eip")]
                if use_eip712sig(jwk) {
                    return Ok(Self::EthereumEip712Signature2021);
                }
                #[cfg(feature = "eip")]
                if use_epsig(jwk) {
                    return Ok(Self::EthereumPersonalSignature2021);
                }
                match verification_method {
                    #[cfg(feature = "eip")]
                    Some(URI::String(ref vm))
                        if (vm.starts_with("did:ethr:") || vm.starts_with("did:pkh:eth:"))
                            && vm.ends_with("#Eip712Method2021") =>
                    {
                        Self::Eip712Signature2021
                    }
                    #[cfg(feature = "secp256k1")]
                    _ => Self::EcdsaSecp256k1RecoverySignature2020,
                    #[cfg(not(feature = "secp256k1"))]
                    _ => {
                        return Err(Error::JWS(ssi_jws::Error::MissingFeatures(
                            "secp256k1 or eip",
                        )))
                    }
                }
            }
            //#[cfg(feature = "bbsplus")]
            Algorithm::BLS12381G2 => Self::BbsBlsSignatureProof2020,
            _ => return Err(Error::ProofTypeNotSupported),
        })
    }

    pub fn is_zkp(&self) -> bool {
        matches!(self, Self::CLSignature2019) || matches!(self, Self::BbsBlsSignatureProof2020)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProofSuite for ProofSuiteType {
    async fn sign(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<Proof, Error> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaSignature2018 => {
                sign(
                    document,
                    options,
                    context_loader,
                    key,
                    self.clone(),
                    Algorithm::RS256,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2018 => {
                sign(
                    document,
                    options,
                    context_loader,
                    key,
                    self.clone(),
                    Algorithm::EdDSA,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2020 => {
                sign_nojws(
                    document,
                    options,
                    context_loader,
                    key,
                    self.clone(),
                    Algorithm::EdDSA,
                    ssi_json_ld::W3ID_ED2020_V1_CONTEXT,
                    extra_proof_properties,
                )
                .await
            }
            Self::DataIntegrityProof => {
                DataIntegrityProof::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1Signature2019 => {
                sign(
                    document,
                    options,
                    context_loader,
                    key,
                    self.clone(),
                    Algorithm::ES256K,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoverySignature2020 => {
                EcdsaSecp256k1RecoverySignature2020
                    .sign(
                        document,
                        options,
                        resolver,
                        context_loader,
                        key,
                        extra_proof_properties,
                    )
                    .await
            }
            #[cfg(feature = "eip")]
            Self::Eip712Signature2021 => {
                Eip712Signature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "eip")]
            Self::EthereumPersonalSignature2021 => {
                EthereumPersonalSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "eip")]
            Self::EthereumEip712Signature2021 => {
                EthereumEip712Signature2021::sign(document, options, key, extra_proof_properties)
                    .await
            }
            #[cfg(feature = "tezos")]
            Self::TezosSignature2021 => {
                TezosSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::TezosJcsSignature2021 => {
                TezosJcsSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "solana")]
            Self::SolanaSignature2021 => {
                SolanaSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "aleo")]
            Self::AleoSignature2021 => {
                AleoSignature2021::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "w3c")]
            Self::JsonWebSignature2020 => {
                JsonWebSignature2020::sign(
                    document,
                    options,
                    context_loader,
                    key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1Signature2019 => {
                sign(
                    document,
                    options,
                    context_loader,
                    key,
                    self.clone(),
                    Algorithm::ES256,
                    extra_proof_properties,
                )
                .await
            }
            Self::CLSignature2019 => todo!(),
            #[cfg(feature = "test")]
            Self::NonJwsProof
            | Self::AnonCredPresentationProofv1
            | Self::AnonCredDerivedCredentialv1 => todo!(),
            //#[cfg(feature = "bbsplus")]
            Self::BbsBlsSignatureProof2020 => {
                sign(
                    document,
                    options,
                    context_loader,
                    key,
                    self.clone(),
                    Algorithm::BLS12381G2,
                    extra_proof_properties,
                )
                .await
            }
        }
    }

    async fn prepare(
        &self,
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        public_key: &JWK,
        extra_proof_properties: Option<Map<String, Value>>,
    ) -> Result<ProofPreparation, Error> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaSignature2018 => {
                prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    self.clone(),
                    Algorithm::RS256,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2018 => {
                prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    self.clone(),
                    Algorithm::EdDSA,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2020 => {
                prepare_nojws(
                    document,
                    options,
                    context_loader,
                    public_key,
                    self.clone(),
                    Algorithm::EdDSA,
                    ssi_json_ld::W3ID_ED2020_V1_CONTEXT,
                    extra_proof_properties,
                )
                .await
            }
            Self::DataIntegrityProof => {
                DataIntegrityProof::prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021::prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1Signature2019 => {
                prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    self.clone(),
                    Algorithm::ES256K,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoverySignature2020 => {
                EcdsaSecp256k1RecoverySignature2020
                    .prepare(
                        document,
                        options,
                        resolver,
                        context_loader,
                        public_key,
                        extra_proof_properties,
                    )
                    .await
            }
            #[cfg(feature = "eip")]
            Self::Eip712Signature2021 => {
                Eip712Signature2021::prepare(
                    document,
                    options,
                    context_loader,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "eip")]
            Self::EthereumPersonalSignature2021 => {
                EthereumPersonalSignature2021::prepare(
                    document,
                    options,
                    context_loader,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "eip")]
            Self::EthereumEip712Signature2021 => {
                EthereumEip712Signature2021::prepare(document, options, extra_proof_properties)
                    .await
            }
            #[cfg(feature = "tezos")]
            Self::TezosSignature2021 => {
                TezosSignature2021::prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::TezosJcsSignature2021 => {
                TezosJcsSignature2021::prepare(
                    document,
                    options,
                    public_key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "solana")]
            Self::SolanaSignature2021 => {
                SolanaSignature2021::prepare(
                    document,
                    options,
                    context_loader,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "aleo")]
            Self::AleoSignature2021 => {
                AleoSignature2021::prepare(
                    document,
                    options,
                    context_loader,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "w3c")]
            Self::JsonWebSignature2020 => {
                JsonWebSignature2020::prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    extra_proof_properties,
                )
                .await
            }
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1Signature2019 => {
                prepare(
                    document,
                    options,
                    context_loader,
                    public_key,
                    self.clone(),
                    Algorithm::ES256,
                    extra_proof_properties,
                )
                .await
            }
            Self::CLSignature2019 => todo!(),
            //#[cfg(feature = "bbsplus")]
            Self::BbsBlsSignatureProof2020 => todo!(),
            #[cfg(feature = "test")]
            Self::NonJwsProof
            | Self::AnonCredPresentationProofv1
            | Self::AnonCredDerivedCredentialv1 => todo!(),
        }
    }

    async fn verify(
        &self,
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        nonce: Option<&String>,
        disclosed_message_indices: Option<&Vec<usize>>,
    ) -> Result<VerificationWarnings, Error> {
        match self {
            #[cfg(feature = "rsa")]
            Self::RsaSignature2018 => verify(proof, document, resolver, context_loader).await,
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2018 => verify(proof, document, resolver, context_loader).await,
            #[cfg(feature = "ed25519")]
            Self::Ed25519Signature2020 => {
                // TODO must also match the VM relationship
                if proof.proof_purpose.is_none() {
                    return Err(Error::MissingProofPurpose);
                };
                verify_nojws(proof, document, resolver, context_loader, Algorithm::EdDSA).await
            }
            Self::DataIntegrityProof => {
                DataIntegrityProof::verify(proof, document, resolver, context_loader).await
            }
            #[cfg(feature = "tezos")]
            Self::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::verify(
                    proof,
                    document,
                    resolver,
                    context_loader,
                )
                .await
            }
            #[cfg(feature = "tezos")]
            Self::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021 => {
                P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021::verify(
                    proof,
                    document,
                    resolver,
                    context_loader,
                )
                .await
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1Signature2019 => {
                verify(proof, document, resolver, context_loader).await
            }
            #[cfg(feature = "secp256k1")]
            Self::EcdsaSecp256k1RecoverySignature2020 => {
                EcdsaSecp256k1RecoverySignature2020
                    .verify(proof, document, resolver, context_loader)
                    .await
            }
            #[cfg(feature = "eip")]
            Self::Eip712Signature2021 => {
                Eip712Signature2021::verify(proof, document, resolver, context_loader).await
            }
            #[cfg(feature = "eip")]
            Self::EthereumPersonalSignature2021 => {
                EthereumPersonalSignature2021::verify(proof, document, resolver, context_loader)
                    .await
            }
            #[cfg(feature = "eip")]
            Self::EthereumEip712Signature2021 => {
                EthereumEip712Signature2021::verify(proof, document, resolver).await
            }
            #[cfg(feature = "tezos")]
            Self::TezosSignature2021 => {
                TezosSignature2021::verify(proof, document, resolver, context_loader).await
            }
            #[cfg(feature = "tezos")]
            Self::TezosJcsSignature2021 => {
                TezosJcsSignature2021::verify(proof, document, resolver).await
            }
            #[cfg(feature = "solana")]
            Self::SolanaSignature2021 => {
                SolanaSignature2021
                    .verify(proof, document, resolver, context_loader)
                    .await
            }
            #[cfg(feature = "aleo")]
            Self::AleoSignature2021 => {
                AleoSignature2021::verify(proof, document, resolver, context_loader).await
            }
            #[cfg(feature = "w3c")]
            Self::JsonWebSignature2020 => {
                JsonWebSignature2020::verify(proof, document, resolver, context_loader).await
            }
            #[cfg(feature = "secp256r1")]
            Self::EcdsaSecp256r1Signature2019 => {
                verify(proof, document, resolver, context_loader).await
            }
            Self::CLSignature2019 => todo!(),
            //#[cfg(feature = "bbsplus")]
            Self::BbsBlsSignatureProof2020 => {
                verify_bbs_proof(
                    proof,
                    document,
                    resolver,
                    context_loader,
                    Algorithm::BLS12381G2,
                    nonce,
                    disclosed_message_indices,
                )
                .await
            }
            #[cfg(feature = "test")]
            Self::NonJwsProof
            | Self::AnonCredPresentationProofv1
            | Self::AnonCredDerivedCredentialv1 => todo!(),
        }
    }

    async fn complete(
        &self,
        preparation: &ProofPreparation,
        signature: &str,
    ) -> Result<Proof, Error> {
        let mut proof = preparation.proof.clone();
        match self.signature_type() {
            SignatureType::LD => {
                proof.proof_value = Some(signature.to_string());
            }
            SignatureType::JWS => {
                let jws_header = preparation
                    .jws_header
                    .as_ref()
                    .ok_or(Error::MissingJWSHeader)?;
                let jws = ssi_jws::complete_sign_unencoded_payload(jws_header, signature)?;
                proof.jws = Some(jws);
            }
        }
        Ok(proof)
    }
}
