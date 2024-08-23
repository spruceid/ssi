use k256::sha2::Sha256;
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{
    canonicalization::{CanonicalizeClaimsAndConfiguration, HashCanonicalClaimsAndConfiguration},
    signing::MultibaseSignature,
    suite::{
        standard::{SignatureAlgorithm, SignatureAndVerificationAlgorithm, VerificationAlgorithm},
        NoConfiguration,
    },
    ProofConfigurationRef, ProofRef, StandardCryptographicSuite, TypeRef,
};
use ssi_verification_methods::{
    protocol::{Base58BtcMultibase, WithProtocol},
    verification_method_union, AleoMethod2021, AnyMethod, BlockchainVerificationMethod2021,
    InvalidVerificationMethod, MessageSigner,
};
use static_iref::iri;

use crate::try_from_type;

/// Aleo Signature 2021
///
/// Linked data signature suite using Aleo.
///
/// Only verification is supported.
///
/// # Transformation algorithm
///
/// This suite accepts linked data documents transformed into a canonical
/// RDF graph using the [URDNA2015][1] algorithm.
///
/// [1]: <https://w3id.org/security#URDNA2015>
///
/// # Hashing algorithm
///
/// The SHA-256 algorithm is used to hash the input canonical RDF graph and the
/// proof configuration graph, also in canonical form. Both hashes are then
/// concatenated into a single 64-bytes message, ready to be signed.
///
/// # Verification method
///
/// The following verification methods my be used to sign/verify a credential
/// with this suite:
/// - [`AleoMethod2021`]
/// - [`BlockchainVerificationMethod2021`]
///
/// # Signature protocol
///
/// The [`Base58BtcMultibase`] protocol is used, where the signer is
/// expected to encode the signature in with [multibase][2] using the
/// `Base58Btc` base.
///
/// [2]: <https://github.com/multiformats/multibase>
#[derive(Debug, Default, Clone, Copy)]
pub struct AleoSignature2021;

impl AleoSignature2021 {
    pub const NAME: &'static str = "AleoSignature2021";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#AleoSignature2021");
}

const BLOCKCHAIN_NETWORK_ID: &str = "1";
const BLOCKCHAIN_NAMESPACE: &str = "aleo";

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodType {
        AleoMethod2021,
        BlockchainVerificationMethod2021
    }
}

impl StandardCryptographicSuite for AleoSignature2021 {
    type Configuration = NoConfiguration;

    type Transformation = CanonicalizeClaimsAndConfiguration;

    type Hashing = HashCanonicalClaimsAndConfiguration<Sha256>;

    type VerificationMethod = VerificationMethod;

    type SignatureAlgorithm = AleoSignatureAlgorithm;

    type ProofOptions = ();

    fn type_(&self) -> TypeRef {
        TypeRef::Other(Self::NAME)
    }
}

try_from_type!(AleoSignature2021);

pub struct AleoSignatureAlgorithm;

impl SignatureAndVerificationAlgorithm for AleoSignatureAlgorithm {
    type Signature = MultibaseSignature;
}

impl<T> SignatureAlgorithm<AleoSignature2021, T> for AleoSignatureAlgorithm
where
    T: MessageSigner<WithProtocol<ssi_jwk::Algorithm, Base58BtcMultibase>>,
{
    async fn sign(
        _verification_method: &VerificationMethod,
        _signer: T,
        _prepared_claims: [u8; 64],
        _proof_configuration: ProofConfigurationRef<'_, AleoSignature2021>,
    ) -> Result<Self::Signature, SignatureError> {
        // ssi_jws::sign_bytes(algorithm, data, key)
        // let signature = ssi_jwk::aleo::sign(hash, key).map_err(MessageSignatureError::signature_failed)?;
        // signer.sign(method., protocol, message)
        // Ok(Base58BtcMultibase::encode_signature(&signature))
        unimplemented!("AleoSignature2021 signing is not supported")
    }
}

impl VerificationAlgorithm<AleoSignature2021> for AleoSignatureAlgorithm {
    fn verify(
        method: &VerificationMethod,
        prepared_claims: [u8; 64],
        proof: ProofRef<AleoSignature2021>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let (_, signature_bytes) = multibase::decode(&proof.signature.proof_value)
            .map_err(|_| ProofValidationError::InvalidSignature)?;

        let account_id = method.blockchain_account_id();

        if account_id.chain_id.namespace != BLOCKCHAIN_NAMESPACE {
            return Err(ProofValidationError::InvalidKey);
        }

        if account_id.chain_id.reference != BLOCKCHAIN_NETWORK_ID {
            return Err(ProofValidationError::InvalidKey);
        }

        let result = ssi_jwk::aleo::verify(
            &prepared_claims,
            &account_id.account_address,
            &signature_bytes,
        );

        match result {
            Ok(()) => Ok(Ok(())),
            Err(ssi_jwk::aleo::AleoVerifyError::InvalidSignature) => {
                Ok(Err(ssi_claims_core::InvalidProof::Signature))
            }
            Err(_) => Err(ProofValidationError::InvalidSignature),
        }
    }
}

// pub fn wallet_sign(message: &[u8], key: &JWK) -> Result<Vec<u8>, MessageSignatureError> {
//     let signature =
//         ssi_jwk::aleo::sign(message, key).map_err(MessageSignatureError::signature_failed)?;
//     Ok(Base58BtcMultibase::encode_signature(&signature))
// }

impl VerificationMethod {
    pub fn blockchain_account_id(&self) -> &ssi_caips::caip10::BlockchainAccountId {
        match self {
            Self::AleoMethod2021(m) => &m.blockchain_account_id,
            Self::BlockchainVerificationMethod2021(m) => &m.blockchain_account_id,
        }
    }
}

impl TryFrom<AnyMethod> for VerificationMethod {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethod) -> Result<Self, Self::Error> {
        match value {
            AnyMethod::AleoMethod2021(m) => Ok(Self::AleoMethod2021(m)),
            AnyMethod::BlockchainVerificationMethod2021(m) => {
                Ok(Self::BlockchainVerificationMethod2021(m))
            }
            m => Err(InvalidVerificationMethod::invalid_type_name(
                ssi_verification_methods::TypedVerificationMethod::type_(&m),
                "AleoMethod2021 or BlockchainVerificationMethod2021",
            )),
        }
    }
}

impl From<VerificationMethod> for AnyMethod {
    fn from(value: VerificationMethod) -> Self {
        match value {
            VerificationMethod::AleoMethod2021(m) => Self::AleoMethod2021(m),
            VerificationMethod::BlockchainVerificationMethod2021(m) => {
                Self::BlockchainVerificationMethod2021(m)
            }
        }
    }
}
