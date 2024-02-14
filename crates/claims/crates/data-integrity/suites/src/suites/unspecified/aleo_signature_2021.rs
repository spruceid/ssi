use ssi_crypto::{protocol::Base58BtcMultibase, MessageSignatureError, MessageSigner};
use ssi_data_integrity_core::{
    suite::HashError, CryptographicSuite, ExpandedConfiguration, ProofConfigurationRef,
};
use ssi_jwk::JWK;
use ssi_verification_methods::{
    verification_method_union, AleoMethod2021, AnyMethod, AnyMethodRef,
    BlockchainVerificationMethod2021, InvalidVerificationMethod, SignatureError,
    TypedVerificationMethod, VerificationError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, suites::sha256_hash, MultibaseSignature, MultibaseSignatureRef,
};

/// Aleo Signature 2021
///
/// Linked data signature suite using [Aleo](crate::aleo).
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
pub struct AleoSignature2021;

impl AleoSignature2021 {
    pub const NAME: &'static str = "AleoSignature2021";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#AleoSignature2021");
}

const BLOCKCHAIN_NETWORK_ID: &str = "1";
const BLOCKCHAIN_NAMESPACE: &str = "aleo";

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        AleoMethod2021,
        BlockchainVerificationMethod2021
    }
}

impl_rdf_input_urdna2015!(AleoSignature2021);

impl CryptographicSuite for AleoSignature2021 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = VerificationMethod;

    type Signature = MultibaseSignature;

    type SignatureProtocol = Base58BtcMultibase;

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

    type Options = ();

    fn name(&self) -> &str {
        Self::NAME
    }

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl SignatureAlgorithm {
    pub fn wallet_sign(message: &[u8], key: &JWK) -> Result<Vec<u8>, MessageSignatureError> {
        let signature =
            ssi_jwk::aleo::sign(&message, key).map_err(MessageSignatureError::signature_failed)?;
        Ok(Base58BtcMultibase::encode_signature(&signature))
    }
}

impl ssi_verification_methods::SignatureAlgorithm<VerificationMethod> for SignatureAlgorithm {
    type Options = ();

    type Signature = MultibaseSignature;

    type Protocol = Base58BtcMultibase;

    type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        _bytes: &[u8],
        _signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        _options: (),
        signature: MultibaseSignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let (_, signature_bytes) = multibase::decode(&signature.proof_value)
            .map_err(|_| VerificationError::InvalidSignature)?;

        let account_id = method.blockchain_account_id();

        if account_id.chain_id.namespace != BLOCKCHAIN_NAMESPACE {
            return Err(VerificationError::InvalidKey);
        }

        if account_id.chain_id.reference != BLOCKCHAIN_NETWORK_ID {
            return Err(VerificationError::InvalidKey);
        }

        let result = ssi_jwk::aleo::verify(bytes, &account_id.account_address, &signature_bytes);

        match result {
            Ok(()) => Ok(true),
            Err(ssi_jwk::aleo::AleoVerifyError::InvalidSignature) => Ok(false),
            Err(_) => Err(VerificationError::InvalidSignature),
        }
    }
}

impl<'a> VerificationMethodRef<'a> {
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

impl<'a> TryFrom<AnyMethodRef<'a>> for VerificationMethodRef<'a> {
    type Error = InvalidVerificationMethod;

    fn try_from(value: AnyMethodRef<'a>) -> Result<Self, Self::Error> {
        match value {
            AnyMethodRef::AleoMethod2021(m) => Ok(Self::AleoMethod2021(m)),
            AnyMethodRef::BlockchainVerificationMethod2021(m) => {
                Ok(Self::BlockchainVerificationMethod2021(m))
            }
            m => Err(InvalidVerificationMethod::invalid_type_name(
                AnyMethod::ref_type(m),
            )),
        }
    }
}

impl<'a> From<VerificationMethodRef<'a>> for AnyMethodRef<'a> {
    fn from(value: VerificationMethodRef<'a>) -> Self {
        match value {
            VerificationMethodRef::AleoMethod2021(m) => Self::AleoMethod2021(m),
            VerificationMethodRef::BlockchainVerificationMethod2021(m) => {
                Self::BlockchainVerificationMethod2021(m)
            }
        }
    }
}
