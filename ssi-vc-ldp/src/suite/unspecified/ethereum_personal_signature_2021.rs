use std::future;

use ssi_crypto::{protocol::EthereumWallet, MessageSignatureError, MessageSigner};
use ssi_jwk::JWK;
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::{
    covariance_rule, verification_method_union, EcdsaSecp256k1RecoveryMethod2020,
    EcdsaSecp256k1VerificationKey2019, Referencable, SignatureError, VerificationError, InvalidSignature,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, suite::{HashError, AnySignature, AnySignatureRef}, CryptographicSuite, ProofConfigurationRef,
};

/// Ethereum Personal Signature 2021.
pub struct EthereumPersonalSignature2021;

impl EthereumPersonalSignature2021 {
    pub const IRI: &iref::Iri = iri!("https://w3id.org/security#EthereumPersonalSignature2021");
}

verification_method_union! {
    pub enum VerificationMethod, VerificationMethodRef, VerificationMethodType {
        EcdsaSecp256k1VerificationKey2019,
        EcdsaSecp256k1RecoveryMethod2020
    }
}

impl_rdf_input_urdna2015!(EthereumPersonalSignature2021);

impl CryptographicSuite for EthereumPersonalSignature2021 {
    type Transformed = String;

    type Hashed = String;

    type VerificationMethod = VerificationMethod;

    type Signature = Signature;

    type SignatureProtocol = EthereumWallet;

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

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
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads(self).into_nquads();
        let message = format!("{proof_quads}\n{data}");
        Ok(message)
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    /// Hex-encoded (with `0x` prefix) signature.
    pub proof_value: String,
}

impl Referencable for Signature {
    type Reference<'a> = SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        SignatureRef {
            proof_value: &self.proof_value,
        }
    }

    covariance_rule!();
}

impl From<Signature> for AnySignature {
    fn from(value: Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl TryFrom<AnySignature> for Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    pub proof_value: &'a str,
}

impl<'a> From<SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?
        })
    }
}

pub struct SignatureAlgorithm;

impl SignatureAlgorithm {
    /// Sign as an Ethereum wallet.
    pub fn wallet_sign(
        message: &[u8],
        secret_key: &k256::SecretKey,
    ) -> Result<String, MessageSignatureError> {
        use k256::ecdsa::signature::Signer;
        let prefixed_message = ssi_crypto::hashes::keccak::prefix_personal_message(message);
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);
        let sig: k256::ecdsa::recoverable::Signature = signing_key
            .try_sign(&prefixed_message)
            .map_err(|e| MessageSignatureError::SignatureFailed(Box::new(e)))?;
        let sig_bytes = &mut sig.as_ref().to_vec();

        // Recovery ID starts at 27 instead of 0.
        sig_bytes[64] += 27;
        Ok(ssi_crypto::hashes::keccak::bytes_to_lowerhex(sig_bytes))
    }
}

impl ssi_verification_methods::SignatureAlgorithm<VerificationMethod> for SignatureAlgorithm {
    type Options = ();

    type Signature = Signature;

    type Protocol = EthereumWallet;

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        _options: (),
        method: VerificationMethodRef,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        _options: (),
        signature: SignatureRef,
        method: VerificationMethodRef,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        // Build the actual signed message.
        let message = ssi_crypto::hashes::keccak::prefix_personal_message(bytes);

        let Some(hex_signature) = signature.proof_value.strip_prefix("0x") else {
            return Err(VerificationError::InvalidSignature);
        };

        let signature_bytes =
            hex::decode(&hex_signature).map_err(|_| VerificationError::InvalidSignature)?;

        let rec_id = k256::ecdsa::recoverable::Id::try_from(signature_bytes[64] % 27)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let sig = k256::ecdsa::Signature::try_from(&signature_bytes[..64])
            .map_err(|_| VerificationError::InvalidSignature)?;
        let sig = k256::ecdsa::recoverable::Signature::new(&sig, rec_id)
            .map_err(|_| VerificationError::InvalidSignature)?;

        let recovered_key = sig
            .recover_verifying_key(&message)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let jwk = JWK {
            params: ssi_jwk::Params::EC(
                ssi_jwk::ECParams::try_from(
                    &k256::PublicKey::from_sec1_bytes(recovered_key.to_bytes().as_slice())
                        .map_err(|_| VerificationError::InvalidSignature)?,
                )
                .map_err(|_| VerificationError::InvalidSignature)?,
            ),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };

        method.check_jwk(&jwk)?;
        Ok(true)
    }
}

impl<'a> VerificationMethodRef<'a> {
    pub fn check_jwk(&self, jwk: &JWK) -> Result<(), VerificationError> {
        match self {
            Self::EcdsaSecp256k1RecoveryMethod2020(m) => {
                if m.public_key.matches(jwk)? {
                    Ok(())
                } else {
                    Err(VerificationError::KeyMismatch)
                }
            }
            Self::EcdsaSecp256k1VerificationKey2019(m) => {
                if m.public_key.jwk()?.equals_public(jwk) {
                    Ok(())
                } else {
                    Err(VerificationError::KeyMismatch)
                }
            }
        }
    }
}
