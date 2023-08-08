use ssi_jwk::JWK;
use ssi_rdf::IntoNQuads;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{Referencable, TezosMethod2021};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, suite::HashError, CryptographicSuite, ProofConfiguration,
    ProofConfigurationRef,
};

/// Tezos signature suite based on URDNA2015.
///
/// # Transformation algorithm
///
/// The input credential RDF graph is normalized into a list of RDF quads using
/// the URDNA2015 canonicalization algorithm.
///
/// # Hashing algorithm
///
/// The proof configuration RDF graph is normalized into into a list of RDF
/// quads using the URDNA2015 canonicalization algorithm. A message is formed
/// by concatenating the `Tezos Signed Message: ` (ending with a space), the
/// credential quads and the configuration quads using the 0xa byte (line feed).
///
/// The output is a bytes string composed of the byte 0x5, followed by the byte
/// 0x1, followed by the 4 bytes encoding the message lenght in big endian,
/// followd by the message.
///
/// [1]: <https://tools.ietf.org/html/rfc8785>
///
/// # Verification method
///
/// The [`TezosMethod2021`] verification method is used.
pub struct TezosSignature2021;

impl_rdf_input_urdna2015!(TezosSignature2021);

impl CryptographicSuite for TezosSignature2021 {
    type Transformed = String;
    type Hashed = Vec<u8>;

    type VerificationMethod = TezosMethod2021;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#TezosSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads(self).into_nquads();
        let message = format!("\n{data}\n{proof_quads}");
        match ssi_tzkey::encode_tezos_signed_message(&message) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    /// Base58-encoded signature.
    proof_value: String,

    /// Signing key.
    public_key: Option<PublicKey>,
}

impl Referencable for Signature {
    type Reference<'a> = SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        SignatureRef {
            proof_value: &self.proof_value,
            public_key: self.public_key.as_ref().map(|k| match k {
                PublicKey::Jwk(jwk) => PublicKeyRef::Jwk(jwk),
                PublicKey::Multibase(m) => PublicKeyRef::Multibase(m),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SignatureRef<'a> {
    /// Base58-encoded signature.
    proof_value: &'a str,

    /// Signing key.
    public_key: Option<PublicKeyRef<'a>>,
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    Jwk(Box<JWK>),
    Multibase(String),
}

#[derive(Debug, Clone, Copy)]
pub enum PublicKeyRef<'a> {
    Jwk(&'a JWK),
    Multibase(&'a str),
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<TezosMethod2021> for SignatureAlgorithm {
    type Signature = Signature;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
        &self,
        method: &TezosMethod2021,
        bytes: &[u8],
        signer: &S,
    ) -> Result<Self::Signature, ssi_verification_methods::SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        signature: SignatureRef,
        method: &TezosMethod2021,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
