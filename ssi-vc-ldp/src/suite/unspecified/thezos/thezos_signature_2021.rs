use ssi_rdf::IntoNQuads;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::TezosMethod2021;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, suite::HashError, verification, CryptographicSuite,
    ProofConfiguration, ProofOptions,
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

#[async_trait::async_trait]
impl CryptographicSuite for TezosSignature2021 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = Vec<u8>;

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<TezosMethod2021>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#TezosSignature2021")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads(self).into_nquads();
        let message = format!("\n{data}\n{proof_quads}");
        match ssi_tzkey::encode_tezos_signed_message(&message) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }
}
