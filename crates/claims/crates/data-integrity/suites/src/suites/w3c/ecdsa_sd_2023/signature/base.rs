use k256::sha2::{Digest, Sha256};
use ssi_claims_core::SignatureError;
use ssi_crypto::algorithm::ES256OrES384;
use ssi_di_sd_primitives::{HmacShaAnyKey, JsonPointerBuf, ShaAny, ShaAnyBytes};
use ssi_multicodec::{MultiEncoded, MultiEncodedBuf};
use ssi_rdf::IntoNQuads;
use ssi_security::MultibaseBuf;
use ssi_verification_methods::MessageSigner;

use crate::ecdsa_sd_2023::BaseHashData;

use super::Signature;

pub async fn generate_proof<T>(
    signer: T,
    hash_data: BaseHashData,
) -> Result<Signature, SignatureError>
where
    T: MessageSigner<ES256OrES384>,
{
    let mut rng = rand::thread_rng();

    // Locally generated P-256 ECDSA key pair, scoped to the specific proof and
    // destroyed with this algorithm terminates.
    let proof_scoped_key_pair = p256::SecretKey::random(&mut rng);

    let signatures: Vec<[u8; 32]> = hash_data
        .transformed_document
        .non_mandatory
        .into_nquads_lines()
        .into_iter()
        .map(|line| Sha256::digest(line).into())
        .collect();

    let public_key: MultiEncodedBuf = MultiEncodedBuf::encode(&proof_scoped_key_pair.public_key());

    let to_sign = serialize_sign_data(hash_data.proof_hash, hash_data.mandatory_hash, &public_key);

    let algorithm = match hash_data.transformed_document.hmac_key.algorithm() {
        ShaAny::Sha256 => ES256OrES384::ES256,
        ShaAny::Sha384 => ES256OrES384::ES384,
    };

    let base_signature = signer.sign(algorithm, &to_sign).await?;

    Ok(Signature::encode_base(
        &base_signature,
        &public_key,
        hash_data.transformed_document.hmac_key,
        &signatures,
        &hash_data.transformed_document.options.mandatory_pointers,
    ))
}

/// Serialize sign data.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#serializesigndata>
fn serialize_sign_data(
    proof_hash: ShaAnyBytes,
    mandatory_hash: ShaAnyBytes,
    public_key: &MultiEncoded,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(proof_hash.len() + mandatory_hash.len() + public_key.len());
    bytes.extend(proof_hash.as_slice());
    bytes.extend(public_key.as_bytes());
    bytes.extend(mandatory_hash.as_slice());
    bytes
}

impl Signature {
    pub fn encode_base(
        base_signature: &[u8],
        public_key: &MultiEncoded,
        hmac_key: HmacShaAnyKey,
        signatures: &[[u8; 32]],
        mandatory_pointers: &[JsonPointerBuf],
    ) -> Self {
        let components = vec![
            serde_cbor::Value::Bytes(base_signature.to_vec()),
            serde_cbor::Value::Bytes(public_key.as_bytes().to_vec()),
            serde_cbor::Value::Bytes(hmac_key.to_vec()),
            serde_cbor::Value::Array(signatures.iter().map(|p| p.to_vec().into()).collect()),
            serde_cbor::Value::Array(
                mandatory_pointers
                    .iter()
                    .map(|p| p.as_str().to_owned().into())
                    .collect(),
            ),
        ];

        let mut proof_value = vec![0xd9, 0x5d, 0x00];
        serde_cbor::to_writer(&mut proof_value, &components).unwrap();

        Self {
            proof_value: MultibaseBuf::encode(multibase::Base::Base64Url, proof_value),
        }
    }
}
