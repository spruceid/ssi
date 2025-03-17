use std::borrow::Cow;

use coset::{
    CborSerializable, ContentType, CoseSign1, Header, Label, ProtectedHeader,
    TaggedCborSerializable,
};
use ssi_crypto::{Error, Signer};

use crate::{algorithm::cose_algorithm, CoseSign1BytesBuf};

/// COSE payload.
///
/// This trait defines how a custom type can be encoded and signed using COSE.
///
/// # Example
///
/// ```
/// use std::borrow::Cow;
/// use serde::{Serialize, Deserialize};
/// use ssi_cose::{CosePayload, CosePayloadType, ContentType};
///
/// // Our custom payload type.
/// #[derive(Serialize, Deserialize)]
/// struct CustomPayload {
///   data: String
/// }
///
/// // Define how the payload is encoded in COSE.
/// impl CosePayload for CustomPayload {
///   fn typ(&self) -> Option<CosePayloadType> {
///     Some(CosePayloadType::Text(
///       "application/json+cose".to_owned(),
///     ))
///   }
///   
///   fn content_type(&self) -> Option<ContentType> {
///     Some(ContentType::Text("application/json".to_owned()))
///   }
///
///   // Serialize the payload as JSON.
///   fn payload_bytes(&self) -> Cow<[u8]> {
///     Cow::Owned(serde_json::to_vec(self).unwrap())
///   }
/// }
/// ```
pub trait CosePayload {
    /// `typ` header parameter.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
    fn typ(&self) -> Option<CosePayloadType> {
        None
    }

    /// Content type header parameter.
    fn content_type(&self) -> Option<ContentType> {
        None
    }

    /// Payload bytes.
    ///
    /// Returns the payload bytes representing this value.
    fn payload_bytes(&self) -> Cow<[u8]>;

    /// Sign the payload to produce a serialized `COSE_Sign1` object.
    ///
    /// The `tagged` flag specifies if the COSE object should be tagged or
    /// not.
    #[allow(async_fn_in_trait)]
    async fn sign(&self, signer: impl Signer, tagged: bool) -> Result<CoseSign1BytesBuf, Error> {
        self.sign_with(signer, None, tagged).await
    }

    #[allow(async_fn_in_trait)]
    async fn sign_with(
        &self,
        signer: impl Signer,
        additional_data: Option<&[u8]>,
        tagged: bool,
    ) -> Result<CoseSign1BytesBuf, Error> {
        let metadata = signer.key_metadata();

        let (key_id, algorithm_params) = metadata.into_id_and_algorithm(None)?;
        let algorithm = algorithm_params.algorithm();

        let mut result = CoseSign1 {
            protected: ProtectedHeader {
                header: Header {
                    alg: cose_algorithm(algorithm),
                    key_id: key_id.unwrap_or_default(),
                    content_type: self.content_type(),
                    rest: match self.typ() {
                        Some(typ) => vec![(TYP_LABEL, typ.into())],
                        None => Vec::new(),
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            unprotected: Header::default(),
            payload: Some(self.payload_bytes().into_owned()),
            signature: Vec::new(),
        };

        let tbs = result.tbs_data(additional_data.unwrap_or_default());

        result.signature = signer.sign(algorithm_params, &tbs).await?.into_vec();

        Ok(if tagged {
            result.to_tagged_vec().unwrap().into()
        } else {
            result.to_vec().unwrap().into()
        })
    }
}

impl CosePayload for [u8] {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

pub const TYP_LABEL: Label = Label::Int(16);

/// COSE payload type.
///
/// Value of the `typ` header parameter.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9596#section-2>
pub enum CosePayloadType {
    UInt(u64),
    Text(String),
}

impl From<CosePayloadType> for crate::CborValue {
    fn from(ty: CosePayloadType) -> Self {
        match ty {
            CosePayloadType::UInt(i) => Self::Integer(i.into()),
            CosePayloadType::Text(t) => Self::Text(t),
        }
    }
}

/// COSE signature bytes.
pub struct CoseSignatureBytes(pub Vec<u8>);

impl CoseSignatureBytes {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{CoseKey, CosePayload, DecodedCoseSign1};

    async fn sign_with(key: &CoseKey, tagged: bool) {
        let bytes = b"PAYLOAD".sign(key, tagged).await.unwrap();
        let decoded: DecodedCoseSign1 = bytes.decode(tagged).unwrap();

        assert_eq!(decoded.signing_bytes.payload.as_bytes(), b"PAYLOAD");

        assert_eq!(decoded.verify(key).await.unwrap(), Ok(()));
    }

    #[cfg(feature = "ed25519")]
    #[async_std::test]
    async fn sign_ed25519() {
        sign_with(&CoseKey::generate_ed25519(), false).await
    }

    #[cfg(feature = "ed25519")]
    #[async_std::test]
    async fn sign_ed25519_tagged() {
        sign_with(&CoseKey::generate_ed25519(), true).await
    }

    #[cfg(feature = "secp256k1")]
    #[async_std::test]
    async fn sign_secp256k1() {
        sign_with(&CoseKey::generate_secp256k1(), false).await
    }

    #[cfg(feature = "secp256k1")]
    #[async_std::test]
    async fn sign_secp256k1_tagged() {
        sign_with(&CoseKey::generate_secp256k1(), true).await
    }

    #[cfg(feature = "secp256r1")]
    #[async_std::test]
    async fn sign_p256() {
        sign_with(&CoseKey::generate_p256(), false).await
    }

    #[cfg(feature = "secp256r1")]
    #[async_std::test]
    async fn sign_p256_tagged() {
        sign_with(&CoseKey::generate_p256(), true).await
    }

    #[cfg(feature = "secp384r1")]
    #[async_std::test]
    async fn sign_p384() {
        sign_with(&CoseKey::generate_p384(), false).await
    }

    #[cfg(feature = "secp384r1")]
    #[async_std::test]
    async fn sign_p384_tagged() {
        sign_with(&CoseKey::generate_p384(), true).await
    }
}
