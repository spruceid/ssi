use ssi_crypto::{AlgorithmInstance, Error, Signer};
use std::borrow::Cow;

use crate::{DecodedJws, DecodedSigningBytes, Header, JwsBuf, JwsSignature};

/// JWS payload type.
///
/// Any type that can be serialized with a give JWS type.
pub trait JwsPayload {
    /// JWS type.
    ///
    /// Value of the `typ` field in the JWS header.
    fn typ(&self) -> Option<&str> {
        None
    }

    /// JWS cty header value.
    fn cty(&self) -> Option<&str> {
        None
    }

    fn payload_bytes(&self) -> Cow<[u8]>;

    #[allow(async_fn_in_trait)]
    async fn sign_into_decoded(
        self,
        signer: impl Signer,
        algorithm_params: Option<AlgorithmInstance>,
    ) -> Result<DecodedJws<'static, Self>, Error>
    where
        Self: Sized,
    {
        let metadata = signer.key_metadata();
        let payload_bytes = self.payload_bytes();

        let (key_id, algorithm_params) = metadata.into_id_and_algorithm(algorithm_params)?;

        let algorithm = algorithm_params.algorithm();

        let header = Header {
            algorithm: algorithm
                .try_into()
                .map_err(|_| Error::AlgorithmUnsupported(algorithm))?,
            key_id: key_id
                .as_deref()
                .map(String::from_utf8_lossy)
                .map(Cow::into_owned),
            content_type: self.cty().map(ToOwned::to_owned),
            type_: self.typ().map(ToOwned::to_owned),
            ..Default::default()
        };

        let signing_bytes = header.encode_signing_bytes(&payload_bytes);
        let signature = JwsSignature::new(signer.sign(algorithm_params, &signing_bytes).await?);

        Ok(DecodedJws {
            signing_bytes: DecodedSigningBytes {
                bytes: Cow::Owned(signing_bytes),
                header,
                payload: self,
            },
            signature,
        })
    }

    #[allow(async_fn_in_trait)]
    async fn sign_to_decoded(
        &self,
        signer: impl Signer,
        algorithm_params: Option<AlgorithmInstance>,
    ) -> Result<DecodedJws<'static, &Self>, Error> {
        <&Self as JwsPayload>::sign_into_decoded(self, signer, algorithm_params).await
    }

    /// Signs the payload and returns a compact JWS.
    #[allow(async_fn_in_trait)]
    async fn sign(
        &self,
        signer: impl Signer,
        algorithm_params: Option<AlgorithmInstance>,
    ) -> Result<JwsBuf, Error> {
        Ok(self
            .sign_to_decoded(signer, algorithm_params)
            .await?
            .into_encoded()
            .into_url_safe()
            .ok()
            .unwrap())
    }

    #[allow(async_fn_in_trait)]
    async fn sign_detached(
        &self,
        signer: impl Signer,
        algorithm_params: Option<AlgorithmInstance>,
    ) -> Result<JwsBuf, Error> {
        Ok(self
            .sign_to_decoded(signer, algorithm_params)
            .await?
            .into_encoded_detached()
            .into_url_safe()
            .ok()
            .unwrap())
    }
}

impl<'a, P: ?Sized + JwsPayload> JwsPayload for &'a P {
    fn typ(&self) -> Option<&str> {
        P::typ(*self)
    }

    fn cty(&self) -> Option<&str> {
        P::cty(*self)
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        P::payload_bytes(*self)
    }
}

impl JwsPayload for [u8] {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

impl JwsPayload for Vec<u8> {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

impl JwsPayload for str {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl JwsPayload for String {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl JwsPayload for serde_json::Value {
    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

// pub struct JwsSignerInfo {
//     pub key_id: Option<String>,
//     pub algorithm: Algorithm,
// }

// /// JWS Signer.
// ///
// /// Any type that can fetch a JWK using the `kid` parameter of a JWS JOSE
// /// header and sign bytes.
// pub trait JwsSigner {
//     #[allow(async_fn_in_trait)]
//     async fn fetch_info(&self) -> Result<JwsSignerInfo, Error>;

//     #[allow(async_fn_in_trait)]
//     async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, Error>;

//     #[allow(async_fn_in_trait)]
//     async fn sign(&self, payload: impl JwsPayload) -> Result<JwsBuf, Error> {
//         Ok(self
//             .sign_into_decoded(payload)
//             .await?
//             .into_encoded()
//             .into_url_safe()
//             .ok()
//             .unwrap())
//     }
// }

// impl<'a, T: JwsSigner> JwsSigner for &'a T {
//     async fn fetch_info(&self) -> Result<JwsSignerInfo, Error> {
//         T::fetch_info(*self).await
//     }

//     async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, Error> {
//         T::sign_bytes(*self, signing_bytes).await
//     }

//     async fn sign(&self, payload: impl JwsPayload) -> Result<JwsBuf, Error> {
//         T::sign(*self, payload).await
//     }
// }

// impl<'a, T: JwsSigner + Clone> JwsSigner for Cow<'a, T> {
//     async fn fetch_info(&self) -> Result<JwsSignerInfo, Error> {
//         T::fetch_info(self.as_ref()).await
//     }

//     async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, Error> {
//         T::sign_bytes(self.as_ref(), signing_bytes).await
//     }

//     async fn sign(&self, payload: impl JwsPayload) -> Result<JwsBuf, Error> {
//         T::sign(self.as_ref(), payload).await
//     }
// }

// impl JwsSigner for JWK {
//     async fn fetch_info(&self) -> Result<JwsSignerInfo, Error> {
//         Ok(JwsSignerInfo {
//             key_id: self.key_id.clone(),
//             algorithm: self
//                 .get_algorithm()
//                 .ok_or(Error::MissingAlgorithm)?,
//         })
//     }

//     async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, Error> {
//         let algorithm = self
//             .get_algorithm()
//             .ok_or(Error::MissingAlgorithm)?;
//         crate::sign_bytes(algorithm, signing_bytes, self).map_err(Into::into)
//     }
// }

// pub struct JwkWithAlgorithm<'a> {
//     pub jwk: &'a JWK,
//     pub algorithm: Algorithm,
// }

// impl<'a> JwkWithAlgorithm<'a> {
//     pub fn new(jwk: &'a JWK, algorithm: Algorithm) -> Self {
//         Self { jwk, algorithm }
//     }
// }

// impl<'a> JwsSigner for JwkWithAlgorithm<'a> {
//     async fn fetch_info(&self) -> Result<JwsSignerInfo, Error> {
//         Ok(JwsSignerInfo {
//             key_id: self.jwk.key_id.clone(),
//             algorithm: self.algorithm,
//         })
//     }

//     async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, Error> {
//         crate::sign_bytes(self.algorithm, signing_bytes, self.jwk).map_err(Into::into)
//     }
// }
