use ssi_core::{covariance_rule, Referencable};
use ssi_crypto::MessageSigner;
use ssi_jwk::Algorithm;
use ssi_jws::{CompactJWSStr, CompactJWSString};
use ssi_verification_methods::{InvalidSignature, SignatureError, VerificationError};

use crate::eip712::Eip712Metadata;

#[derive(
    Debug,
    Default,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
#[serde(rename_all = "camelCase")]
pub struct AnySignature {
    #[ld("sec:proofValue")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,

    #[ld("sec:signatureValue")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_value: Option<String>,

    #[ld("sec:jws")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<CompactJWSString>,

    #[ld("https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#eip712-domain")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip712: Option<Eip712Metadata>,
    // #[ld("sec:publicKeyJwk")]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub public_key_jwk: Option<Box<JWK>>,

    // #[ld("sec:publicKeyMultibase")]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub public_key_multibase: Option<MultibaseBuf>,
}

impl Referencable for AnySignature {
    type Reference<'a> = AnySignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        AnySignatureRef {
            proof_value: self.proof_value.as_deref(),
            signature_value: self.signature_value.as_deref(),
            jws: self.jws.as_deref(),
            eip712: self.eip712.as_ref(),
            // public_key_jwk: self.public_key_jwk.as_deref(),
            // public_key_multibase: self.public_key_multibase.as_deref(),
        }
    }

    covariance_rule!();
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AnySignatureRef<'a> {
    pub proof_value: Option<&'a str>,

    pub signature_value: Option<&'a str>,

    pub jws: Option<&'a CompactJWSStr>,

    pub eip712: Option<&'a Eip712Metadata>,
    // pub public_key_jwk: Option<&'a JWK>,

    // pub public_key_multibase: Option<&'a Multibase>,
}

/// Common signature format where the proof value is multibase-encoded.
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct MultibaseSignature {
    /// Multibase encoded signature.
    #[serde(rename = "proofValue")]
    #[ld("sec:proofValue")]
    pub proof_value: String,
}

impl MultibaseSignature {
    pub fn new_base58btc(signature: Vec<u8>) -> Self {
        Self {
            proof_value: multibase::encode(multibase::Base::Base58Btc, signature),
        }
    }

    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        multibase::decode(&self.proof_value)
            .map(|(_, data)| data)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

impl Referencable for MultibaseSignature {
    type Reference<'a> = MultibaseSignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        MultibaseSignatureRef {
            proof_value: &self.proof_value,
        }
    }

    covariance_rule!();
}

impl From<MultibaseSignature> for AnySignature {
    fn from(value: MultibaseSignature) -> Self {
        AnySignature {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MultibaseSignatureRef<'a> {
    /// Multibase encoded signature.
    pub proof_value: &'a str,
}

impl<'a> MultibaseSignatureRef<'a> {
    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        multibase::decode(self.proof_value)
            .map(|(_, data)| data)
            .map_err(|_| VerificationError::InvalidSignature)
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for MultibaseSignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.proof_value {
            Some(v) => Ok(Self { proof_value: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct JwsSignature {
    #[ld("sec:jws")]
    pub jws: CompactJWSString,
}

impl JwsSignature {
    pub fn new(jws: CompactJWSString) -> Self {
        Self { jws }
    }

    pub async fn sign_detached<A: Clone + Into<ssi_jwk::Algorithm>, S: MessageSigner<A>>(
        payload: &[u8],
        signer: S,
        key_id: Option<String>,
        algorithm: A,
    ) -> Result<Self, SignatureError> {
        let header = ssi_jws::Header::new_unencoded(algorithm.clone().into(), key_id);
        let signing_bytes = header.encode_signing_bytes(payload);
        let signature = signer.sign(algorithm, (), &signing_bytes).await?;
        let jws = ssi_jws::CompactJWSString::encode_detached(header, &signature);
        Ok(JwsSignature::new(jws))
    }
}

impl Referencable for JwsSignature {
    type Reference<'a> = JwsSignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        JwsSignatureRef { jws: &self.jws }
    }

    covariance_rule!();
}

impl From<JwsSignature> for AnySignature {
    fn from(value: JwsSignature) -> Self {
        AnySignature {
            jws: Some(value.jws),
            ..Default::default()
        }
    }
}

#[derive(
    Debug, Clone, Copy, serde::Serialize, linked_data::Serialize, linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct JwsSignatureRef<'a> {
    #[ld("sec:jws")]
    pub jws: &'a CompactJWSStr,
}

impl<'a> JwsSignatureRef<'a> {
    /// Decodes the signature for the given message.
    ///
    /// Returns the signing bytes, the signature bytes and the signature algorithm.
    pub fn decode(
        &self,
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Algorithm), VerificationError> {
        let (header, _, signature_bytes) = self
            .jws
            .decode()
            .map_err(|_| VerificationError::InvalidSignature)?;
        let signing_bytes = header.encode_signing_bytes(message);
        Ok((signing_bytes, signature_bytes, header.algorithm))
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for JwsSignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        match value.jws {
            Some(v) => Ok(Self { jws: v }),
            None => Err(InvalidSignature::MissingValue),
        }
    }
}

// struct UnboundSignIntoDetachedJws<S, A>(PhantomData<(S, A)>);

// impl<'a, A: 'a, S: 'a + MessageSigner<A>> UnboundedRefFuture<'a>
//     for UnboundSignIntoDetachedJws<S, A>
// {
//     type Owned = Vec<u8>;

//     type Bound<'r> = S::Sign<'r> where 'a: 'r;

//     type Output = Result<Vec<u8>, MessageSignatureError>;
// }

// struct SignIntoDetachedJwsBinder<S, A> {
//     // signing_bytes: Vec<u8>
//     signer: S,

//     algorithm: A,
// }

// impl<'a, A: 'a, S: 'a + MessageSigner<A>> RefFutureBinder<'a, UnboundSignIntoDetachedJws<S, A>>
//     for SignIntoDetachedJwsBinder<S, A>
// {
//     fn bind<'r>(context: Self, value: &'r Vec<u8>) -> S::Sign<'r>
//     where
//         'a: 'r,
//     {
//         context.signer.sign(context.algorithm, (), value)
//     }
// }

// #[pin_project]
// pub struct SignIntoDetachedJws<'a, S: 'a + MessageSigner<A>, A: 'a> {
//     header: Option<ssi_jws::Header>,

//     #[pin]
//     sign: SelfRefFuture<'a, UnboundSignIntoDetachedJws<S, A>>,
// }

// impl<'a, A: Clone + Into<ssi_jwk::Algorithm>, S: 'a + MessageSigner<A>>
//     SignIntoDetachedJws<'a, S, A>
// {
//     pub fn new(payload: &[u8], signer: S, key_id: Option<String>, algorithm: A) -> Self {
//         let header = ssi_jws::Header::new_unencoded(algorithm.clone().into(), key_id);

//         let signing_bytes = header.encode_signing_bytes(payload);
//         Self {
//             header: Some(header),
//             sign: SelfRefFuture::new(
//                 signing_bytes,
//                 SignIntoDetachedJwsBinder { signer, algorithm },
//             ),
//         }
//     }
// }

// impl<'a, A, S: 'a + MessageSigner<A>> Future for SignIntoDetachedJws<'a, S, A> {
//     type Output = Result<JwsSignature, SignatureError>;

//     fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
//         let this = self.project();
//         this.sign.poll(cx).map(|(r, _)| match r {
//             Ok(signature) => {
//                 let header = this.header.take().unwrap();
//                 let jws = ssi_jws::CompactJWSString::encode_detached(header, &signature);
//                 Ok(JwsSignature::new(jws))
//             }
//             Err(e) => Err(e.into()),
//         })
//     }
// }
