use std::future::Future;
use std::task;
use std::pin::Pin;
use iref::UriBuf;
use linked_data::{
    LinkedData, LinkedDataGraph
};
use pin_project::pin_project;
use rdf_types::{Interpretation, Vocabulary};
use ssi_crypto::MessageSigner;
use ssi_jwk::algorithm::AnyES256K;
use ssi_verification_methods::{covariance_rule, Referencable, InvalidSignature, VerificationError, SignatureError};

use crate::suite::{AnySignature, AnySignatureRef};

/// Common signature format for EIP-712-based cryptographic suites.
/// 
/// See: <https://eips.ethereum.org/EIPS/eip-712>
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Signature {
    /// Hex encoded output of the EIP712 signature function according to
    /// [EIP712](https://eips.ethereum.org/EIPS/eip-712).
    pub proof_value: String,
}

impl Eip712Signature {
    pub fn from_bytes(signature_bytes: Vec<u8>) -> Self {
        Self {
            proof_value: format!("0x{}", hex::encode(signature_bytes))
        }
    }
}

impl Referencable for Eip712Signature {
    type Reference<'a> = Eip712SignatureRef<'a> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        Eip712SignatureRef {
            proof_value: &self.proof_value
        }
    }

    covariance_rule!();
}

impl From<Eip712Signature> for AnySignature {
    fn from(value: Eip712Signature) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl TryFrom<AnySignature> for Eip712Signature {
    type Error = InvalidSignature;

    fn try_from(value: AnySignature) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?
        })
    }
}

/// Reference to [`Eip712Signature`].
#[derive(Debug, Clone, Copy)]
pub struct Eip712SignatureRef<'a> {
    /// Proof value
    pub proof_value: &'a str
}

impl<'a> Eip712SignatureRef<'a> {
    pub fn decode(&self) -> Result<Vec<u8>, VerificationError> {
        if self.proof_value.len() >= 4 && &self.proof_value[0..2] == "0x" {
            hex::decode(&self.proof_value[2..]).map_err(|_| VerificationError::InvalidSignature)
        } else {
            Err(VerificationError::InvalidSignature)
        }
    }
}

impl<'a> From<Eip712SignatureRef<'a>> for AnySignatureRef<'a> {
    fn from(value: Eip712SignatureRef<'a>) -> Self {
        Self {
            proof_value: Some(value.proof_value),
            ..Default::default()
        }
    }
}

impl<'a> TryFrom<AnySignatureRef<'a>> for Eip712SignatureRef<'a> {
    type Error = InvalidSignature;

    fn try_from(value: AnySignatureRef<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            proof_value: value.proof_value.ok_or(InvalidSignature::MissingValue)?
        })
    }
}

/// Meta-information about the signature generation process.
///
/// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021>
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, linked_data::Serialize, linked_data::Deserialize)]
#[ld(prefix("eip712" = "https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#"))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Eip712Metadata {
    /// URI to an object containing the JSON schema describing the message to
    /// be signed.
    ///
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[ld("eip712:types")]
    #[serde(rename = "types", alias = "messageSchema")]
    pub types_or_uri: TypesOrURI,

    /// Value of the `primaryType` property of the `TypedData` object.
    #[ld("eip712:primaryType")]
    pub primary_type: ssi_eip712::StructName,

    /// Value of the `domain` property of the `TypedData` object.
    #[ld("eip712:domain")]
    pub domain: ssi_eip712::Value,
}

/// Object containing EIP-712 types, or a URI for such.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum TypesOrURI {
    URI(UriBuf),
    Object(ssi_eip712::Types),
}

linked_data::json_literal!(TypesOrURI);

impl<V: Vocabulary, I: Interpretation> LinkedDataGraph<I, V> for TypesOrURI {
    fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<I, V>,
    {
        visitor.subject(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedData<I, V> for TypesOrURI {
    fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        visitor.default_graph(self)?;
        visitor.end()
    }
}

#[pin_project]
pub struct Eip712Sign<'a, S: 'a + MessageSigner<AnyES256K>> {
    #[pin]
    inner: Eip712SignInner<'a, S>
}

impl<'a, S: 'a + MessageSigner<AnyES256K>> Eip712Sign<'a, S> {
    pub fn new(
        bytes: &'a [u8],
        signer: S,
        algorithm: AnyES256K
    ) -> Self {
        Self {
            inner: Eip712SignInner::Ok(Eip712SignOk {
                sign: signer.sign(algorithm, (), bytes)
            })
        }
    }

    pub fn err(error: SignatureError) -> Self {
        Self {
            inner: Eip712SignInner::Err(Some(error))
        }
    }
}

impl<'a, S: 'a + MessageSigner<AnyES256K>> Future for Eip712Sign<'a, S> {
    type Output = Result<Eip712Signature, SignatureError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}

#[pin_project(project = Eip712SignInnerProject)]
enum Eip712SignInner<'a, S: 'a + MessageSigner<AnyES256K>> {
    Ok(#[pin] Eip712SignOk<'a, S>),
    Err(Option<SignatureError>)
}

impl<'a, S: 'a + MessageSigner<AnyES256K>> Future for Eip712SignInner<'a, S> {
    type Output = Result<Eip712Signature, SignatureError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            Eip712SignInnerProject::Ok(f) => f.poll(cx),
            Eip712SignInnerProject::Err(e) => task::Poll::Ready(Err(e.take().unwrap()))
        }
    }
}

#[pin_project]
struct Eip712SignOk<'a, S: 'a + MessageSigner<AnyES256K>> {
    #[pin]
    sign: S::Sign<'a>
}

impl<'a, S: 'a + MessageSigner<AnyES256K>> Future for Eip712SignOk<'a, S> {
    type Output = Result<Eip712Signature, SignatureError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.sign.poll(cx).map(|r| {
            let signature = r?;
            Ok(Eip712Signature::from_bytes(signature))
        })
    }
}