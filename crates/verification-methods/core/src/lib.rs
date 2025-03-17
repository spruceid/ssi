use std::{borrow::Cow, collections::HashMap, sync::Arc};

use iref::{Iri, IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_crypto::{Error, Issuer, Verifier};
use ssi_jwk::JWK;
use static_iref::iri;

mod controller;
// mod methods;
// mod reference;
mod signature;
mod verification;

pub use controller::*;
// pub use methods::*;
// pub use reference::*;
pub use signature::*;
pub use verification::*;

#[doc(hidden)]
pub use ssi_core;

/// IRI of the RDF property associated to the `controller` term found in a
/// verification method.
pub const CONTROLLER_IRI: &Iri = iri!("https://w3id.org/security#controller");

/// Expected verification method type.
#[derive(Debug, Clone)]
pub enum ExpectedType {
    One(String),
    Many(Vec<String>),
}

impl From<String> for ExpectedType {
    fn from(value: String) -> Self {
        Self::One(value)
    }
}

/// Verification method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Identifier of the verification method.
    pub id: IriBuf,

    /// Verification method type.
    #[serde(rename = "type")]
    pub r#type: String,

    /// Returns the IRI of the verification method controller.
    pub controller: UriBuf,

    /// Other properties.
    #[serde(flatten)]
    pub properties: HashMap<String, serde_json::Value>,
}

pub trait GetVerificationMethod {
    fn get_verification_method(&self) -> VerificationMethod;
}

pub trait VerificationMethodIssuer: Issuer<Signer: GetVerificationMethod> {}

impl<T: Issuer<Signer: GetVerificationMethod>> VerificationMethodIssuer for T {}

pub trait VerificationMethodVerifier: Verifier<VerifyingKey: GetVerificationMethod> {}

impl<T: Verifier<VerifyingKey: GetVerificationMethod>> VerificationMethodVerifier for T {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CowVerificationMethod {
    Ref(IriBuf),
    Owned(VerificationMethod),
}

impl CowVerificationMethod {
    pub fn id(&self) -> &Iri {
        match self {
            Self::Ref(r) => r,
            Self::Owned(o) => &o.id,
        }
    }
}

// #[derive(Debug, thiserror::Error)]
// pub enum VerificationMethodResolutionError {
//     #[error("unknown key")]
//     UnknownKey,

//     /// Invalid key identifier.
//     #[error("invalid key id `{0}`")]
//     InvalidKeyId(String),

//     /// Not a verification method.
//     #[error("id `{0}` is not referring to a verification method")]
//     NotAVerificationMethod(String),

//     /// Unsupported key identifier.
//     #[error("unsupported key id `{0}`")]
//     UnsupportedKeyId(String),

//     #[error("missing verification method")]
//     MissingVerificationMethod,

//     #[error(transparent)]
//     InvalidVerificationMethod(#[from] InvalidVerificationMethod),

//     /// Verifier internal error.
//     #[error("internal error: {0}")]
//     InternalError(String),
// }

// impl From<VerificationMethodResolutionError> for ProofValidationError {
//     fn from(value: VerificationMethodResolutionError) -> Self {
//         match value {
//             VerificationMethodResolutionError::MissingVerificationMethod => Self::MissingPublicKey,
//             e => Self::Other(e.to_string()),
//         }
//     }
// }

// impl From<VerificationMethodResolutionError> for Error {
//     fn from(value: VerificationMethodResolutionError) -> Self {
//         Self::other(value)
//     }
// }

// pub trait VerificationMethodSet: VerificationMethod {
//     type TypeSet: VerificationMethodTypeSet;

//     fn type_set() -> Self::TypeSet;
// }

// pub trait VerificationMethodTypeSet: 'static + Send + Sync {
//     fn pick(&self) -> Option<&str>;
//     fn contains(&self, ty: &str) -> bool;
// }

// impl VerificationMethodTypeSet for &'static str {
//     fn contains(&self, ty: &str) -> bool {
//         ty == *self
//     }

//     fn pick(&self) -> Option<&str> {
//         Some(self)
//     }
// }

// impl VerificationMethodTypeSet for &'static [&'static str] {
//     fn contains(&self, ty: &str) -> bool {
//         self.iter().any(|&t| t == ty)
//     }

//     fn pick(&self) -> Option<&str> {
//         self.first().copied()
//     }
// }

// #[derive(Default)]
// pub struct ResolutionOptions {
//     /// Accepted verification method types.
//     pub accept: Option<Box<dyn VerificationMethodTypeSet>>,
// }

// pub trait VerificationMethodResolver {
//     /// Verification method type.
//     type Method: Clone;

//     /// Resolve the verification method reference.
//     #[allow(async_fn_in_trait)]
//     async fn resolve_verification_method_with(
//         &self,
//         issuer: Option<&Iri>,
//         method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
//         options: ResolutionOptions,
//     ) -> Result<Cow<Self::Method>, VerificationMethodResolutionError>;

//     /// Resolve the verification method reference with the default options.
//     #[allow(async_fn_in_trait)]
//     async fn resolve_verification_method(
//         &self,
//         issuer: Option<&Iri>,
//         method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
//     ) -> Result<Cow<Self::Method>, VerificationMethodResolutionError> {
//         self.resolve_verification_method_with(issuer, method, Default::default())
//             .await
//     }
// }

// impl<'t, T: VerificationMethodResolver> VerificationMethodResolver for &'t T {
//     type Method = T::Method;

//     async fn resolve_verification_method_with(
//         &self,
//         issuer: Option<&Iri>,
//         method: Option<ReferenceOrOwnedRef<'_, T::Method>>,
//         options: ResolutionOptions,
//     ) -> Result<Cow<T::Method>, VerificationMethodResolutionError> {
//         T::resolve_verification_method_with(self, issuer, method, options).await
//     }
// }

// impl<M: VerificationMethod> VerificationMethodResolver for HashMap<IriBuf, M> {
//     type Method = M;

//     async fn resolve_verification_method_with(
//         &self,
//         _issuer: Option<&Iri>,
//         method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
//         _options: ResolutionOptions,
//     ) -> Result<Cow<Self::Method>, VerificationMethodResolutionError> {
//         match method {
//             Some(ReferenceOrOwnedRef::Owned(method)) => Ok(Cow::Owned(method.clone())),
//             Some(ReferenceOrOwnedRef::Reference(iri)) => match self.get(iri) {
//                 Some(method) => Ok(Cow::Borrowed(method)),
//                 None => Err(VerificationMethodResolutionError::UnknownKey),
//             },
//             None => Err(VerificationMethodResolutionError::MissingVerificationMethod),
//         }
//     }
// }

// pub trait SigningMethod<S>: VerificationMethod {
//     fn sign_bytes(
//         &self,
//         secret: &S,
//         algorithm: AlgorithmInstance,
//         bytes: &[u8],
//     ) -> Result<Vec<u8>, MessageError>;

//     fn sign_bytes_multi(
//         &self,
//         secret: &S,
//         algorithm: AlgorithmInstance,
//         messages: &[Vec<u8>],
//     ) -> Result<Vec<u8>, MessageError> {
//         match messages.split_first() {
//             Some((message, [])) => self.sign_bytes(secret, algorithm, message),
//             // Some(_) => Err(MessageError::TooManyMessages),
//             Some(_) => todo!(),
//             None => Err(MessageError::MissingMessage),
//         }
//     }
// }

// pub struct MethodWithSecret<M: VerificationMethod, S> {
//     pub method: M,
//     pub secret: Arc<S>,
// }

// impl<M: VerificationMethod, S> MethodWithSecret<M, S> {
//     pub fn new(method: M, secret: Arc<S>) -> Self {
//         Self { method, secret }
//     }
// }

// impl<M: SigningMethod<S>, S> MessageSigner
//     for MethodWithSecret<M, S>
// {
//     async fn sign(
//         self,
//         algorithm: AlgorithmInstance,
//         message: &[u8],
//     ) -> Result<Vec<u8>, MessageError> {
//         self.method.sign_bytes(&self.secret, algorithm, message)
//     }

//     async fn sign_multi(
//         self,
//         algorithm: AlgorithmInstance,
//         messages: &[Vec<u8>],
//     ) -> Result<Vec<u8>, MessageError> {
//         self.method
//             .sign_bytes_multi(&self.secret, algorithm, messages)
//     }
// }

// pub trait TypedVerificationMethod: VerificationMethod {
//     fn expected_type() -> Option<ExpectedType>;

//     fn type_match(ty: &str) -> bool;

//     fn type_(&self) -> &str;
// }

// pub trait LinkedDataVerificationMethod {
//     fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object;
// }

// impl<'a, T: LinkedDataVerificationMethod> LinkedDataVerificationMethod for &'a T {
//     fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
//         T::quads(*self, quads)
//     }
// }

// #[derive(Debug, thiserror::Error)]
// pub enum InvalidVerificationMethod {
//     #[error("invalid verification method IRI `{0}`")]
//     InvalidIri(String),

//     #[error("invalid verification method type IRI `{0}`")]
//     InvalidTypeIri(IriBuf),

//     #[error("invalid verification method type name `{0}`, expected `{1}`")]
//     InvalidTypeName(String, String),

//     #[error("missing verification method required property `{0}`")]
//     MissingProperty(String),

//     #[error("invalid verification method property `{0}`")]
//     InvalidProperty(String),

//     #[error("ambiguous public key")]
//     AmbiguousPublicKey,

//     #[error("unsupported method type `{0}`")]
//     UnsupportedMethodType(String),
// }

// impl InvalidVerificationMethod {
//     pub fn invalid_type_iri(iri: &Iri) -> Self {
//         Self::InvalidTypeIri(iri.to_owned())
//     }

//     pub fn invalid_type_name(name: &str, expected: &str) -> Self {
//         Self::InvalidTypeName(name.to_owned(), expected.to_owned())
//     }

//     pub fn missing_property(name: &str) -> Self {
//         Self::MissingProperty(name.to_owned())
//     }

//     pub fn invalid_property(name: &str) -> Self {
//         Self::InvalidProperty(name.to_owned())
//     }
// }

// impl From<InvalidVerificationMethod> for ProofValidationError {
//     fn from(_value: InvalidVerificationMethod) -> Self {
//         Self::InvalidKey
//     }
// }

// impl From<InvalidVerificationMethod> for Error {
//     fn from(value: InvalidVerificationMethod) -> Self {
//         Self::other(value)
//     }
// }

// /// Verification method that can be turned into a JSON Web Key.
// pub trait JwkVerificationMethod: VerificationMethod {
//     fn to_jwk(&self) -> Cow<JWK>;
// }

// /// Verification method that *may* be turned into a JSON Web Key.
// pub trait MaybeJwkVerificationMethod: VerificationMethod {
//     fn try_to_jwk(&self) -> Option<Cow<JWK>>;
// }

// impl<M: JwkVerificationMethod> MaybeJwkVerificationMethod for M {
//     fn try_to_jwk(&self) -> Option<Cow<JWK>> {
//         Some(M::to_jwk(self))
//     }
// }
