use std::hash::Hash;

use crate::{signature, AnyContext};
use async_trait::async_trait;
use rdf_types::VocabularyMut;
use treeldr_rust_prelude::{AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

macro_rules! any_verification_method {
	{
		$(
			$(#[$doc:meta])*
			$name:ident
		),*
	} => {
		/// Verification method type.
		#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
		pub enum Type {
			$(
				$(#[$doc])*
				$name
			),*
		}

		/// Any known verification method.
		#[derive(Debug, Clone)]
		pub enum Any {
			$(
				$(#[$doc])*
				$name(crate::$name)
			),*
		}

		impl Any {
			pub fn id(&self) -> iref::Iri {
				use crate::VerificationMethod;
				match self {
					$(
						Self::$name(m) => m.id()
					),*
				}
			}

			pub fn type_(&self) -> Type {
				match self {
					$(
						Self::$name(_) => Type::$name
					),*
				}
			}
		}

		impl ssi_crypto::VerificationMethod for Any {
			type Context<'c> = AnyContext<'c>;

			type Reference<'a> = AnyRef<'a> where Self: 'a;

			fn as_reference(&self) -> Self::Reference<'_> {
				match self {
					$(
						Self::$name(m) => AnyRef::$name(m)
					),*
				}
			}

			type Signature = signature::Any;
		}

		impl crate::VerificationMethod for Any {
			fn id(&self) -> iref::Iri {
				match self {
					$(
						Self::$name(m) => m.id()
					),*
				}
			}

			fn controller(&self) -> iref::Iri {
				match self {
					$(
						Self::$name(m) => m.controller()
					),*
				}
			}

			fn expected_type() -> Option<crate::ExpectedType> {
				None
			}

			fn type_(&self) -> &str {
				match self {
					$(
						Self::$name(m) => m.type_()
					),*
				}
			}
		}

		/// Any known verification method.
		#[derive(Debug, Clone)]
		pub enum AnyRef<'a> {
			$(
				$(#[$doc])*
				$name(&'a crate::$name)
			),*
		}

		impl<'a> AnyRef<'a> {
			pub fn id(&self) -> iref::Iri {
				use crate::VerificationMethod;
				match self {
					$(
						Self::$name(m) => m.id()
					),*
				}
			}

			pub fn type_(&self) -> Type {
				match self {
					$(
						Self::$name(_) => Type::$name
					),*
				}
			}
		}

		#[async_trait]
		impl<'a> crate::VerificationMethodRef<'a, Any> for AnyRef<'a> {
			async fn verify<'c: 'async_trait, 's: 'async_trait>(
				self,
				controllers: &impl crate::ControllerProvider,
				context: AnyContext<'c>,
				proof_purpose: ssi_crypto::ProofPurpose,
				signing_bytes: &[u8],
				signature: signature::AnyRef<'s>,
			) -> Result<bool, ssi_crypto::VerificationError> {
				match self {
					$(
						Self::$name(m) => m.verify(
							controllers,
							context.try_into()?,
							proof_purpose,
							signing_bytes,
							signature.try_into()?
						).await
					),*
				}
			}
		}

		impl crate::LinkedDataVerificationMethod for Any {
			fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
				match self {
					$(
						Self::$name(m) => m.quads(quads)
					),*
				}
			}
		}

		impl<V: VocabularyMut, I, M: Clone> IntoJsonLdObjectMeta<V, I, M> for Any
		where
			V::Iri: Eq + Hash,
			V::BlankId: Eq + Hash,
		{
			fn into_json_ld_object_meta(
				self,
				vocabulary: &mut V,
				interpretation: &I,
				meta: M,
			) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
				match self {
					$(
						Self::$name(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta)
					),*
				}
			}
		}

		impl<V: VocabularyMut, I, M: Clone> AsJsonLdObjectMeta<V, I, M> for Any
		where
			V::Iri: Eq + Hash,
			V::BlankId: Eq + Hash,
		{
			fn as_json_ld_object_meta(
				&self,
				vocabulary: &mut V,
				interpretation: &I,
				meta: M,
			) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
				match self {
					$(
						Self::$name(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta)
					),*
				}
			}
		}

		$(
			impl crate::TryFromVerificationMethod<Self> for crate::$name {
				fn try_from_verification_method(method: Self) -> Result<Self, crate::InvalidVerificationMethod> {
					Ok(method)
				}
			}

			impl<'a> crate::TryFromVerificationMethod<&'a Self> for &'a crate::$name {
				fn try_from_verification_method(method: &'a Self) -> Result<Self, crate::InvalidVerificationMethod> {
					Ok(method)
				}
			}

			impl crate::TryFromVerificationMethod<Any> for crate::$name {
				fn try_from_verification_method(method: Any) -> Result<Self, crate::InvalidVerificationMethod> {
					match method {
						Any::$name(method) => Ok(method),
						other => Err(crate::InvalidVerificationMethod(other.id().to_owned()))
					}
				}
			}

			impl<'a> crate::TryFromVerificationMethod<AnyRef<'a>> for &'a crate::$name {
				fn try_from_verification_method(method: AnyRef<'a>) -> Result<Self, crate::InvalidVerificationMethod> {
					match method {
						AnyRef::$name(method) => Ok(method),
						other => Err(crate::InvalidVerificationMethod(other.id().to_owned()))
					}
				}
			}

			impl From<crate::$name> for Any {
				fn from(method: crate::$name) -> Self {
					Self::$name(method)
				}
			}

			impl crate::IntoAnyVerificationMethod for crate::$name {
				type Output = Any;

				fn into_any_verification_method(self) -> Any {
					self.into()
				}
			}

			impl<'a, S: ssi_crypto::Signer<Any>> ssi_crypto::Signer<crate::$name> for AnySigner<'a, S> {
				fn sign(
					&self,
					context: <crate::$name as ssi_crypto::VerificationMethod>::Context<'_>,
					method: &crate::$name,
					bytes: &[u8],
				) -> Result<<crate::$name as ssi_crypto::VerificationMethod>::Signature, ssi_crypto::SignatureError> {
					let method = Any::$name(method.clone());
					Ok(self.0.sign(context.into(), &method, bytes)?.try_into().unwrap())
				}
			}

			impl<'a, S: ssi_crypto::Signer<crate::Reference<Any>>> ssi_crypto::Signer<crate::Reference<crate::$name>> for AnySigner<'a, S> {
				fn sign(
					&self,
					context: <crate::$name as ssi_crypto::VerificationMethod>::Context<'_>,
					method: &crate::Reference<crate::$name>,
					bytes: &[u8],
				) -> Result<<crate::$name as ssi_crypto::VerificationMethod>::Signature, ssi_crypto::SignatureError> {
					let method = method.clone().into_any();
					Ok(self.0.sign(context.into(), &method, bytes)?.try_into().unwrap())
				}
			}

			impl<'a, S: ssi_crypto::Signer<crate::ReferenceOrOwned<Any>>> ssi_crypto::Signer<crate::ReferenceOrOwned<crate::$name>> for AnySigner<'a, S> {
				fn sign(
					&self,
					context: <crate::$name as ssi_crypto::VerificationMethod>::Context<'_>,
					method: &crate::ReferenceOrOwned<crate::$name>,
					bytes: &[u8],
				) -> Result<<crate::$name as ssi_crypto::VerificationMethod>::Signature, ssi_crypto::SignatureError> {
					let method = match method {
						crate::ReferenceOrOwned::Owned(m) => crate::ReferenceOrOwned::Owned(Any::$name(m.clone())),
						crate::ReferenceOrOwned::Reference(r) => crate::ReferenceOrOwned::Reference(r.clone().into_any())
					};

					Ok(self.0.sign(context.into(), &method, bytes)?.try_into().unwrap())
				}
			}

			#[async_trait::async_trait]
			impl<'a, S: ssi_crypto::Verifier<Any>> ssi_crypto::Verifier<crate::$name> for AnyVerifier<'a, S> {
				async fn verify<'c: 'async_trait, 'm: 'async_trait, 's: 'async_trait>(
					&self,
					context: <crate::$name as ssi_crypto::VerificationMethod>::Context<'c>,
					method: &'m crate::$name,
					purpose: ssi_crypto::ProofPurpose,
					bytes: &[u8],
					signature: <<crate::$name as ssi_crypto::VerificationMethod>::Signature as ssi_crypto::Signature>::Reference<'s>,
				) -> Result<bool, ssi_crypto::VerificationError> {
					let method = AnyRef::$name(method);
					self.0.verify(context.into(), method, purpose, bytes, signature.into()).await
				}
			}

			#[async_trait::async_trait]
			impl<'a, S: ssi_crypto::Verifier<crate::Reference<Any>>> ssi_crypto::Verifier<crate::Reference<crate::$name>> for AnyVerifier<'a, S> {
				async fn verify<'c: 'async_trait, 'm: 'async_trait, 's: 'async_trait>(
					&self,
					context: <crate::$name as ssi_crypto::VerificationMethod>::Context<'c>,
					method: crate::ReferenceRef<'m, crate::$name>,
					purpose: ssi_crypto::ProofPurpose,
					bytes: &[u8],
					signature: <<crate::$name as ssi_crypto::VerificationMethod>::Signature as ssi_crypto::Signature>::Reference<'s>,
				) -> Result<bool, ssi_crypto::VerificationError> {
					self.0.verify(context.into(), method.as_any(), purpose, bytes, signature.into()).await
				}
			}

			#[async_trait::async_trait]
			impl<'a, S: ssi_crypto::Verifier<crate::ReferenceOrOwned<Any>>> ssi_crypto::Verifier<crate::ReferenceOrOwned<crate::$name>> for AnyVerifier<'a, S> {
				async fn verify<'c: 'async_trait, 'm: 'async_trait, 's: 'async_trait>(
					&self,
					context: <crate::$name as ssi_crypto::VerificationMethod>::Context<'c>,
					method: crate::ReferenceOrOwnedRef<'m, crate::$name>,
					purpose: ssi_crypto::ProofPurpose,
					bytes: &[u8],
					signature: <<crate::$name as ssi_crypto::VerificationMethod>::Signature as ssi_crypto::Signature>::Reference<'s>,
				) -> Result<bool, ssi_crypto::VerificationError> {
					let method = match method {
						crate::ReferenceOrOwnedRef::Owned(m) => crate::ReferenceOrOwnedRef::Owned(AnyRef::$name(m)),
						crate::ReferenceOrOwnedRef::Reference(r) => crate::ReferenceOrOwnedRef::Reference(r.as_any())
					};

					self.0.verify(context.into(), method, purpose, bytes, signature.into()).await
				}
			}
		)*
	};
}

// pub struct Closed<T>(pub T);

// impl<'a, S> ssi_crypto::Signer<Any> for S {
// 	fn sign(
// 		&self,
// 		method: &crate::$name,
// 		bytes: &[u8],
// 	) -> Result<<crate::$name as ssi_crypto::VerificationMethod>::Signature, ssi_crypto::SignatureError> {
// 		let method = Any::$name(method.clone());
// 		Ok(crate::$name::try_import_signature(self.0.sign(&method, bytes)?).unwrap())
// 	}
// }

any_verification_method! {
    /// Deprecated verification method for the `RsaSignature2018` suite.
    RsaVerificationKey2018,

    /// Deprecated verification method for the `Ed25519Signature2018` suite.
    Ed25519VerificationKey2018,

    /// Deprecated verification method for the `Ed25519Signature2020` suite.
    Ed25519VerificationKey2020,

    EcdsaSecp256k1VerificationKey2019,

    EcdsaSecp256k1RecoveryMethod2020,

    EcdsaSecp256r1VerificationKey2019,

    /// `JsonWebKey2020`.
    JsonWebKey2020,

    /// `Multikey`.
    Multikey,

    Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021
}

pub struct AnySigner<'a, S>(pub &'a S);

pub struct AnyVerifier<'a, V>(pub &'a V);
