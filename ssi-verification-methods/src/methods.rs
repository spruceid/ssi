pub mod any;
pub use any::*;

mod w3c;
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

#[macro_export]
macro_rules! verification_method_union {
	{
		$vis:vis enum $name:ident, $ref_name:ident
		where
			Signature = $signature:ty,
			ProofContext = $context:ty
		{
			$(
				$variant:ident
			),*
		}
	} => {
		#[derive(Clone)]
		$vis enum $name {
			$(
				$variant($variant)
			),*
		}

		#[derive(Clone, Copy)]
		$vis enum $ref_name<'a> {
			$(
				$variant(&'a $variant)
			),*
		}

		impl ssi_crypto::Referencable for $name {
			type Reference<'a> = $ref_name<'a>;

			fn as_reference(&self) -> Self::Reference<'_> {
				match self {
					$(
						Self::$variant(m) => $ref_name::$variant(m)
					),*
				}
			}
		}

		impl ssi_crypto::VerificationMethod for $name {
			type ProofContext = $context;

			type Signature = $signature;
		}

		impl $crate::VerificationMethod for $name {
			fn id(&self) -> iref::Iri {
				match self {
					$(
						Self::$variant(m) => m.id()
					),*
				}
			}

			fn expected_type() -> Option<$crate::ExpectedType> {
				let mut types = Vec::new();

				$(
					match $variant::expected_type() {
						Some($crate::ExpectedType::One(t)) => types.push(t),
						Some($crate::ExpectedType::Many(ts)) => types.extend(ts),
						None => ()
					}
				)*

				match types.len() {
					0 => None,
					1 => Some($crate::ExpectedType::One(types.pop().unwrap())),
					_ => Some($crate::ExpectedType::Many(types))
				}
			}

			fn type_(&self) -> &str {
				match self {
					$(
						Self::$variant(m) => m.type_()
					),*
				}
			}

			fn controller(&self) -> iref::Iri {
				match self {
					$(
						Self::$variant(m) => m.controller()
					),*
				}
			}
		}

		#[async_trait::async_trait]
		impl<'a> $crate::VerificationMethodRef<'a, $name> for $ref_name<'a> {
			async fn verify<'c: 'async_trait, 's: 'async_trait>(
				self,
				controllers: &impl $crate::ControllerProvider,
				context: <$context as ssi_crypto::Referencable>::Reference<'c>,
				proof_purpose: ssi_crypto::ProofPurpose,
				data: &[u8],
				signature: <$signature as ssi_crypto::Referencable>::Reference<'s>,
			) -> Result<bool, ssi_crypto::VerificationError> {
				match self {
					$(
						Self::$variant(m) => {
							let signature = signature.try_into()?;
							let context = context.try_into()?;
							m.verify(controllers, context, proof_purpose, data, signature).await
						}
					),*
				}
			}
		}

		impl $crate::LinkedDataVerificationMethod for $name {
			fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
				match self {
					$(
						Self::$variant(m) => m.quads(quads)
					),*
				}
			}
		}

		impl<V: rdf_types::VocabularyMut, I, M: Clone> treeldr_rust_prelude::IntoJsonLdObjectMeta<V, I, M> for $name
		where
			V::Iri: Eq + std::hash::Hash,
			V::BlankId: Eq + std::hash::Hash,
		{
			fn into_json_ld_object_meta(
				self,
				vocabulary: &mut V,
				interpretation: &I,
				meta: M,
			) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
				match self {
					$(
						Self::$variant(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta)
					),*
				}
			}
		}

		impl<V: rdf_types::VocabularyMut, I, M: Clone> treeldr_rust_prelude::AsJsonLdObjectMeta<V, I, M> for $name
		where
			V::Iri: Eq + std::hash::Hash,
			V::BlankId: Eq + std::hash::Hash,
		{
			fn as_json_ld_object_meta(
				&self,
				vocabulary: &mut V,
				interpretation: &I,
				meta: M,
			) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
				match self {
					$(
						Self::$variant(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta)
					),*
				}
			}
		}
	};
}
