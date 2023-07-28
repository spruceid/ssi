mod any;
mod jwk;
mod proof_value;
mod signature_value;

pub use any::*;
pub use jwk::*;
pub use proof_value::*;
pub use signature_value::*;

#[macro_export]
macro_rules! signature_union {
	{
		$(#[$meta:meta])*
		$vis:vis enum $name:ident, $ref_name:ident {
			$(
				$(#[$variant_meta:meta])*
				$variant:ident($variant_ty:ty)
			),*
		}
	} => {
		$(#[$meta])*
		$vis enum $name {
			$(
				$(#[$variant_meta])*
				$variant($variant_ty)
			),*
		}

		#[derive(Clone, Copy)]
		$vis enum $ref_name<'a> {
			$(
				$(#[$variant_meta])*
				$variant(<$variant_ty as ssi_crypto::Referencable>::Reference<'a>)
			),*
		}

		impl ssi_crypto::Referencable for $name {
			type Reference<'a> = $ref_name<'a> where Self: 'a;

			fn as_reference(&self) -> Self::Reference<'_> {
				match self {
					$(
						Self::$variant(m) => {
							$ref_name::$variant(m.as_reference())
						}
					),*
				}
			}
		}

		impl<V, I: rdf_types::Interpretation> $crate::treeldr_rust_prelude::FromRdf<V, I> for $name
		where
		$(
			$variant_ty: $crate::treeldr_rust_prelude::FromRdf<V, I>
		),*
		{
			fn from_rdf<G>(
				vocabulary: &V,
				interpretation: &I,
				graph: &G,
				id: &I::Resource,
			) -> Result<Self, $crate::treeldr_rust_prelude::FromRdfError>
			where
				G: $crate::treeldr_rust_prelude::grdf::Graph<Subject = I::Resource, Predicate = I::Resource, Object = I::Resource>,
			{
				$(
					match <$variant_ty as $crate::treeldr_rust_prelude::FromRdf<V, I>>::from_rdf(vocabulary, interpretation, graph, id) {
						Ok(s) => return Ok(Self::$variant(s)),
						Err($crate::treeldr_rust_prelude::FromRdfError::MissingRequiredPropertyValue) => (),
						Err(e) => return Err(e)
					}
				)*

				Err($crate::treeldr_rust_prelude::FromRdfError::MissingRequiredPropertyValue)
			}
		}

		impl<V, I> $crate::json_ld::FlattenIntoJsonLdNode<V, I> for $name
		where
			V: rdf_types::VocabularyMut,
			V::Iri: Eq + core::hash::Hash,
			V::BlankId: Eq + core::hash::Hash
		{
			fn flatten_into_json_ld_node(
				self,
				vocabulary: &mut V,
				interpretation: &I,
				node: &mut json_ld::Node<V::Iri, V::BlankId, ()>
			) {
				match self {
					$(
						Self::$variant(m) => m.flatten_into_json_ld_node(vocabulary, interpretation, node)
					),*
				}
			}
		}

		$(
			impl From<$variant_ty> for Any {
				fn from(value: $variant_ty) -> Self {
					Self::$variant(value)
				}
			}

			impl<'a> From<<$variant_ty as ssi_crypto::Referencable>::Reference<'a>> for AnyRef<'a> {
				fn from(value: <$variant_ty as ssi_crypto::Referencable>::Reference<'a>) -> Self {
					Self::$variant(value)
				}
			}

			impl TryFrom<Any> for $variant_ty {
				type Error = ssi_crypto::VerificationError;

				fn try_from(value: Any) -> Result<Self, Self::Error> {
					match value {
						Any::$variant(m) => Ok(m),
						_ => Err(ssi_crypto::VerificationError::InvalidSignature)
					}
				}
			}

			impl<'a> TryFrom<AnyRef<'a>> for <$variant_ty as ssi_crypto::Referencable>::Reference<'a> {
				type Error = ssi_crypto::VerificationError;

				fn try_from(value: AnyRef<'a>) -> Result<Self, Self::Error> {
					match value {
						AnyRef::$variant(m) => Ok(m),
						_ => Err(ssi_crypto::VerificationError::InvalidSignature)
					}
				}
			}
		)*
	};
}
