// pub mod any;
// pub use any::*;

mod w3c;
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

#[macro_export]
macro_rules! verification_method_union {
	{
		$vis:vis enum $name:ident {
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
