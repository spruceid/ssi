mod w3c;
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

#[macro_export]
macro_rules! verification_method_union {
	{
		$vis:vis enum $name:ident, $name_ref:ident, $kind:ident {
			$(
				$(#[$meta:meta])*
				$variant:ident
			),*
		}
	} => {
		#[derive(Clone)]
		$vis enum $name {
			$(
				$(#[$meta])*
				$variant($variant)
			),*
		}

		#[derive(Clone, Copy)]
		$vis enum $name_ref<'a> {
			$(
				$(#[$meta])*
				$variant(&'a $variant)
			),*
		}

		#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis enum $kind {
			$(
				$(#[$meta])*
				$variant
			),*
		}

		impl $name {
			pub fn type_(&self) -> $kind {
				match self {
					$(
						Self::$variant(_) => $kind::$variant
					),*
				}
			}
		}

		impl<'a> $name_ref<'a> {
			fn id(&self) -> iref::Iri {
				use $crate::VerificationMethod;
				match self {
					$(
						Self::$variant(m) => m.id()
					),*
				}
			}

			pub fn type_(&self) -> $kind {
				match self {
					$(
						Self::$variant(_) => $kind::$variant
					),*
				}
			}
		}

		impl $crate::Referencable for $name {
			type Reference<'a> = $name_ref<'a> where Self: 'a;

			fn as_reference(&self) -> $name_ref<'_> {
				match self {
					$(
						Self::$variant(m) => $name_ref::$variant(m)
					),*
				}
			}
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

			fn controller(&self) -> Option<iref::Iri> {
				match self {
					$(
						Self::$variant(m) => m.controller()
					),*
				}
			}
		}

		impl<'a> $crate::VerificationMethodRef<'a> for $name_ref<'a> {
			fn id(&self) -> iref::Iri<'a> {
				match self {
					$(
						Self::$variant(m) => m.id()
					),*
				}
			}

			fn controller(&self) -> Option<iref::Iri<'a>> {
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

		impl<'a> $crate::LinkedDataVerificationMethod for $name_ref<'a> {
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

		$(
			impl<'a> TryFrom<$name_ref<'a>> for &'a $variant {
				type Error = $crate::InvalidVerificationMethod;
			
				fn try_from(value: $name_ref<'a>) -> Result<Self, Self::Error> {
					match value {
						$name_ref::$variant(m) => Ok(m),
						other => Err($crate::InvalidVerificationMethod(other.id().to_owned()))
					}
				}
			}
		)*
	};
}

verification_method_union! {
    pub enum AnyMethod, AnyMethodRef, AnyMethodType {
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
	
		Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,
	
		P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021,

		TezosMethod2021,

		AleoMethod2021,

		BlockchainVerificationMethod2021,

		Eip712Method2021,

		SolanaMethod2021
	}
}