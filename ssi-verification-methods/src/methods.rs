mod w3c;
pub use w3c::*;

mod unspecified;
pub use unspecified::*;

mod generic;
pub use generic::*;

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
		#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, linked_data::Serialize, linked_data::Deserialize)]
		$vis enum $name {
			$(
				$(#[$meta])*
				$variant($variant)
			),*
		}

		#[derive(Debug, Clone, Copy, serde::Serialize, linked_data::Serialize)]
		$vis enum $name_ref<'a> {
			$(
				$(#[$meta])*
				$variant(&'a $variant)
			),*
		}

		#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
			fn id(&self) -> &iref::Iri {
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

			fn apply_covariance<'big: 'small, 'small>(r: Self::Reference<'big>) -> Self::Reference<'small> where Self: 'big {
				match r {
					$(
						$name_ref::$variant(m) => $name_ref::$variant(m)
					),*
				}
			}
		}

		impl $crate::VerificationMethod for $name {
			fn id(&self) -> &iref::Iri {
				match self {
					$(
						Self::$variant(m) => m.id()
					),*
				}
			}

			fn controller(&self) -> Option<&iref::Iri> {
				match self {
					$(
						Self::$variant(m) => m.controller()
					),*
				}
			}

			fn ref_id<'a>(r: Self::Reference<'a>) -> &'a iref::Iri {
				match r {
					$(
						$name_ref::$variant(m) => $variant::ref_id(m)
					),*
				}
			}
		
			fn ref_controller<'a>(r: Self::Reference<'a>) -> Option<&'a iref::Iri> {
				match r {
					$(
						$name_ref::$variant(m) => $variant::ref_controller(m)
					),*
				}
			}
		}

		impl $crate::TypedVerificationMethod for $name {
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

			fn type_match(ty: &str) -> bool {
				$(
					if <$variant as $crate::TypedVerificationMethod>::type_match(ty) {
						return true
					}
				)*

				false
			}

			fn type_(&self) -> &str {
				match self {
					$(
						Self::$variant(m) => m.type_()
					),*
				}
			}

			fn ref_type<'a>(r: Self::Reference<'a>) -> &'a str {
				match r {
					$(
						$name_ref::$variant(m) => <$variant as $crate::TypedVerificationMethod>::ref_type(m)
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
						other => Err($crate::InvalidVerificationMethod::invalid_type_iri(other.id()))
					}
				}
			}
		)*

		impl TryFrom<$crate::GenericVerificationMethod> for $name {
			type Error = $crate::InvalidVerificationMethod;

			fn try_from(value: $crate::GenericVerificationMethod) -> Result<Self, Self::Error> {
				$(
					if <$variant as $crate::TypedVerificationMethod>::type_match(&value.type_) {
						return <$variant as TryFrom<$crate::GenericVerificationMethod>>::try_from(value).map(Self::$variant)
					}
				)*

				Err($crate::InvalidVerificationMethod::UnsupportedMethodType)
			}
		}
	};
}
