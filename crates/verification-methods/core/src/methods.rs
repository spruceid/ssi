use std::collections::BTreeMap;

use iref::{IriBuf, UriBuf};

use crate::{TypedVerificationMethod, VerificationMethod};

/// Generic verification method.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenericVerificationMethod {
    /// Identifier.
    pub id: IriBuf,

    /// Type name.
    #[serde(rename = "type")]
    pub type_: String,

    /// Method controller.
    pub controller: UriBuf,

    /// Other properties.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

impl VerificationMethod for GenericVerificationMethod {
    fn id(&self) -> &iref::Iri {
        &self.id
    }

    fn controller(&self) -> Option<&iref::Iri> {
        Some(self.controller.as_iri())
    }
}

impl TypedVerificationMethod for GenericVerificationMethod {
    fn type_(&self) -> &str {
        &self.type_
    }

    fn expected_type() -> Option<crate::ExpectedType> {
        None
    }

    fn type_match(_ty: &str) -> bool {
        true
    }
}

#[macro_export]
macro_rules! verification_method_union {
	{
		$vis:vis enum $name:ident, $kind:ident {
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

		impl $crate::VerificationMethodSet for $name {
			type TypeSet = &'static [&'static str];

			fn type_set() -> Self::TypeSet {
				&[
					$(
						$(#[$meta])*
						$variant::NAME
					),*
				]
			}
		}

		#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis enum $kind {
			$(
				$(#[$meta])*
				$variant
			),*
		}

		impl $kind {
			pub fn iri(&self) -> &iref::Iri {
				match self {
					$(
						$(#[$meta])*
						Self::$variant => $variant::IRI
					),*
				}
			}
		}

		impl $name {
			pub fn type_(&self) -> $kind {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(_) => $kind::$variant
					),*
				}
			}
		}

		impl $crate::VerificationMethod for $name {
			fn id(&self) -> &iref::Iri {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(m) => m.id()
					),*
				}
			}

			fn controller(&self) -> Option<&iref::Iri> {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(m) => m.controller()
					),*
				}
			}
		}

		impl $crate::TypedVerificationMethod for $name {
			fn expected_type() -> Option<$crate::ExpectedType> {
				let mut types = Vec::new();

				$(
					$(#[$meta])*
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
					$(#[$meta])*
					if <$variant as $crate::TypedVerificationMethod>::type_match(ty) {
						return true
					}
				)*

				false
			}

			fn type_(&self) -> &str {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(m) => m.type_()
					),*
				}
			}
		}

		$(
			$(#[$meta])*
			impl TryFrom<$name> for $variant {
				type Error = $crate::InvalidVerificationMethod;

				fn try_from(value: $name) -> Result<Self, Self::Error> {
					match value {
						$name::$variant(m) => Ok(m),
						other => Err($crate::InvalidVerificationMethod::invalid_type_iri(other.type_().iri()))
					}
				}
			}

			$(#[$meta])*
			impl From<$variant> for $name {
				fn from(value: $variant) -> Self {
					Self::$variant(value)
				}
			}
		)*

		impl TryFrom<$crate::GenericVerificationMethod> for $name {
			type Error = $crate::InvalidVerificationMethod;

			fn try_from(value: $crate::GenericVerificationMethod) -> Result<Self, Self::Error> {
				$(
					$(#[$meta])*
					if <$variant as $crate::TypedVerificationMethod>::type_match(&value.type_) {
						return <$variant as TryFrom<$crate::GenericVerificationMethod>>::try_from(value).map(Self::$variant)
					}
				)*

				Err($crate::InvalidVerificationMethod::UnsupportedMethodType(value.type_))
			}
		}
	};
}

#[macro_export]
macro_rules! complete_verification_method_union {
	{
		$vis:vis enum $name:ident, $kind:ident, $kind_ref:ident {
			$(
				$(#[$meta:meta])*
				$variant:ident
			),*
		}
	} => {
		#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, linked_data::Serialize, linked_data::Deserialize)]
		#[serde(untagged)]
		$vis enum $name {
			$(
				$(#[$meta])*
				$variant($variant),
			)*
			Unknown(GenericVerificationMethod)
		}

		impl $crate::VerificationMethodSet for $name {
			type TypeSet = &'static [&'static str];

			fn type_set() -> Self::TypeSet {
				&[
					$(
						$(#[$meta])*
						$variant::NAME
					),*
				]
			}
		}

		#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis enum $kind {
			$(
				$(#[$meta])*
				$variant,
			)*
			Unknown(String)
		}

		impl $kind {
			pub fn name(&self) -> &str {
				match self {
					$(
						$(#[$meta])*
						Self::$variant => $variant::NAME,
					)*
					Self::Unknown(name) => name
				}
			}
		}

		#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis enum $kind_ref<'a> {
			$(
				$(#[$meta])*
				$variant,
			)*
			Unknown(&'a str)
		}

		impl<'a> $kind_ref<'a> {
			pub fn name(&self) -> &'a str {
				match self {
					$(
						$(#[$meta])*
						Self::$variant => $variant::NAME,
					)*
					Self::Unknown(name) => name
				}
			}
		}

		impl $name {
			pub fn type_(&self) -> $kind_ref {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(_) => $kind_ref::$variant,
					)*
					Self::Unknown(m) => $kind_ref::Unknown(&m.type_)
				}
			}
		}

		impl $crate::VerificationMethod for $name {
			fn id(&self) -> &iref::Iri {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(m) => m.id(),
					)*
					Self::Unknown(m) => &m.id
				}
			}

			fn controller(&self) -> Option<&iref::Iri> {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(m) => m.controller(),
					)*
					Self::Unknown(m) => Some(m.controller.as_iri())
				}
			}
		}

		impl $crate::TypedVerificationMethod for $name {
			fn expected_type() -> Option<$crate::ExpectedType> {
				None
			}

			fn type_match(_: &str) -> bool {
				true
			}

			fn type_(&self) -> &str {
				match self {
					$(
						$(#[$meta])*
						Self::$variant(m) => m.type_(),
					)*
					Self::Unknown(m) => &m.type_
				}
			}
		}

		$(
			$(#[$meta])*
			impl TryFrom<$name> for $variant {
				type Error = $crate::InvalidVerificationMethod;

				fn try_from(value: $name) -> Result<Self, Self::Error> {
					use ssi_verification_methods_core::VerificationMethodSet;
					match value {
						$name::$variant(m) => Ok(m),
						other => Err($crate::InvalidVerificationMethod::invalid_type_name(other.type_().name(), Self::type_set()))
					}
				}
			}

			$(#[$meta])*
			impl From<$variant> for $name {
				fn from(value: $variant) -> Self {
					Self::$variant(value)
				}
			}
		)*

		impl TryFrom<$crate::GenericVerificationMethod> for $name {
			type Error = $crate::InvalidVerificationMethod;

			fn try_from(value: $crate::GenericVerificationMethod) -> Result<Self, Self::Error> {
				$(
					$(#[$meta])*
					if <$variant as $crate::TypedVerificationMethod>::type_match(&value.type_) {
						return <$variant as TryFrom<$crate::GenericVerificationMethod>>::try_from(value)
							.map(Self::$variant)
					}
				)*

				Ok(Self::Unknown(value))
			}
		}
	};
}
