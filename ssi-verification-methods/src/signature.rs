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
				$variant(<$variant_ty as ssi_crypto::Signature>::Reference<'a>)
			),*
		}

		impl ssi_crypto::Signature for $name {
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

		$(
			impl From<$variant_ty> for Any {
				fn from(value: $variant_ty) -> Self {
					Self::$variant(value)
				}
			}

			impl<'a> From<<$variant_ty as ssi_crypto::Signature>::Reference<'a>> for AnyRef<'a> {
				fn from(value: <$variant_ty as ssi_crypto::Signature>::Reference<'a>) -> Self {
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

			impl<'a> TryFrom<AnyRef<'a>> for <$variant_ty as ssi_crypto::Signature>::Reference<'a> {
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
