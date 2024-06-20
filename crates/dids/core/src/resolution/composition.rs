use crate::DIDResolver;

use super::{DIDMethodResolver, Error};

macro_rules! define_composition {
	($($n:tt: $ty:ident),*) => {
		impl<$($ty : DIDMethodResolver,)*> DIDResolver for ($($ty,)*) {
			async fn resolve_representation<'a>(
				&'a self,
				did: &'a crate::DID,
				options: super::Options,
			) -> Result<super::Output<Vec<u8>>, Error> {
				let method = did.method_name();

				$(
					if $ty::DID_METHOD_NAME == method {
						return self.$n.resolve_method_representation(did.method_specific_id(), options).await
					}
				)*

				Err(Error::MethodNotSupported(method.to_owned()))
			}
		}
	};
}

define_composition!(0: T0);
define_composition!(0: T0, 1: T1);
define_composition!(0: T0, 1: T1, 2: T2);
define_composition!(0: T0, 1: T1, 2: T2, 3: T3);
define_composition!(0: T0, 1: T1, 2: T2, 3: T3, 4: T4);
define_composition!(0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5);
define_composition!(0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6);
define_composition!(0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7);
