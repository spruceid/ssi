use std::borrow::Cow;

use crate::Claim;

/// Dynamic claim type matching.
///
/// # Usage
///
/// There are two ways to use this macro.
/// The first one is to simply match on the value of a claim type parameter:
/// ```ignore
/// match_claim_type! {
///   match MyClaimTypeParameter {
///     TypeA => { ... },
///     TypeB => { ... },
///     _ => { ... }
///   }
/// }
/// ```
///
/// The second one also allows you to properly cast a claim variable.
/// ```ignore
/// match_claim_type! {
///   match claim: MyClaimTypeParameter {
///     TypeA => {
///       // In this block, `claim` has type `TypeA`.
///       ...
///     },
///     TypeB => {
///       // In this block, `claim` has type `TypeB`.
///       ...
///     },
///     _ => {
///       // In this block, `claim` has type `MyClaimTypeParameter`.
///       ...
///     },
///   }
/// }
/// ```
#[macro_export]
macro_rules! match_claim_type {
    {
        match $id:ident {
            $($ty:ident => $e:expr,)*
            _ => $default_case:expr
        }
    } => {
        $(
            if std::any::TypeId::of::<$id>() == std::any::TypeId::of::<$ty>() {
				let result = $e;
				return unsafe {
                    // SAFETY: We just checked that `$ty` is equal to `$id`.
                    $crate::CastClaim::<$ty, $id>::cast_claim(result)
                };
			}
        )*

        $default_case
    };
	{
        match $x:ident: $id:ident {
            $($ty:ident => $e:expr,)*
            _ => $default_case:expr
        }
    } => {
        $(
            if std::any::TypeId::of::<$id>() == std::any::TypeId::of::<$ty>() {
				let $x: $ty = unsafe {
                    // SAFETY: We just checked that `$ty` is equal to `$id`.
                    $crate::CastClaim::<$id, $ty>::cast_claim($x)
                };
				let result = $e;
				return unsafe {
                    // SAFETY: We just checked that `$ty` is equal to `$id`.
                    $crate::CastClaim::<$ty, $id>::cast_claim(result)
                };
			}
        )*

        $default_case
    };
}

/// Cast claim type `A` into `B`.
pub trait CastClaim<A, B>: Sized {
    type Target;

    /// Cast claim type `A` into `B`.
    ///
    /// # Safety
    ///
    /// `A` **must** be equal to `B`.
    unsafe fn cast_claim(value: Self) -> Self::Target;
}

impl<A: Claim, B: Claim> CastClaim<A, B> for A {
    type Target = B;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        // SAFETY: The precondition to this function is that `A` (`Self`) is
        //         equal to `B`, meaning that the transmute does nothing.
        //         We are just copying `value`, and forgetting the original.
        let result = std::mem::transmute_copy(&value);
        std::mem::forget(value);
        result
    }
}

impl<'a, A: Claim, B: Claim> CastClaim<A, B> for &'a A {
    type Target = &'a B;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        std::mem::transmute_copy(&value)
    }
}

impl<A, B> CastClaim<A, B> for () {
    type Target = Self;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        value
    }
}

impl<A, B> CastClaim<A, B> for bool {
    type Target = Self;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        value
    }
}

impl<A, B, T: CastClaim<A, B>> CastClaim<A, B> for Option<T> {
    type Target = Option<T::Target>;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        value.map(|t| T::cast_claim(t))
    }
}

impl<A, B, T: CastClaim<A, B>, E> CastClaim<A, B> for Result<T, E> {
    type Target = Result<T::Target, E>;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        value.map(|t| T::cast_claim(t))
    }
}

impl<'a, A: Claim, B: Claim> CastClaim<A, B> for Cow<'a, A> {
    type Target = Cow<'a, B>;

    unsafe fn cast_claim(value: Self) -> Self::Target {
        match value {
            Self::Owned(value) => Cow::Owned(CastClaim::cast_claim(value)),
            Self::Borrowed(value) => Cow::Borrowed(CastClaim::cast_claim(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::borrow::Cow;

    use crate::{AnyClaims, Claim, ClaimSet, InvalidClaimValue};

    #[derive(Clone, Serialize, Deserialize)]
    struct CustomClaim;

    impl Claim for CustomClaim {
        const JWT_CLAIM_NAME: &'static str = "custom";
    }

    #[allow(unused)]
    struct CustomClaimSet {
        custom: Option<CustomClaim>,
        other_claims: AnyClaims,
    }

    impl ClaimSet for CustomClaimSet {
        fn contains<C: Claim>(&self) -> bool {
            match_claim_type! {
                match C {
                    CustomClaim => self.custom.is_some(),
                    _ => ClaimSet::contains::<C>(&self.other_claims)
                }
            }
        }

        fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
            match_claim_type! {
                match C {
                    CustomClaim => {
                        Ok(self.custom.as_ref().map(Cow::Borrowed))
                    },
                    _ => {
                        ClaimSet::try_get::<C>(&self.other_claims)
                    }
                }
            }
        }

        fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
            match_claim_type! {
                match claim: C {
                    CustomClaim => {
                        self.custom = Some(claim);
                        Ok(Ok(()))
                    },
                    _ => {
                        ClaimSet::try_set(&mut self.other_claims, claim)
                    }
                }
            }
        }

        fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
            match_claim_type! {
                match C {
                    CustomClaim => {
                        Ok(self.custom.take())
                    },
                    _ => {
                        ClaimSet::try_remove::<C>(&mut self.other_claims)
                    }
                }
            }
        }
    }
}
