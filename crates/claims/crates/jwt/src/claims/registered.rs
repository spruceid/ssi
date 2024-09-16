use super::{Claim, InvalidClaimValue, JWTClaims};
use crate::{CastClaim, ClaimSet, InfallibleClaimSet, NumericDate, StringOrURI};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, ValidateClaims};
use ssi_core::OneOrMany;
use ssi_jws::JwsPayload;
use std::{borrow::Cow, collections::BTreeMap};

pub trait RegisteredClaim: Claim + Into<AnyRegisteredClaim> {
    const JWT_REGISTERED_CLAIM_KIND: RegisteredClaimKind;

    fn extract(claim: AnyRegisteredClaim) -> Option<Self>;

    fn extract_ref(claim: &AnyRegisteredClaim) -> Option<&Self>;

    fn extract_mut(claim: &mut AnyRegisteredClaim) -> Option<&mut Self>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegisteredClaims(BTreeMap<RegisteredClaimKind, AnyRegisteredClaim>);

impl RegisteredClaims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> RegisteredClaimsIter {
        self.0.values()
    }

    pub fn contains<C: RegisteredClaim>(&self) -> bool {
        self.0.contains_key(&C::JWT_REGISTERED_CLAIM_KIND)
    }

    pub fn get<C: RegisteredClaim>(&self) -> Option<&C> {
        self.0
            .get(&C::JWT_REGISTERED_CLAIM_KIND)
            .and_then(C::extract_ref)
    }

    pub fn get_mut<C: RegisteredClaim>(&mut self) -> Option<&mut C> {
        self.0
            .get_mut(&C::JWT_REGISTERED_CLAIM_KIND)
            .and_then(C::extract_mut)
    }

    pub fn set<C: RegisteredClaim>(&mut self, claim: C) -> Option<C> {
        self.0
            .insert(C::JWT_REGISTERED_CLAIM_KIND, claim.into())
            .and_then(C::extract)
    }

    pub fn insert_any(&mut self, claim: AnyRegisteredClaim) -> Option<AnyRegisteredClaim> {
        self.0.insert(claim.kind(), claim)
    }

    pub fn remove<C: RegisteredClaim>(&mut self) -> Option<C> {
        self.0
            .remove(&C::JWT_REGISTERED_CLAIM_KIND)
            .and_then(C::extract)
    }

    pub fn with_private_claims<P>(self, claims: P) -> JWTClaims<P> {
        JWTClaims {
            registered: self,
            private: claims,
        }
    }
}

impl InfallibleClaimSet for RegisteredClaims {}

impl JwsPayload for RegisteredClaims {
    fn typ(&self) -> Option<&'static str> {
        Some("JWT")
    }

    fn payload_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl<E, P> ValidateClaims<E, P> for RegisteredClaims
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, env: &E, _proof: &P) -> ClaimsValidity {
        ClaimSet::validate_registered_claims(self, env)
    }
}

pub type RegisteredClaimsIter<'a> =
    std::collections::btree_map::Values<'a, RegisteredClaimKind, AnyRegisteredClaim>;

impl<'a> IntoIterator for &'a RegisteredClaims {
    type IntoIter = RegisteredClaimsIter<'a>;
    type Item = &'a AnyRegisteredClaim;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl serde::Serialize for RegisteredClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;

        for claim in self {
            claim.serialize(&mut map)?;
        }

        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for RegisteredClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RegisteredClaims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "JWT registered claim set")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = RegisteredClaims::new();
                while let Some(kind) = map.next_key::<RegisteredClaimKind>()? {
                    let claim = kind.deserialize_value(&mut map)?;
                    result.insert_any(claim);
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

pub trait TryIntoClaim<C> {
    type Error;

    fn try_into_claim(self) -> Result<C, Self::Error>;
}

macro_rules! registered_claims {
    ($($(#[$meta:meta])* $name:literal: $variant:ident ( $ty:ty )),*) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            #[derive(serde::Serialize, serde::Deserialize)]
            #[serde(transparent)]
            pub struct $variant(pub $ty);

            impl Claim for $variant {
                const JWT_CLAIM_NAME: &'static str = $name;
            }

            impl<T> TryIntoClaim<$variant> for T
            where
                T: TryInto<$ty>
            {
                type Error = T::Error;

                fn try_into_claim(self) -> Result<$variant, Self::Error> {
                    self.try_into().map($variant)
                }
            }

            impl RegisteredClaim for $variant {
                const JWT_REGISTERED_CLAIM_KIND: RegisteredClaimKind = RegisteredClaimKind::$variant;

                fn extract(claim: AnyRegisteredClaim) -> Option<Self> {
                    match claim {
                        AnyRegisteredClaim::$variant(value) => Some(value),
                        _ => None
                    }
                }

                fn extract_ref(claim: &AnyRegisteredClaim) -> Option<&Self> {
                    match claim {
                        AnyRegisteredClaim::$variant(value) => Some(value),
                        _ => None
                    }
                }

                fn extract_mut(claim: &mut AnyRegisteredClaim) -> Option<&mut Self> {
                    match claim {
                        AnyRegisteredClaim::$variant(value) => Some(value),
                        _ => None
                    }
                }
            }
        )*

        impl ClaimSet for RegisteredClaims {
            fn contains<C: Claim>(&self) -> bool {
                $(
                    if std::any::TypeId::of::<C>() == std::any::TypeId::of::<$variant>() {
                        return self.contains::<$variant>();
                    }
                )*

                false
            }

            fn try_get<C: Claim>(&self) -> Result<Option<Cow<C>>, InvalidClaimValue> {
                $(
                    if std::any::TypeId::of::<C>() == std::any::TypeId::of::<$variant>() {
                        return Ok(unsafe { CastClaim::cast_claim(self.get::<$variant>()) }.map(Cow::Borrowed));
                    }
                )*

                Ok(None)
            }

            fn try_set<C: Claim>(&mut self, claim: C) -> Result<Result<(), C>, InvalidClaimValue> {
                $(
                    if std::any::TypeId::of::<C>() == std::any::TypeId::of::<$variant>() {
                        self.set::<$variant>(unsafe { CastClaim::cast_claim(claim) });
                        return Ok(Ok(()))
                    }
                )*

                Ok(Err(claim))
            }

            fn try_remove<C: Claim>(&mut self) -> Result<Option<C>, InvalidClaimValue> {
                $(
                    if std::any::TypeId::of::<C>() == std::any::TypeId::of::<$variant>() {
                        return Ok(unsafe { CastClaim::cast_claim(self.remove::<$variant>()) });
                    }
                )*

                Ok(None)
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum RegisteredClaimKind {
            $(
                $variant
            ),*
        }

        impl RegisteredClaimKind {
            pub fn new(s: &str) -> Option<Self> {
                match s {
                    $(
                        $name => Some(Self::$variant),
                    )*
                    _ => None
                }
            }

            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        Self::$variant => $name,
                    )*
                }
            }

            pub(crate) fn deserialize_value<'de, M: serde::de::MapAccess<'de>>(&self, map: &mut M) -> Result<AnyRegisteredClaim, M::Error> {
                match self {
                    $(
                        Self::$variant => {
                            map.next_value().map(AnyRegisteredClaim::$variant)
                        }
                    ),*
                }
            }
        }

		impl<'de> serde::Deserialize<'de> for RegisteredClaimKind {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: serde::Deserializer<'de>
			{
				let name = String::deserialize(deserializer)?;
				match Self::new(&name) {
					Some(r) => Ok(r),
					None => Err(serde::de::Error::custom(format!("unknown registered claim `{}`", name)))
				}
			}
		}

        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum AnyRegisteredClaim {
            $(
                $variant($variant)
            ),*
        }

        impl AnyRegisteredClaim {
            pub fn kind(&self) -> RegisteredClaimKind {
                match self {
                    $(
                        Self::$variant(_) => RegisteredClaimKind::$variant
                    ),*
                }
            }

            fn serialize<S: serde::ser::SerializeMap>(&self, serializer: &mut S) -> Result<(), S::Error> {
                match self {
                    $(
                        Self::$variant(value) => {
                            serializer.serialize_entry(
                                $name,
                                value
                            )
                        }
                    ),*
                }
            }
        }

        $(
            impl From<$variant> for AnyRegisteredClaim {
                fn from(value: $variant) -> Self {
                    Self::$variant(value)
                }
            }
        )*
    };
}

registered_claims! {
    /// Issuer (`iss`) claim.
    ///
    /// Principal that issued the JWT. The processing of this claim is generally
    /// application specific.
    "iss": Issuer(StringOrURI),

    /// Subject (`sub`) claim.
    ///
    /// Principal that is the subject of the JWT. The claims in a JWT are
    /// normally statements about the subject. The subject value MUST either be
    /// scoped to be locally unique in the context of the issuer or be globally
    /// unique.
    ///
    /// The processing of this claim is generally application specific.
    "sub": Subject(StringOrURI),

    /// Audience (`aud`) claim.
    ///
    /// Recipients that the JWT is intended for. Each principal intended to
    /// process the JWT MUST identify itself with a value in the audience claim.
    /// If the principal processing the claim does not identify itself with a
    /// value in the `aud` claim when this claim is present, then the JWT MUST
    /// be rejected.
    "aud": Audience(OneOrMany<StringOrURI>),

    /// Expiration Time (`exp`) claim.
    ///
    /// Expiration time on or after which the JWT MUST NOT be accepted for
    /// processing. The processing of the `exp` claim requires that the current
    /// date/time MUST be before the expiration date/time listed in the `exp`
    /// claim.
    "exp": ExpirationTime(NumericDate),

    /// Not Before (`nbf`) claim.
    ///
    /// Time before which the JWT MUST NOT be accepted for processing. The
    /// processing of the `nbf` claim requires that the current date/time MUST
    /// be after or equal to the not-before date/time listed in the "nbf" claim.
    /// Implementers MAY provide for some small leeway, usually no more than a
    /// few minutes, to account for clock skew.
    "nbf": NotBefore(NumericDate),

    /// Issued At (`iat`) claim.
    ///
    /// Time at which the JWT was issued. This claim can be used to determine
    /// the age of the JWT.
    "iat": IssuedAt(NumericDate),

    /// JWT ID (`jti`) claim.
    ///
    /// Unique identifier for the JWT. The identifier value MUST be assigned in
    /// a manner that ensures that there is a negligible probability that the
    /// same value will be accidentally assigned to a different data object; if
    /// the application uses multiple issuers, collisions MUST be prevented
    /// among values produced by different issuers as well.
    ///
    /// The "jti" claim can be used to prevent the JWT from being replayed.
    "jti": JwtId(String),

    "nonce": Nonce(String),

    "vc": VerifiableCredential(json_syntax::Value),

    "vp": VerifiablePresentation(json_syntax::Value)
}
