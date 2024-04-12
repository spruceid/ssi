use core::fmt;

use hashbrown::HashMap;
use slab::Slab;
use ssi_core::OneOrMany;

use crate::{NumericDate, StringOrURI};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimKind<U = String> {
    Registered(RegisteredClaimKind),
    Unregistered(U),
}

impl ClaimKind {
    pub fn as_ref(&self) -> ClaimKind<&str> {
        match self {
            Self::Registered(r) => ClaimKind::Registered(*r),
            Self::Unregistered(u) => ClaimKind::Unregistered(u),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ClaimKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        match RegisteredClaimKind::new(&name) {
            Some(r) => Ok(Self::Registered(r)),
            None => Ok(Self::Unregistered(name)),
        }
    }
}

impl<'a> ClaimKind<&'a str> {
    pub fn into_owned(self) -> ClaimKind {
        match self {
            Self::Registered(r) => ClaimKind::Registered(r),
            Self::Unregistered(u) => ClaimKind::Unregistered(u.to_owned()),
        }
    }
}

impl hashbrown::Equivalent<ClaimKind<String>> for ClaimKind<&str> {
    fn equivalent(&self, key: &ClaimKind<String>) -> bool {
        *self == key.as_ref()
    }
}

pub enum Claim {
    Registered(RegisteredClaim),
    Unregistered(String, serde_json::Value),
}

impl Claim {
    pub fn kind(&self) -> ClaimKind<&str> {
        match self {
            Self::Registered(r) => ClaimKind::Registered(r.kind()),
            Self::Unregistered(k, _) => ClaimKind::Unregistered(k),
        }
    }
}

macro_rules! registered_claims {
    ($($(#[$meta:meta])* $name:literal: $variant:ident ( $ty:ty )),*) => {
        /// Claims kind, defined in the [IANA "JSON Web Token Claims" registry][1].
        ///
        /// [1]: <https://www.iana.org/assignments/jwt/jwt.xhtml>
        ///
        /// See: <https://datatracker.ietf.org/doc/html/rfc7519#section-4.2>
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum RegisteredClaimKind {
            $(
                $(#[$meta])*
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

            pub(crate) fn deserialize_value<'de, M: serde::de::MapAccess<'de>>(&self, map: &mut M) -> Result<RegisteredClaim, M::Error> {
                match self {
                    $(
                        Self::$variant => {
                            map.next_value().map(RegisteredClaim::$variant)
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

        /// Claims defined in the [IANA "JSON Web Token Claims" registry][1].
        ///
        /// [1]: <https://www.iana.org/assignments/jwt/jwt.xhtml>
        ///
        /// See: <https://datatracker.ietf.org/doc/html/rfc7519#section-4.2>
        #[derive(Debug, Clone)]
        pub enum RegisteredClaim {
            $(
                $(#[$meta])*
                $variant($ty)
            ),*
        }

        impl RegisteredClaim {
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

/// Set of registered claims, defined in the
/// [IANA "JSON Web Token Claims" registry][1].
///
/// [1]: <https://www.iana.org/assignments/jwt/jwt.xhtml>
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7519#section-4.2>
#[derive(Default, Clone)]
pub struct RegisteredClaims {
    by_kind: HashMap<RegisteredClaimKind, usize>,
    entries: Slab<RegisteredClaim>,
}

impl RegisteredClaims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, kind: RegisteredClaimKind) -> Option<&RegisteredClaim> {
        let i = *self.by_kind.get(&kind)?;
        Some(&self.entries[i])
    }

    pub fn iter(&self) -> RegisteredClaimsIter {
        RegisteredClaimsIter {
            map: self.by_kind.values().copied(),
            entries: &self.entries,
        }
    }

    pub fn insert(&mut self, claim: RegisteredClaim) -> Option<RegisteredClaim> {
        let kind = claim.kind();
        match self.by_kind.get(&kind).copied() {
            Some(i) => Some(std::mem::replace(&mut self.entries[i], claim)),
            None => {
                let entry = self.entries.vacant_entry();
                self.by_kind.insert(kind, entry.key());
                entry.insert(claim);
                None
            }
        }
    }

    pub fn remove(&mut self, kind: RegisteredClaimKind) -> Option<RegisteredClaim> {
        let i = self.by_kind.remove(&kind)?;
        Some(self.entries.remove(i))
    }
}

impl<'a> IntoIterator for &'a RegisteredClaims {
    type IntoIter = RegisteredClaimsIter<'a>;
    type Item = &'a RegisteredClaim;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for RegisteredClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.entries.fmt(f)
    }
}

pub struct RegisteredClaimsIter<'a> {
    map: std::iter::Copied<hashbrown::hash_map::Values<'a, RegisteredClaimKind, usize>>,
    entries: &'a Slab<RegisteredClaim>,
}

impl<'a> Iterator for RegisteredClaimsIter<'a> {
    type Item = &'a RegisteredClaim;

    fn next(&mut self) -> Option<Self::Item> {
        self.map.next().map(|i| &self.entries[i])
    }
}

impl serde::Serialize for RegisteredClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;

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
                    result.insert(claim);
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

/// Set of claims.
#[derive(Default)]
pub struct Claims {
    by_kind: HashMap<ClaimKind, usize>,
    entries: Vec<Claim>,
}

impl Claims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<'a>(&self, claim: impl Into<ClaimKind<&'a str>>) -> Option<&Claim> {
        let kind = claim.into();
        let i = *self.by_kind.get(&kind)?;
        Some(&self.entries[i])
    }

    pub fn insert(&mut self, claim: Claim) -> Option<Claim> {
        let kind = claim.kind();
        match self.by_kind.get(&kind).copied() {
            Some(i) => Some(std::mem::replace(&mut self.entries[i], claim)),
            None => {
                let i = self.entries.len();
                self.by_kind.insert(kind.into_owned(), i);
                self.entries.push(claim);
                None
            }
        }
    }
}

pub struct ClaimsIter<'a>(std::slice::Iter<'a, Claim>);

impl<'a> Iterator for ClaimsIter<'a> {
    type Item = &'a Claim;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl serde::Serialize for Claims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;

        for claim in &self.entries {
            match claim {
                Claim::Registered(r) => {
                    r.serialize(&mut map)?;
                }
                Claim::Unregistered(key, value) => {
                    map.serialize_entry(key, value)?;
                }
            }
        }

        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Claims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Claims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "JWT claim set")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = Claims::new();
                while let Some(key) = map.next_key()? {
                    let claim = match key {
                        ClaimKind::Registered(r) => {
                            let claim = r.deserialize_value(&mut map)?;
                            Claim::Registered(claim)
                        }
                        ClaimKind::Unregistered(key) => {
                            let value = map.next_value()?;
                            Claim::Unregistered(key, value)
                        }
                    };

                    result.insert(claim);
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}
