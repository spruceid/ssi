mod registered;
use core::fmt;
use std::borrow::Cow;

use chrono::Utc;
pub use registered::*;
mod private;
pub use private::*;
mod mixed;
pub use mixed::*;
use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, InvalidClaims};
// use ssi_verification_methods::{
//     MaybeJwkVerificationMethod, ReferenceOrOwnedRef, SignatureError, Signer,
//     VerificationMethodResolver,
// };

/// JWT claim.
///
/// You do not need to implement this trait yourself to define a private claim
/// type. Simply implement the [`PrivateClaim`] trait instead.
pub trait Claim: Clone {
    /// This same claim type, as a private claim.
    type Private: PrivateClaim;

    /// This same claim type, as a registered claim.
    type Registered: RegisteredClaim;

    const JWT_CLAIM_NAME: &'static str;
    const IS_REGISTERED_JWT_CLAIM: bool;

    fn from_registered(claim: Self::Registered) -> Option<Self>;

    fn from_registered_ref(claim: &Self::Registered) -> Option<&Self>;

    fn from_registered_mut(claim: &mut Self::Registered) -> Option<&mut Self>;

    fn from_registered_cow(claim: Cow<Self::Registered>) -> Option<Cow<Self>> {
        match claim {
            Cow::Owned(c) => Self::from_registered(c).map(Cow::Owned),
            Cow::Borrowed(c) => Self::from_registered_ref(c).map(Cow::Borrowed),
        }
    }

    fn from_private(claim: Self::Private) -> Option<Self>;

    fn from_private_ref(claim: &Self::Private) -> Option<&Self>;

    fn from_private_mut(claim: &mut Self::Private) -> Option<&mut Self>;

    fn from_private_cow(claim: Cow<Self::Private>) -> Option<Cow<Self>> {
        match claim {
            Cow::Owned(c) => Self::from_private(c).map(Cow::Owned),
            Cow::Borrowed(c) => Self::from_private_ref(c).map(Cow::Borrowed),
        }
    }

    fn into_registered(self) -> Result<Self::Registered, Self::Private>;
}

/// Set of JWT claims.
pub trait ClaimSet {
    type Error: fmt::Display;

    fn try_get<C: Clone>(&self) -> Result<Option<Cow<C>>, Self::Error>
    where
        Self: TryGetClaim<C>,
    {
        TryGetClaim::<C>::try_get_claim(self)
    }

    fn get<C: Clone>(&self) -> Option<Cow<C>>
    where
        Self: GetClaim<C>,
    {
        GetClaim::<C>::get_claim(self)
    }

    fn try_set<C: Clone>(&mut self, claim: C) -> Result<(), Self::Error>
    where
        Self: TrySetClaim<C>,
    {
        TrySetClaim::<C>::try_set_claim(self, claim)
    }

    fn set<C: Clone>(&mut self, claim: C)
    where
        Self: SetClaim<C>,
    {
        SetClaim::<C>::set_claim(self, claim)
    }

    fn try_remove<C: Clone>(&mut self) -> Result<Option<C>, Self::Error>
    where
        Self: TryRemoveClaim<C>,
    {
        TryRemoveClaim::<C>::try_remove_claim(self)
    }

    fn remove<C: Clone>(&mut self) -> Option<C>
    where
        Self: RemoveClaim<C>,
    {
        RemoveClaim::<C>::remove_claim(self)
    }

    fn validate_registered_claims<E>(&self, env: &E) -> ClaimsValidity
    where
        E: DateTimeEnvironment,
        Self: TryGetClaim<IssuedAt> + TryGetClaim<NotBefore> + TryGetClaim<ExpirationTime>,
    {
        let now = env.date_time();

        if let Some(iat) = self.try_get::<IssuedAt>().map_err(InvalidClaims::other)? {
            let valid_from: chrono::DateTime<Utc> = iat.0.into();
            if valid_from > now {
                return Err(InvalidClaims::Premature { now, valid_from });
            }
        }

        if let Some(nbf) = self.try_get::<NotBefore>().map_err(InvalidClaims::other)? {
            let valid_from: chrono::DateTime<Utc> = nbf.0.into();
            if valid_from > now {
                return Err(InvalidClaims::Premature { now, valid_from });
            }
        }

        if let Some(exp) = self
            .try_get::<ExpirationTime>()
            .map_err(InvalidClaims::other)?
        {
            let valid_until: chrono::DateTime<Utc> = exp.0.into();
            if valid_until <= now {
                return Err(InvalidClaims::Expired { now, valid_until });
            }
        }

        Ok(())
    }
}

/// JWT claim set supporting reading claim `C`.
pub trait TryGetClaim<C: Clone>: ClaimSet {
    /// Returns the value of the given claim.
    fn try_get_claim(&self) -> Result<Option<Cow<C>>, Self::Error>;
}

/// JWT claim set supporting reading claim `C`.
pub trait GetClaim<C: Clone>: ClaimSet {
    /// Returns the value of the given claim.
    fn get_claim(&self) -> Option<Cow<C>>;
}

/// JWT claim set supporting writing claim `C`.
pub trait TrySetClaim<C>: ClaimSet {
    fn try_set_claim(&mut self, claim: C) -> Result<(), Self::Error>;
}

/// JWT claim set supporting writing claim `C`.
pub trait SetClaim<C>: ClaimSet {
    fn set_claim(&mut self, claim: C);
}

/// JWT claim set supporting removing claim `C`.
pub trait TryRemoveClaim<C: Clone>: ClaimSet {
    /// Removes and return the claim.
    fn try_remove_claim(&mut self) -> Result<Option<C>, Self::Error>;
}

/// JWT claim set supporting removing claim `C`.
pub trait RemoveClaim<C: Clone>: ClaimSet {
    /// Removes and return the claim.
    fn remove_claim(&mut self) -> Option<C>;
}

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
