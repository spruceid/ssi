use crate::{NoClaim, RemoveClaim, TryGetClaim, TryRemoveClaim, TrySetClaim};

use super::{Claim, ClaimSet, GetClaim, SetClaim};
use core::fmt;
use std::borrow::Cow;

pub trait PrivateClaim: Clone {
    const JWT_PRIVATE_CLAIM_NAME: &'static str;
}

impl<T: PrivateClaim> Claim for T {
    type Private = Self;
    type Registered = NoClaim;

    const JWT_CLAIM_NAME: &'static str = T::JWT_PRIVATE_CLAIM_NAME;
    const IS_REGISTERED_JWT_CLAIM: bool = false;

    fn from_registered(_: Self::Registered) -> Option<Self> {
        None
    }

    fn from_registered_ref(_: &Self::Registered) -> Option<&Self> {
        None
    }

    fn from_registered_mut(_: &mut Self::Registered) -> Option<&mut Self> {
        None
    }

    fn from_private(claim: Self::Private) -> Option<Self> {
        Some(claim)
    }

    fn from_private_ref(claim: &Self::Private) -> Option<&Self> {
        Some(claim)
    }

    fn from_private_mut(claim: &mut Self::Private) -> Option<&mut Self> {
        Some(claim)
    }

    fn into_registered(self) -> Result<Self::Registered, Self::Private> {
        Err(self)
    }
}

pub trait PrivateClaimSet {
    type Error: fmt::Display;
}

impl<T: PrivateClaimSet> ClaimSet for T {
    type Error = <T as PrivateClaimSet>::Error;
}

impl<T: PrivateClaimSet> GetClaim<NoClaim> for T {
    fn get_claim(&self) -> Option<Cow<NoClaim>> {
        None
    }
}

impl<T: PrivateClaimSet> TryGetClaim<NoClaim> for T {
    fn try_get_claim(&self) -> Result<Option<Cow<NoClaim>>, Self::Error> {
        Ok(None)
    }
}

impl<T: PrivateClaimSet> SetClaim<NoClaim> for T {
    fn set_claim(&mut self, _: NoClaim) {
        unreachable!()
    }
}

impl<T: PrivateClaimSet> TrySetClaim<NoClaim> for T {
    fn try_set_claim(&mut self, _: NoClaim) -> Result<(), Self::Error> {
        unreachable!()
    }
}

impl<T: PrivateClaimSet> RemoveClaim<NoClaim> for T {
    fn remove_claim(&mut self) -> Option<NoClaim> {
        None
    }
}

impl<T: PrivateClaimSet> TryRemoveClaim<NoClaim> for T {
    fn try_remove_claim(&mut self) -> Result<Option<NoClaim>, Self::Error> {
        Ok(None)
    }
}
