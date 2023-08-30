use iref::Iri;
use pin_project::pin_project;
use std::{future::Future, pin::Pin, task};

use crate::{ProofPurpose, ProofPurposes, VerificationError};

/// Verification method controller.
///
/// A verification method controller stores the proof purposes for its
/// controlled verification methods. All verification methods have a controller.
/// The [`VerificationMethod::controller`](crate::VerificationMethod) returns
/// an identifier for its controller, which can then be retrieved using a
/// [`ControllerProvider`].
///
/// [`VerificationMethod::controller`]: crate::VerificationMethod::controller
pub trait Controller {
    /// Checks that the controller allows using the verification method for the
    /// given proof purposes.
    fn allows_verification_method(&self, id: &Iri, proof_purposes: ProofPurposes) -> bool;
}

impl<'a, T: Controller> Controller for &'a T {
    fn allows_verification_method(&self, id: &Iri, proof_purposes: ProofPurposes) -> bool {
        T::allows_verification_method(*self, id, proof_purposes)
    }
}

/// Controller provider.
///
/// A provider is in charge of retrieving the verification method controllers
/// from their identifiers.
pub trait ControllerProvider {
    /// Controller reference type.
    type Controller<'a>: Controller
    where
        Self: 'a;

    /// Future returned by the `get_controller` method.
    type GetController<'a>: Future<Output = Result<Option<Self::Controller<'a>>, ControllerError>>
    where
        Self: 'a;

    /// Returns the controller with the given identifier, if it can be found.
    fn get_controller<'a>(&'a self, id: &'a Iri) -> Self::GetController<'a>;

    /// Returns the controller with the given identifier, or fails if it cannot
    /// be found.
    fn require_controller<'a>(&'a self, id: &'a Iri) -> RequireController<'a, Self> {
        RequireController {
            id,
            get: self.get_controller(id),
        }
    }

    /// Checks that the controller identified by `controller_id` allows the use
    /// of the verification method `method_id` with the given proof purposes.
    fn allows_verification_method<'a>(
        &'a self,
        controller_id: &'a Iri,
        method_id: &'a Iri,
        proof_purposes: ProofPurposes,
    ) -> AllowsVerificationMethod<'a, Self> {
        AllowsVerificationMethod {
            method_id,
            proof_purposes,
            require: self.require_controller(controller_id),
        }
    }

    /// Ensures that the controller identified by `controller_id` allows the use
    /// of the verification method `method_id` with the given proof purposes.
    ///
    /// Contrarily to the [`allows_verification_method`] function, this function
    /// returns an error if one of the input proof purposes is not allowed.
    fn ensure_allows_verification_method<'a>(
        &'a self,
        controller_id: &'a Iri,
        method_id: &'a Iri,
        proof_purpose: ProofPurpose,
    ) -> EnsureAllowsVerificationMethod<'a, Self> {
        EnsureAllowsVerificationMethod {
            method_id,
            proof_purpose,
            require: self.require_controller(controller_id),
        }
    }
}

#[pin_project]
pub struct RequireController<'a, C: 'a + ?Sized + ControllerProvider> {
    id: &'a Iri,

    #[pin]
    get: C::GetController<'a>,
}

impl<'a, C: 'a + ?Sized + ControllerProvider> Future for RequireController<'a, C> {
    type Output = Result<C::Controller<'a>, ControllerError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.get.poll(cx).map(|result| {
            result.and_then(|c| c.ok_or_else(|| ControllerError::NotFound(this.id.to_string())))
        })
    }
}

#[pin_project]
pub struct AllowsVerificationMethod<'a, C: 'a + ?Sized + ControllerProvider> {
    method_id: &'a Iri,

    proof_purposes: ProofPurposes,

    #[pin]
    require: RequireController<'a, C>,
}

impl<'a, C: 'a + ?Sized + ControllerProvider> Future for AllowsVerificationMethod<'a, C> {
    type Output = Result<bool, ControllerError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.require
            .poll(cx)
            .map_ok(|c| c.allows_verification_method(*this.method_id, *this.proof_purposes))
    }
}

#[pin_project]
pub struct EnsureAllowsVerificationMethod<'a, C: 'a + ?Sized + ControllerProvider> {
    method_id: &'a Iri,

    proof_purpose: ProofPurpose,

    #[pin]
    require: RequireController<'a, C>,
}

impl<'a, C: 'a + ?Sized + ControllerProvider> Future for EnsureAllowsVerificationMethod<'a, C> {
    type Output = Result<(), VerificationError>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.require
            .poll(cx)
            .map_ok(|c| c.allows_verification_method(*this.method_id, (*this.proof_purpose).into()))
            .map(|result| match result {
                Ok(true) => Ok(()),
                Ok(false) => Err(VerificationError::InvalidKeyUse(*this.proof_purpose)),
                Err(e) => Err(e.into()),
            })
    }
}

/// Error that can be returned by a controller provider.
pub enum ControllerError {
    /// Controller was not found.
    ///
    /// The controller identifier is provided as argument.
    NotFound(String),

    /// Invalid controller.
    ///
    /// The controller was found, but could not be interpreted as a valid
    /// controller.
    Invalid,

    /// Unsupported controller identifier scheme.
    ///
    /// The controller scheme is provided as argument.
    UnsupportedScheme(String),

    /// Custom error from the controller provider.
    InternalError(String),
}

impl From<ControllerError> for VerificationError {
    fn from(value: ControllerError) -> Self {
        match value {
            ControllerError::NotFound(id) => Self::KeyControllerNotFound(id),
            ControllerError::Invalid => Self::InvalidKeyController,
            ControllerError::UnsupportedScheme(s) => Self::UnsupportedControllerScheme(s),
            ControllerError::InternalError(e) => Self::InternalError(e),
        }
    }
}
