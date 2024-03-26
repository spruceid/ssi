use iref::Iri;

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

    /// Returns the controller with the given identifier, if it can be found.
    #[allow(async_fn_in_trait)]
    async fn get_controller<'a>(
        &'a self,
        id: &'a Iri,
    ) -> Result<Option<Self::Controller<'a>>, ControllerError>;

    /// Returns the controller with the given identifier, or fails if it cannot
    /// be found.
    #[allow(async_fn_in_trait)]
    async fn require_controller<'a>(
        &'a self,
        id: &'a Iri,
    ) -> Result<Self::Controller<'a>, ControllerError> {
        self.get_controller(id)
            .await?
            .ok_or_else(|| ControllerError::NotFound(id.to_string()))
    }

    /// Checks that the controller identified by `controller_id` allows the use
    /// of the verification method `method_id` with the given proof purposes.
    #[allow(async_fn_in_trait)]
    async fn allows_verification_method<'a>(
        &'a self,
        controller_id: &'a Iri,
        method_id: &'a Iri,
        proof_purposes: ProofPurposes,
    ) -> Result<bool, ControllerError> {
        let controller = self.require_controller(controller_id).await?;
        Ok(controller.allows_verification_method(method_id, proof_purposes))
    }

    /// Ensures that the controller identified by `controller_id` allows the use
    /// of the verification method `method_id` with the given proof purposes.
    ///
    /// Contrarily to the [`allows_verification_method`] function, this function
    /// returns an error if one of the input proof purposes is not allowed.
    ///
    /// [`allows_verification_method`]: ControllerProvider::allows_verification_method
    #[allow(async_fn_in_trait)]
    async fn ensure_allows_verification_method<'a>(
        &'a self,
        controller_id: &'a Iri,
        method_id: &'a Iri,
        proof_purpose: ProofPurpose,
    ) -> Result<(), VerificationError> {
        let controller = self.require_controller(controller_id).await?;
        if controller.allows_verification_method(method_id, proof_purpose.into()) {
            Ok(())
        } else {
            Err(VerificationError::InvalidKeyUse(proof_purpose))
        }
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
