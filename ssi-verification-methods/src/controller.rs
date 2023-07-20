use async_trait::async_trait;
use iref::Iri;
use ssi_crypto::{ProofPurpose, ProofPurposes};

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
    fn allows_verification_method(&self, id: Iri, proof_purposes: ProofPurposes) -> bool;
}

impl<'a, T: Controller> Controller for &'a T {
    fn allows_verification_method(&self, id: Iri, proof_purposes: ProofPurposes) -> bool {
        T::allows_verification_method(*self, id, proof_purposes)
    }
}

/// Controller provider.
///
/// A provider is in charge of retrieving the verification method controllers
/// from their identifiers.
#[async_trait]
pub trait ControllerProvider: Sync {
    /// Controller reference type.
    type Controller<'a>: Controller
    where
        Self: 'a;

    /// Returns the controller with the given identifier, if it can be found.
    async fn get_controller(
        &self,
        id: Iri<'_>,
    ) -> Result<Option<Self::Controller<'_>>, ControllerError>;

    /// Returns the controller with the given identifier, or fails if it cannot
    /// be found.
    async fn require_controller(
        &self,
        id: Iri<'_>,
    ) -> Result<Self::Controller<'_>, ControllerError> {
        self.get_controller(id)
            .await?
            .ok_or_else(|| ControllerError::NotFound(id.to_string()))
    }

    /// Checks that the controller identified by `controller_id` allows the use
    /// of the verification method `method_id` with the given proof purposes.
    async fn allows_verification_method(
        &self,
        controller_id: Iri<'_>,
        method_id: Iri<'_>,
        proof_purposes: ProofPurposes,
    ) -> Result<bool, ControllerError> {
        Ok(self
            .get_controller(controller_id)
            .await?
            .ok_or_else(|| ControllerError::NotFound(controller_id.to_string()))?
            .allows_verification_method(method_id, proof_purposes))
    }

    /// Ensures that the controller identified by `controller_id` allows the use
    /// of the verification method `method_id` with the given proof purposes.
    ///
    /// Contrarily to the [`allows_verification_method`] function, this function
    /// returns an error if one of the input proof purposes is not allowed.
    async fn ensure_allows_verification_method(
        &self,
        controller_id: Iri<'_>,
        method_id: Iri<'_>,
        proof_purpose: ProofPurpose,
    ) -> Result<(), ssi_crypto::VerificationError> {
        if self
            .allows_verification_method(controller_id, method_id, proof_purpose.into())
            .await?
        {
            Ok(())
        } else {
            Err(ssi_crypto::VerificationError::InvalidKeyUse(proof_purpose))
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
    InternalError(Box<dyn Send + std::error::Error>),
}

impl From<ControllerError> for ssi_crypto::VerificationError {
    fn from(value: ControllerError) -> Self {
        match value {
            ControllerError::NotFound(id) => Self::KeyControllerNotFound(id),
            ControllerError::Invalid => Self::InvalidKeyController,
            ControllerError::UnsupportedScheme(s) => Self::UnsupportedControllerScheme(s),
            ControllerError::InternalError(e) => Self::InternalError(e),
        }
    }
}
