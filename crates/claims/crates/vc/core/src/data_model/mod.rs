mod credential;
mod presentation;
mod issuer;
mod status;
mod refresh_service;
mod evidence;
mod terms_of_use;

pub use credential::*;
pub use presentation::*;
pub use issuer::*;
pub use status::*;
pub use refresh_service::*;
pub use evidence::*;
pub use terms_of_use::*;

pub trait CredentialOrPresentation {
	/// Validates the credential or presentation.
	/// 
	/// Validation consists in verifying that the claims themselves are
	/// consistent and valid with regard to the verification environment.
	/// For instance, checking that a credential's expiration date is not in the
	/// past, or the issue date not in the future.
	/// 
	/// Validation may fail even if the credential or presentation's proof is
	/// successfully verified.
	/// 
	/// You do not need to call this method yourself when verifying a
	/// credential or presentation. It is automatically called by
	/// [`VerifiableWith::verify_with`].
	/// 
	/// If you need to implement this function, you can simply reuse
	/// [`Credential::is_valid`] or [`Presentation::is_valid`].
	fn is_valid(&self) -> bool;
}

/// Verifiable Credential or Presentation.
pub trait VerifiableCredentialOrPresentation {
	type Proof;

	/// Proofs.
	/// 
	/// At least one proof is *required* for the credential to be *verifiable*.
	fn proofs(&self) -> &[Self::Proof];
}