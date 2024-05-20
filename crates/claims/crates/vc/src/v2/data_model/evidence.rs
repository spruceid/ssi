use super::MaybeIdentified;

/// Evidence.
///
/// Can be included by an issuer to provide the verifier with additional
/// supporting information in a verifiable credential.
pub trait Evidence: MaybeIdentified {
    fn types(&self) -> &[String];
}

impl Evidence for std::convert::Infallible {
    fn types(&self) -> &[String] {
        unreachable!()
    }
}
