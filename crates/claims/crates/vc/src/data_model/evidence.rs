use iref::Uri;

/// Evidence.
///
/// Can be included by an issuer to provide the verifier with additional
/// supporting information in a verifiable credential.
pub trait Evidence {
    fn id(&self) -> Option<&Uri>;

    fn type_(&self) -> &[String];
}

impl Evidence for std::convert::Infallible {
    fn id(&self) -> Option<&Uri> {
        unreachable!()
    }

    fn type_(&self) -> &[String] {
        unreachable!()
    }
}
