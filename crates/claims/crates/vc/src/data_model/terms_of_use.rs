use iref::Uri;

/// Terms of Use.
///
/// Terms of use can be utilized by an issuer or a holder to communicate the
/// terms under which a verifiable credential or verifiable presentation was
/// issued.
pub trait TermsOfUse {
    fn id(&self) -> Option<&Uri>;

    fn type_(&self) -> &str;
}

impl TermsOfUse for std::convert::Infallible {
    fn id(&self) -> Option<&Uri> {
        unreachable!()
    }

    fn type_(&self) -> &str {
        unreachable!()
    }
}
