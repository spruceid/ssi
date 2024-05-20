use super::MaybeIdentified;

/// Terms of Use.
///
/// Terms of use can be utilized by an issuer or a holder to communicate the
/// terms under which a verifiable credential or verifiable presentation was
/// issued.
pub trait TermsOfUse: MaybeIdentified {
    fn type_(&self) -> &[&str];
}

impl TermsOfUse for std::convert::Infallible {
    fn type_(&self) -> &[&str] {
        &[]
    }
}
