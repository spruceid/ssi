use iref::Uri;

pub trait CredentialStatus {
    fn id(&self) -> &Uri;
}

impl CredentialStatus for Uri {
    fn id(&self) -> &Uri {
        self
    }
}

impl CredentialStatus for std::convert::Infallible {
    fn id(&self) -> &Uri {
        unreachable!()
    }
}
