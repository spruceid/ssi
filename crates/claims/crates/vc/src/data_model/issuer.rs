use iref::Uri;

pub trait Issuer {
    fn id(&self) -> &Uri;
}

impl Issuer for Uri {
    fn id(&self) -> &Uri {
        self
    }
}
