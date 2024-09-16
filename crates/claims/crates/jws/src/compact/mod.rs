mod bytes;
pub use bytes::*;

mod str;
pub use str::*;

mod url_safe;
pub use url_safe::*;

#[derive(Debug, thiserror::Error)]
#[error("invalid JWS")]
pub struct InvalidJws<B = String>(pub B);

impl<'a> InvalidJws<&'a [u8]> {
    pub fn into_owned(self) -> InvalidJws<Vec<u8>> {
        InvalidJws(self.0.to_owned())
    }
}
