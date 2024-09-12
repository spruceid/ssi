pub const fn is_url_safe_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

pub trait TryRetainMut {
    type Item;

    fn try_retain_mut<E>(
        &mut self,
        f: impl FnMut(&mut Self::Item) -> Result<bool, E>,
    ) -> Result<(), E>;
}

impl<T> TryRetainMut for Vec<T> {
    type Item = T;

    fn try_retain_mut<E>(
        &mut self,
        mut f: impl FnMut(&mut Self::Item) -> Result<bool, E>,
    ) -> Result<(), E> {
        let mut result = Ok(());

        self.retain_mut(|t| {
            if result.is_ok() {
                match f(t) {
                    Ok(retain) => retain,
                    Err(e) => {
                        result = Err(e);
                        false
                    }
                }
            } else {
                true
            }
        });

        result
    }
}
