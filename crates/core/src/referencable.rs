pub trait Referencable {
    type Reference<'a>: Copy
    where
        Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_>;

    fn apply_covariance<'big: 'small, 'small>(r: Self::Reference<'big>) -> Self::Reference<'small>
    where
        Self: 'big;
}

#[macro_export]
macro_rules! covariance_rule {
    () => {
        fn apply_covariance<'big: 'small, 'small>(
            r: <Self as $crate::Referencable>::Reference<'big>,
        ) -> <Self as $crate::Referencable>::Reference<'small>
        where
            Self: 'big,
        {
            r
        }
    };
}

impl Referencable for () {
    type Reference<'a> = ();

    fn as_reference(&self) -> Self::Reference<'_> {
        *self
    }

    covariance_rule!();
}

impl<'t, T> Referencable for &'t T {
    type Reference<'a> = &'t T where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}

impl Referencable for Vec<u8> {
    type Reference<'a> = &'a [u8] where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        self
    }

    covariance_rule!();
}
