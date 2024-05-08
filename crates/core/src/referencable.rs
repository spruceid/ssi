/// Type providing a custom reference type.
///
/// # Example
///
/// This trait is a solution to a common problem found in ssi: intersection
/// type reference specialization.
/// For instance, consider the following setup where the `AB` type is the
/// intersection between type `A` and `B`:
///
/// ```ignore
/// struct A {
///   foo: Foo
/// }
///
/// struct B {
///   bar: Bar
/// }
///
/// struct AB {
///   foo: Foo,
///   bar: Bar
/// }
/// ```
///
/// Since `AB` is the intersection between `A` and `B`, we can easily define a
/// conversion from `AB` to `A` and `AB` to `B`. This is *specialization*, which
/// is easy to define for *owned* types.
/// However, it is not directly possible to specialize references this way.
/// We cannot define a conversion from `&AB` to `&A`, or `&AB` to `&B`.
/// This issue can be solved by the `Referencable` trait by specifying more
/// flexible reference types for `A`, `B` and `AB`.
///
/// ```ignore
/// struct ARef<'a> {
///   foo: &'a Foo
/// }
///
/// struct BRef<'a> {
///   bar: &'a Bar
/// }
///
/// struct ABRef<'a> {
///   foo: &'a Foo,
///   bar: &'a Bar
/// }
/// ```
///
/// As with the owned types `A`, `B` and `AB` we can easily define a conversion
/// from `ABRef` to `ARef` and `BRef`. We use the `Referencable` trait to
/// connect each owned type (e.g. `AB`) to its borrowed version (e.g. `ABRef`).
///
/// ```ignore
/// impl Referencable for AB {
///     type Reference<'a> = ABRef<'a> where Self: 'a;
///
///     fn as_reference(&self) -> ABRef {
///         ABRef {
///             foo: &self.foo,
///             bar: &self.bar
///         }
///     }
///
///     covariance_rule!()
/// }
/// ```
///
/// The [`covariance_rule`] macro provides a straightforward implementation of
/// the [`Referencable::apply_covariance`] function, allowing the caller to
/// shorted the associated `Reference` type lifetime.
pub trait Referencable {
    /// Custom reference type.
    type Reference<'a>: Copy
    where
        Self: 'a;

    /// Borrows `self` into a `Self::Reference`.
    fn as_reference(&self) -> Self::Reference<'_>;

    /// Shortens the associated `Self::Reference` type lifetime.
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
