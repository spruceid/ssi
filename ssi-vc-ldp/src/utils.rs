use std::{future::Future, pin::Pin, task};

use pin_project::pin_project;

/// Future owning and referencing the same piece of data at the same time.
///
/// Once the future is resolved, the owned data is returned as well, ending the
/// reference.
pub trait UnboundedRefFuture<'min, 'max> {
    /// Owned data.
    type Owned: 'max;

    /// The future itself.
    type Bound<'a: 'min>: Future<Output = Self::Output>
    where
        'max: 'a;

    /// Output.
    type Output;
}

pub trait RefFutureBinder<'min, 'max, B: UnboundedRefFuture<'min, 'max>> {
    fn bind<'a: 'min>(context: Self, value: &'a B::Owned) -> B::Bound<'a>
    where
        'max: 'a;
}

/// Self-referential type.
#[pin_project]
pub struct SelfRefFuture<'min, 'max: 'min, Q: UnboundedRefFuture<'min, 'max>> {
    value: Option<Box<Q::Owned>>,

    #[pin]
    reference: Q::Bound<'max>,
}

impl<'min, 'max, Q: UnboundedRefFuture<'min, 'max>> SelfRefFuture<'min, 'max, Q> {
    pub fn new<T>(t: Q::Owned, context: T) -> Self
    where
        T: RefFutureBinder<'min, 'max, Q>,
    {
        let value = Box::new(t);

        let reference = unsafe {
            // SAFETY: this is safe because
            //  - the actual lifetime of `value` is never leaked.
            //  - `value` is never moved or destroyed while `reference` is
            //    alive.
            let static_value_ref: &'max Q::Owned = std::mem::transmute(&value);
            T::bind(context, static_value_ref)
        };

        Self {
            value: Some(value),
            reference,
        }
    }
}

impl<'min, 'max, Q: UnboundedRefFuture<'min, 'max>> Future for SelfRefFuture<'min, 'max, Q> {
    type Output = (Q::Output, Q::Owned);

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        if this.value.is_some() {
            this.reference
                .poll(cx)
                .map(|r| (r, *this.value.take().unwrap()))
        } else {
            panic!("future already completed")
        }
    }
}
