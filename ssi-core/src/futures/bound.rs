use std::{future::Future, pin::Pin, task};

use pin_project::pin_project;

/// Future owning and referencing the same piece of data at the same time.
///
/// Once the future is resolved, the owned data is returned as well, ending the
/// reference.
pub trait UnboundedRefFuture<'max> {
    /// Owned data.
    type Owned: 'max;

    /// The future itself.
    type Bound<'a>: Future<Output = Self::Output>
    where
        'max: 'a;

    /// Output.
    type Output;
}

pub trait RefFutureBinder<'max, B: UnboundedRefFuture<'max>> {
    fn bind<'a>(context: Self, value: &'a B::Owned) -> B::Bound<'a>
    where
        'max: 'a;
}

/// Self-referential type.
#[pin_project]
pub struct SelfRefFuture<'max, Q: UnboundedRefFuture<'max>> {
    value: Option<Box<Q::Owned>>,

    #[pin]
    reference: Q::Bound<'max>,
}

impl<'max, Q: UnboundedRefFuture<'max>> SelfRefFuture<'max, Q> {
    pub fn new<T>(t: Q::Owned, context: T) -> Self
    where
        T: RefFutureBinder<'max, Q>,
    {
        let value = Box::new(t);
        let reference = unsafe {
            // SAFETY: this is safe because
            //  - the actual lifetime of `value` is never leaked.
            //  - `value` is never moved or destroyed while `reference` is
            //    alive.
            let value_ref: &Q::Owned = value.as_ref();
            let static_value_ref: &'max Q::Owned = std::mem::transmute(value_ref);
            T::bind(context, static_value_ref)
        };

        Self {
            value: Some(value),
            reference,
        }
    }
}

impl<'max, Q: UnboundedRefFuture<'max>> Future for SelfRefFuture<'max, Q> {
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

/// Future that can fail before even starting.
#[pin_project]
pub struct FailibleFuture<F, E> {
    #[pin]
    inner: FailibleFutureInner<F, E>,
}

impl<F, E> FailibleFuture<F, E> {
    pub fn ok(f: F) -> Self {
        Self {
            inner: FailibleFutureInner::Ok(f),
        }
    }

    pub fn err(e: E) -> Self {
        Self {
            inner: FailibleFutureInner::Err(Some(e)),
        }
    }
}

impl<F, E> From<Result<F, E>> for FailibleFuture<F, E> {
    fn from(value: Result<F, E>) -> Self {
        match value {
            Ok(f) => Self::ok(f),
            Err(e) => Self::err(e),
        }
    }
}

impl<T, F: Future<Output = Result<T, E>>, E> Future for FailibleFuture<F, E> {
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}

#[pin_project(project = FailibleFutureProj)]
enum FailibleFutureInner<F, E> {
    Ok(#[pin] F),
    Err(Option<E>),
}

impl<T, F: Future<Output = Result<T, E>>, E> Future for FailibleFutureInner<F, E> {
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        match self.project() {
            FailibleFutureProj::Ok(f) => f.poll(cx),
            FailibleFutureProj::Err(e) => task::Poll::Ready(Err(e.take().unwrap())),
        }
    }
}
