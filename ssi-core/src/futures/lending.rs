use std::future::Future;
use std::pin::Pin;
use std::task;

use pin_project::pin_project;

#[pin_project]
pub struct LendingMutFuture<T, R: Lending> {
    #[pin]
    t: T,
    ptr: R::Ptr,

    /// Flag to make sure the `t` future is not polled again after completion
    /// so that the lent references are not touched ever again.
    is_done: bool,
}

impl<T, R: Lending> LendingMutFuture<T, R> {
    pub fn new(mut r: R, t: impl FnOnce(R) -> T) -> Self {
        let ptr = r.as_mut_ptr();
        Self {
            t: t(r),
            ptr,
            is_done: false,
        }
    }
}

impl<T: Future, R: Lending> Future for LendingMutFuture<T, R> {
    type Output = (T::Output, R);

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();

        if *this.is_done {
            panic!("polled completed future")
        } else {
            this.t.poll(cx).map(|output| {
                *this.is_done = true;
                let r = unsafe { R::from_mut_ptr(*this.ptr) };
                (output, r)
            })
        }
    }
}

pub trait Lending {
    type Ptr: Copy;

    fn as_mut_ptr(&mut self) -> Self::Ptr;

    unsafe fn from_mut_ptr(ptr: Self::Ptr) -> Self;
}

impl<'a, T1> Lending for &'a mut T1 {
    type Ptr = *mut T1;

    fn as_mut_ptr(&mut self) -> Self::Ptr {
        *self as *mut T1
    }

    unsafe fn from_mut_ptr(ptr: Self::Ptr) -> Self {
        &mut *ptr
    }
}

impl<'a, T1, T2> Lending for (&'a mut T1, &'a mut T2) {
    type Ptr = (*mut T1, *mut T2);

    fn as_mut_ptr(&mut self) -> Self::Ptr {
        (self.0 as *mut T1, self.1 as *mut T2)
    }

    unsafe fn from_mut_ptr(ptr: Self::Ptr) -> Self {
        (&mut *ptr.0, &mut *ptr.1)
    }
}
