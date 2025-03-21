use std::{
    any::{Any, TypeId},
    borrow::Cow,
    collections::HashMap,
};

/// Arbitrary signing or verification options.
///
/// Some cryptographic schemes require optional parameters that can be provided
/// using this type.
#[derive(Debug, Default)]
pub struct Options(HashMap<TypeId, Box<dyn Send + Sync + Any>>);

impl Options {
    pub fn get<T: 'static + Send + Sync>(&self) -> Option<&T> {
        self.0.get(&TypeId::of::<T>()).map(downcast_ref)
    }

    pub fn get_or_default<T: 'static + Default + Clone + Send + Sync>(&self) -> Cow<T> {
        self.0
            .get(&TypeId::of::<T>())
            .map(downcast_ref)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(T::default()))
    }

    pub fn get_mut<T: 'static + Send + Sync>(&mut self) -> Option<&mut T> {
        self.0.get_mut(&TypeId::of::<T>()).map(downcast_mut)
    }

    pub fn insert<T: 'static + Send + Sync>(&mut self, value: T) -> Option<T> {
        self.0
            .insert(TypeId::of::<T>(), Box::new(value))
            .map(downcast)
    }

    pub fn remove<T: 'static + Send + Sync>(&mut self) -> Option<T> {
        self.0.remove(&TypeId::of::<T>()).map(downcast)
    }
}

fn downcast<T: 'static>(t: Box<dyn Send + Sync + Any>) -> T {
    *<Box<dyn Send + Sync + Any>>::downcast(t).unwrap()
}

#[allow(clippy::borrowed_box)]
fn downcast_ref<T: 'static>(t: &Box<dyn Send + Sync + Any>) -> &T {
    t.downcast_ref().unwrap()
}

#[allow(clippy::borrowed_box)]
fn downcast_mut<T: 'static>(t: &mut Box<dyn Send + Sync + Any>) -> &mut T {
    t.downcast_mut().unwrap()
}
