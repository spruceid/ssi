use std::marker::PhantomData;
use serde::Serialize;

use super::InvalidValue;

pub struct NonSerializable<T>(PhantomData<T>);

impl<V> serde::ser::SerializeMap for NonSerializable<V> {
    type Ok = V;
    type Error = InvalidValue;

    fn serialize_key<T: ?Sized>(&mut self, _key: &T) -> Result<(), Self::Error>
        where
            T: Serialize {
        unreachable!()
    }

    fn serialize_value<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize {
        unreachable!()
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }
}

impl<V> serde::ser::SerializeSeq for NonSerializable<V> {
    type Ok = V;
    type Error = InvalidValue;

    fn serialize_element<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize {
        unreachable!()
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }
}

impl<V> serde::ser::SerializeStruct for NonSerializable<V> {
    type Ok = V;
    type Error = InvalidValue;

    fn serialize_field<T: ?Sized>(
            &mut self,
            _key: &'static str,
            _value: &T,
        ) -> Result<(), Self::Error>
        where
            T: Serialize {
        unreachable!()
    }

    fn skip_field(&mut self, _key: &'static str) -> Result<(), Self::Error> {
        unreachable!()
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }
}

impl<V> serde::ser::SerializeStructVariant for NonSerializable<V> {
    type Ok = V;
    type Error = InvalidValue;

    fn serialize_field<T: ?Sized>(
            &mut self,
            _key: &'static str,
            _value: &T,
        ) -> Result<(), Self::Error>
        where
            T: Serialize {
        unreachable!()
    }

    fn skip_field(&mut self, _key: &'static str) -> Result<(), Self::Error> {
        unreachable!()
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        unreachable!()
    }
}

impl<V> serde::ser::SerializeTuple for NonSerializable<V> {
	type Ok = V;
	type Error = InvalidValue;

	fn serialize_element<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
		where
			T: Serialize {
		unreachable!()
	}

	fn end(self) -> Result<Self::Ok, Self::Error> {
		unreachable!()
	}
}

impl<V> serde::ser::SerializeTupleStruct for NonSerializable<V> {
	type Ok = V;
	type Error = InvalidValue;

	fn serialize_field<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
		where
			T: Serialize {
		unreachable!()
	}

	fn end(self) -> Result<Self::Ok, Self::Error> {
		unreachable!()
	}
}

impl<V> serde::ser::SerializeTupleVariant for NonSerializable<V> {
	type Ok = V;
	type Error = InvalidValue;

	fn serialize_field<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
		where
			T: Serialize {
		unreachable!()
	}

	fn end(self) -> Result<Self::Ok, Self::Error> {
		unreachable!()
	}
}