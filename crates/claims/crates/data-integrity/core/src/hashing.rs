use digest::{
    consts::{U32, U48},
    generic_array::{ArrayLength, GenericArray},
};

pub trait ConcatOutputSize: ArrayLength<u8> {
    type ConcatOutput;

    fn concat(a: GenericArray<u8, Self>, b: GenericArray<u8, Self>) -> Self::ConcatOutput;
}

impl ConcatOutputSize for U32 {
    type ConcatOutput = [u8; 64];

    fn concat(a: GenericArray<u8, U32>, b: GenericArray<u8, U32>) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&a);
        result[32..].copy_from_slice(&b);
        result
    }
}

impl ConcatOutputSize for U48 {
    type ConcatOutput = [u8; 96];

    fn concat(a: GenericArray<u8, U48>, b: GenericArray<u8, U48>) -> [u8; 96] {
        let mut result = [0u8; 96];
        result[..48].copy_from_slice(&a);
        result[48..].copy_from_slice(&b);
        result
    }
}
