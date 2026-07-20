#![allow(deprecated)] // TODO upgrade `digest` crate when possible.
use digest::{
    array::{Array, ArraySize},
    consts::{U32, U48},
};

pub trait ConcatOutputSize: ArraySize {
    type ConcatOutput;

    fn concat(a: Array<u8, Self>, b: Array<u8, Self>) -> Self::ConcatOutput;
}

impl ConcatOutputSize for U32 {
    type ConcatOutput = [u8; 64];

    fn concat(a: Array<u8, U32>, b: Array<u8, U32>) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&a);
        result[32..].copy_from_slice(&b);
        result
    }
}

impl ConcatOutputSize for U48 {
    type ConcatOutput = [u8; 96];

    fn concat(a: Array<u8, U48>, b: Array<u8, U48>) -> [u8; 96] {
        let mut result = [0u8; 96];
        result[..48].copy_from_slice(&a);
        result[48..].copy_from_slice(&b);
        result
    }
}
