use crate::hash_to_field::BaseFromRO;
use digest::generic_array::{typenum::U48, GenericArray};
use ff::{Field, PrimeField, PrimeFieldDecodingError, PrimeFieldRepr};
use std::io::{Cursor, Read};

#[derive(PrimeField, Zeroize)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "7"]
pub struct Fr(FrRepr);

/// set the default value for Fr to 0
impl ::std::default::Default for Fr {
    fn default() -> Self {
        Fr::zero()
    }
}

/// # Safety
pub const unsafe fn transmute(r: FrRepr) -> Fr {
    Fr(r)
}

impl BaseFromRO for Fr {
    type BaseLength = U48;

    fn from_okm(okm: &GenericArray<u8, U48>) -> Fr {
        const F_2_192: Fr = Fr(FrRepr([
            0x16A0A73150000000u64,
            0xB8114D6D7DE87ADBu64,
            0xE81AC1E7808072C9u64,
            0x10216F7BA065E00Du64,
        ]));

        // unwraps are safe here: we only use 24 bytes at a time, which is strictly less than p
        let mut repr = FrRepr::default();
        repr.read_be(Cursor::new([0; 8]).chain(Cursor::new(&okm[..24])))
            .unwrap();
        let mut elm = Fr::from_repr(repr).unwrap();
        elm.mul_assign(&F_2_192);

        repr.read_be(Cursor::new([0; 8]).chain(Cursor::new(&okm[24..])))
            .unwrap();
        elm.add_assign(&Fr::from_repr(repr).unwrap());
        elm
    }
}

#[cfg(test)]
use crate::serdes::SerDes;

// #[test]
// fn test_to_hex() {
//     use ff::to_hex;
//     assert_eq!(
//         to_hex(&Fr::one()),
//         "0000000000000000000000000000000000000000000000000000000000000001"
//     );
// }
//
// #[test]
// fn test_fr_from_hex() {
//     use ff::from_hex;
//     let fr: Fr =
//         from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
//     assert_eq!(fr, Fr::one());
//
//     let fr: Fr =
//         from_hex("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
//     assert_eq!(fr, Fr::one());
//
//     let fr: Fr = from_hex("0x01").unwrap();
//     assert_eq!(fr, Fr::one());
//
//     let fr: Fr = from_hex("0x00").unwrap();
//     assert_eq!(fr, Fr::zero());
//
//     let fr: Fr = from_hex("00").unwrap();
//     assert_eq!(fr, Fr::zero());
// }
//
#[test]
fn test_roots_of_unity() {
    assert_eq!(Fr::S, 28);
}

#[test]
fn test_default() {
    assert_eq!(Fr::default(), Fr::zero());
}

#[test]
fn print_fr_repr() {
    const F_2_192: Fr = Fr(FrRepr([
        0x59476ebc41b4528fu64,
        0xc5a30cb243fcc152u64,
        0x2b34e63940ccbd72u64,
        0x1e179025ca247088u64,
    ]));
    let mut out = [0u8; 32];
    F_2_192.serialize(&mut out.as_mut(), true).unwrap();
    println!("{:?}", hex::encode(out));
}