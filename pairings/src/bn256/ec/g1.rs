use super::g2::G2Affine;
use super::super::{Bn256, Fq, Fq12, FqRepr, Fr, FrRepr};
use crate::{CurveAffine, CurveProjective, EncodedPoint, Engine, GroupDecodingError, SubgroupCheck};
use ff::{BitIterator, Field, PrimeField, PrimeFieldRepr, SqrtField};
use std::fmt;

curve_impl!(
    "G1",
    G1,
    G1Affine,
    G1Prepared,
    Fq,
    Fr,
    G1Uncompressed,
    G1Compressed,
    G2Affine
);

#[derive(Copy, Clone)]
pub struct G1Uncompressed([u8; 64]);

impl AsRef<[u8]> for G1Uncompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G1Uncompressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G1Uncompressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G1Uncompressed {
    type Affine = G1Affine;

    fn empty() -> Self {
        G1Uncompressed([0; 64])
    }
    fn size() -> usize {
        64
    }
    fn into_affine(&self) -> Result<G1Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        if !affine.is_on_curve() {
            Err(GroupDecodingError::NotOnCurve)
        } else if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G1Affine, GroupDecodingError> {
        // Create a copy of this representation.
        let mut copy = self.0;

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G1Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            if copy[0] & (1 << 7) != 0 {
                // The bit indicating the y-coordinate should be lexicographically
                // largest is set, but this is an uncompressed element.
                return Err(GroupDecodingError::UnexpectedInformation);
            }

            // Unset the two most significant bits.
            copy[0] &= 0x3f;

            let mut x = FqRepr([0; 4]);
            let mut y = FqRepr([0; 4]);

            {
                let mut reader = &copy[..];

                x.read_be(&mut reader).unwrap();
                y.read_be(&mut reader).unwrap();
            }

            Ok(G1Affine {
                x: Fq::from_repr(x)
                    .map_err(|e| GroupDecodingError::CoordinateDecodingError("x coordinate", e))?,
                y: Fq::from_repr(y)
                    .map_err(|e| GroupDecodingError::CoordinateDecodingError("y coordinate", e))?,
                infinity: false,
            })
        }
    }
    fn from_affine(affine: G1Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            let mut writer = &mut res.0[..];

            affine.x.into_repr().write_be(&mut writer).unwrap();
            affine.y.into_repr().write_be(&mut writer).unwrap();
        }

        res
    }
}

#[derive(Copy, Clone)]
pub struct G1Compressed([u8; 32]);

impl AsRef<[u8]> for G1Compressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G1Compressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G1Compressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G1Compressed {
    type Affine = G1Affine;

    fn empty() -> Self {
        G1Compressed([0; 32])
    }
    fn size() -> usize {
        32
    }
    fn into_affine(&self) -> Result<G1Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        // NB: Decompression guarantees that it is on the curve already.

        if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G1Affine, GroupDecodingError> {
        // Create a copy of this representation.
        let mut copy = self.0;

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G1Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            // Determine if the intended y coordinate must be greater
            // lexicographically.
            let greatest = copy[0] & (1 << 7) != 0;

            // Unset the two most significant bits.
            copy[0] &= 0x3f;

            let mut x = FqRepr([0; 4]);

            {
                let mut reader = &copy[..];

                x.read_be(&mut reader).unwrap();
            }

            // Interpret as Fq element.
            let x = Fq::from_repr(x)
                .map_err(|e| GroupDecodingError::CoordinateDecodingError("x coordinate", e))?;

            G1Affine::get_point_from_x(x, greatest).ok_or(GroupDecodingError::NotOnCurve)
        }
    }
    fn from_affine(affine: G1Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            {
                let mut writer = &mut res.0[..];

                affine.x.into_repr().write_be(&mut writer).unwrap();
            }

            let mut negy = affine.y;
            negy.negate();

            // Set the third most significant bit if the correct y-coordinate
            // is lexicographically largest.
            if affine.y > negy {
                res.0[0] |= 1 << 7;
            }
        }

        res
    }
}

impl G1Affine {
    pub(crate) fn scale_by_cofactor(&self) -> G1 {
         self.into_projective()
    }

    fn get_generator() -> Self {
        G1Affine {
            x: super::super::fq::G1_GENERATOR_X,
            y: super::super::fq::G1_GENERATOR_Y,
            infinity: false,
        }
    }

    fn get_coeff_b() -> Fq {
        super::super::fq::B_COEFF
    }

    fn perform_pairing(&self, other: &G2Affine) -> Fq12 {
        super::super::Bn256::pairing(*self, *other)
    }
}

impl G1 {
    fn empirical_recommended_wnaf_for_scalar(scalar: FrRepr) -> usize {
        let num_bits = scalar.num_bits() as usize;

        if num_bits >= 130 {
            4
        } else if num_bits >= 34 {
            3
        } else {
            2
        }
    }

    fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 12] =
            [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];

        let mut ret = 4;
        for r in &RECOMMENDATIONS {
            if num_scalars > *r {
                ret += 1;
            } else {
                break;
            }
        }

        ret
    }
}

#[derive(Clone, Debug)]
pub struct G1Prepared(pub(crate) G1Affine);

impl G1Prepared {
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn from_affine(p: G1Affine) -> Self {
        G1Prepared(p)
    }
}

mod subgroup_check {

    use super::G1Affine;
    #[cfg(test)]
    use super::G1;
    use crate::SubgroupCheck;
    #[cfg(test)]
    use crate::{CurveAffine, CurveProjective};
    #[cfg(test)]
    use rand_core::SeedableRng;

    impl SubgroupCheck for G1Affine {
        fn in_subgroup(&self) -> bool {
            self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[test]
    fn test_g1_subgroup_check() {
        use crate::ClearH;
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..32 {
            let p = G1::random(&mut rng).into_affine();
            assert_eq!(
                p.in_subgroup(),
                p.is_in_correct_subgroup_assuming_on_curve()
            );

            let mut pp = p.into_projective();
            pp.clear_h();
            let p = pp.into_affine();
            assert!(p.in_subgroup() && p.is_in_correct_subgroup_assuming_on_curve());
        }
    }
}

#[test]
fn g1_generator() {
    use SqrtField;

    let mut x = Fq::zero();
    let mut i = 0;
    loop {
        // y^2 = x^3 + b
        let mut rhs = x;
        rhs.square();
        rhs.mul_assign(&x);
        rhs.add_assign(&G1Affine::get_coeff_b());

        if let Some(y) = rhs.sqrt() {
            let yrepr = y.into_repr();
            let mut negy = y;
            negy.negate();
            let negyrepr = negy.into_repr();

            let p = G1Affine {
                x,
                y: if yrepr < negyrepr { y } else { negy },
                infinity: false,
            };
            //assert!(!p.in_subgroup());

            let g1 = p.into_projective();
            if !g1.is_zero() {
                assert_eq!(i, 1);
                let g1 = G1Affine::from(g1);

                assert_eq!(g1, G1Affine::one());
                break;
            }
        }

        i += 1;
        x.add_assign(&Fq::one());
    }
}

#[test]

fn test_base_point_addition_and_doubling() {
    let mut a = G1::one();
    print!("{}\n\n", a);

    a.add_assign(&G1::one());

    print!("{}\n\n", a);
}

#[test]
fn g1_curve_tests() {
    crate::tests::curve::curve_tests::<G1>();
    // crate::tests::curve::random_transformation_tests::<G1>();
}
