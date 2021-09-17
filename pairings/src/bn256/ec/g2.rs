use super::g1::G1Affine;
use crate::bn256::{Bn256, Fq, Fq12, Fq2, FqRepr, Fr, FrRepr};
use crate::{CurveAffine, CurveProjective, EncodedPoint, Engine, GroupDecodingError, SubgroupCheck};
use ff::{BitIterator, Field, PrimeField, PrimeFieldRepr, SqrtField};
use std::fmt;

curve_impl!(
    "G2",
    G2,
    G2Affine,
    G2Prepared,
    Fq2,
    Fr,
    G2Uncompressed,
    G2Compressed,
    G1Affine
);

#[derive(Copy, Clone)]
pub struct G2Uncompressed([u8; 128]);

impl AsRef<[u8]> for G2Uncompressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G2Uncompressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G2Uncompressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G2Uncompressed {
    type Affine = G2Affine;

    fn empty() -> Self {
        G2Uncompressed([0; 128])
    }
    fn size() -> usize {
        128
    }
    fn into_affine(&self) -> Result<G2Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        if !affine.is_on_curve() {
            Err(GroupDecodingError::NotOnCurve)
        } else if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G2Affine, GroupDecodingError> {
        // Create a copy of this representation.
        let mut copy = self.0;

        if copy[0] & (1 << 7) != 0 {
            // Distinguisher bit is set, but this should be uncompressed!
            return Err(GroupDecodingError::UnexpectedCompressionMode);
        }

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G2Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            // Unset the two most significant bits.
            copy[0] &= 0x3f;

            let mut x_c0 = FqRepr([0; 4]);
            let mut x_c1 = FqRepr([0; 4]);
            let mut y_c0 = FqRepr([0; 4]);
            let mut y_c1 = FqRepr([0; 4]);

            {
                let mut reader = &copy[..];

                x_c1.read_be(&mut reader).unwrap();
                x_c0.read_be(&mut reader).unwrap();
                y_c1.read_be(&mut reader).unwrap();
                y_c0.read_be(&mut reader).unwrap();
            }

            Ok(G2Affine {
                x: Fq2 {
                    c0: Fq::from_repr(x_c0).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate (c0)", e)
                    })?,
                    c1: Fq::from_repr(x_c1).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("x coordinate (c1)", e)
                    })?,
                },
                y: Fq2 {
                    c0: Fq::from_repr(y_c0).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("y coordinate (c0)", e)
                    })?,
                    c1: Fq::from_repr(y_c1).map_err(|e| {
                        GroupDecodingError::CoordinateDecodingError("y coordinate (c1)", e)
                    })?,
                },
                infinity: false,
            })
        }
    }
    fn from_affine(affine: G2Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            let mut writer = &mut res.0[..];

            affine.x.c1.into_repr().write_be(&mut writer).unwrap();
            affine.x.c0.into_repr().write_be(&mut writer).unwrap();
            affine.y.c1.into_repr().write_be(&mut writer).unwrap();
            affine.y.c0.into_repr().write_be(&mut writer).unwrap();
        }

        res
    }
}

#[derive(Copy, Clone)]
pub struct G2Compressed([u8; 64]);

impl AsRef<[u8]> for G2Compressed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for G2Compressed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Debug for G2Compressed {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl EncodedPoint for G2Compressed {
    type Affine = G2Affine;

    fn empty() -> Self {
        G2Compressed([0; 64])
    }
    fn size() -> usize {
        64
    }
    fn into_affine(&self) -> Result<G2Affine, GroupDecodingError> {
        let affine = self.into_affine_unchecked()?;

        // NB: Decompression guarantees that it is on the curve already.

        if !affine.in_subgroup() {
            Err(GroupDecodingError::NotInSubgroup)
        } else {
            Ok(affine)
        }
    }
    fn into_affine_unchecked(&self) -> Result<G2Affine, GroupDecodingError> {
        // Create a copy of this representation.
        let mut copy = self.0;

        if copy[0] & (1 << 6) != 0 {
            // This is the point at infinity, which means that if we mask away
            // the first two bits, the entire representation should consist
            // of zeroes.
            copy[0] &= 0x3f;

            if copy.iter().all(|b| *b == 0) {
                Ok(G2Affine::zero())
            } else {
                Err(GroupDecodingError::UnexpectedInformation)
            }
        } else {
            // Determine if the intended y coordinate must be greater
            // lexicographically.
            let greatest = copy[0] & (1 << 7) != 0;

            // Unset the two most significant bits.
            copy[0] &= 0x3f;

            let mut x_c1 = FqRepr([0; 4]);
            let mut x_c0 = FqRepr([0; 4]);

            {
                let mut reader = &copy[..];

                x_c1.read_be(&mut reader).unwrap();
                x_c0.read_be(&mut reader).unwrap();
            }

            // Interpret as Fq element.
            let x = Fq2 {
                c0: Fq::from_repr(x_c0).map_err(|e| {
                    GroupDecodingError::CoordinateDecodingError("x coordinate (c0)", e)
                })?,
                c1: Fq::from_repr(x_c1).map_err(|e| {
                    GroupDecodingError::CoordinateDecodingError("x coordinate (c1)", e)
                })?,
            };

            G2Affine::get_point_from_x(x, greatest).ok_or(GroupDecodingError::NotOnCurve)
        }
    }
    fn from_affine(affine: G2Affine) -> Self {
        let mut res = Self::empty();

        if affine.is_zero() {
            // Set the second-most significant bit to indicate this point
            // is at infinity.
            res.0[0] |= 1 << 6;
        } else {
            {
                let mut writer = &mut res.0[..];

                affine.x.c1.into_repr().write_be(&mut writer).unwrap();
                affine.x.c0.into_repr().write_be(&mut writer).unwrap();
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

impl G2Affine {
    pub(crate) fn scale_by_cofactor(&self) -> G2 {
        // G2 cofactor = 2p - n = 2q - r
        // 0x30644e72e131a029b85045b68181585e06ceecda572a2489345f2299c0f9fa8d
        let cofactor = BitIterator::new([
            0x345f2299c0f9fa8d,
            0x06ceecda572a2489,
            0xb85045b68181585e,
            0x30644e72e131a029,
        ]);
        self.mul_bits(cofactor)
    }

    fn get_generator() -> Self {
        G2Affine {
            x: Fq2 {
                c0: super::super::fq::G2_GENERATOR_X_C0,
                c1: super::super::fq::G2_GENERATOR_X_C1,
            },
            y: Fq2 {
                c0: super::super::fq::G2_GENERATOR_Y_C0,
                c1: super::super::fq::G2_GENERATOR_Y_C1,
            },
            infinity: false,
        }
    }

    fn get_coeff_b() -> Fq2 {
        super::super::fq::B_COEFF_FQ2
    }

    fn perform_pairing(&self, other: &G1Affine) -> Fq12 {
        super::super::Bn256::pairing(*other, *self)
    }
}

impl G2 {
    fn empirical_recommended_wnaf_for_scalar(scalar: FrRepr) -> usize {
        let num_bits = scalar.num_bits() as usize;

        if num_bits >= 103 {
            4
        } else if num_bits >= 37 {
            3
        } else {
            2
        }
    }

    fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 11] = [1, 3, 8, 20, 47, 126, 260, 826, 1501, 4555, 84071];

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
pub struct G2Prepared {
    pub(crate) coeffs: Vec<(Fq2, Fq2, Fq2)>,
    pub(crate) infinity: bool,
}

mod subgroup_check {
    use super::G2Affine;
    #[cfg(test)]
    use crate::CurveAffine;
    use crate::SubgroupCheck;
    #[cfg(test)]
    use rand_core::SeedableRng;

    impl SubgroupCheck for G2Affine {
        fn in_subgroup(&self) -> bool {
            self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[test]
    fn test_g2_subgroup_check() {
        use crate::{
            ClearH,
            bn256::G2,
            CurveProjective,
        };
        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        for _ in 0..32 {
            let p = G2::random(&mut rng).into_affine();
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

// This generator does not take a random element in Fp2
// and tries to increment it to be on a curve, but
// generates a random scalar and multiplies predefined generator by it

#[test]
fn g2_generator() {
    use SqrtField;

    let mut x = Fq2::zero();
    loop {
        // y^2 = x^3 + b
        let mut rhs = x;
        rhs.square();
        rhs.mul_assign(&x);
        rhs.add_assign(&G2Affine::get_coeff_b());

        if let Some(y) = rhs.sqrt() {
            let mut negy = y;
            negy.negate();

            let p = G2Affine {
                x,
                y: if y < negy { y } else { negy },
                infinity: false,
            };

            let g2 = p.into_projective();
            if !g2.is_zero() {
                let _g2 = G2Affine::from(g2);
                break;
            }
        }

        x.add_assign(&Fq2::one());
    }
}

#[test]
fn test_generate_g2_in_subgroup() {
    use SqrtField;

    let mut x = Fq2::zero();
    loop {
        // y^2 = x^3 + b
        let mut rhs = x;
        rhs.square();
        rhs.mul_assign(&x);
        rhs.add_assign(&G2Affine::get_coeff_b());

        if let Some(y) = rhs.sqrt() {
            let mut negy = y;
            negy.negate();

            let p = G2Affine {
                x: x,
                y: if y < negy { y } else { negy },
                infinity: false,
            };

            let g2 = p.into_projective();
            let mut minus_one = Fr::one();
            minus_one.negate();

            let mut expected_zero = p.mul(minus_one);
            expected_zero.add_assign(&g2);

            if !expected_zero.is_zero() {
                let p = expected_zero.into_affine();
                let scaled_by_cofactor = p.scale_by_cofactor();
                if scaled_by_cofactor.is_zero() {
                    let g2 = G2Affine::from(expected_zero);
                    println!("Invalid subgroup point = {}", g2);
                    return;
                }
            }
        }

        x.add_assign(&Fq2::one());
    }
}

#[cfg(test)]
use rand_core::SeedableRng;
#[cfg(test)]
use rand_xorshift::XorShiftRng;

#[test]
fn g2_generator_on_curve() {
    use SqrtField;

    let gen = G2Affine::get_generator();
    let x = gen.x;
    // y^2 = x^3 + 3/xi
    let mut rhs = x;
    rhs.square();
    rhs.mul_assign(&x);
    rhs.add_assign(&G2Affine::get_coeff_b());

    if let Some(y) = rhs.sqrt() {
        let mut negy = y;
        negy.negate();

        let p = G2Affine {
            x: x,
            y: if y < negy { y } else { negy },
            infinity: false,
        };

        assert_eq!(p.y, gen.y);
        assert_eq!(p, G2Affine::one());
        return;
    }
    panic!();
}

#[test]
fn g2_curve_tests() {
    crate::tests::curve::curve_tests::<G2>();
    // crate::tests::curve::random_transformation_tests::<G2>();
}

#[test]

fn test_b_coeff() {
    let b2 = G2Affine::get_coeff_b();
    print!("{}\n\n", b2);
}

#[test]
fn test_base_point_addition_and_doubling() {
    let mut two = G2::one();
    two.add_assign(&G2::one());

    let one = G2::one();

    let mut three21 = two;
    three21.add_assign(&one);

    let mut three12 = one;
    three12.add_assign(&two);

    assert_eq!(three12, three21);
}

#[test]
fn test_addition_and_doubling() {
    let mut rng = XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);

    for _ in 0..1000 {
        let a = G2::random(&mut rng);
        assert!(a.into_affine().is_on_curve());
        let b = G2::random(&mut rng);
        let c = G2::random(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();
        let c_affine = c.into_affine();

        // a + a should equal the doubling
        {
            let mut aplusa = a;
            aplusa.add_assign(&a);

            let mut aplusamixed = a;
            aplusamixed.add_assign_mixed(&a.into_affine());

            let mut adouble = a;
            adouble.double();

            assert_eq!(aplusa, adouble);
            assert_eq!(aplusamixed, adouble);
        }

        let mut ab = a;
        ab.add_assign(&b);

        let mut ba = b;
        ba.add_assign(&a);

        assert_eq!(ab, ba, "Addition should not depend on order");

        let mut tmp = vec![G2::zero(); 6];

        // (a + b) + c
        tmp[0] = a;
        tmp[0].add_assign(&b);
        tmp[0].add_assign(&c);

        // a + (b + c)
        tmp[1] = b;
        tmp[1].add_assign(&c);
        tmp[1].add_assign(&a);

        // (a + c) + b
        tmp[2] = a;
        tmp[2].add_assign(&c);
        tmp[2].add_assign(&b);

        // Mixed addition

        // (a + b) + c
        tmp[3] = a_affine.into_projective();
        tmp[3].add_assign_mixed(&b_affine);
        tmp[3].add_assign_mixed(&c_affine);

        // a + (b + c)
        tmp[4] = b_affine.into_projective();
        tmp[4].add_assign_mixed(&c_affine);
        tmp[4].add_assign_mixed(&a_affine);

        // (a + c) + b
        tmp[5] = a_affine.into_projective();
        tmp[5].add_assign_mixed(&c_affine);
        tmp[5].add_assign_mixed(&b_affine);

        // Comparisons
        for i in 0..6 {
            for j in 0..6 {
                assert_eq!(tmp[i], tmp[j]);
                assert_eq!(tmp[i].into_affine(), tmp[j].into_affine());
            }

            assert!(tmp[i] != a);
            assert!(tmp[i] != b);
            assert!(tmp[i] != c);

            assert!(a != tmp[i]);
            assert!(b != tmp[i]);
            assert!(c != tmp[i]);
        }
    }
}

#[test]
fn random_negation_tests() {
    let mut rng = XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);

    for _ in 0..1000 {
        // let r = G2::rand(&mut rng);
        // assert!(r.into_affine().is_on_curve());

        let mut r = G2::one();
        let k = Fr::random(&mut rng);
        r.mul_assign(k);

        let s = Fr::random(&mut rng);
        let mut sneg = s;
        sneg.negate();

        let mut t1 = r;
        t1.mul_assign(s);

        let mut t2 = r;
        t2.mul_assign(sneg);

        let mut t3 = t1;
        t3.add_assign(&t2);
        assert!(t3.is_zero());

        let mut t4 = t1;
        t4.add_assign_mixed(&t2.into_affine());
        assert!(t4.is_zero());

        t1.negate();
        assert_eq!(t1, t2);
    }
}

#[test]
fn mul_by_order_tests() {
    let mut rng = XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);

    for _ in 0..1000 {
        // let r = G2::rand(&mut rng);

        let mut r = G2::one();
        let k = Fr::random(&mut rng);
        r.mul_assign(k);

        let order = Fr::char();

        let mut q = G2::one();
        q.mul_assign(order);
        assert!(q.is_zero());

        r.mul_assign(order);
        assert!(r.is_zero());

        //let mut t = G2::random(&mut rng);
        //t.mul_assign(order);
        //assert!(t.is_zero());
    }
}
