use crate::{bn256::{G1, G2}, CurveProjective, ClearH};

impl ClearH for G1 {
    fn clear_h(&mut self) {
        // Cofactor for BN256 is 1 do thing
    }
}

/// Implements hashing to G2 cofactor clearing
/// as defined in the paper by Fuentes-Castaneda, Knapp and Rodriguez-Henriquez
/// <https://link.springer.com/chapter/10.1007/978-3-642-28496-0_25>
/// in Section 6.1
/// which states Q -> xQ + F(3xQ) + F(F(xQ)) + F(F(F(Q)))
///
/// where F is the Frobenius map
///
/// However according to section 3.3 in
/// <https://eprint.iacr.org/2015/247.pdf>
///
/// This is actually not necessary. So for now we just multiply by h2
impl ClearH for G2 {
    fn clear_h(&mut self) {
        // TODO: try to get this to work
        *self = self.into_affine().scale_by_cofactor()
    }
}

#[test]
fn clear_cofactor() {
    use crate::SubgroupCheck;
    let g = G2::one();
    // g.clear_h();
    let ga = g.into_affine();
    assert!(ga.scale_by_cofactor().into_affine().in_subgroup());
    assert_eq!(g, ga.scale_by_cofactor());
}