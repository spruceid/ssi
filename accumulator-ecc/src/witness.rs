use crate::{
    accumulator::{Accumulator, Coefficient, Element},
    dad,
    error::Error,
    key::{PublicKey, SecretKey},
    BigArray, PolynomialG1,
};
use ff_zeroize::{Field, PrimeField};
use pairings::{
    bls12_381::{Bls12, Fq12, Fr, FrRepr, G1, G2},
    serdes::SerDes,
    CurveAffine, CurveProjective, Engine,
};
use serde::{
    de::{Error as DError, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{convert::TryFrom, fmt, io::Cursor};

struct_impl!(
/// A membership witness that can be used for membership proof generation
/// as described in section 4 in
/// <https://eprint.iacr.org/2020/777>
#[derive(Copy, Clone, Debug)]
MembershipWitness, MembershipWitnessInner,
    c: G1 => 48,
    y: Fr => 32,
);
display_impl!(MembershipWitness);

impl MembershipWitness {
    const BYTES: usize = 80;

    /// Compute the witness using a prehashed element
    pub fn new(value: &Element, accumulator: Accumulator, secret_key: &SecretKey) -> Self {
        let witness = accumulator.remove(secret_key, value);
        Self {
            c: witness.0,
            y: value.0,
        }
    }

    /// Verify this is a valid witness as per section 4 in
    /// <https://eprint.iacr.org/2020/777>
    pub fn verify(&self, pubkey: PublicKey, accumulator: Accumulator) -> bool {
        let mut p = G2::one();
        p.mul_assign(self.y);
        p.add_assign(&pubkey.0);

        let mut g2 = G2::one();
        g2.negate();

        let p = p.into_affine().prepare();
        let w = self.c.into_affine().prepare();

        let v = accumulator.0.into_affine().prepare();
        let g = g2.into_affine().prepare();

        let mut values = Vec::new();
        values.push((&w, &p));
        values.push((&v, &g));

        // e(C, yP~ + Q~) == e(V, P)
        match Bls12::final_exponentiation(&Bls12::miller_loop(values.as_slice())) {
            None => false,
            Some(product) => product == Fq12::one(),
        }
    }

    pub fn apply_delta(&self, delta: Delta) -> Self {
        let mut t = self.clone();
        t.apply_delta_assign(delta);
        t
    }

    pub fn apply_delta_assign(&mut self, delta: Delta) {
        // C * dA(x) / dD(x)
        self.c.mul_assign(delta.d);
        // C + 1 / dD *〈Υy,Ω〉
        self.c.add_assign(&delta.p);
    }

    /// Membership witness update as defined in section 4, return a new witness
    pub fn update(
        &self,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) -> Self {
        let mut clone = *self;
        clone.update_assign(old_accumulator, new_accumulator, additions, deletions);
        clone
    }

    /// Perform in place the membership witness update as defined in section 4
    pub fn update_assign(
        &mut self,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) {
        // C' = 1/(y' - y) (C - V')
        for d in deletions {
            let mut diff = d.0;
            diff.sub_assign(&self.y);
            // If this fails, then this value was removed
            match diff.inverse() {
                None => return,
                Some(dd) => diff = dd,
            }
            self.c.sub_assign(&new_accumulator.0);
            self.c.mul_assign(diff);
        }
        // C' = (y' - y)C + V
        for a in additions {
            let mut diff = a.0;
            diff.sub_assign(&self.y);
            self.c.mul_assign(diff);
            self.c.add_assign(&old_accumulator.0);
        }
    }

    pub fn batch_update(
        &self,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) -> Self {
        let mut cn = *self;
        cn.batch_update_assign(additions, deletions, coefficients);
        cn
    }

    pub fn batch_update_assign(
        &mut self,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) {
        if let Ok(delta) = evaluate_delta(Element(self.y), additions, deletions, coefficients) {
            self.apply_delta_assign(delta);
        }
    }

    pub fn multi_batch_update<A, D, C>(&mut self, deltas: &[(A, D, C)]) -> Self
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        let mut cn = *self;
        cn.multi_batch_update_assign(deltas);
        cn
    }

    pub fn multi_batch_update_assign<A, D, C>(&mut self, deltas: &[(A, D, C)])
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        if let Ok(delta) = evaluate_deltas(Element(self.y), deltas) {
            self.apply_delta_assign(delta);
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        let mut c = std::io::Cursor::new(res.as_mut());
        self.c.serialize(&mut c, true).unwrap();
        self.y.serialize(&mut c, true).unwrap();
        res
    }

    pub fn element(&self) -> Element {
        Element(self.y)
    }
}

struct_impl!(
/// A non-membership witness that can be used for non-membership proof generation
/// as described in section 4 in
/// <https://eprint.iacr.org/2020/777>
#[derive(Copy, Clone, Debug)]
NonMembershipWitness, NonMembershipWitnessInner,
    c: G1 => 48,
    d: Fr => 32,
    y: Fr => 32,
);
display_impl!(NonMembershipWitness);

impl NonMembershipWitness {
    const BYTES: usize = 112;

    /// Compute the witness using a prehashed element
    pub fn new(value: &Element, elements: &[Element], secret_key: &SecretKey) -> Self {
        // f_V(x) = \prod_{y U Y_v U Y_v0}{y_i + x)
        // d = f_V(-y)
        let (mut fv_alpha, d) = elements
            .iter()
            .map(|e| {
                let mut s = e.0;
                s.add_assign(&secret_key.0);
                let mut t = e.0;
                t.sub_assign(&value.0);
                (s, t)
            })
            .fold((Fr::one(), Fr::one()), |mut a, y| {
                a.0.mul_assign(&y.0);
                a.1.mul_assign(&y.1);
                a
            });
        let mut denom = value.0;
        denom.add_assign(&secret_key.0);
        fv_alpha.sub_assign(&d);
        fv_alpha.mul_assign(&denom.inverse().unwrap());
        let mut c = G1::one();
        c.mul_assign(fv_alpha);

        Self { c, d, y: value.0 }
    }

    /// Verify this is a valid witness as per section 4 in
    /// <https://eprint.iacr.org/2020/777>
    pub fn verify(&self, pubkey: PublicKey, accumulator: Accumulator) -> bool {
        let mut p = G2::one();
        p.mul_assign(self.y);
        p.add_assign(&pubkey.0);

        let mut pd = G1::one();
        pd.mul_assign(self.d);

        let mut g2 = G2::one();
        g2.negate();

        let p = p.into_affine().prepare();
        let w = self.c.into_affine().prepare();

        let pda = pd.into_affine().prepare();
        let g2a = G2::one().into_affine().prepare();

        let v = accumulator.0.into_affine().prepare();
        let g = g2.into_affine().prepare();

        let mut values = Vec::new();
        values.push((&w, &p));
        values.push((&pda, &g2a));
        values.push((&v, &g));

        // e(C, yP~ + Q~)e(P, P~)^d == e(V, P)
        match Bls12::final_exponentiation(&Bls12::miller_loop(values.as_slice())) {
            None => false,
            Some(product) => product == Fq12::one(),
        }
    }

    pub fn apply_delta(&self, delta: Delta) -> Self {
        let mut t = self.clone();
        t.apply_delta_assign(delta);
        t
    }

    pub fn apply_delta_assign(&mut self, delta: Delta) {
        // C * dA(x) / dD(x)
        self.c.mul_assign(delta.d);
        // d * dA(x) / dD(x)
        self.d.mul_assign(&delta.d);
        // C + 1 / dD *〈Υy,Ω〉
        self.c.add_assign(&delta.p);
    }

    /// Non-membership witness update as defined in section 4, return a new witness
    pub fn update(
        &self,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) -> Self {
        let mut clone = *self;
        clone.update_assign(old_accumulator, new_accumulator, additions, deletions);
        clone
    }

    /// Perform in place the non-membership witness update as defined in section 4
    pub fn update_assign(
        &mut self,
        old_accumulator: Accumulator,
        new_accumulator: Accumulator,
        additions: &[Element],
        deletions: &[Element],
    ) {
        // C' = 1/(y' - y) (C - V')
        // d' = d * 1 / (y' - y)
        for d in deletions {
            let mut diff = d.0.clone();
            diff.sub_assign(&self.y);
            // If this fails, then this value was removed
            match diff.inverse() {
                None => return,
                Some(dd) => diff = dd,
            };
            self.c.sub_assign(&new_accumulator.0);
            self.c.mul_assign(diff);
            self.d.mul_assign(&diff);
        }
        // C' = (y' - y)C + V
        // d' = d (y' - y)
        for a in additions {
            let mut diff = a.0.clone();
            diff.sub_assign(&self.y);
            self.c.mul_assign(diff);
            self.c.add_assign(&old_accumulator.0);
            self.d.mul_assign(&diff);
        }
    }

    pub fn batch_update(
        &self,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) -> Self {
        let mut cn = *self;
        cn.batch_update_assign(additions, deletions, coefficients);
        cn
    }

    pub fn batch_update_assign(
        &mut self,
        additions: &[Element],
        deletions: &[Element],
        coefficients: &[Coefficient],
    ) {
        if let Ok(delta) = evaluate_delta(Element(self.y), additions, deletions, coefficients) {
            self.apply_delta_assign(delta);
        }
    }

    pub fn multi_batch_update<A, D, C>(&mut self, deltas: &[(A, D, C)]) -> Self
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        let mut cn = *self;
        cn.multi_batch_update_assign(deltas);
        cn
    }

    pub fn multi_batch_update_assign<A, D, C>(&mut self, deltas: &[(A, D, C)])
    where
        A: AsRef<[Element]>,
        D: AsRef<[Element]>,
        C: AsRef<[Coefficient]>,
    {
        if let Ok(delta) = evaluate_deltas(Element(self.y), deltas) {
            self.apply_delta_assign(delta);
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        let mut c = std::io::Cursor::new(res.as_mut());
        self.y.serialize(&mut c, true).unwrap();
        self.c.serialize(&mut c, true).unwrap();
        self.d.serialize(&mut c, true).unwrap();
        res
    }
}

/// A compressed delta after evaluating the polynomials w.r.t an element
#[derive(Copy, Clone, Debug)]
pub struct Delta {
    d: Fr,
    p: G1,
}

impl Serialize for Delta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut o = [0u8; 80];
        self.d.serialize(&mut o.as_mut(), true).unwrap();
        self.p.serialize(&mut o[32..].as_mut(), true).unwrap();
        let mut seq = serializer.serialize_tuple(o.len())?;
        for e in &o[..] {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Delta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor;

        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = Delta;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an array of length 80")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Delta, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut a = [0u8; 80];
                for i in 0..a.len() {
                    a[i] = seq
                        .next_element()?
                        .ok_or_else(|| DError::invalid_length(i, &self))?;
                }
                let mut c = Cursor::new(a);
                let d = Fr::deserialize(&mut c, true)
                    .map_err(|_| DError::invalid_value(Unexpected::Bytes(&a), &self))?;
                let p = G1::deserialize(&mut c, true)
                    .map_err(|_| DError::invalid_value(Unexpected::Bytes(&a), &self))?;
                Ok(Delta { d, p })
            }
        }

        deserializer.deserialize_tuple(80, ArrayVisitor)
    }
}

pub fn evaluate_deltas<A, D, C>(y: Element, deltas: &[(A, D, C)]) -> Result<Delta, Error>
where
    A: AsRef<[Element]>,
    D: AsRef<[Element]>,
    C: AsRef<[Coefficient]>,
{
    let one = Fr::from_repr(FrRepr::from(1u64)).unwrap();

    // dA(x) =  ∏ 1..n (yA_i - x)
    let mut aa = Vec::new();
    // dD(x) = ∏ 1..m (yD_i - x)
    let mut dd = Vec::new();

    let mut a = one;
    let mut d = one;

    // dA = ∏ a..b dA
    // dD = ∏ a..b dD
    for (adds, dels, _) in deltas {
        let ta = dad(adds.as_ref(), y.0);
        let td = dad(dels.as_ref(), y.0);

        a.mul_assign(&ta);
        d.mul_assign(&td);

        aa.push(ta);
        dd.push(td);
    }

    // If this fails, then this value was removed
    match d.inverse() {
        None => return Err(Error::from_msg(1, "no inverse exists")),
        Some(ddd) => d = ddd,
    };

    //〈Υy,Ω〉
    let mut p = PolynomialG1::with_capacity(deltas.len());

    // Ωi->j+1 = ∑ 1..t (dAt * dDt-1) · Ω
    for i in 0..deltas.len() {
        // t = i+1
        // ∏^(t-1)_(h=i+1)
        let mut ddh = one;
        for h in 0..i {
            ddh.mul_assign(&dd[h]);
        }

        let mut dak = one;
        // ∏^(j+1)_(k=t+1)
        for k in (i + 1)..deltas.len() {
            dak.mul_assign(&aa[k]);
        }

        dak.mul_assign(&ddh);
        let mut pp = PolynomialG1(deltas[i].2.as_ref().iter().map(|c| c.0).collect());
        pp *= dak;
        p += pp;
    }

    a.mul_assign(&d);

    if let Some(mut v) = p.evaluate(y.0) {
        // 1 / dD *〈Υy,Ω〉
        v.mul_assign(d);
        Ok(Delta { d: a, p: v })
    } else {
        Err(Error::from_msg(2, "polynomial could not be evaluated"))
    }
}

/// Computes the compressed delta needed to update a witness
pub fn evaluate_delta<A, D, C>(
    y: Element,
    additions: A,
    deletions: D,
    coefficients: C,
) -> Result<Delta, Error>
where
    A: AsRef<[Element]>,
    D: AsRef<[Element]>,
    C: AsRef<[Coefficient]>,
{
    // dD(x) = ∏ 1..m (yD_i - x)
    let mut d = dad(deletions.as_ref(), y.0);
    // If this fails, then this value was removed
    match d.inverse() {
        None => return Err(Error::from_msg(1, "no inverse exists")),
        Some(dd) => d = dd,
    };

    //dA(x) =  ∏ 1..n (yA_i - x)
    let mut a = dad(additions.as_ref(), y.0);
    a.mul_assign(&d);

    let p = PolynomialG1(coefficients.as_ref().iter().map(|c| c.0).collect());
    //〈Υy,Ω〉
    if let Some(mut v) = p.evaluate(y.0) {
        // C + 1 / dD *〈Υy,Ω〉
        v.mul_assign(d);
        Ok(Delta { d: a, p: v })
    } else {
        Err(Error::from_msg(2, "polynomial could not be evaluated"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_batch_update() {
        let key = SecretKey::new(Some(b"1234567890"));
        let pubkey = PublicKey::from(&key);
        let elements = [
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
            Element::hash(b"6"),
            Element::hash(b"7"),
            Element::hash(b"8"),
            Element::hash(b"9"),
        ];
        let mut acc = Accumulator::with_elements(&key, 0, &elements);
        let mut wit = MembershipWitness::new(&elements[3], acc, &key);

        assert!(wit.verify(pubkey, acc));

        let data = vec![
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let additions = &data[0..2];
        let deletions = &data[2..5];
        let coefficients = acc.update_assign(&key, additions, deletions);

        wit.batch_update_assign(additions, deletions, coefficients.as_slice());
        assert!(wit.verify(pubkey, acc));
    }

    #[test]
    fn membership_multi_batch_update() {
        let key = SecretKey::new(Some(b"1234567890"));
        let pubkey = PublicKey::from(&key);
        let elements = [
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
            Element::hash(b"6"),
            Element::hash(b"7"),
            Element::hash(b"8"),
            Element::hash(b"9"),
            Element::hash(b"10"),
            Element::hash(b"11"),
            Element::hash(b"12"),
            Element::hash(b"13"),
            Element::hash(b"14"),
            Element::hash(b"15"),
            Element::hash(b"16"),
            Element::hash(b"17"),
            Element::hash(b"18"),
            Element::hash(b"19"),
            Element::hash(b"20"),
        ];
        let mut acc = Accumulator::with_elements(&key, 0, &elements);
        let mut wit = MembershipWitness::new(&elements[3], acc, &key);

        assert!(wit.verify(pubkey, acc));

        let data = vec![
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        let adds1 = &data[0..2];
        let dels1 = &data[2..5];
        let coeffs1 = acc.update_assign(&key, adds1, dels1);

        let dels2 = &elements[8..10];
        let coeffs2 = acc.update_assign(&key, &[], dels2);

        let dels3 = &elements[11..14];
        let coeffs3 = acc.update_assign(&key, &[], dels3);

        wit.multi_batch_update_assign(&[
            (adds1, dels1, coeffs1.as_slice()),
            (&[], dels2, coeffs2.as_slice()),
            (&[], dels3, coeffs3.as_slice()),
        ]);
        assert!(wit.verify(pubkey, acc));
    }
}
