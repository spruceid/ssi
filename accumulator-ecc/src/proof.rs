use crate::{
    accumulator::Accumulator,
    generate_fr, hash_to_g1,
    key::PublicKey,
    witness::{MembershipWitness, NonMembershipWitness},
    BigArray, SALT,
};
use ff_zeroize::{Field, PrimeField};
use pairings::{
    bls12_381::{Bls12, Fq12, Fr, G1Affine, G1, G2},
    serdes::SerDes,
    CurveAffine, CurveProjective, Engine,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

struct_impl!(
/// Section 8 in <https://eprint.iacr.org/2020/777>
/// setup calls for four distinct generators in G1
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
ProofParams, ProofParamsInner,
            x: G1 => 48,
            y: G1 => 48,
            z: G1 => 48,
            k: G1 => 48,
);
display_impl!(ProofParams);

impl ProofParams {
    pub const BYTES: usize = 192;

    pub fn new(pk: PublicKey, entropy: Option<&[u8]>) -> Self {
        let mut data = Vec::new();
        data.append(&mut vec![0xFFu8, 32]);
        data.extend_from_slice(entropy.unwrap_or(&[]));
        data.extend_from_slice(&pk.to_bytes());

        let z = hash_to_g1(data.as_slice());

        data[0] = 0xFE;
        let y = hash_to_g1(data.as_slice());

        data[0] = 0xFD;
        let x = hash_to_g1(data.as_slice());

        data[0] = 0xFC;
        let k = hash_to_g1(data.as_slice());
        Self { k, x, y, z }
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut result = [0u8; Self::BYTES];
        result[..48].copy_from_slice(&g1_bytes(&self.x));
        result[48..96].copy_from_slice(&g1_bytes(&self.y));
        result[96..144].copy_from_slice(&g1_bytes(&self.z));
        result[144..].copy_from_slice(&g1_bytes(&self.k));
        result
    }
}

/// The commit or blinding step for generating a ZKP
/// The next step is to call `get_bytes_for_challenge`
/// to create the fiat shamir heuristic
#[derive(Debug, Copy, Clone)]
pub struct MembershipProofCommitting {
    e_c: G1,
    t_sigma: G1,
    t_rho: G1,
    delta_sigma: Fr,
    delta_rho: Fr,
    blinding_factor: Fr,
    r_sigma: Fr,
    r_rho: Fr,
    r_delta_sigma: Fr,
    r_delta_rho: Fr,
    sigma: Fr,
    rho: Fr,
    cap_r_sigma: G1,
    cap_r_rho: G1,
    cap_r_delta_sigma: G1,
    cap_r_delta_rho: G1,
    cap_r_e: Fq12,
    accumulator: G1,
    witness_value: Fr,
    x_g1: G1,
    y_g1: G1,
    z_g1: G1,
}

impl MembershipProofCommitting {
    /// Create a new membership proof committing phase
    pub fn new(
        witness: &MembershipWitness,
        accumulator: Accumulator,
        proof_params: ProofParams,
        pubkey: PublicKey,
        blinding_factor: Option<crate::Element>,
    ) -> Self {
        // Randomly select σ, ρ
        let sigma = generate_fr(SALT, None);
        let rho = generate_fr(SALT, None);

        // E_C = C + (σ + ρ)Z
        let mut t = sigma;
        t.add_assign(&rho);
        let mut e_c = proof_params.z;
        e_c.mul_assign(t);
        e_c.add_assign(&witness.c);

        // T_σ = σX
        let mut t_sigma = proof_params.x;
        t_sigma.mul_assign(sigma);

        // T_ρ = ρY
        let mut t_rho = proof_params.y;
        t_rho.mul_assign(rho);

        // δ_σ = yσ
        let mut delta_sigma = witness.y;
        delta_sigma.mul_assign(&sigma);

        // δ_ρ = yρ
        let mut delta_rho = witness.y;
        delta_rho.mul_assign(&rho);

        // Randomly pick r_σ,r_ρ,r_δσ,r_δρ
        // r_y is either generated randomly or supplied in case this proof is used to
        // bind to an external proof
        let r_y = blinding_factor
            .map(|bf| bf.into())
            .unwrap_or(generate_fr(SALT, None));
        let r_sigma = generate_fr(SALT, None);
        let r_rho = generate_fr(SALT, None);
        let r_delta_sigma = generate_fr(SALT, None);
        let r_delta_rho = generate_fr(SALT, None);

        // R_σ = r_σ X
        let mut cap_r_sigma = proof_params.x;
        cap_r_sigma.mul_assign(r_sigma);

        // R_ρ = ρY
        let mut cap_r_rho = proof_params.y;
        cap_r_rho.mul_assign(r_rho);

        // R_δσ = r_y T_σ - r_δσ X
        let mut neg_x = proof_params.x;
        neg_x.negate();
        let cap_r_delta_sigma = cap_r(&[t_sigma, neg_x], &[r_y, r_delta_sigma]);

        // R_δρ = r_y T_ρ - r_δρ Y
        let mut neg_y = proof_params.y;
        neg_y.negate();
        let cap_r_delta_rho = cap_r(&[t_rho, neg_y], &[r_y, r_delta_rho]);

        // R_E = e(E_C, P~)^r_y
        let g2 = G2::one();

        // R_E *= e(Z, P~)^-r_δσ - r_δρ
        let mut exp = r_delta_sigma;
        exp.add_assign(&r_delta_rho);
        exp.negate();

        // Optimize one less pairing by computing
        // R_E = e(E_C^r_y + Z^{-r_δσ - r_δρ}, P~)
        let mut lhs = e_c;
        lhs.mul_assign(r_y);
        let mut z = proof_params.z;
        z.mul_assign(exp);
        lhs.add_assign(&z);
        let mut cap_r_e = pair(lhs, g2);

        // R_E *= e(Z, Q~)^-r_σ - r_ρ
        let mut exp = r_sigma;
        exp.add_assign(&r_rho);
        exp.negate();
        cap_r_e.mul_assign(&pairing(proof_params.z, pubkey.0, exp));

        Self {
            e_c,
            t_sigma,
            t_rho,
            delta_sigma,
            delta_rho,
            blinding_factor: r_y,
            r_sigma,
            r_rho,
            r_delta_sigma,
            r_delta_rho,
            sigma,
            rho,
            cap_r_e,
            cap_r_sigma,
            cap_r_rho,
            cap_r_delta_sigma,
            cap_r_delta_rho,
            accumulator: accumulator.0,
            witness_value: witness.y,
            x_g1: proof_params.x,
            y_g1: proof_params.y,
            z_g1: proof_params.z,
        }
    }

    /// Return bytes that need to be hashed for generating challenge.
    ///
    /// V || Ec || T_sigma || T_rho || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(self) -> Vec<u8> {
        let mut out = g1_bytes(&self.accumulator).to_vec();
        out.extend_from_slice(&g1_bytes(&self.e_c));
        out.extend_from_slice(&g1_bytes(&self.t_sigma));
        out.extend_from_slice(&g1_bytes(&self.t_rho));
        out.extend_from_slice(&fq12_bytes(&self.cap_r_e));
        out.extend_from_slice(&g1_bytes(&self.cap_r_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_rho));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_rho));
        out
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(&self, challenge_hash: crate::Element) -> MembershipProof {
        let challenge_hash: Fr = challenge_hash.into();
        // s_y = r_y - cy
        let s_y = schnorr(self.blinding_factor, self.witness_value, challenge_hash);
        // s_σ = r_σ - cσ
        let s_sigma = schnorr(self.r_sigma, self.sigma, challenge_hash);
        // s_ρ = r_ρ - cρ
        let s_rho = schnorr(self.r_rho, self.rho, challenge_hash);
        // s_δσ = rδσ - cδ_σ
        let s_delta_sigma = schnorr(self.r_delta_sigma, self.delta_sigma, challenge_hash);
        // s_δρ = rδρ - cδ_ρ
        let s_delta_rho = schnorr(self.r_delta_rho, self.delta_rho, challenge_hash);
        MembershipProof {
            e_c: self.e_c,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            s_y,
            s_sigma,
            s_rho,
            s_delta_sigma,
            s_delta_rho,
        }
    }
}

struct_impl!(
/// A ZKP membership proof
#[derive(Debug, Copy, Clone)]
MembershipProof, MembershipProofInner,
    e_c: G1 => 48,
    t_sigma: G1 => 48,
    t_rho: G1 => 48,
    s_sigma: Fr => 32,
    s_rho: Fr => 32,
    s_delta_sigma: Fr => 32,
    s_delta_rho: Fr => 32,
    s_y: Fr => 32,
);
display_impl!(MembershipProof);

impl MembershipProof {
    const BYTES: usize = 304;

    /// Generate the structure that can be used in the challenge hash
    /// returns a struct to avoid recomputing
    pub fn finalize(
        &self,
        accumulator: Accumulator,
        proof_params: ProofParams,
        pubkey: PublicKey,
        challenge_hash: crate::Element,
    ) -> MembershipProofFinal {
        let challenge_hash = challenge_hash.into();
        // R_σ = s_δ X - c T_σ
        let mut neg_t_sigma = self.t_sigma;
        neg_t_sigma.negate();
        let cap_r_sigma = cap_r(
            &[proof_params.x, neg_t_sigma],
            &[self.s_sigma, challenge_hash],
        );

        // R_ρ = s_ρ Y - c T_ρ
        let mut neg_t_rho = self.t_rho;
        neg_t_rho.negate();
        let cap_r_rho = cap_r(&[proof_params.y, neg_t_rho], &[self.s_rho, challenge_hash]);

        // R_δσ =  s_y T_σ - s_δσ X
        let mut neg_x = proof_params.x;
        neg_x.negate();
        let cap_r_delta_sigma = cap_r(&[self.t_sigma, neg_x], &[self.s_y, self.s_delta_sigma]);

        // R_δρ =  s_y T_ρ - s_δρ Y
        let mut neg_y = proof_params.y;
        neg_y.negate();
        let cap_r_delta_rho = cap_r(&[self.t_rho, neg_y], &[self.s_y, self.s_delta_rho]);

        let g2 = G2::one();

        // We can eliminate three pairings by combining
        // e(E_C, P~)^s_y * e(Z, P~)^-(s_delta_sigma + s_delta_rho) * e(V, P~)^-c
        // to
        // e(E_C^s_y + Z^-(s_delta_sigma + s_delta_rho) + V^-c, P~)
        // and
        // e(Z, Q~)^-(s_sigma + s_rho) * e(E_C, Q~)^c
        // to
        // e(Z^-(s_sigma + s_rho) + E_C^c, Q~)

        // e(E_C, P~)^s_y
        let mut lhs = self.e_c;
        lhs.mul_assign(self.s_y);

        // e(Z, P~)^-(s_delta_sigma + s_delta_rho)
        let mut exp = self.s_delta_sigma;
        exp.add_assign(&self.s_delta_rho);
        exp.negate();
        let mut rhs = proof_params.z;
        rhs.mul_assign(exp);
        lhs.add_assign(&rhs);

        // e(V, P~)^-c
        exp = challenge_hash;
        exp.negate();
        rhs = accumulator.0;
        rhs.mul_assign(exp);
        lhs.add_assign(&rhs);
        let mut cap_r_e = pair(lhs, g2);

        // e(Z, Q~)^-(s_sigma + s_rho)
        exp = self.s_sigma;
        exp.add_assign(&self.s_rho);
        exp.negate();
        lhs = proof_params.z;
        lhs.mul_assign(exp);

        // e(E_C, Q~)^c
        rhs = self.e_c;
        rhs.mul_assign(challenge_hash);
        lhs.add_assign(&rhs);
        cap_r_e.mul_assign(&pair(lhs, pubkey.0));

        MembershipProofFinal {
            accumulator: accumulator.0,
            e_c: self.e_c,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            cap_r_e,
            cap_r_sigma,
            cap_r_rho,
            cap_r_delta_sigma,
            cap_r_delta_rho,
        }
    }

    /// Get the byte representation of the proof
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        let mut c = std::io::Cursor::new(res.as_mut());
        self.e_c.serialize(&mut c, true).unwrap();
        self.t_sigma.serialize(&mut c, true).unwrap();
        self.t_rho.serialize(&mut c, true).unwrap();
        self.s_sigma.serialize(&mut c, true).unwrap();
        self.s_rho.serialize(&mut c, true).unwrap();
        self.s_delta_sigma.serialize(&mut c, true).unwrap();
        self.s_delta_rho.serialize(&mut c, true).unwrap();
        self.s_y.serialize(&mut c, true).unwrap();
        res
    }
}

/// The computed values after running MembershipProof.finalize
#[derive(Debug, Copy, Clone)]
pub struct MembershipProofFinal {
    accumulator: G1,
    e_c: G1,
    t_sigma: G1,
    t_rho: G1,
    cap_r_e: Fq12,
    cap_r_sigma: G1,
    cap_r_rho: G1,
    cap_r_delta_sigma: G1,
    cap_r_delta_rho: G1,
}

impl MembershipProofFinal {
    /// V || Ec || T_sigma || T_rho || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(&self) -> Vec<u8> {
        let mut out = g1_bytes(&self.accumulator).to_vec();
        out.extend_from_slice(&g1_bytes(&self.e_c));
        out.extend_from_slice(&g1_bytes(&self.t_sigma));
        out.extend_from_slice(&g1_bytes(&self.t_rho));
        out.extend_from_slice(&fq12_bytes(&self.cap_r_e));
        out.extend_from_slice(&g1_bytes(&self.cap_r_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_rho));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_rho));
        out
    }
}

/// The commit or blinding step for generating a ZKP
/// The next step is to call `get_bytes_for_challenge`
/// to create the fiat shamir heuristic
#[derive(Debug, Copy, Clone)]
pub struct NonMembershipProofCommitting {
    e_c: G1,
    e_d: G1,
    e_dm1: G1,
    t_sigma: G1,
    t_rho: G1,
    delta_sigma: Fr,
    delta_rho: Fr,
    blinding_factor: Fr,
    r_u: Fr,
    r_v: Fr,
    r_w: Fr,
    r_sigma: Fr,
    r_rho: Fr,
    r_delta_sigma: Fr,
    r_delta_rho: Fr,
    sigma: Fr,
    rho: Fr,
    tau: Fr,
    pi: Fr,
    cap_r_a: G1,
    cap_r_b: G1,
    cap_r_sigma: G1,
    cap_r_rho: G1,
    cap_r_delta_sigma: G1,
    cap_r_delta_rho: G1,
    cap_r_e: Fq12,
    accumulator: G1,
    witness_d: Fr,
    witness_value: Fr,
    x_g1: G1,
    y_g1: G1,
    z_g1: G1,
    k_g1: G1,
}

impl NonMembershipProofCommitting {
    /// Create a new nonmembership proof committing phase
    pub fn new(
        witness: &NonMembershipWitness,
        accumulator: Accumulator,
        proof_params: ProofParams,
        pubkey: PublicKey,
        blinding_factor: Option<crate::Element>,
    ) -> Self {
        // Randomly pick r_σ,r_ρ,r_δσ,r_δρ

        // Randomly select σ, ρ
        let sigma = generate_fr(SALT, None);
        let rho = generate_fr(SALT, None);

        // E_C = C + (σ + ρ)Z
        let mut t = sigma;
        t.add_assign(&rho);
        let mut e_c = proof_params.z;
        e_c.mul_assign(t);
        e_c.add_assign(&witness.c);

        // T_σ = σX
        let mut t_sigma = proof_params.x;
        t_sigma.mul_assign(sigma);

        // T_ρ = ρY
        let mut t_rho = proof_params.y;
        t_rho.mul_assign(rho);

        // δ_σ = yσ
        let mut delta_sigma = witness.y;
        delta_sigma.mul_assign(&sigma);

        // δ_ρ = yρ
        let mut delta_rho = witness.y;
        delta_rho.mul_assign(&rho);

        // Randomly pick r_σ,r_ρ,r_δσ,r_δρ
        // r_y is either generated randomly or supplied in case this proof is used to
        // bind to an external proof
        let r_y = blinding_factor
            .map(|bf| bf.into())
            .unwrap_or(generate_fr(SALT, None));
        let r_sigma = generate_fr(SALT, None);
        let r_rho = generate_fr(SALT, None);
        let r_delta_sigma = generate_fr(SALT, None);
        let r_delta_rho = generate_fr(SALT, None);

        // R_σ = r_σ X
        let mut cap_r_sigma = proof_params.x;
        cap_r_sigma.mul_assign(r_sigma);

        // R_ρ = ρY
        let mut cap_r_rho = proof_params.y;
        cap_r_rho.mul_assign(r_rho);

        // R_δσ = r_y T_σ - r_δσ X
        let mut neg_x = proof_params.x;
        neg_x.negate();
        let cap_r_delta_sigma = cap_r(&[t_sigma, neg_x], &[r_y, r_delta_sigma]);

        // R_δρ = r_y T_ρ - r_δρ Y
        let mut neg_y = proof_params.y;
        neg_y.negate();
        let cap_r_delta_rho = cap_r(&[t_rho, neg_y], &[r_y, r_delta_rho]);

        // Randomly pick \tau, \pi
        let tau = generate_fr(SALT, None);
        let pi = generate_fr(SALT, None);

        // E_d = d P + \tau K
        let e_d = cap_r(&[G1::one(), proof_params.k], &[witness.d, tau]);

        // E_{d^{-1}} = d^{-1}P + \pi K
        let e_dm1 = cap_r(
            &[G1::one(), proof_params.k],
            &[witness.d.inverse().unwrap(), pi],
        );

        // Randomly pick r_u,r_v,r_w
        let r_u = generate_fr(SALT, None);
        let r_v = generate_fr(SALT, None);
        let r_w = generate_fr(SALT, None);

        // R_A = r_u P + r_v K
        let cap_r_a = cap_r(&[G1::one(), proof_params.k], &[r_u, r_v]);

        // R_B = r_u E_d^{-1} + r_w K
        let cap_r_b = cap_r(&[e_dm1, proof_params.k], &[r_u, r_w]);

        // R_E = e(E_C, P~)^r_y
        let g2 = G2::one();

        // R_E *= e(Z, P~)^-r_δσ - r_δρ
        let mut exp = r_delta_sigma;
        exp.add_assign(&r_delta_rho);
        exp.negate();

        // Optimize one less pairing by computing
        // R_E = e(E_C^r_y + Z^{-r_δσ - r_δρ}, P~)
        let mut lhs = e_c;
        lhs.mul_assign(r_y);
        let mut z = proof_params.z;
        z.mul_assign(exp);
        lhs.add_assign(&z);

        // R_E *= e(K, P~)^-r_v
        let mut exp = r_v;
        exp.negate();
        let mut k = proof_params.k;
        k.mul_assign(exp);
        lhs.add_assign(&k);

        let mut cap_r_e = pair(lhs, g2);

        // R_E *= e(Z, Q~)^-r_σ - r_ρ
        let mut exp = r_sigma;
        exp.add_assign(&r_rho);
        exp.negate();
        cap_r_e.mul_assign(&pairing(proof_params.z, pubkey.0, exp));

        Self {
            e_c,
            e_d,
            e_dm1,
            t_sigma,
            t_rho,
            delta_sigma,
            delta_rho,
            blinding_factor: r_y,
            sigma,
            rho,
            tau,
            pi,
            r_u,
            r_v,
            r_w,
            r_sigma,
            r_rho,
            r_delta_sigma,
            r_delta_rho,
            cap_r_a,
            cap_r_b,
            cap_r_e,
            cap_r_delta_rho,
            cap_r_delta_sigma,
            cap_r_rho,
            cap_r_sigma,
            accumulator: accumulator.0,
            witness_d: witness.d,
            witness_value: witness.y,
            k_g1: proof_params.k,
            x_g1: proof_params.x,
            y_g1: proof_params.y,
            z_g1: proof_params.z,
        }
    }

    /// Return bytes that need to be hashed for generating challenge.
    ///
    /// V || Ec || Ed || Ed^{-1] || T_sigma || T_rho || R_A || R_B || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(self) -> Vec<u8> {
        let mut out = g1_bytes(&self.accumulator).to_vec();
        out.extend_from_slice(&g1_bytes(&self.e_c));
        out.extend_from_slice(&g1_bytes(&self.e_d));
        out.extend_from_slice(&g1_bytes(&self.e_dm1));
        out.extend_from_slice(&g1_bytes(&self.t_sigma));
        out.extend_from_slice(&g1_bytes(&self.t_rho));
        out.extend_from_slice(&g1_bytes(&self.cap_r_a));
        out.extend_from_slice(&g1_bytes(&self.cap_r_b));
        out.extend_from_slice(&fq12_bytes(&self.cap_r_e));
        out.extend_from_slice(&g1_bytes(&self.cap_r_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_rho));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_rho));
        out
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(&self, challenge_hash: Fr) -> NonMembershipProof {
        // s_y = r_y - cy
        let s_y = schnorr(self.blinding_factor, self.witness_value, challenge_hash);
        // s_σ = r_σ - cσ
        let s_sigma = schnorr(self.r_sigma, self.sigma, challenge_hash);
        // s_ρ = r_ρ - cρ
        let s_rho = schnorr(self.r_rho, self.rho, challenge_hash);
        // s_δσ = rδσ - cδ_σ
        let s_delta_sigma = schnorr(self.r_delta_sigma, self.delta_sigma, challenge_hash);
        // s_δρ = rδρ - cδ_ρ
        let s_delta_rho = schnorr(self.r_delta_rho, self.delta_rho, challenge_hash);
        // s_u = r_u + c d
        let s_u = schnorr(self.r_u, self.witness_d, challenge_hash);
        // s_v = r_v + c tau
        let s_v = schnorr(self.r_v, self.tau, challenge_hash);
        // s_w = r_w - c d pi
        let mut pi = self.pi;
        pi.mul_assign(&self.witness_d);
        pi.negate();
        let s_w = schnorr(self.r_w, pi, challenge_hash);

        NonMembershipProof {
            e_c: self.e_c,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            s_sigma,
            s_rho,
            s_delta_sigma,
            s_delta_rho,
            s_y,
            e_d: self.e_d,
            e_dm1: self.e_dm1,
            s_u,
            s_v,
            s_w,
        }
    }
}

struct_impl!(
/// A ZKP non-membership proof
#[derive(Debug, Copy, Clone)]
NonMembershipProof, NonMembershipProofInner,
    e_c: G1 => 48,
    e_d: G1 => 48,
    e_dm1: G1 => 48,
    t_sigma: G1 => 48,
    t_rho: G1 => 48,
    s_sigma: Fr => 32,
    s_rho: Fr => 32,
    s_delta_sigma: Fr => 32,
    s_delta_rho: Fr => 32,
    s_u: Fr => 32,
    s_v: Fr => 32,
    s_w: Fr => 32,
    s_y: Fr => 32,
);
display_impl!(NonMembershipProof);

impl NonMembershipProof {
    const BYTES: usize = 496;
    /// Generate the structure that can be used in the challenge hash
    /// returns a struct to avoid recomputing
    pub fn finalize(
        &self,
        accumulator: Accumulator,
        proof_params: ProofParams,
        pubkey: PublicKey,
        challenge_hash: crate::Element,
    ) -> NonMembershipProofFinal {
        // R_σ = s_δ X - c T_σ
        let mut neg_t_sigma = self.t_sigma;
        neg_t_sigma.negate();
        let cap_r_sigma = cap_r(
            &[proof_params.x, neg_t_sigma],
            &[self.s_sigma, challenge_hash.0],
        );

        // R_ρ = s_ρ Y - c T_ρ
        let mut neg_t_rho = self.t_rho;
        neg_t_rho.negate();
        let cap_r_rho = cap_r(
            &[proof_params.y, neg_t_rho],
            &[self.s_rho, challenge_hash.0],
        );

        // R_δσ =  s_y T_σ - s_δσ X
        let mut neg_x = proof_params.x;
        neg_x.negate();
        let cap_r_delta_sigma = cap_r(&[self.t_sigma, neg_x], &[self.s_y, self.s_delta_sigma]);

        // R_δρ =  s_y T_ρ - s_δρ Y
        let mut neg_y = proof_params.y;
        neg_y.negate();
        let cap_r_delta_rho = cap_r(&[self.t_rho, neg_y], &[self.s_y, self.s_delta_rho]);

        let g2 = G2::one();

        // We can eliminate multiple pairings by combining
        // e(E_C, P~)^s_y * e(Z, P~)^-(s_delta_sigma + s_delta_rho) * e(V, P~)^-c * e(K, P~)^-s_v * e(Ed, P~)^c
        // to
        // e(E_C^s_y + Z^-(s_delta_sigma + s_delta_rho) + V^-c - s_v K + c E_d, P~)
        // and
        // e(Z, Q~)^-(s_sigma + s_rho) * e(E_C, Q~)^c
        // to
        // e(Z^-(s_sigma + s_rho) + E_C^c, Q~)

        // e(E_C, P~)^s_y
        let mut lhs = self.e_c;
        lhs.mul_assign(self.s_y);

        // e(Z, P~)^-(s_delta_sigma + s_delta_rho)
        let mut exp = self.s_delta_sigma;
        exp.add_assign(&self.s_delta_rho);
        exp.negate();
        let mut rhs = proof_params.z;
        rhs.mul_assign(exp);
        lhs.add_assign(&rhs);

        // e(V, P~)^-c
        exp = challenge_hash.0;
        exp.negate();
        rhs = accumulator.0;
        rhs.mul_assign(exp);
        lhs.add_assign(&rhs);

        //e(K, P~)^-s_v
        exp = self.s_v;
        exp.negate();
        rhs = proof_params.k;
        rhs.mul_assign(exp);
        lhs.add_assign(&rhs);

        // e(Ed, P~)^c
        exp = challenge_hash.0;
        rhs = self.e_d;
        rhs.mul_assign(exp);
        lhs.add_assign(&rhs);
        let mut cap_r_e = pair(lhs, g2);

        // e(Z, Q~)^-(s_sigma + s_rho)
        exp = self.s_sigma;
        exp.add_assign(&self.s_rho);
        exp.negate();
        lhs = proof_params.z;
        lhs.mul_assign(exp);

        // e(E_C, Q~)^c
        rhs = self.e_c;
        rhs.mul_assign(challenge_hash.0);
        lhs.add_assign(&rhs);
        cap_r_e.mul_assign(&pair(lhs, pubkey.0));

        let g1 = G1::one();

        // R_A = s_u P + s_v K - c E_d
        let mut negc = challenge_hash.0;
        negc.negate();
        let cap_r_a = cap_r(&[g1, proof_params.k, self.e_d], &[self.s_u, self.s_v, negc]);

        // R_B = s_w K + s_u E_d^-1 - c P
        let cap_r_b = cap_r(
            &[proof_params.k, self.e_dm1, g1],
            &[self.s_w, self.s_u, negc],
        );

        NonMembershipProofFinal {
            accumulator: accumulator.0,
            e_c: self.e_c,
            e_d: self.e_d,
            e_dm1: self.e_dm1,
            t_sigma: self.t_sigma,
            t_rho: self.t_rho,
            cap_r_a,
            cap_r_b,
            cap_r_e,
            cap_r_sigma,
            cap_r_rho,
            cap_r_delta_sigma,
            cap_r_delta_rho,
        }
    }

    /// Get the byte representation of the proof
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut res = [0u8; Self::BYTES];
        let mut c = std::io::Cursor::new(res.as_mut());

        self.e_c.serialize(&mut c, true).unwrap();
        self.e_d.serialize(&mut c, true).unwrap();
        self.e_dm1.serialize(&mut c, true).unwrap();
        self.t_sigma.serialize(&mut c, true).unwrap();
        self.t_rho.serialize(&mut c, true).unwrap();
        self.s_sigma.serialize(&mut c, true).unwrap();
        self.s_rho.serialize(&mut c, true).unwrap();
        self.s_delta_sigma.serialize(&mut c, true).unwrap();
        self.s_delta_rho.serialize(&mut c, true).unwrap();
        self.s_u.serialize(&mut c, true).unwrap();
        self.s_v.serialize(&mut c, true).unwrap();
        self.s_w.serialize(&mut c, true).unwrap();
        self.s_y.serialize(&mut c, true).unwrap();

        res
    }
}

/// The computed values after running NonMembershipProof.finalize
#[derive(Debug, Copy, Clone)]
pub struct NonMembershipProofFinal {
    accumulator: G1,
    e_c: G1,
    e_d: G1,
    e_dm1: G1,
    t_sigma: G1,
    t_rho: G1,
    cap_r_a: G1,
    cap_r_b: G1,
    cap_r_e: Fq12,
    cap_r_sigma: G1,
    cap_r_rho: G1,
    cap_r_delta_sigma: G1,
    cap_r_delta_rho: G1,
}

impl NonMembershipProofFinal {
    /// V || Ec || E_d || E_d^-1 || T_sigma || T_rho || R_A || R_B || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho
    pub fn get_bytes_for_challenge(&self) -> Vec<u8> {
        let mut out = g1_bytes(&self.accumulator).to_vec();
        out.extend_from_slice(&g1_bytes(&self.e_c));
        out.extend_from_slice(&g1_bytes(&self.e_d));
        out.extend_from_slice(&g1_bytes(&self.e_dm1));
        out.extend_from_slice(&g1_bytes(&self.t_sigma));
        out.extend_from_slice(&g1_bytes(&self.t_rho));
        out.extend_from_slice(&g1_bytes(&self.cap_r_a));
        out.extend_from_slice(&g1_bytes(&self.cap_r_b));
        out.extend_from_slice(&fq12_bytes(&self.cap_r_e));
        out.extend_from_slice(&g1_bytes(&self.cap_r_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_rho));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_sigma));
        out.extend_from_slice(&g1_bytes(&self.cap_r_delta_rho));
        out
    }
}

fn cap_r(bases: &[G1], scalars: &[Fr]) -> G1 {
    let bases: Vec<_> = bases.iter().map(|b| b.into_affine()).collect();
    let scalars: Vec<[u64; 4]> = scalars
        .iter()
        .map(|s| {
            let mut t = [0u64; 4];
            t.clone_from_slice(s.into_repr().as_ref());
            t
        })
        .collect();
    let s: Vec<&[u64; 4]> = scalars.iter().map(|u| u).collect();
    G1Affine::sum_of_products(bases.as_slice(), s.as_slice())
}

fn pair(g1: G1, g2: G2) -> Fq12 {
    Bls12::final_exponentiation(&Bls12::miller_loop(&[(
        &g1.into_affine().prepare(),
        &g2.into_affine().prepare(),
    )]))
    .unwrap()
}

fn pairing(g1: G1, g2: G2, exp: Fr) -> Fq12 {
    let mut base = g1;
    base.mul_assign(exp);
    Bls12::final_exponentiation(&Bls12::miller_loop(&[(
        &base.into_affine().prepare(),
        &g2.into_affine().prepare(),
    )]))
    .unwrap()
}

fn schnorr(r: Fr, v: Fr, challenge: Fr) -> Fr {
    let mut res = v;
    res.mul_assign(&challenge);
    res.add_assign(&r);
    res
}

fn fq12_bytes(fp12: &Fq12) -> [u8; 576] {
    let mut bytes = [0u8; 576];
    fp12.serialize(&mut bytes.as_mut(), true).unwrap();
    bytes
}

fn g1_bytes(g1: &G1) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    g1.serialize(&mut bytes.as_mut(), true).unwrap();
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{accumulator::Element, key::SecretKey};

    #[test]
    fn byte_round_trip() {
        let sk = SecretKey::new(None);
        let pk = PublicKey::from(&sk);
        let params = ProofParams::new(pk, None);

        let bytes = params.to_bytes();
        let params2 = ProofParams::from(bytes);
        assert_eq!(params, params2);
    }

    #[test]
    fn basic_membership_proof() {
        let sk = SecretKey::from([
            83, 88, 211, 208, 98, 73, 80, 160, 247, 119, 30, 138, 197, 40, 149, 84, 224, 194, 132,
            99, 42, 220, 247, 225, 118, 194, 100, 61, 247, 72, 186, 15,
        ]);
        let pk = PublicKey::from([
            168, 83, 108, 197, 136, 167, 236, 76, 60, 181, 29, 189, 41, 15, 208, 225, 77, 81, 119,
            249, 194, 58, 100, 196, 98, 244, 8, 97, 204, 251, 189, 248, 238, 95, 150, 54, 54, 127,
            66, 188, 162, 128, 79, 60, 156, 222, 235, 28, 4, 95, 12, 179, 243, 26, 97, 173, 200,
            160, 200, 111, 69, 201, 189, 253, 31, 18, 212, 249, 81, 167, 39, 151, 160, 64, 27, 230,
            226, 58, 15, 175, 209, 166, 225, 205, 178, 42, 19, 204, 66, 30, 36, 197, 228, 54, 69,
            194,
        ]);
        let acc = Accumulator::from([
            162, 157, 54, 99, 191, 50, 255, 216, 22, 66, 234, 165, 116, 208, 142, 152, 22, 50, 11,
            47, 153, 44, 78, 5, 17, 35, 237, 52, 145, 154, 161, 38, 192, 192, 93, 209, 29, 99, 201,
            178, 238, 202, 184, 83, 185, 135, 194, 211,
        ]);
        let proof_params = ProofParams::from([
            137, 163, 2, 225, 231, 88, 50, 201, 244, 21, 220, 3, 217, 153, 224, 136, 41, 211, 94,
            149, 93, 72, 159, 205, 42, 127, 58, 196, 21, 156, 19, 116, 47, 226, 132, 36, 54, 148,
            225, 237, 73, 159, 26, 5, 69, 163, 113, 79, 177, 24, 18, 229, 113, 76, 130, 213, 70,
            216, 41, 209, 57, 61, 94, 190, 75, 81, 84, 103, 103, 49, 83, 146, 233, 9, 33, 79, 205,
            201, 193, 85, 205, 104, 126, 213, 125, 70, 108, 243, 118, 182, 54, 200, 208, 223, 4,
            138, 164, 154, 166, 2, 232, 165, 211, 111, 105, 86, 156, 56, 47, 224, 204, 59, 235,
            217, 166, 24, 217, 131, 126, 90, 7, 248, 79, 254, 24, 175, 88, 70, 31, 178, 89, 68,
            199, 110, 18, 207, 41, 238, 47, 224, 98, 58, 92, 81, 164, 11, 10, 26, 227, 183, 218,
            83, 99, 7, 190, 245, 126, 133, 186, 64, 31, 250, 218, 172, 105, 201, 65, 184, 87, 185,
            163, 167, 117, 26, 218, 50, 167, 21, 80, 24, 90, 113, 197, 189, 88, 17, 155, 33, 222,
            96, 33, 144,
        ]);

        let mw = MembershipWitness::new(&Element::hash(b"basic_membership_proof"), acc, &sk);
        let mpc = MembershipProofCommitting::new(&mw, acc, proof_params, pk, None);

        let challenge = generate_fr(SALT, Some(mpc.get_bytes_for_challenge().as_slice()));
        let proof = mpc.gen_proof(Element::from(challenge));
        let final_proof = proof.finalize(acc, proof_params, pk, Element::from(challenge));

        let challenge2 = generate_fr(SALT, Some(final_proof.get_bytes_for_challenge().as_slice()));
        assert_eq!(challenge, challenge2);
    }

    #[test]
    fn basic_nonmembership_proof() {
        let sk = SecretKey::from([
            83, 88, 211, 208, 98, 73, 80, 160, 247, 119, 30, 138, 197, 40, 149, 84, 224, 194, 132,
            99, 42, 220, 247, 225, 118, 194, 100, 61, 247, 72, 186, 15,
        ]);
        let pk = PublicKey::from([
            168, 83, 108, 197, 136, 167, 236, 76, 60, 181, 29, 189, 41, 15, 208, 225, 77, 81, 119,
            249, 194, 58, 100, 196, 98, 244, 8, 97, 204, 251, 189, 248, 238, 95, 150, 54, 54, 127,
            66, 188, 162, 128, 79, 60, 156, 222, 235, 28, 4, 95, 12, 179, 243, 26, 97, 173, 200,
            160, 200, 111, 69, 201, 189, 253, 31, 18, 212, 249, 81, 167, 39, 151, 160, 64, 27, 230,
            226, 58, 15, 175, 209, 166, 225, 205, 178, 42, 19, 204, 66, 30, 36, 197, 228, 54, 69,
            194,
        ]);
        let proof_params = ProofParams::from([
            137, 163, 2, 225, 231, 88, 50, 201, 244, 21, 220, 3, 217, 153, 224, 136, 41, 211, 94,
            149, 93, 72, 159, 205, 42, 127, 58, 196, 21, 156, 19, 116, 47, 226, 132, 36, 54, 148,
            225, 237, 73, 159, 26, 5, 69, 163, 113, 79, 177, 24, 18, 229, 113, 76, 130, 213, 70,
            216, 41, 209, 57, 61, 94, 190, 75, 81, 84, 103, 103, 49, 83, 146, 233, 9, 33, 79, 205,
            201, 193, 85, 205, 104, 126, 213, 125, 70, 108, 243, 118, 182, 54, 200, 208, 223, 4,
            138, 164, 154, 166, 2, 232, 165, 211, 111, 105, 86, 156, 56, 47, 224, 204, 59, 235,
            217, 166, 24, 217, 131, 126, 90, 7, 248, 79, 254, 24, 175, 88, 70, 31, 178, 89, 68,
            199, 110, 18, 207, 41, 238, 47, 224, 98, 58, 92, 81, 164, 11, 10, 26, 227, 183, 218,
            83, 99, 7, 190, 245, 126, 133, 186, 64, 31, 250, 218, 172, 105, 201, 65, 184, 87, 185,
            163, 167, 117, 26, 218, 50, 167, 21, 80, 24, 90, 113, 197, 189, 88, 17, 155, 33, 222,
            96, 33, 144,
        ]);
        let blinding_factor = Some(Element::from(generate_fr(
            SALT,
            Some(b"basic_nonmembership_proof_blinding_factor"),
        )));
        let mut acc = Accumulator::new(&sk, 0);
        let elements = [
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        acc.add_elements_assign(&sk, &elements);

        let nmw =
            NonMembershipWitness::new(&Element::hash(b"basic_nonmembership_proof"), &elements, &sk);

        let nmpc = NonMembershipProofCommitting::new(&nmw, acc, proof_params, pk, blinding_factor);
        let challenge = generate_fr(SALT, Some(nmpc.get_bytes_for_challenge().as_slice()));
        let proof = nmpc.gen_proof(challenge);
        let final_proof = proof.finalize(acc, proof_params, pk, Element::from(challenge));

        let challenge2 = generate_fr(SALT, Some(final_proof.get_bytes_for_challenge().as_slice()));
        assert_eq!(challenge, challenge2);
    }

    #[test]
    fn growing_accumulator() {
        let sk = SecretKey::from([
            83, 88, 211, 208, 98, 73, 80, 160, 247, 119, 30, 138, 197, 40, 149, 84, 224, 194, 132,
            99, 42, 220, 247, 225, 118, 194, 100, 61, 247, 72, 186, 15,
        ]);
        let pk = PublicKey::from([
            168, 83, 108, 197, 136, 167, 236, 76, 60, 181, 29, 189, 41, 15, 208, 225, 77, 81, 119,
            249, 194, 58, 100, 196, 98, 244, 8, 97, 204, 251, 189, 248, 238, 95, 150, 54, 54, 127,
            66, 188, 162, 128, 79, 60, 156, 222, 235, 28, 4, 95, 12, 179, 243, 26, 97, 173, 200,
            160, 200, 111, 69, 201, 189, 253, 31, 18, 212, 249, 81, 167, 39, 151, 160, 64, 27, 230,
            226, 58, 15, 175, 209, 166, 225, 205, 178, 42, 19, 204, 66, 30, 36, 197, 228, 54, 69,
            194,
        ]);
        let proof_params = ProofParams::from([
            137, 163, 2, 225, 231, 88, 50, 201, 244, 21, 220, 3, 217, 153, 224, 136, 41, 211, 94,
            149, 93, 72, 159, 205, 42, 127, 58, 196, 21, 156, 19, 116, 47, 226, 132, 36, 54, 148,
            225, 237, 73, 159, 26, 5, 69, 163, 113, 79, 177, 24, 18, 229, 113, 76, 130, 213, 70,
            216, 41, 209, 57, 61, 94, 190, 75, 81, 84, 103, 103, 49, 83, 146, 233, 9, 33, 79, 205,
            201, 193, 85, 205, 104, 126, 213, 125, 70, 108, 243, 118, 182, 54, 200, 208, 223, 4,
            138, 164, 154, 166, 2, 232, 165, 211, 111, 105, 86, 156, 56, 47, 224, 204, 59, 235,
            217, 166, 24, 217, 131, 126, 90, 7, 248, 79, 254, 24, 175, 88, 70, 31, 178, 89, 68,
            199, 110, 18, 207, 41, 238, 47, 224, 98, 58, 92, 81, 164, 11, 10, 26, 227, 183, 218,
            83, 99, 7, 190, 245, 126, 133, 186, 64, 31, 250, 218, 172, 105, 201, 65, 184, 87, 185,
            163, 167, 117, 26, 218, 50, 167, 21, 80, 24, 90, 113, 197, 189, 88, 17, 155, 33, 222,
            96, 33, 144,
        ]);
        let blinding_factor = Some(Element::from(generate_fr(
            SALT,
            Some(b"basic_nonmembership_proof_blinding_factor"),
        )));

        let mut acc = Accumulator::new(&sk, 0);
        let elements = [
            Element::hash(b"1"),
            Element::hash(b"2"),
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
        ];
        acc.add_elements_assign(&sk, &elements);
        let nmw =
            NonMembershipWitness::new(&Element::hash(b"basic_nonmembership_proof"), &elements, &sk);

        acc.add_assign(&sk, &Element::hash(b"6"));

        let nmpc = NonMembershipProofCommitting::new(&nmw, acc, proof_params, pk, blinding_factor);
        let challenge = generate_fr(SALT, Some(nmpc.get_bytes_for_challenge().as_slice()));
        let proof = nmpc.gen_proof(challenge);
        let final_proof = proof.finalize(acc, proof_params, pk, Element::from(challenge));

        let challenge2 = generate_fr(SALT, Some(final_proof.get_bytes_for_challenge().as_slice()));
        assert_ne!(challenge, challenge2);
    }
}
