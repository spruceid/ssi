use bbs::prelude::*;
use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand_old::prelude::*;
use serde::de::Error;
use serde::{
    de::{Error as DError, SeqAccess, Unexpected, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;

// This shows how the generators are created with nothing up my sleeve values
// const PREHASH: &'static [u8] = b"To be, or not to be- that is the question:
// Whether 'tis nobler in the mind to suffer
// The slings and arrows of outrageous fortune
// Or to take arms against a sea of troubles,
// And by opposing end them. To die- to sleep-
// No more; and by a sleep to say we end
// The heartache, and the thousand natural shocks
// That flesh is heir to. 'Tis a consummation
// Devoutly to be wish'd. To die- to sleep.
// To sleep- perchance to dream: ay, there's the rub!
// For in that sleep of death what dreams may come
// When we have shuffled off this mortal coil,
// Must give us pause. There's the respect
// That makes calamity of so long life.
// For who would bear the whips and scorns of time,
// Th' oppressor's wrong, the proud man's contumely,
// The pangs of despis'd love, the law's delay,
// The insolence of office, and the spurns
// That patient merit of th' unworthy takes,
// When he himself might his quietus make
// With a bare bodkin? Who would these fardels bear,
// To grunt and sweat under a weary life,
// But that the dread of something after death-
// The undiscover'd country, from whose bourn
// No traveller returns- puzzles the will,
// And makes us rather bear those ills we have
// Than fly to others that we know not of?
// Thus conscience does make cowards of us all,
// And thus the native hue of resolution
// Is sicklied o'er with the pale cast of thought,
// And enterprises of great pith and moment
// With this regard their currents turn awry
// And lose the name of action.- Soft you now!
// The fair Ophelia!- Nymph, in thy orisons
// Be all my sins rememb'red.";
// const DST_G1: &'static [u8] = b"BLS12381G1_XMD:BLAKE2B_SSWU_RO_BLS_SIGNATURES:1_0_0";
// const DST_G2: &'static [u8] = b"BLS12381G2_XMD:BLAKE2B_SSWU_RO_BLS_SIGNATURES:1_0_0";
//
// fn main() {
//     let g1 = <G1 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(PREHASH, DST_G1);
//     let g2 = <G2 as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(PREHASH, DST_G2);
//
//     let mut g1_bytes = Vec::new();
//     let mut g2_bytes = Vec::new();
//
//     g1.serialize(&mut g1_bytes, true).unwrap();
//     g2.serialize(&mut g2_bytes, true).unwrap();
//
//     println!("g1 = {}", hex::encode(g1_bytes.as_slice()));
//     println!("g2 = {}", hex::encode(g2_bytes.as_slice()));
// }
// g1 = b9c9058e8a44b87014f98be4e1818db718f8b2d5101fc89e6983625f321f14b84d7cf6e155004987a215ee426df173c9
// g2 = a963de2adfb1163cf4bed24d708ce47432742d2080b2573ebe2e19a8698f60c541cec000fcb19783e9be73341356df5f1191cddec7c476d7742bcc421afc5d505e63373c627ea01fda04f0e40159d25bdd12f45a010d8580a78f6a7d262272f3

const BLINDING_G1: &'static [u8] = &[
    185, 201, 5, 142, 138, 68, 184, 112, 20, 249, 139, 228, 225, 129, 141, 183, 24, 248, 178, 213,
    16, 31, 200, 158, 105, 131, 98, 95, 50, 31, 20, 184, 77, 124, 246, 225, 85, 0, 73, 135, 162,
    21, 238, 66, 109, 241, 115, 201,
];
const BLINDING_G2: &'static [u8] = &[
    169, 99, 222, 42, 223, 177, 22, 60, 244, 190, 210, 77, 112, 140, 228, 116, 50, 116, 45, 32,
    128, 178, 87, 62, 190, 46, 25, 168, 105, 143, 96, 197, 65, 206, 192, 0, 252, 177, 151, 131,
    233, 190, 115, 52, 19, 86, 223, 95, 17, 145, 205, 222, 199, 196, 118, 215, 116, 43, 204, 66,
    26, 252, 93, 80, 94, 99, 55, 60, 98, 126, 160, 31, 218, 4, 240, 228, 1, 89, 210, 91, 221, 18,
    244, 90, 1, 13, 133, 128, 167, 143, 106, 125, 38, 34, 114, 243,
];

/// A Bls and BBS+ secret key
#[derive(Clone, Debug)]
pub struct BlsSecretKey(pub Fr);

impl From<SecretKey> for BlsSecretKey {
    fn from(x: SecretKey) -> Self {
        unsafe { std::mem::transmute(x) }
    }
}

impl Zeroize for BlsSecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for BlsSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for BlsSecretKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ss = s.serialize_tuple(32)?;
        let mut bytes = [0u8; 32];
        self.0.serialize(&mut bytes.as_mut(), true).unwrap();
        for b in &bytes {
            ss.serialize_element(b)?;
        }
        ss.end()
    }
}

impl<'de> Deserialize<'de> for BlsSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, dyn DError>
    where
        D: Deserializer<'de>,
    {
    }
}

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fr
/// and public key `W` = `G2` * `x` * `Blinding_G2` * `r`
pub fn bls_generate_blinded_g2_key() -> BlsKeyPair<G2> {
    bls_generate_keypair(None, Some(BLINDING_G2))
}

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fr
/// and public key `W` = `G1` * `x` * `Blinding_G1` * `r`
pub fn bls_generate_blinded_g1_key() -> BlsKeyPair<G1> {
    bls_generate_keypair(None, Some(BLINDING_G1))
}

/// Generate a BLS key pair where secret key `x` in Fr
/// and public key `W` = `G1` * `x`
pub fn bls_generate_g2_key() -> BlsKeyPair<G2> {
    bls_generate_keypair(None, None)
}

/// Generate a BLS key pair where secret key `x` in Fr
/// and public key `W` = `G1` * `x`
pub fn bls_generate_g1_key() -> BlsKeyPair<G1> {
    bls_generate_keypair(None, None)
}

/// A BLS public key where the public key can be either in G1 or G2
#[derive(Copy, Clone, Debug)]
pub struct BlsPublicKey<G: CurveProjective<Engine = Bls12, Scalar = Fr>>(pub G);

impl<G: CurveProjective<Engine = Bls12, Scalar = Fr>> Zeroize for BlsPublicKey<G> {
    fn zeroize(&mut self) {
        let tv = self.0;
        self.0.sub_assign(&tv);
    }
}

impl BlsPublicKey<G2> {
    pub fn to_bbs_public_key(&self, message_count: usize) -> PublicKey {
        let dpk = DeterministicPublicKey::from(self.0);
        dpk.to_public_key(message_count).unwrap()
    }
}

/// A BLS keypair where the public key can be in either G1 or G2
pub struct BlsKeyPair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes> {
    pub secret_key: BlsSecretKey,
    pub public_key: BlsPublicKey<G>,
    pub blinder: Option<Fr>,
}

impl<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes> BlsKeyPair<G> {
    pub fn new(seed: Option<&[u8]>, blinder: Option<&[u8]>) -> Self {
        bls_generate_keypair(seed, blinder)
    }
}

impl From<BlsSecretKey> for SecretKey {
    fn from(k: BlsSecretKey) -> Self {
        SecretKey::from(k.0)
    }
}

impl BlsSecretKey {
    pub fn to_bbs_public_key(&self, message_count: usize) -> PublicKey {
        let mut g2 = G2::one();
        g2.mul_assign(&sk.0);
        let dpk = DeterministicPublicKey::from(g2);
        dpk.to_public_key(message_count).unwrap()
    }
}

fn bls_generate_keypair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    seed: Option<&[u8]>,
    blinder: Option<&[u8]>,
) -> BlsKeyPair<G> {
    let mut passed_seed = seed.is_some();
    let seed = match seed {
        Some(arg) => {
            passed_seed = true;
            arg.to_vec()
        }
        None => {
            let mut rng = thread_rng();
            let mut seed_data = vec![0u8, 32];
            rng.fill_bytes(seed_data.as_mut_slice());
            seed_data
        }
    };

    let sk = gen_sk(seed.as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let r = match blinder {
        Some(g) => {
            let mut data = g.to_vec();
            let mut gg = g.clone();
            if passed_seed {
                data.extend_from_slice(seed.as_slice());
            } else {
                let mut rng = thread_rng();
                let mut blinding_factor = vec![0u8, 32];
                rng.fill_bytes(blinding_factor.as_mut_slice());
                data.extend_from_slice(blinding_factor.as_slice());
            }
            let mut blinding_g = G::deserialize(&mut gg, true).unwrap();
            let r = gen_sk(data.as_slice());
            blinding_g.mul_assign(r);
            pk.add_assign(&blinding_g);
            Some(r)
        }
        None => None,
    };

    BlsKeyPair {
        secret_key: BlsSecretKey(sk),
        public_key: BlsPublicKey(pk),
        blinder: r,
    }
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2_old::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(
        hkdf::Hkdf::<sha2_old::Sha256>::new(Some(SALT), &msg_prime[..])
            .expand(&[0, 48], &mut result)
            .is_ok()
    );
    Fr::from_okm(&result)
}
