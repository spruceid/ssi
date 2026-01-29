use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, InvalidClaims, ValidateClaims};
use ssi_jwk::Algorithm;
use ssi_jws::{JwsPayload, ValidateJwsHeader};
use ssi_jwt::{Claim, ExpirationTime, IssuedAt, Nonce, NotBefore};

use crate::{SdAlg, SdJwt};

/// Value of the `typ` JOSE header of a KB-JWT.
pub const KB_JWT_TYP: &str = "kb+jwt";

/// KB-JWT payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbJwtPayload<T = serde_json::Map<String, serde_json::Value>> {
    /// Issuance date.
    pub iat: IssuedAt,

    /// Audience.
    pub aud: String,

    /// Nonce.
    pub nonce: Nonce,

    /// Hashing algorithm.
    pub sd_hash: SdHash,

    /// Expiration date.
    pub exp: Option<ExpirationTime>,

    /// Validity start date.
    pub nbf: Option<NotBefore>,

    /// Other claims.
    #[serde(flatten)]
    pub claims: T,
}

impl KbJwtPayload {
    /// Creates a new KB-JWT payload.
    pub fn new(aud: String, nonce: String, sd_alg: SdAlg, sd_jwt: &SdJwt) -> Self {
        Self {
            iat: IssuedAt::now(),
            aud,
            nonce: Nonce(nonce),
            sd_hash: SdHash::new(sd_alg, sd_jwt),
            exp: None,
            nbf: None,
            claims: Default::default(),
        }
    }
}

impl JwsPayload for KbJwtPayload {
    fn typ(&self) -> Option<&str> {
        Some(KB_JWT_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl<E> ValidateJwsHeader<E> for KbJwtPayload {
    fn validate_jws_header(&self, _params: &E, header: &ssi_jws::Header) -> ClaimsValidity {
        if header.type_.as_deref() != Some(KB_JWT_TYP) {
            return Err(InvalidClaims::other("invalid JWT type"));
        }

        if header.algorithm == Algorithm::None {
            return Err(InvalidClaims::other("algorithm can't be `none`"));
        }

        Ok(())
    }
}

impl<E, P> ValidateClaims<E, P> for KbJwtPayload
where
    E: DateTimeProvider,
{
    fn validate_claims(&self, params: &E, _proof: &P) -> ClaimsValidity {
        let now = params.date_time();

        self.iat.verify(now)?;

        if let Some(nbf) = &self.nbf {
            nbf.verify(now)?;
        }

        if let Some(exp) = &self.exp {
            exp.verify(now)?;
        }

        Ok(())
    }
}

/// KB-JWT `sd_hash` claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SdHash(pub String);

impl SdHash {
    /// Creates a new hash.
    pub fn new(sd_alg: SdAlg, sd_jwt: &SdJwt) -> Self {
        Self(sd_alg.hash(sd_jwt.trim_kb().as_bytes()))
    }

    /// Verifies the hash.
    pub fn verify(&self, alg: SdAlg, sd_jwt: &SdJwt) -> bool {
        alg.verify(sd_jwt.trim_kb().as_bytes(), &self.0)
    }
}

impl Claim for SdHash {
    const JWT_CLAIM_NAME: &str = "sd_hash";
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use serde::Deserialize;
    use serde_json::json;
    use ssi_claims_core::{ValidateClaims, VerificationParameters};
    use ssi_core::JsonPointerBuf;
    use ssi_jwk::JWK;
    use ssi_jws::JwsPayload;
    use ssi_jwt::{ClaimSet, JWTClaims};

    use crate::{sd_jwt, ConcealJwtClaims, KbJwtPayload, SdAlg, SdJwt};

    #[async_std::test]
    async fn kb_sign() {
        let claims = JWTClaims::builder()
            .iss("https://example.com/issuer")
            .iat(1683000000)
            .exp(1883000000)
            .sub("user_42")
            .build()
            .unwrap();

        let jwk = JWK::generate_p256();
        let cnf_jwk = JWK::generate_p256();

        let pointers: &[JsonPointerBuf] = &[];
        let mut sd_jwt = claims
            .conceal_and_sign(SdAlg::Sha256, pointers, &jwk)
            .await
            .unwrap();

        let kb_jwt = KbJwtPayload::new(
            "issuer".to_owned(),
            "123nonce".to_owned(),
            SdAlg::Sha256,
            &sd_jwt,
        )
        .sign(&cnf_jwk)
        .await
        .unwrap();

        sd_jwt.set_kb(&kb_jwt);

        // SD-JWT+KB is ready. Now we verify it.

        let params = VerificationParameters::from_resolver(&jwk);
        let (revealed, verification_result) =
            sd_jwt.decode_reveal_verify_any(&params).await.unwrap();

        verification_result.expect("SD-JWT verification failed");

        // Decode the KB-JWT part.
        let kb_jwt = sd_jwt
            .decode_kb()
            .expect("invalid KB-JWT")
            .expect("missing KB-JWT");

        // Verify the KB-JWT claims.
        let kb_jwt_claims = &kb_jwt.signing_bytes.payload;
        assert_eq!(kb_jwt_claims.aud, "issuer");
        assert_eq!(kb_jwt_claims.nonce.0, "123nonce");
        assert!(kb_jwt_claims.sd_hash.verify(revealed.sd_alg, &sd_jwt));

        // Verify the KB-JWT signature (and expiration status).
        let params = VerificationParameters::from_resolver(cnf_jwk);
        kb_jwt
            .verify(&params)
            .await
            .expect("KB-JWT verification failed")
            .expect("invalid KB-JWT signature");
    }

    #[async_std::test]
    async fn kb_verify() {
        let params = VerificationParameters::from_resolver(&*JWK);

        // Decode and verify the SD-JWT.
        let (revealed, verification_result) = SD_JWT_KB
            .decode_reveal_verify::<ExampleClaims, _>(&params)
            .await
            .unwrap();

        let cnf_jwk = &revealed.jwt.signing_bytes.payload.private.cnf.jwk;

        verification_result.expect("SD-JWT verification failed");

        // Decode the KB-JWT part.
        let kb_jwt = SD_JWT_KB
            .decode_kb()
            .expect("invalid KB-JWT")
            .expect("missing KB-JWT");

        // Verify the KB-JWT claims.
        let kb_jwt_claims = &kb_jwt.signing_bytes.payload;
        assert_eq!(kb_jwt_claims.aud, "https://verifier.example.org");
        assert_eq!(kb_jwt_claims.nonce.0, "1234567890");
        assert!(kb_jwt_claims.sd_hash.verify(revealed.sd_alg, SD_JWT_KB));

        // Verify the KB-JWT signature (and expiration status).
        let params = VerificationParameters::from_resolver(cnf_jwk);
        kb_jwt
            .verify(&params)
            .await
            .expect("KB-JWT verification failed")
            .expect("invalid KB-JWT signature");
    }

    static JWK: LazyLock<JWK> = LazyLock::new(|| {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
        })
        .try_into()
        .unwrap()
    });

    const SD_JWT_KB: &SdJwt = sd_jwt!("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz-CXo6R04b7jYrpj9mNRAvVssXou1iw~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIjBfQWYtMkItRWhMV1g1eWRoX3cyeHp3bU82aU02NkJfMlFDRWFuSTRmVVkifQ.T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm261eLiJ1YiuONFiMN8QlCmYzDlBLAdPvrXh52KaLgUQ");

    #[derive(Debug, PartialEq, Deserialize)]
    struct ExampleAddress {
        street_address: Option<String>,
        locality: Option<String>,
        region: Option<String>,
        country: Option<String>,
    }

    #[derive(Debug, PartialEq, Deserialize)]
    struct ExampleClaims {
        cnf: Cnf,
        given_name: Option<String>,
        family_name: Option<String>,
        email: Option<String>,
        phone_number: Option<String>,
        address: ExampleAddress,
        birthdate: Option<String>,
    }

    #[derive(Debug, PartialEq, Deserialize)]
    struct Cnf {
        jwk: JWK,
    }

    impl ClaimSet for ExampleClaims {}
    impl<E, P> ValidateClaims<E, P> for ExampleClaims {}
}
