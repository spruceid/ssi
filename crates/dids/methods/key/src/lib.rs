use std::collections::BTreeMap;

use iref::Iri;
use ssi_dids_core::{
    document::{
        self,
        representation::{self, MediaType},
        verification_method::ValueOrReference,
        DIDVerificationMethod,
    },
    resolution::{self, DIDMethodResolver, Error},
    DIDBuf, DIDMethod, DIDURLBuf, Document,
};
use static_iref::iri;

mod json_ld_context;
use json_ld_context::*;
use ssi_jwk::JWK;

const DID_KEY_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];
const DID_KEY_SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
const DID_KEY_BLS12381_G2_PREFIX: [u8; 2] = [0xeb, 0x01];
const DID_KEY_P256_PREFIX: [u8; 2] = [0x80, 0x24];
const DID_KEY_P384_PREFIX: [u8; 2] = [0x81, 0x24];
const DID_KEY_RSA_PREFIX: [u8; 2] = [0x85, 0x24];

#[derive(Debug, thiserror::Error)]
pub enum Unsupported {
    #[error("did:key type secp256k1 not supported")]
    Secp256k1,

    #[error("did:key type P-256 not supported")]
    P256,

    #[error("did:key type P-384 not supported")]
    P384,
}

pub struct DIDKey;

impl DIDKey {
    pub fn generate(jwk: &JWK) -> Option<DIDBuf> {
        use ssi_jwk::Params;
        let id = match jwk.params {
            Params::OKP(ref params) => {
                match &params.curve[..] {
                    "Ed25519" => Some(multibase::encode(
                        multibase::Base::Base58Btc,
                        [DID_KEY_ED25519_PREFIX.to_vec(), params.public_key.0.clone()].concat(),
                    )),
                    "Bls12381G2" => Some(multibase::encode(
                        multibase::Base::Base58Btc,
                        [
                            DID_KEY_BLS12381_G2_PREFIX.to_vec(),
                            params.public_key.0.clone(),
                        ]
                        .concat(),
                    )),
                    //_ => return Some(Err(DIDKeyError::UnsupportedCurve(params.curve.clone()))),
                    _ => return None,
                }
            }
            Params::EC(ref params) => {
                let curve = match params.curve {
                    Some(ref curve) => curve,
                    None => return None,
                };
                match &curve[..] {
                    #[cfg(feature = "secp256k1")]
                    "secp256k1" => {
                        use k256::elliptic_curve::sec1::ToEncodedPoint;
                        let pk = match k256::PublicKey::try_from(params) {
                            Ok(pk) => pk,
                            Err(_err) => return None,
                        };

                        Some(multibase::encode(
                            multibase::Base::Base58Btc,
                            [
                                DID_KEY_SECP256K1_PREFIX.to_vec(),
                                pk.to_encoded_point(true).as_bytes().to_vec(),
                            ]
                            .concat(),
                        ))
                    }
                    #[cfg(feature = "secp256r1")]
                    "P-256" => {
                        use p256::elliptic_curve::sec1::ToEncodedPoint;
                        let pk = match p256::PublicKey::try_from(params) {
                            Ok(pk) => pk,
                            Err(_err) => return None,
                        };

                        Some(multibase::encode(
                            multibase::Base::Base58Btc,
                            [
                                DID_KEY_P256_PREFIX.to_vec(),
                                pk.to_encoded_point(true).as_bytes().to_vec(),
                            ]
                            .concat(),
                        ))
                    }
                    #[cfg(feature = "secp384r1")]
                    "P-384" => {
                        let pk_bytes = match ssi_jwk::serialize_p384(params) {
                            Ok(pk) => pk,
                            Err(_err) => return None,
                        };

                        Some(multibase::encode(
                            multibase::Base::Base58Btc,
                            [DID_KEY_P384_PREFIX.to_vec(), pk_bytes].concat(),
                        ))
                    }
                    //_ => return Some(Err(DIDKeyError::UnsupportedCurve(params.curve.clone()))),
                    _ => return None,
                }
            }
            Params::RSA(ref params) => {
                let der = simple_asn1::der_encode(&params.to_public()).ok()?;
                Some(multibase::encode(
                    multibase::Base::Base58Btc,
                    [DID_KEY_RSA_PREFIX.to_vec(), der.to_vec()].concat(),
                ))
            }
            _ => return None, // _ => return Some(Err(DIDKeyError::UnsupportedKeyType)),
        };

        id.map(|id| DIDBuf::from_string(format!("did:key:{id}")).unwrap())
    }
}

impl DIDMethod for DIDKey {
    const DID_METHOD_NAME: &'static str = "key";
}

impl DIDMethodResolver for DIDKey {
    async fn resolve_method_representation<'a>(
        &'a self,
        id: &'a str,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, Error> {
        let did = DIDBuf::from_string(format!("did:key:{id}")).unwrap();

        let (_base, data) =
            multibase::decode(id).map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?;

        let (public_key, vm_type) = build_public_key(id, &data)?;

        let mut json_ld_context = JsonLdContext::default();
        json_ld_context.add_verification_method_type(vm_type);

        let vm_didurl = DIDURLBuf::from_string(format!("{did}#{id}")).unwrap();

        let mut doc = Document::new(did.to_owned());
        doc.verification_method.push(
            VerificationMethod {
                id: vm_didurl.clone(),
                type_: vm_type,
                controller: did,
                public_key,
            }
            .into(),
        );
        doc.verification_relationships
            .authentication
            .push(ValueOrReference::Reference(vm_didurl.clone().into()));
        doc.verification_relationships
            .assertion_method
            .push(ValueOrReference::Reference(vm_didurl.into()));

        let content_type = options.accept.unwrap_or(MediaType::JsonLd);
        let represented = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || representation::json_ld::Options {
                context: representation::json_ld::Context::array(
                    representation::json_ld::DIDContext::V1,
                    json_ld_context.into_entries(),
                ),
            },
        ));

        Ok(resolution::Output::new(
            represented.to_bytes(),
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(content_type.to_string())),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VerificationMethodType {
    Ed25519VerificationKey2018,
    EcdsaSecp256k1VerificationKey2019,
    EcdsaSecp256r1VerificationKey2019,
    JsonWebKey2020,
    Bls12381G2Key2020,
}

impl VerificationMethodType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ed25519VerificationKey2018 => "Ed25519VerificationKey2018",
            Self::EcdsaSecp256k1VerificationKey2019 => "EcdsaSecp256k1VerificationKey2019",
            Self::EcdsaSecp256r1VerificationKey2019 => "EcdsaSecp256r1VerificationKey2019",
            Self::JsonWebKey2020 => "JsonWebKey2020",
            Self::Bls12381G2Key2020 => "Bls12381G2Key2020",
        }
    }

    pub fn iri(&self) -> &'static Iri {
        match self {
            Self::Ed25519VerificationKey2018 => {
                iri!("https://w3id.org/security#Ed25519VerificationKey2018")
            }
            Self::EcdsaSecp256k1VerificationKey2019 => {
                iri!("https://w3id.org/security#EcdsaSecp256k1VerificationKey2019")
            }
            Self::EcdsaSecp256r1VerificationKey2019 => {
                iri!("https://w3id.org/security#EcdsaSecp256r1VerificationKey2019")
            }
            Self::JsonWebKey2020 => iri!("https://w3id.org/security#JsonWebKey2020"),
            Self::Bls12381G2Key2020 => iri!("https://w3id.org/security#Bls12381G2Key2020"),
        }
    }
}

pub struct VerificationMethod {
    id: DIDURLBuf,
    type_: VerificationMethodType,
    controller: DIDBuf,
    public_key: PublicKey,
}

impl From<VerificationMethod> for DIDVerificationMethod {
    fn from(value: VerificationMethod) -> Self {
        let mut properties = BTreeMap::new();

        match value.public_key {
            PublicKey::Jwk(jwk) => {
                properties.insert(
                    "publicKeyJwk".to_owned(),
                    serde_json::to_value(jwk).unwrap(),
                );
            }
            PublicKey::Base58(key) => {
                properties.insert("publicKeyBase58".to_owned(), key.into());
            }
            PublicKey::Multibase(key) => {
                properties.insert("publicKeyMultibase".to_owned(), key.into());
            }
        }

        Self {
            id: value.id,
            type_: value.type_.name().to_owned(),
            controller: value.controller,
            properties,
        }
    }
}

pub enum PublicKey {
    Jwk(JWK),
    Base58(String),
    Multibase(String),
}

fn build_public_key(id: &str, data: &[u8]) -> Result<(PublicKey, VerificationMethodType), Error> {
    use ssi_jwk::{Base64urlUInt, OctetParams, Params};

    if data.len() < 2 {
        return Err(Error::InvalidMethodSpecificId(id.to_owned()));
    }

    if data[0] == DID_KEY_ED25519_PREFIX[0] && data[1] == DID_KEY_ED25519_PREFIX[1] {
        if data.len() - 2 != 32 {
            return Err(Error::InvalidMethodSpecificId(id.to_owned()));
        }

        // let jwk = JWK {
        //     params: Params::OKP(OctetParams {
        //         curve: "Ed25519".to_string(),
        //         public_key: Base64urlUInt(data[2..].to_vec()),
        //         private_key: None,
        //     }),
        //     public_key_use: None,
        //     key_operations: None,
        //     algorithm: None,
        //     key_id: None,
        //     x509_url: None,
        //     x509_certificate_chain: None,
        //     x509_thumbprint_sha1: None,
        //     x509_thumbprint_sha256: None,
        // };

        let key = bs58::encode(&data[2..]).into_string();

        Ok((
            PublicKey::Base58(key),
            VerificationMethodType::Ed25519VerificationKey2018,
        ))
    } else if data[0] == DID_KEY_SECP256K1_PREFIX[0] && data[1] == DID_KEY_SECP256K1_PREFIX[1] {
        if data.len() - 2 != 33 {
            return Err(Error::InvalidMethodSpecificId(id.to_owned()));
        }

        #[cfg(feature = "secp256k1")]
        match ssi_jwk::secp256k1_parse(&data[2..]) {
            Ok(jwk) => Ok((
                PublicKey::Jwk(jwk),
                VerificationMethodType::EcdsaSecp256k1VerificationKey2019,
            )),
            Err(_) => Err(Error::InvalidMethodSpecificId(id.to_owned())),
        }
        #[cfg(not(feature = "secp256k1"))]
        Err(Error::Internal(Box::new(Unsupported::Secp256k1)))
    } else if data[0] == DID_KEY_P256_PREFIX[0] && data[1] == DID_KEY_P256_PREFIX[1] {
        #[cfg(feature = "secp256r1")]
        {
            let encoded_key =
                ssi_multicodec::MultiEncodedBuf::encode(ssi_multicodec::P256_PUB, &data[2..]);
            let multibase_key =
                multibase::encode(multibase::Base::Base58Btc, encoded_key.as_bytes());

            Ok((
                PublicKey::Multibase(multibase_key),
                VerificationMethodType::EcdsaSecp256r1VerificationKey2019,
            ))
        }
        #[cfg(not(feature = "secp256r1"))]
        return Err(Error::Internal(Box::new(Unsupported::P256)));
    } else if data[0] == DID_KEY_P384_PREFIX[0] && data[1] == DID_KEY_P384_PREFIX[1] {
        #[cfg(feature = "secp384r1")]
        match ssi_jwk::p384_parse(&data[2..]) {
            Ok(jwk) => Ok((PublicKey::Jwk(jwk), VerificationMethodType::JsonWebKey2020)),
            Err(_) => Err(Error::InvalidMethodSpecificId(id.to_owned())),
        }
        #[cfg(not(feature = "secp384r1"))]
        Err(Error::Internal(Box::new(Unsupported::P384)))
    } else if data[0] == DID_KEY_RSA_PREFIX[0] && data[1] == DID_KEY_RSA_PREFIX[1] {
        match ssi_jwk::rsa_x509_pub_parse(&data[2..]) {
            Ok(jwk) => Ok((PublicKey::Jwk(jwk), VerificationMethodType::JsonWebKey2020)),
            Err(_) => Err(Error::InvalidMethodSpecificId(id.to_owned())),
        }
    } else if data[0] == DID_KEY_BLS12381_G2_PREFIX[0] && data[1] == DID_KEY_BLS12381_G2_PREFIX[1] {
        if data.len() - 2 != 96 {
            return Err(Error::InvalidMethodSpecificId(id.to_owned()));
        }

        let jwk = JWK::from(Params::OKP(OctetParams {
            curve: "Bls12381G2".to_string(),
            public_key: Base64urlUInt(data[2..].to_vec()),
            private_key: None,
        }));

        // https://datatracker.ietf.org/doc/html/draft-denhartog-pairing-curves-jose-cose-00#section-3.1.3
        // FIXME: This should be a base 58 key according to the spec.
        Ok((
            PublicKey::Jwk(jwk),
            VerificationMethodType::Bls12381G2Key2020,
        ))
    } else {
        Err(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::rand_core::SeedableRng as SeedableRngOld;
    use rand_chacha_old::rand_core::SeedableRng;
    use ssi_claims::vc::{
        data_integrity::{AnyInputContext, AnySuite, AnySuiteOptions},
        Claims, JsonCredential,
    };
    use ssi_dids_core::{did, resolution::Options, DIDResolver, DIDVerifier, DIDURL};
    use ssi_vc_data_integrity::{
        verification::{
            method::{signer::SingleSecretSigner, ProofPurpose},
            MethodReferenceOrOwned,
        },
        CryptographicSuiteInput, ProofConfiguration,
    };
    use static_iref::uri;

    use super::*;
    // use ssi_dids_core::did_resolve::{dereference, Content, DereferencingInputMetadata};
    // use ssi_dids_core::Resource;

    #[async_std::test]
    async fn from_did_key() {
        let did_url = DIDURL::new(b"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
        let output = DIDKey.dereference(did_url).await.unwrap();
        let vm = output.content.into_verification_method().unwrap();
        vm.properties.get("publicKeyBase58").unwrap();
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn from_did_key_secp256k1() {
        let did = did!("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme");
        DIDKey.resolve_with(did, Options::default()).await.unwrap();

        let did_url = DIDURL::new(b"did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme#zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme").unwrap();
        let output = DIDKey.dereference(did_url).await.unwrap();
        let mut vm = output.content.into_verification_method().unwrap();
        let key: JWK =
            serde_json::from_value(vm.properties.remove("publicKeyJwk").unwrap()).unwrap();

        // convert back to DID from JWK
        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[cfg(feature = "secp256r1")]
    #[async_std::test]
    async fn from_did_key_p256() {
        // https://w3c-ccg.github.io/did-method-key/#p-256
        let did = did!("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169");
        DIDKey.resolve_with(did, Options::default()).await.unwrap();

        let did_url = DIDURL::new(b"did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169").unwrap();
        let output = DIDKey.dereference(did_url).await.unwrap();
        let vm = output.content.into_verification_method().unwrap();
        let multibase_key = vm
            .properties
            .get("publicKeyMultibase")
            .unwrap()
            .as_str()
            .unwrap();
        let (base, encoded_key) = multibase::decode(multibase_key).unwrap();
        assert_eq!(base, multibase::Base::Base58Btc);
        let encoded_key = ssi_multicodec::MultiEncodedBuf::new(encoded_key).unwrap();
        assert_eq!(encoded_key.codec(), ssi_multicodec::P256_PUB);
        let key = ssi_jwk::JWK::from_multicodec(&encoded_key).unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        // https://github.com/w3c-ccg/did-method-key/blob/master/test-vectors/nist-curves.json#L64-L69
        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
            "y": "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[async_std::test]
    async fn from_did_key_bls() {
        // https://w3c-ccg.github.io/did-method-key/#bls-12381
        let did = did!("did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY");
        DIDKey.resolve_with(did, Options::default()).await.unwrap();

        let did_url = DIDURL::new(b"did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY#zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY").unwrap();
        let output = DIDKey.dereference(did_url).await.unwrap();
        let mut vm = output.content.into_verification_method().unwrap();
        let key: JWK =
            serde_json::from_value(vm.properties.remove("publicKeyJwk").unwrap()).unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        // Note: this "x" value is generated by this implementation - not yet confirmed with other
        // implementations.
        // Related issue: https://github.com/mattrglobal/bls12381-jwk-draft/issues/5
        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Bls12381G2",
            "x": "tKWJu0SOY7onl4tEyOOH11XBriQN2JgzV-UmjgBMSsNkcAx3_l97SVYViSDBouTVBkBfrLh33C5icDD-4UEDxNO3Wn1ijMHvn2N63DU4pkezA3kGN81jGbwbrsMPpiOF"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    #[async_std::test]
    async fn from_did_key_rsa() {
        let did = did!("did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i");
        DIDKey.resolve_with(did, Options::default()).await.unwrap();

        let vm = DIDURL::new(b"did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i#z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i").unwrap();
        let output = DIDKey.dereference(vm).await.unwrap();
        let mut vm = output.content.into_verification_method().unwrap();
        let key: JWK =
            serde_json::from_value(vm.properties.remove("publicKeyJwk").unwrap()).unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "e": "AQAB",
            "n": "sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey::generate(&key).unwrap();
        assert_eq!(did1, did);
    }

    // #[derive(Clone, serde::Serialize, linked_data::Serialize)]
    // #[ld(prefix("cred" = "https://www.w3.org/2018/credentials#"))]
    // #[ld(type = "cred:VerifiableCredential")]
    // #[serde(rename_all = "camelCase")]
    // struct TestCredential {
    //     #[ld(id)]
    //     id: Option<IriBuf>,

    //     #[ld("cred:issuer")]
    //     issuer: IriBuf,

    //     #[ld("cred:issuanceDate")]
    //     issuance_date: xsd_types::DateTime,

    //     #[ld("cred:credentialSubject")]
    //     credential_subject: CredentialSubject,
    // }

    // #[derive(Clone, serde::Serialize, linked_data::Serialize)]
    // struct CredentialSubject {
    //     #[ld(id)]
    //     id: IriBuf,
    // }

    #[async_std::test]
    async fn credential_prove_verify_did_key() {
        let didkey = DIDVerifier::new(DIDKey);

        let mut rng = rand_chacha_old::ChaCha8Rng::seed_from_u64(2);
        let key = JWK::generate_ed25519_from(&mut rng).unwrap();
        let did = DIDKey::generate(&key).unwrap();

        let cred = JsonCredential::new(
            Some(uri!("http://example.org/credentials/3731").to_owned()),
            did.clone().into_uri().into(),
            "2020-08-19T21:41:50Z".parse().unwrap(),
            vec![json_syntax::json!({
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            })],
        );

        let verification_method = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let verification_method_ref =
            MethodReferenceOrOwned::Reference(verification_method.id.into());
        // issue_options.verification_method = Some(URI::String(verification_method));
        let suite = AnySuite::pick(&key, Some(&verification_method_ref)).unwrap();

        let issue_options = ProofConfiguration {
            created: "2020-08-19T21:41:50Z".parse().unwrap(),
            verification_method: verification_method_ref,
            proof_purpose: ProofPurpose::Assertion,
            options: AnySuiteOptions::default(),
        };
        let signer = SingleSecretSigner::new(&didkey, key);
        let vc = suite
            .sign(cred, AnyInputContext::default(), &signer, issue_options)
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(vc.proof()).unwrap()
        );
        assert_eq!(vc.proof().first().unwrap().signature().jws.as_ref().unwrap().as_str(), "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..o4SzDo1RBQqdK49OPdmfVRVh68xCTNEmb7hq39IVqISkelld6t6Aatg4PCXKpopIXmX8RCCF4BwrO8ERg1YFBg");
        assert!(vc.verify(&didkey).await.unwrap().is_valid());

        // test that issuer is verified
        let vc_bad_issuer = Claims::tamper(vc.clone(), AnyInputContext::default(), |mut cred| {
            cred.issuer = uri!("did:pkh:example:bad").to_owned().into();
            cred
        })
        .await
        .unwrap();
        // It should fail.
        assert!(vc_bad_issuer.verify(&didkey).await.unwrap().is_invalid());
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn credential_prove_verify_did_key_secp256k1() {
        let didkey = DIDVerifier::new(DIDKey);

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let key = JWK::generate_secp256k1_from(&mut rng).unwrap();
        let did = DIDKey::generate(&key).unwrap();

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:17:46Z".parse().unwrap(),
            vec![json_syntax::json!({
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            })],
        );

        let verification_method = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let verification_method_ref =
            MethodReferenceOrOwned::Reference(verification_method.id.into());
        // issue_options.verification_method = Some(URI::String(verification_method));
        let suite = AnySuite::pick(&key, Some(&verification_method_ref)).unwrap();
        eprintln!("suite: {suite:?}");
        let issue_options = ProofConfiguration {
            created: "2021-02-18T20:17:46Z".parse().unwrap(),
            verification_method: verification_method_ref,
            proof_purpose: ProofPurpose::Assertion,
            options: AnySuiteOptions::default(),
        };
        let signer = SingleSecretSigner::new(&didkey, key);
        let vc = suite
            .sign(cred, AnyInputContext::default(), &signer, issue_options)
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(vc.proof()).unwrap()
        );
        assert_eq!(vc.proof().first().unwrap().signature().jws.as_ref().unwrap().as_str(), "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..jTUkFd_eYI72Y8j2OS5LRLhlc3gZn-gVsb76soi3FuJ5gWrbOb0W2CW6D-sjEsCuLkvSOfYd8Y8hB9pyeeZ2TQ");
        assert!(vc.verify(&didkey).await.unwrap().is_valid());

        // test that issuer is verified
        let vc_bad_issuer = Claims::tamper(vc.clone(), AnyInputContext::default(), |mut cred| {
            cred.issuer = uri!("did:pkh:example:bad").to_owned().into();
            cred
        })
        .await
        .unwrap();
        // It should fail.
        assert!(vc_bad_issuer.verify(&didkey).await.unwrap().is_invalid());
    }

    #[async_std::test]
    #[cfg(feature = "secp256r1")]
    async fn credential_prove_verify_did_key_p256() {
        let didkey = DIDVerifier::new(DIDKey);

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let key = JWK::generate_p256_from(&mut rng);
        let did = DIDKey::generate(&key).unwrap();

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:17:46Z".parse().unwrap(),
            vec![json_syntax::json!({
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            })],
        );

        let verification_method = DIDKey
            .resolve_into_any_verification_method(&did)
            .await
            .unwrap()
            .unwrap();
        let verification_method_ref =
            MethodReferenceOrOwned::Reference(verification_method.id.into());
        // issue_options.verification_method = Some(URI::String(verification_method));
        let suite = AnySuite::pick(&key, Some(&verification_method_ref)).unwrap();
        eprintln!("suite: {suite:?}");
        let issue_options = ProofConfiguration {
            created: "2021-02-18T20:17:46Z".parse().unwrap(),
            verification_method: verification_method_ref,
            proof_purpose: ProofPurpose::Assertion,
            options: AnySuiteOptions::default(),
        };
        let signer = SingleSecretSigner::new(&didkey, key);
        let vc = suite
            .sign(cred, AnyInputContext::default(), &signer, issue_options)
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(vc.proof()).unwrap()
        );
        assert!(vc.verify(&didkey).await.unwrap().is_valid());

        // test that issuer is verified
        let vc_bad_issuer = Claims::tamper(vc.clone(), AnyInputContext::default(), |mut cred| {
            cred.issuer = uri!("did:pkh:example:bad").to_owned().into();
            cred
        })
        .await
        .unwrap();
        // It should fail.
        assert!(vc_bad_issuer.verify(&didkey).await.unwrap().is_invalid());
    }
}
