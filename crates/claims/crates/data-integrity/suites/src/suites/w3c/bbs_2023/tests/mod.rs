use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    hash::Hash,
};

use iref::Iri;
use json_syntax::Parse;
use lazy_static::lazy_static;
use rdf_types::{BlankIdBuf, VocabularyMut};
use serde::{Deserialize, Serialize};
use ssi_bbs::{BBSplusPublicKey, BBSplusSecretKey};
use ssi_claims_core::{ClaimsValidity, ValidateClaims};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject};
use static_iref::iri;

/// JSON Credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: ssi_json_ld::syntax::Context,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: Vec<String>,

    #[serde(flatten)]
    pub properties: BTreeMap<String, json_syntax::Value>,
}

impl JsonLdObject for JsonCredential {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(&self.context))
    }
}

impl JsonLdNodeObject for JsonCredential {
    fn json_ld_type(&self) -> JsonLdTypes {
        JsonLdTypes::new(&[], Cow::Borrowed(&self.types))
    }
}

impl<E, P> ValidateClaims<E, P> for JsonCredential {
    fn validate_claims(&self, _env: &E, _proof: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl ssi_json_ld::Expandable for JsonCredential {
    type Error = JsonLdError;

    type Expanded<I, V> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    #[allow(async_fn_in_trait)]
    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl ssi_json_ld::Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        let json = ssi_json_ld::CompactJsonLd(json_syntax::to_value(self).unwrap());
        json.expand_with(ld, loader).await
    }
}

pub const VERIFICATION_METHOD_IRI: &Iri = iri!("did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ#zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ");

pub const HMAC_KEY_STRING: &str =
    "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

pub const PUBLIC_KEY_HEX: &str = "a4ef1afa3da575496f122b9b78b8c24761531a8a093206ae7c45b80759c168ba4f7a260f9c3367b6c019b4677841104b10665edbe70ba3ebe7d9cfbffbf71eb016f70abfbb163317f372697dc63efd21fc55764f63926a8f02eaea325a2a888f";
pub const SECRET_KEY_HEX: &str = "66d36e118832af4c5e28b2dfe1b9577857e57b042a33e06bdea37b811ed09ee0";

pub const PRESENTATION_HEADER_HEX: &str = "113377aa";

// TODO this can't be used because the BBS API (based on zkryptium) does not
// allow providing a seed.
// pub const PSEUDO_RANDOM_SEED_HEX: &str = "332e313431353932363533353839373933323338343632363433333833323739";

pub const BBS_PROOF_HEX: &str = "85b72d74b55aae76e4f8e986387352f6d3e13f19387f5935a9f34c59aa3af77885501ef1dba67576bd24e6dab1b1c5b3891671112c26982c441d4f352e1bc8f5451127fbda2ad240d9a5d6933f455db741cc3e79d3281bc5b611118b363461f2b6a5ecdd423f6b76711680824665f50eec1f5cbaf219ee90e66ceac575146d1a8935f770be6d29a376b00e4e39a4fa7755ecf4eb42aa3babfd6e48bb23e91081f08d0d259b4029683d01c25378be3c61213a097750b8ce2a3c0915061a547405b3ce587d1d8299269fad29103509b3e53067f7b6078e9dc66a5112192aede3662e6dac5876d945fd05863fb249b0fca02e10ab5173650ef665e92c3ea72eaba94fca860cd6c639538e5156f8cbc3b4d222f7a11f837bb9e76ba54d58c1b4ac834ef338a3db4bf645b4622153c897f477255f40e4fcc7919348ae5bf9032a9f7c0876e47a6666ca9f178673ac7a41b864480d8e84c6655cd2f0e1866dedc467590a2ba76c28cb41f3d5582e0773b737914b8353fea4df918a022aa5aa92f490f0b3c2edf4a4d5538b8d07aa2530f118863e654eeaaac69c2c020509c24294c13bda721c73b8610bbce7e7030d1710dd5148731a5026c741d1da9e0693d32b90d09bb58a8e4a295a32fb27f654a03c31c56e6c3afb1aa3f2fa240f5095f31fe8b95f8179bc4408cf96713f3aec6a06409a6f1486a99d9923befdb274d3e04f6faa9bf316ce9a2c4f5e1bc6db031593323b";

lazy_static! {
    pub static ref MANDATORY_POINTERS: Vec<JsonPointerBuf> = vec![
        "/issuer".parse().unwrap(),
        "/credentialSubject/sailNumber".parse().unwrap(),
        "/credentialSubject/sails/1".parse().unwrap(),
        "/credentialSubject/boards/0/year".parse().unwrap(),
        "/credentialSubject/sails/2".parse().unwrap()
    ];
    pub static ref SELECTIVE_POINTERS: [JsonPointerBuf; 2] = [
        "/credentialSubject/boards/0".parse().unwrap(),
        "/credentialSubject/boards/1".parse().unwrap()
    ];
    pub static ref UNSIGNED_BASE_DOCUMENT: JsonCredential =
        serde_json::from_str(include_str!("unsigned-base-document.jsonld")).unwrap();
    pub static ref SIGNED_BASE_DOCUMENT: json_syntax::Object =
        json_syntax::Value::parse_str(include_str!("signed-base-document.jsonld"))
            .unwrap()
            .0
            .into_object()
            .unwrap();
    pub static ref UNSIGNED_REVEAL_DOCUMENT: json_syntax::Object =
        json_syntax::Value::parse_str(include_str!("unsigned-reveal-document.jsonld"))
            .unwrap()
            .0
            .into_object()
            .unwrap();
    pub static ref PUBLIC_KEY: BBSplusPublicKey =
        BBSplusPublicKey::from_bytes(&hex::decode(PUBLIC_KEY_HEX).unwrap()).unwrap();
    pub static ref SECRET_KEY: BBSplusSecretKey =
        BBSplusSecretKey::from_bytes(&hex::decode(SECRET_KEY_HEX).unwrap()).unwrap();
    pub static ref PRESENTATION_HEADER: Vec<u8> = hex::decode(PRESENTATION_HEADER_HEX).unwrap();
    pub static ref LABEL_MAP: HashMap<BlankIdBuf, BlankIdBuf> = [
        ("_:c14n0".parse().unwrap(), "_:b2".parse().unwrap()),
        ("_:c14n1".parse().unwrap(), "_:b4".parse().unwrap()),
        ("_:c14n2".parse().unwrap(), "_:b3".parse().unwrap()),
        ("_:c14n3".parse().unwrap(), "_:b7".parse().unwrap()),
        ("_:c14n4".parse().unwrap(), "_:b6".parse().unwrap()),
        ("_:c14n5".parse().unwrap(), "_:b0".parse().unwrap())
    ]
    .into_iter()
    .collect();
    pub static ref BBS_PROOF: Vec<u8> = hex::decode(BBS_PROOF_HEX).unwrap();
}
