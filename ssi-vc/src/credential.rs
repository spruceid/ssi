use std::collections::BTreeMap;

use iref::{Iri, IriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};
use ssi_core::one_or_many::OneOrMany;
use static_iref::iri_ref;

/// Generic credential type.
#[derive(Debug, Default, Serialize, Deserialize, LinkedData)]
#[ld(prefix("cred" = "https://www.w3.org/2018/credentials#"))]
#[serde(rename_all = "camelCase")]
pub struct Credential<
    Subject = serde_json::Value,
    Proof = serde_json::Value,
    Issuer = self::Issuer,
    Evidence = self::Evidence,
    Status = self::Status,
    TermsOfUse = self::TermsOfUse,
    RefreshService = self::RefreshService,
    Extension = BTreeMap<String, serde_json::Value>,
> {
    /// JSON-LD context.
    #[ld(ignore)]
    #[serde(rename = "@context")]
    pub context: json_ld::syntax::Context,

    /// Credential type.
    #[ld(type)]
    #[serde(rename = "type")]
    pub type_: Option<OneOrMany<IriBuf>>,

    #[ld("cred:credentialSubject")]
    pub credential_suject: Option<OneOrMany<Subject>>,

    #[ld("cred:issuer")]
    pub issuer: Option<Issuer>,

    #[ld("cred:issuanceDate")]
    pub issuance_date: Option<xsd_types::DateTime>,

    #[ld("cred:proof")]
    pub proof: Option<OneOrMany<Proof>>,

    #[ld("cred:expirationDate")]
    pub expiration_date: Option<xsd_types::DateTime>,

    #[ld("cred:credentialStatus")]
    pub credential_status: Option<Status>,

    #[ld("cred:termsOfUse")]
    pub terms_of_use: Option<TermsOfUse>,

    #[ld("cred:evidence")]
    pub evidence: Option<OneOrMany<Evidence>>,

    #[ld("cred:credentialSchema")]
    pub credential_schema: Option<OneOrMany<Schema>>,

    #[ld("cred:refreshService")]
    pub refresh_service: Option<OneOrMany<RefreshService>>,

    #[ld(flatten)]
    #[serde(flatten)]
    pub extension: Extension,
}

pub fn w3c_credential_v1_context() -> json_ld::syntax::ContextEntry {
    json_ld::syntax::ContextEntry::IriRef(
        iri_ref!("https://www.w3.org/2018/credentials/v1").to_owned(),
    )
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum Issuer {
    Iri(IriBuf),
    Object(ObjectWithId),
}

impl Issuer {
    pub fn id(&self) -> &Iri {
        match self {
            Self::Iri(iri) => iri,
            Self::Object(object) => &object.id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWithId {
    pub id: IriBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    pub id: IriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<IriBuf>,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<IriBuf>,

    #[serde(rename = "type")]
    pub type_: Vec<String>,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: IriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: IriBuf,

    #[serde(rename = "type")]
    pub type_: String,

    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, serde_json::Value>>,
}
