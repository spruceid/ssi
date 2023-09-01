use std::collections::BTreeMap;

use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi_core::one_or_many::OneOrMany;

/// DID Service.
///
/// Services express ways of communicating with the DID subject or associated
/// entities.
///
// See: <https://w3c.github.io/did-core/#service-properties>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// id property (URI) of a service map.
    pub id: UriBuf,

    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint: Option<OneOrMany<Endpoint>>,

    #[serde(flatten)]
    pub property_set: BTreeMap<String, serde_json::Value>,
}

/// Service endpoint.
///
/// Value for a [serviceEndpoint](https://www.w3.org/TR/did-core/#dfn-serviceendpoint) property of
/// a [service](https://www.w3.org/TR/did-core/#services) map in a DID document.
///
/// "The value of the serviceEndpoint property MUST be a string \[URI], a map, or a set composed of one or
/// more strings \[URIs] and/or maps."
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Endpoint {
    Uri(UriBuf), // TODO must be an URI
    Map(serde_json::Value),
}
