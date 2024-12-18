use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use crate::syntax::{not_null, value_or_array, IdOr, IdentifiedObject};
use crate::v2::{Context, Credential};
use iref::{Uri, UriBuf};
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, ValidateClaims};
use ssi_json_ld::{JsonLdError, JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader};
use ssi_rdf::{Interpretation, LdEnvironment, LinkedDataResource, LinkedDataSubject};

use super::JsonCredential;

pub use crate::v1::syntax::{
    JsonPresentationTypes, PresentationType, VERIFIABLE_PRESENTATION_TYPE,
};

/// JSON Presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "C: serde::Serialize",
    deserialize = "C: serde::Deserialize<'de>"
))]
pub struct JsonPresentation<C = JsonCredential> {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context,

    /// Presentation identifier.
    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<UriBuf>,

    /// Presentation type.
    #[serde(rename = "type")]
    pub types: JsonPresentationTypes,

    /// Holders.
    #[serde(rename = "holder")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub holders: Vec<IdOr<IdentifiedObject>>,

    /// Verifiable credentials.
    #[serde(rename = "verifiableCredential")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verifiable_credentials: Vec<C>,

    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, json_syntax::Value>,
}

impl Default for JsonPresentation {
    fn default() -> Self {
        Self {
            context: Context::default(),
            id: None,
            types: JsonPresentationTypes::default(),
            verifiable_credentials: Vec::new(),
            holders: Vec::new(),
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<C> JsonPresentation<C> {
    pub fn new(
        id: Option<UriBuf>,
        holders: Vec<IdOr<IdentifiedObject>>,
        verifiable_credentials: Vec<C>,
    ) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonPresentationTypes::default(),
            holders,
            verifiable_credentials,
            additional_properties: BTreeMap::new(),
        }
    }
}

impl<C> JsonLdObject for JsonPresentation<C> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl<C> JsonLdNodeObject for JsonPresentation<C> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<C, E, P> ValidateClaims<E, P> for JsonPresentation<C> {
    fn validate_claims(&self, _: &E, _: &P) -> ClaimsValidity {
        Ok(())
    }
}

impl<C: Credential> crate::MaybeIdentified for JsonPresentation<C> {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }
}

impl<C: Credential> crate::v2::Presentation for JsonPresentation<C> {
    /// Verifiable credential type.
    type Credential = C;

    type Holder = IdOr<IdentifiedObject>;

    /// Types, without the `VerifiablePresentation` type.
    fn additional_types(&self) -> &[String] {
        self.types.additional_types()
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        &self.verifiable_credentials
    }

    fn holders(&self) -> &[Self::Holder] {
        &self.holders
    }
}

impl<C> ssi_json_ld::Expandable for JsonPresentation<C>
where
    C: Serialize,
{
    type Error = JsonLdError;

    type Expanded<I, V> = ssi_json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
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

#[cfg(test)]
mod test {
    use ssi_data_integrity::{AnySuite, DataIntegrity};

    use super::*;

    #[test]
    fn deserialize_single_domain() {
        let _: DataIntegrity<JsonPresentation, AnySuite> = serde_json::from_value(serde_json::json!(
            {
              "@context": [
                "https://www.w3.org/ns/credentials/v2"
              ],
              "id": "urn:uuid:e6f93061-dcac-46a0-8aba-9d6278e2ada1",
              "type": [
                "VerifiablePresentation"
              ],
              "holder": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IndPTjRDTmlHX1BxaWl1R0JEbnpRa1lqVG9jaDJnaTRBTHluWVIwdnN1c0kiLCJ5Ijoia2JlZ25iRzUxZHFETW9wdHgtOVIxcmpIU1B6TkhYLWdQbnFhbWJ6a1pzNCJ9",
              "verifiableCredential": {
                "@context": [
                  "https://www.w3.org/ns/credentials/v2",
                  "https://examples.vcplayground.org/contexts/movie-ticket-vcdm-v2/v1.json"
                ],
                "id": "urn:uuid:df7bbd25-6f01-46dc-b65c-c483a7841739",
                "type": [
                  "VerifiableCredential",
                  "MovieTicketCredential"
                ],
                "credentialSubject": {
                  "id": "did:example:b34AA2I0ZdwAACBDu",
                  "owns": {
                    "location": {
                      "address": {
                        "addressLocality": "Your Town",
                        "addressRegion": "VA",
                        "postalCode": "24060",
                        "streetAddress": "123 Main St."
                      },
                      "name": "Hometown Theatres, Inc."
                    },
                    "startDate": "2022-08-26T19:00:00.000Z",
                    "ticketNumber": "457812",
                    "ticketToken": "urn:1a1e549a-2867",
                    "ticketedSeat": {
                      "seatNumber": "11",
                      "seatRow": "E",
                      "seatSection": "Theatre 3"
                    },
                    "type": "Ticket"
                  }
                },
                "issuer": {
                  "id": "did:key:zDnaerPmH7xAjZoWanUBkRzY6xi9aTywRRoyAaHyRAsAYHCRq",
                  "name": "Hometown Theatres, Inc."
                },
                "description": "Admit one: Plan 9 from Outer Space, 3pm showing.",
                "image": "data:image/png;base64,iVBO...",
                "proof": {
                  "created": "2024-12-18T09:55:11Z",
                  "cryptosuite": "ecdsa-rdfc-2019",
                  "proofPurpose": "assertionMethod",
                  "proofValue": "znvWgrZtpc9aqGRhyCnf22WLddL6L1rGA1CRPEBPWRbw7sKUCC1DrC2GrASDEyA5W3C3DCV3p4zZg6Zp4sYSKduT",
                  "type": "DataIntegrityProof",
                  "verificationMethod": "did:key:zDnaerPmH7xAjZoWanUBkRzY6xi9aTywRRoyAaHyRAsAYHCRq#zDnaerPmH7xAjZoWanUBkRzY6xi9aTywRRoyAaHyRAsAYHCRq"
                }
              },
              "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "ecdsa-rdfc-2019",
                "created": "2024-12-18T10:31:42.962679Z",
                "verificationMethod": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IndPTjRDTmlHX1BxaWl1R0JEbnpRa1lqVG9jaDJnaTRBTHluWVIwdnN1c0kiLCJ5Ijoia2JlZ25iRzUxZHFETW9wdHgtOVIxcmpIU1B6TkhYLWdQbnFhbWJ6a1pzNCJ9#0",
                "proofPurpose": "authentication",
                "domain": "https://qa.veresexchanger.dev/exchangers/z19vRLNoFaBKDeDaMzRjUj8hi/exchanges/z19jYTCujFf4b6JFdCNMTXJ3s/openid/client/authorization/response",
                "challenge": "z19jYTCujFf4b6JFdCNMTXJ3s",
                "proofValue": "z3H5Bi3cF6BGEgoWdAqp13gQHEibVGtNtVbJECwfQStGmBio1gmjHrq2TGtjJ3L18pd1pKCsb4Pos9oMDpginN68h"
              }
            }
        )).expect("Could not deserialize");
    }
}
