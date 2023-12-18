use anyhow::Result;
use serde::Deserialize;
use ssi_core::one_or_many::OneOrMany;
use ssi_dids::{Service, ServiceEndpoint, VerificationMethod, DIDURL};
use std::convert::TryFrom;
use url::Url;

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub async fn retrieve_did_manager(tzkt_url: &str, address: &str) -> Result<Option<String>> {
    let client = reqwest::Client::builder().build()?;
    let url = Url::parse(tzkt_url)?;
    let contracts: Vec<String> = client
        .get(url.join("/v1/contracts")?)
        .query(&[
            ("creator", address),
            ("sort", "lastActivity"),
            ("select", "address"),
            // TODO using codeHash while all contracts have the same code and until tezedge-client provide a way to fetch TZIP-016 metadata.
            ("codeHash", "1222545108"),
        ])
        .send()
        .await?
        .json()
        .await?;

    if !contracts.is_empty() {
        Ok(Some(contracts[0].clone()))
    } else {
        Ok(None)
    }
}

#[derive(Deserialize)]
struct ServiceResult {
    service: ServiceResultService,
}

#[derive(Deserialize)]
struct ServiceResultService {
    type_: String,
    endpoint: String,
}

// Not using TZIP-016 for now as TzKT doesn't have an endpoint to execute views and tezedge-client doesn't support it yet.
pub async fn execute_service_view(tzkt_url: &str, did: &str, contract: &str) -> Result<Service> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static(USER_AGENT),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;
    let url = Url::parse(tzkt_url)?;
    let service_result: ServiceResult = client
        .get(url.join(&format!("/v1/contracts/{contract}/storage"))?)
        .send()
        .await?
        .json()
        .await?;
    Ok(Service {
        id: format!("{}{}", did, "#discovery"),
        type_: OneOrMany::One(service_result.service.type_.clone()),
        service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
            service_result.service.endpoint,
        ))),
        property_set: None,
    })
}

#[derive(Deserialize)]
struct AuthResult {
    verification_method: String,
}

pub async fn execute_auth_view(tzkt_url: &str, contract: &str) -> Result<VerificationMethod> {
    let client = reqwest::Client::builder().build()?;
    let url = Url::parse(tzkt_url)?;
    let auth_result: AuthResult = client
        .get(url.join(&format!("/v1/contracts/{contract}/storage"))?)
        .send()
        .await?
        .json()
        .await?;
    Ok(VerificationMethod::DIDURL(DIDURL::try_from(
        auth_result.verification_method,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TZKT_URL: &str = "https://api.tzkt.io/";
    const LIVE_TZ1: &str = "tz1giDGsifWB9q9siekCKQaJKrmC9da5M43J";
    const LIVE_NETWORK: &str = "mainnet";
    const LIVE_DID_MANAGER: &str = "KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi";

    #[tokio::test]
    async fn test_retrieve_did_manager() {
        let did_manager = retrieve_did_manager(TZKT_URL, LIVE_TZ1).await;
        assert!(did_manager.is_ok());
        assert_eq!(did_manager.unwrap().unwrap(), LIVE_DID_MANAGER.to_string());
    }

    #[tokio::test]
    async fn test_execute_view() {
        let service_endpoint = execute_service_view(
            TZKT_URL,
            &format!("did:tz:{}:{}", LIVE_NETWORK, LIVE_TZ1),
            LIVE_DID_MANAGER,
        )
        .await;
        assert!(service_endpoint.is_ok());
        match service_endpoint.unwrap().service_endpoint.unwrap() {
            OneOrMany::One(ServiceEndpoint::URI(endpoint)) => {
                assert_eq!(endpoint, "http://example.com")
            }
            _ => panic!("Should have many."),
        };
        let verification_method = execute_auth_view(TZKT_URL, LIVE_DID_MANAGER).await;
        assert!(verification_method.is_ok());
        match verification_method.unwrap() {
            VerificationMethod::DIDURL(did_url) => {
                assert_eq!(
                    did_url.to_string(),
                    format!("did:pkh:tz:{}#TezosMethod2021", LIVE_TZ1)
                )
            }
            _ => panic!("Impossible format."),
        };
    }
}
