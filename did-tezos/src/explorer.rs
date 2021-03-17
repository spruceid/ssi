use anyhow::Result;
use reqwest;
use serde::Deserialize;
use ssi::did::{Service, ServiceEndpoint};
use ssi::one_or_many::OneOrMany;
use url::Url;

#[derive(Deserialize)]
struct Contract {
    value: String,
    body: ContractDetails,
}

#[derive(Deserialize)]
struct ContractDetails {
    entrypoints: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type")]
enum SearchItem {
    Contract(Contract),
}

#[derive(Deserialize)]
struct SearchResult {
    items: Vec<SearchItem>,
}

pub async fn retrieve_did_manager(
    bcd_url: &str,
    address: &str,
    network: &str,
) -> Result<Option<String>> {
    let client = reqwest::Client::builder().build()?;
    let url = Url::parse(bcd_url)?;
    let mut search_result: SearchResult = client
        .get(url.join("/v1/search")?)
        .query(&[
            ("q", address),
            ("f", "manager"),
            ("n", network),
            ("i", "contract"),
        ])
        .send()
        .await?
        .json()
        .await?;

    // TODO this is a hack for the tests as there were multiple DID managers deployed
    search_result.items.reverse();
    for search_item in search_result.items {
        match search_item {
            SearchItem::Contract(c) => {
                if c.body
                    .entrypoints
                    .contains(&"rotateAuthentication".to_string())
                    && c.body.entrypoints.contains(&"rotateService".to_string())
                {
                    return Ok(Some(c.value));
                }
            }
        }
    }
    Ok(None)
}

#[derive(Deserialize)]
struct ServiceResult {
    children: Vec<ServiceResultItem>,
}

#[derive(Deserialize)]
struct ServiceResultItem {
    value: String,
}

pub async fn execute_service_view(
    bcd_url: &str,
    did: &str,
    contract: &str,
    network: &str,
) -> Result<Service> {
    let client = reqwest::Client::builder().build()?;
    let url = Url::parse(bcd_url)?;
    let service_result: ServiceResult = client
        .post(url.join(&format!(
            "/v1/contract/{}/{}/views/execute",
            network, contract
        ))?)
        .json(&serde_json::json!({"data": {}, "name": "GetService", "implementation": 0}))
        .send()
        .await?
        .json()
        .await?;
    Ok(Service {
        id: format!("{}{}", did, "#discovery"),
        type_: OneOrMany::One(service_result.children[1].value.clone()),
        service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
            service_result.children[0].value.clone(),
        ))),
        property_set: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Not using the api endpoint because it returns empty results at the moment
    const BCD_URL: &str = "https://better-call.dev/";
    const LIVE_TZ1: &str = "tz1Z3yNumnSFoHtMsMPAkiCqDQpTcnw7fk1s";
    const LIVE_NETWORK: &str = "delphinet";
    const LIVE_DID_MANAGER: &str = "KT1XFk3nxojBisE5WpXugmuPuh9GRzo54gxL";

    #[tokio::test]
    async fn test_retrieve_did_manager() {
        let did_manager = retrieve_did_manager(BCD_URL, LIVE_TZ1, LIVE_NETWORK).await;
        assert!(did_manager.is_ok());
        assert_eq!(did_manager.unwrap().unwrap(), LIVE_DID_MANAGER.to_string());
    }

    #[tokio::test]
    async fn test_execute_view() {
        let service_endpoint = execute_service_view(
            BCD_URL,
            &format!("did:tz:{}:{}", LIVE_NETWORK, LIVE_TZ1),
            LIVE_DID_MANAGER,
            LIVE_NETWORK,
        )
        .await;
        println!("{:?}", service_endpoint);
        assert!(service_endpoint.is_ok());
    }
}
