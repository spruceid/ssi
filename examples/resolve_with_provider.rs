//! Resolve a did:ethr DID using a real Ethereum JSON-RPC endpoint.
//!
//! Implements `EthProvider` over raw HTTP JSON-RPC (works with any endpoint),
//! walks the ERC-1056 event chain, and prints the resolved DID document.
//!
//! Run with:
//!   cargo run --example resolve_with_provider

use did_ethr::{BlockRef, DIDEthr, EthProvider, Log, LogFilter, NetworkConfig};
use serde::{de::DeserializeOwned, Serialize};
use ssi_dids_core::{did, DIDResolver};

// ── Hex helpers ──────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| e.to_string())
}

// ── HttpProvider ─────────────────────────────────────────────────────────────

struct HttpProvider {
    client: reqwest::Client,
    url: String,
}

impl HttpProvider {
    async fn rpc<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        let resp: serde_json::Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if let Some(err) = resp.get("error") {
            return Err(err.to_string());
        }
        serde_json::from_value(resp["result"].clone()).map_err(|e| e.to_string())
    }
}

#[derive(Debug)]
struct ProviderError(String);

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ProviderError {}

impl EthProvider for HttpProvider {
    type Error = ProviderError;

    async fn call(
        &self,
        to: [u8; 20],
        data: Vec<u8>,
        block: BlockRef,
    ) -> Result<Vec<u8>, Self::Error> {
        let block_param = match block {
            BlockRef::Latest => "latest".to_owned(),
            BlockRef::Number(n) => format!("0x{n:x}"),
        };
        let result: String = self
            .rpc(
                "eth_call",
                serde_json::json!([
                    {"to": hex_encode(&to), "data": hex_encode(&data)},
                    block_param,
                ]),
            )
            .await
            .map_err(ProviderError)?;
        hex_decode(&result).map_err(ProviderError)
    }

    async fn get_logs(&self, filter: LogFilter) -> Result<Vec<Log>, Self::Error> {
        // topic0: multiple hashes → inner array (OR semantics)
        let topic0: Vec<String> = filter.topic0.iter().map(|t| hex_encode(t)).collect();
        // topic1: optional single hash
        let topic1 = filter
            .topic1
            .as_ref()
            .map(|t| serde_json::Value::String(hex_encode(t)))
            .unwrap_or(serde_json::Value::Null);

        let raw: Vec<serde_json::Value> = self
            .rpc(
                "eth_getLogs",
                serde_json::json!([{
                    "address": hex_encode(&filter.address),
                    "topics": [topic0, topic1],
                    "fromBlock": format!("0x{:x}", filter.from_block),
                    "toBlock": format!("0x{:x}", filter.to_block),
                }]),
            )
            .await
            .map_err(ProviderError)?;

        raw.into_iter()
            .map(|entry| {
                let topics = entry["topics"]
                    .as_array()
                    .ok_or_else(|| ProviderError("missing topics".into()))?
                    .iter()
                    .map(|t| {
                        let bytes = hex_decode(t.as_str().unwrap_or(""))
                            .map_err(ProviderError)?;
                        bytes
                            .try_into()
                            .map_err(|_| ProviderError("topic not 32 bytes".into()))
                    })
                    .collect::<Result<Vec<[u8; 32]>, _>>()?;

                let data = hex_decode(entry["data"].as_str().unwrap_or("0x"))
                    .map_err(ProviderError)?;

                let addr_bytes = hex_decode(entry["address"].as_str().unwrap_or("0x"))
                    .map_err(ProviderError)?;
                let address: [u8; 20] = addr_bytes
                    .try_into()
                    .map_err(|_| ProviderError("address not 20 bytes".into()))?;

                let bn_str = entry["blockNumber"].as_str().unwrap_or("0x0");
                let block_number = u64::from_str_radix(bn_str.trim_start_matches("0x"), 16)
                    .map_err(|e| ProviderError(e.to_string()))?;

                Ok(Log { address, topics, data, block_number })
            })
            .collect()
    }

    async fn block_timestamp(&self, block: u64) -> Result<u64, Self::Error> {
        let result: serde_json::Value = self
            .rpc(
                "eth_getBlockByNumber",
                serde_json::json!([format!("0x{block:x}"), false]),
            )
            .await
            .map_err(ProviderError)?;
        let ts_str = result["timestamp"]
            .as_str()
            .ok_or_else(|| ProviderError("missing timestamp".into()))?;
        u64::from_str_radix(ts_str.trim_start_matches("0x"), 16)
            .map_err(|e| ProviderError(e.to_string()))
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    const MAINNET_REGISTRY: [u8; 20] = [
        0xdc, 0xa7, 0xef, 0x03, 0xe9, 0x8e, 0x0d, 0xc2,
        0xb8, 0x55, 0xbe, 0x64, 0x7c, 0x39, 0xab, 0xe9,
        0x84, 0xfc, 0xf2, 0x1b,
    ];

    let mut resolver = DIDEthr::new();
    resolver.add_network(
        "mainnet",
        NetworkConfig {
            chain_id: 1,
            registry: MAINNET_REGISTRY,
            provider: HttpProvider {
                client: reqwest::Client::new(),
                url: "https://mainnet.gateway.tenderly.co".to_owned(),
            },
        },
    );

    let output = resolver
        .resolve(did!("did:ethr:0xee9bddd4cdd24174f91949293f415bfad57cfa22"))
        .await
        .expect("resolution failed");

    println!("{}", serde_json::to_string_pretty(&output.document).unwrap());
}
