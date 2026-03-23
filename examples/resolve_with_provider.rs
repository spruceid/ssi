//! Resolve a did:ethr DID using a real Ethereum JSON-RPC endpoint.
//!
//! Implements `EthProvider` over raw HTTP JSON-RPC (works with any endpoint),
//! walks the ERC-1056 event chain, and prints the resolved DID document.
//!
//! Run with:
//!   cargo run --example resolve_with_provider -- [DID] [RPC_URL] [REGISTRY]

use did_ethr::{BlockRef, DIDEthr, EthProvider, Log, LogFilter, NetworkConfig};
use serde::{de::DeserializeOwned, Serialize};
use ssi_dids_core::DIDResolver;

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
    ) -> Result<R, ProviderError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        let mut resp: serde_json::Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError(e.to_string()))?
            .json()
            .await
            .map_err(|e| ProviderError(e.to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(ProviderError(err.to_string()));
        }
        serde_json::from_value(resp["result"].take()).map_err(|e| ProviderError(e.to_string()))
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
            .await?;
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
            .await?;

        raw.into_iter()
            .map(|entry| {
                let topics = entry["topics"]
                    .as_array()
                    .ok_or_else(|| ProviderError("missing topics".into()))?
                    .iter()
                    .map(|t| {
                        let s = t.as_str().ok_or_else(|| ProviderError("topic not a string".into()))?;
                        let bytes = hex_decode(s).map_err(ProviderError)?;
                        bytes.try_into().map_err(|_| ProviderError("topic not 32 bytes".into()))
                    })
                    .collect::<Result<Vec<[u8; 32]>, _>>()?;

                let data = hex_decode(
                    entry["data"].as_str().ok_or_else(|| ProviderError("missing data".into()))?,
                )
                .map_err(ProviderError)?;

                let addr_bytes = hex_decode(
                    entry["address"].as_str().ok_or_else(|| ProviderError("missing address".into()))?,
                )
                .map_err(ProviderError)?;
                let address: [u8; 20] = addr_bytes
                    .try_into()
                    .map_err(|_| ProviderError("address not 20 bytes".into()))?;

                let bn_str = entry["blockNumber"]
                    .as_str()
                    .ok_or_else(|| ProviderError("missing blockNumber".into()))?;
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
            .await?;
        let ts_str = result["timestamp"]
            .as_str()
            .ok_or_else(|| ProviderError("missing timestamp".into()))?;
        u64::from_str_radix(ts_str.trim_start_matches("0x"), 16)
            .map_err(|e| ProviderError(e.to_string()))
    }
}

// ── main ──────────────────────────────────────────────────────────────────────
//
// Usage: resolve_with_provider [DID] [RPC_URL] [REGISTRY]
//
// Defaults:
//   DID      = did:ethr:0x3ec96eb0ca7e28bdda8345dba863ff62d3a0f603
//   RPC_URL  = https://mainnet.gateway.tenderly.co
//   REGISTRY = 0xdca7ef03e98e0dc2b855be647c39abe984fcf21b (mainnet default)

// a DID that had an owner change. The blockchainAccountId of the #controller entry should be different than the address of the DID
const DEFAULT_DID: &str = "did:ethr:0x3ec96eb0ca7e28bdda8345dba863ff62d3a0f603";
const DEFAULT_RPC: &str = "https://mainnet.gateway.tenderly.co";
const DEFAULT_REGISTRY: &str = "0xdca7ef03e98e0dc2b855be647c39abe984fcf21b";

/// Well-known ERC-1056 registries per network name.
fn default_registry(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("0xdca7ef03e98e0dc2b855be647c39abe984fcf21b"),
        "sepolia" => Some("0x03d5003bf0e79C5F5223588F347ebA39AfbC3818"),
        _ => None,
    }
}

/// Well-known chain IDs per network name.
fn chain_id_for(network: &str) -> u64 {
    match network {
        "mainnet" => 1,
        "sepolia" => 11155111,
        _ => 1,
    }
}

/// Extract the network name from a did:ethr DID string.
/// Returns "mainnet" if no network segment is present.
fn network_from_did(did_str: &str) -> &str {
    // did:ethr:<network>:<address> or did:ethr:<address>
    let rest = did_str
        .strip_prefix("did:ethr:")
        .unwrap_or(did_str);
    match rest.split_once(':') {
        Some((network, _)) if !network.starts_with("0x") => network,
        _ => "mainnet",
    }
}

fn parse_registry(hex_str: &str) -> Result<[u8; 20], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad registry hex: {e}"))?;
    bytes.try_into().map_err(|_| "registry must be 20 bytes".into())
}

async fn resolve_did(did_str: &str, rpc_url: &str, registry_hex: &str) -> Result<serde_json::Value, String> {
    let network = network_from_did(did_str);
    let registry = parse_registry(registry_hex)?;

    let mut resolver = DIDEthr::new();
    resolver.add_network(
        network,
        NetworkConfig {
            chain_id: chain_id_for(network),
            registry,
            provider: HttpProvider {
                client: reqwest::Client::new(),
                url: rpc_url.to_owned(),
            },
        },
    );

    let did = ssi_dids_core::DIDBuf::from_string(did_str.to_owned())
        .map_err(|e| format!("invalid DID: {e}"))?;
    let output = resolver
        .resolve(&did)
        .await
        .map_err(|e| format!("resolution failed: {e}"))?;
    serde_json::to_value(&output.document).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let did_str = args.get(1).map(String::as_str).unwrap_or(DEFAULT_DID);
    let rpc_url = args.get(2).map(String::as_str).unwrap_or(DEFAULT_RPC);
    let registry_arg = args.get(3).map(String::as_str);

    // Resolve registry: CLI arg > well-known default for network > global default
    let network = network_from_did(did_str);
    let registry_hex = registry_arg
        .or_else(|| default_registry(network))
        .unwrap_or(DEFAULT_REGISTRY);

    eprintln!("DID:      {did_str}");
    eprintln!("RPC:      {rpc_url}");
    eprintln!("Network:  {network}");
    eprintln!("Registry: {registry_hex}");

    match resolve_did(did_str, rpc_url, registry_hex).await {
        Ok(doc) => println!("{}", serde_json::to_string_pretty(&doc).unwrap()),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
