/// Block reference for eth_call
pub enum BlockRef {
    Latest,
    Number(u64),
}

/// Log filter for eth_getLogs
///
/// `topic0` filters by event signature hash(es) — multiple values are OR'd.
/// `topic1` filters by the first indexed parameter (e.g. identity address).
pub struct LogFilter {
    pub address: [u8; 20],
    pub topic0: Vec<[u8; 32]>,
    pub topic1: Option<[u8; 32]>,
    pub from_block: u64,
    pub to_block: u64,
}

/// Ethereum event log
pub struct Log {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub block_number: u64,
    /// Position of the log within its block (from eth_getLogs `logIndex`).
    /// Used to preserve intra-block event ordering.
    pub log_index: u64,
}

/// Minimal async trait for Ethereum JSON-RPC interaction.
/// Users implement this with their preferred client (ethers-rs, alloy, etc.)
pub trait EthProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// eth_chainId — return the connected chain's numeric ID
    fn chain_id(&self) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;

    /// eth_call — execute a read-only contract call
    fn call(
        &self,
        to: [u8; 20],
        data: Vec<u8>,
        block: BlockRef,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send;

    /// eth_getLogs — query event logs
    fn get_logs(
        &self,
        filter: LogFilter,
    ) -> impl std::future::Future<Output = Result<Vec<Log>, Self::Error>> + Send;

    /// Get block timestamp (seconds since epoch)
    fn block_timestamp(
        &self,
        block: u64,
    ) -> impl std::future::Future<Output = Result<u64, Self::Error>> + Send;
}

/// Per-network Ethereum configuration
pub struct NetworkConfig<P> {
    pub registry: [u8; 20],
    pub provider: P,
}
