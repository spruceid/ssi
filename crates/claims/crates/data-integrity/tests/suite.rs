mod common;
use common::Test;

#[async_std::test]
async fn ecdsa_sd_2023_signature() {
    Test::load("ecdsa_sd_2023/signature.json").run().await
}

#[async_std::test]
async fn ecdsa_sd_2023_selection() {
    Test::load("ecdsa_sd_2023/selection.json").run().await
}
