mod common;
use common::Test;

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
#[async_std::test]
async fn ecdsa_rdfc_2019_p256_signature() {
    Test::load("ecdsa_rdfc_2019/p256_signature.json")
        .run()
        .await
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
#[async_std::test]
async fn ecdsa_rdfc_2019_p256_verification() {
    Test::load("ecdsa_rdfc_2019/p256_verification.json")
        .run()
        .await
}

#[cfg(all(feature = "w3c", feature = "secp384r1"))]
#[async_std::test]
async fn ecdsa_rdfc_2019_p384_signature() {
    Test::load("ecdsa_rdfc_2019/p384_signature.json")
        .run()
        .await
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
#[async_std::test]
async fn ecdsa_sd_2023_signature() {
    Test::load("ecdsa_sd_2023/signature.json").run().await
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
#[async_std::test]
async fn ecdsa_sd_2023_selection() {
    Test::load("ecdsa_sd_2023/selection.json").run().await
}

#[cfg(all(feature = "w3c", feature = "secp256r1"))]
#[async_std::test]
async fn ecdsa_sd_2023_verification() {
    Test::load("ecdsa_sd_2023/verification.json").run().await
}
