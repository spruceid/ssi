#[async_std::main]
#[ignore] // Skip expensive key generation
async fn main() -> Result<(), ssi_jwk::Error> {
    #[cfg(feature = "aleo")]
    {
        let jwk = ssi::jwk::JWK::generate_aleo()?;
        let writer = std::io::BufWriter::new(std::io::stdout());
        serde_json::to_writer_pretty(writer, &jwk).unwrap();
    }
    Ok(())
}
