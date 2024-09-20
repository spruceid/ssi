//! Status List Client Example.
//!
//! This example demonstrates how to write a simple credential status list
//! client using `ssi_status`.
//! For a give revokable input credential, this command line utility will return
//! whether or not the credential is revoked.
//!
//! # Usage
//!
//! ```console
//! $ cargo run --example status_list_client -- -t application/vc+ld+json examples/files/status_list_revocable_1.jsonld
//! unrevoked
//! $ cargo run --example status_list_client -- -t application/vc+ld+json examples/files/status_list_revocable_3.jsonld
//! REVOKED
//! ```
//!
//! The `status_list_revocable_*.jsonld` provided in the `examples/files`
//! directory will fetch the status list located at
//! `http://127.0.0.1:3000/#statusList`. To reproduce the example above you
//! serve the status list using the `status-list-server` example:
//! ```console
//! $ cargo run --example status_list_server -- -t application/vc+ld+json examples/files/local-status-list-credential.jsonld
//! serving /#statusList at 127.0.0.1:3000...
//! ```
use clap::Parser;
use core::fmt;
use ssi_claims_core::VerificationParameters;
use ssi_dids::{VerificationMethodDIDResolver, DIDJWK};
use ssi_status::{
    any::{AnyEntrySet, AnyStatusMap},
    client::StatusMapProvider,
    FromBytes, StatusMapEntry, StatusMapEntrySet, StatusPurpose,
};
use std::{
    fs,
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[clap(
    name = "status-list-client",
    bin_name = "cargo run --example status_list_client --"
)]
struct Args {
    /// Input credential filename.
    ///
    /// If not provided, read the credential from the standard input.
    filename: Option<PathBuf>,

    /// Input credential media type.
    #[clap(short = 't', long)]
    media_type: String,

    /// Server address.
    #[clap(short, long)]
    addr: Option<SocketAddr>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error("unable to read {0}: {1}")]
    ReadFile(Source, io::Error),

    #[error("unable to decode {0}: {1}")]
    Decode(Source, ssi_status::any::EntrySetFromBytesError),

    #[error("unable to fetch status list: {0}")]
    Provider(#[from] ssi_status::client::ProviderError),

    #[error("missing entry {0}")]
    MissingEntry(usize),
}

async fn run(args: Args) -> Result<(), Error> {
    let input = args.filename.map(Source::File).unwrap_or_default();
    let bytes = match input.read() {
        Ok(bytes) => bytes,
        Err(e) => return Err(Error::ReadFile(input, e)),
    };

    let verifier =
        VerificationParameters::from_resolver(VerificationMethodDIDResolver::new(DIDJWK));

    let entry_set = AnyEntrySet::from_bytes(&bytes, &args.media_type, &verifier)
        .await
        .map_err(|e| Error::Decode(input, e))?;

    let client = ssi_status::client::HttpClient::new(verifier);

    if let Some(entry) = entry_set.get_entry(StatusPurpose::Revocation) {
        use ssi_status::StatusMap;

        let status_list = client.get::<AnyStatusMap>(entry.status_list_url()).await?;

        let status = status_list
            .get_entry(&entry)
            .unwrap()
            .ok_or(Error::MissingEntry(entry.key()))?;

        match status {
            0 => println!("unrevoked"),
            _ => println!("REVOKED"),
        }
    }

    Ok(())
}

/// Status list source.
#[derive(Debug, Default)]
enum Source {
    #[default]
    Stdin,
    File(PathBuf),
}

impl Source {
    fn read(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer = Vec::new();
        match self {
            Self::Stdin => {
                io::stdin().read_to_end(&mut buffer)?;
            }
            Self::File(path) => {
                let mut file = fs::File::open(path)?;
                file.read_to_end(&mut buffer)?;
            }
        }
        Ok(buffer)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdin => write!(f, "standard input"),
            Self::File(path) => write!(f, "file `{}`", path.display()),
        }
    }
}
