//! Command line interface and example showing how to read and create status lists.
//!
//! # Usage
//!
//! Read a status list from a JWT, JWT-VC claims or Credential:
//! ```console
//! $ cargo run --example status_list -- examples/files/status-list.jwt
//! $ cargo run --example status_list -- examples/files/status-list-jwt-payload.json
//! $ cargo run --example status_list -- examples/files/status-list-credential.json
//! $ cargo run --example status_list -- examples/files/status-list-credential-di.json
//! ```
//!
//! Create a new status list:
//! ```console
//! $ cargo run --example status_list -- create "http://example.org/#statusList" 0 0 1 0
//! ```
use clap::{Parser, Subcommand};
use core::fmt;
use iref::UriBuf;
use serde::Serialize;
use ssi_data_integrity::{AnyInputContext, AnySuite, ProofConfiguration};
use ssi_dids::{VerificationMethodDIDResolver, DIDJWK};
use ssi_jwk::JWK;
use ssi_status::{any::AnyStatusMap, bitstream_status_list, EncodedStatusMap};
use ssi_verification_methods::{ReferenceOrOwned, SingleSecretSigner};
use std::{
    fs,
    io::{self, stdout, Read, Write},
    num::ParseIntError,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

/// Command line interface to read and create status lists.
#[derive(Parser)]
#[clap(name = "status-list", bin_name = "cargo run --example status_list --")]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read a status list.
    Read {
        /// Path to a file representing the status list.
        ///
        /// If unspecified, the status list is read from the standard input.
        filename: Option<PathBuf>,
    },

    /// Create a new status list.
    Create {
        /// Status list credential identifier.
        id: UriBuf,

        /// Status values.
        list: Vec<StatusValue>,

        /// Secret key to sign the status list.
        #[clap(short, long)]
        key: Option<PathBuf>,
    },
}

impl Command {
    async fn run(self) -> Result<(), Error> {
        match self {
            Self::Read { filename } => {
                let input = filename.map(Source::File).unwrap_or_default();
                let bytes = match input.read() {
                    Ok(content) => content,
                    Err(e) => return Err(Error::ReadFile(input, e)),
                };

                let (status_list, _) =
                    AnyStatusMap::decode(&bytes, None).map_err(|e| Error::Decode(input, e))?;

                let report = match status_list {
                    AnyStatusMap::BitstringStatusList(cred) => {
                        let status_list = cred.decode()?;
                        Report {
                            format: StatusListFormat::BitstringStatusListCredential,
                            security: if cred.other_properties.contains_key("proof") {
                                Some(SecurityType::DataIntegrity)
                            } else {
                                None
                            },
                            list: status_list.iter().collect(),
                        }
                    }
                };

                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                Ok(())
            }
            Self::Create { id, list, key } => {
                let data = create_status_list(id.clone(), list, key).await?;
                stdout().write_all(&data).unwrap();
                Ok(())
            }
        }
    }
}

async fn create_status_list(
    id: UriBuf,
    list: Vec<StatusValue>,
    key: Option<PathBuf>,
) -> Result<Vec<u8>, Error> {
    let mut status_list = bitstream_status_list::StatusList::new(
        bitstream_status_list::StatusSize::default(),
        bitstream_status_list::TimeToLive::default(),
        // list.into_iter().map(|v| v.0).collect(),
    );

    for v in list {
        status_list.push(v.0);
    }

    let credential = bitstream_status_list::BitstringStatusListCredential::new(
        Some(id),
        status_list.to_credential_subject(
            None,
            bitstream_status_list::StatusPurpose::Revocation,
            Vec::new(),
        ),
    );

    match key {
        Some(path) => {
            use ssi_data_integrity::CryptographicSuiteInput;
            let jwk = read_jwk(&path)?;
            let did = DIDJWK::generate_url(&jwk.to_public());
            let resolver = VerificationMethodDIDResolver::new(DIDJWK);
            let signer = SingleSecretSigner::new(jwk.clone());
            let verification_method = ReferenceOrOwned::Reference(did.into());
            let suite = AnySuite::pick(&jwk, Some(&verification_method)).unwrap();
            let params = ProofConfiguration::from_method(verification_method);
            let vc = suite
                .sign(
                    credential,
                    AnyInputContext::default(),
                    &resolver,
                    &signer,
                    params,
                )
                .await
                .unwrap();

            Ok(serde_json::to_string_pretty(&vc).unwrap().into_bytes())
        }
        None => Ok(serde_json::to_string_pretty(&credential)
            .unwrap()
            .into_bytes()),
    }
}

fn read_jwk(path: &Path) -> Result<JWK, KeyError> {
    let buffer = fs::read_to_string(path)?;
    serde_json::from_str(&buffer).map_err(Into::into)
}

#[derive(Serialize)]
pub struct Report {
    format: StatusListFormat,
    security: Option<SecurityType>,
    list: Vec<u8>,
}

#[derive(Serialize)]
pub enum StatusListFormat {
    BitstringStatusListCredential,
}

#[derive(Serialize)]
pub enum SecurityType {
    DataIntegrity,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("could not read from {0}: {1}")]
    ReadFile(Source, io::Error),

    #[error("unable to decode {0}: {1}")]
    Decode(Source, ssi_status::any::Error),

    #[error("unable to decode `BitstringStatusList`: {0}")]
    BitstringStatusListDecode(#[from] ssi_status::bitstream_status_list::DecodeError),

    #[error("unable to read key: {0}")]
    Key(#[from] KeyError),
}

#[derive(Debug, thiserror::Error)]
enum KeyError {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

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

#[derive(Debug, Clone, Copy)]
struct StatusValue(u8);

impl FromStr for StatusValue {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u8::from_str_radix(s, 16).map(Self)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    env_logger::init();
    match args.command.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
