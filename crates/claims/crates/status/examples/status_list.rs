//! Command line interface and example showing how to read and create status lists.
//! 
//! # Usage
//! 
//! Read a status list from a JWT, JWT-VC claims or Credential:
//! ```console
//! cargo run --example status_list -- examples/status-list.jwt
//! cargo run --example status_list -- examples/status-list-jwt-payload.json
//! cargo run --example status_list -- examples/status-list-credential.json
//! cargo run --example status_list -- examples/status-list-credential-di.json
//! ```
//! 
//! Create a new status list:
//! ```console
//! cargo run --example status_list -- create "http://example.org/#statusList" 0 0 1 0
//! ```
use core::fmt;
use std::{fs, io::{self, Read}, num::ParseIntError, path::{Path, PathBuf}, process::ExitCode, str::FromStr};
use clap::{Parser, Subcommand};
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi_data_integrity::{AnyInputContext, AnySuite, ProofConfiguration};
use ssi_dids::{DIDMethodResolver, DIDResolver, VerificationMethodDIDResolver, DIDJWK};
use ssi_jwk::JWK;
use ssi_jws::CompactJWS;
use ssi_jwt::JWTClaims;
use ssi_status::{bitstream_status_list::{self, BitstringStatusListCredential}, EncodedStatusMap};
use ssi_vc::VCPublicClaims;
use ssi_verification_methods::{ReferenceOrOwned, SingleSecretSigner, VerificationMethod};

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
        key: Option<PathBuf>
    },
}

impl Command {
    async fn run(self) -> Result<(), Error> {
        match self {
            Self::Read { filename } => {
                let input = filename.map(Input::File).unwrap_or_default();
                let content = match input.read() {
                    Ok(content) => content,
                    Err(e) => return Err(Error::ReadFile(input, e))
                };

                let report = match InputValue::decode(input, &content)? {
                    InputValue::BitstringStatusListCredential(cred) => {
                        let status_list = cred.decode()?;
                        Report {
                            format: StatusListFormat::BitstringStatusListCredential,
                            security: if cred.other_properties.contains_key("proof") {
                                Some(SecurityType::DataIntegrity)
                            } else {
                                None
                            },
                            list: status_list.iter().collect()
                        }
                    }
                };

                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                Ok(())
            }
            Self::Create { id, list, key } => {
                let status_list = bitstream_status_list::StatusList::from_bytes(
                    bitstream_status_list::StatusSize::default(),
                    bitstream_status_list::TimeToLive::default(),
                    list.into_iter().map(|v| v.0).collect()
                );

                let credential = bitstream_status_list::BitstringStatusListCredential::new(
                    Some(id),
                    status_list.to_credential_subject(
                        None,
                        bitstream_status_list::StatusPurpose::Revocation,
                        Vec::new()
                    )
                );

                match key {
                    Some(path) => {
                        use ssi_data_integrity::CryptographicSuiteInput;
                        let jwk = read_jwk(&path)?;
                        let did = DIDJWK::generate(&jwk.to_public());
                        let resolver = VerificationMethodDIDResolver::new(DIDJWK);
                        let signer = SingleSecretSigner::new(jwk.clone());
                        let verification_method = ReferenceOrOwned::Reference(did.into());
                        let suite = AnySuite::pick(&jwk, Some(&verification_method)).unwrap();
                        let params = ProofConfiguration::from_method(verification_method);
                        let vc = suite.sign(
                            credential,
                            AnyInputContext::default(),
                            &resolver,
                            &signer,
                            params
                        ).await.unwrap();

                        println!("{}", serde_json::to_string_pretty(&vc).unwrap());
                    }
                    None => {
                        println!("{}", serde_json::to_string_pretty(&credential).unwrap());
                    }
                }

                Ok(())
            }
        }
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
    list: Vec<u8>
}

#[derive(Serialize)]
pub enum StatusListFormat {
    BitstringStatusListCredential
}

#[derive(Serialize)]
pub enum SecurityType {
    DataIntegrity
}

pub enum InputValue {
    BitstringStatusListCredential(BitstringStatusListCredential)
}

impl InputValue {
    fn decode_jwt_vc_claims(input: Input, claims: JWTClaims<VCPublicClaims>) -> Result<Self, Error> {
        match ssi_vc::decode_jwt_vc_claims(claims) {
            Ok(cred) => match cred {
                Credential::BitstringStatusListCredential(cred) => Ok(InputValue::BitstringStatusListCredential(cred)),
            }
            Err(_) => {
                Err(Error::UnrecognizedInput(input))
            }
        }
    }
    
    fn decode(input: Input, bytes: &[u8]) -> Result<Self, Error> {
        match serde_json::from_slice(bytes) {
            Ok(json) => match json {
                JsonInputValue::BitstringStatusListCredential(cred) => Ok(Self::BitstringStatusListCredential(cred)),
                JsonInputValue::JwtVc(jwt_vc) => {
                    Self::decode_jwt_vc_claims(input, jwt_vc)
                }
            },
            Err(_) => match CompactJWS::new(bytes) {
                Ok(jws) => {
                    let (_, payload, _) = jws.decode()?;
                    match serde_json::from_slice(&payload) {
                        Ok(jwt_vc) => Self::decode_jwt_vc_claims(input, jwt_vc),
                        Err(_) => {
                            Err(Error::UnrecognizedInput(input))
                        }
                    }
                }
                Err(_) => {
                    Err(Error::UnrecognizedInput(input))
                }
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Credential {
    BitstringStatusListCredential(BitstringStatusListCredential)
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum JsonInputValue {
    BitstringStatusListCredential(BitstringStatusListCredential),
    JwtVc(ssi_jwt::JWTClaims<ssi_vc::VCPublicClaims>),
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("could not read from {0}: {1}")]
    ReadFile(Input, io::Error),

    #[error("unrecognized input value from {0}")]
    UnrecognizedInput(Input),

    #[error("unable to decode `BitstringStatusList`: {0}")]
    BitstringStatusListDecode(#[from] ssi_status::bitstream_status_list::DecodeError),

    #[error("invalid JWS: {0}")]
    Jws(#[from] ssi_jws::DecodeError),

    #[error("unable to read key: {0}")]
    Key(#[from] KeyError)
}

#[derive(Debug, thiserror::Error)]
enum KeyError {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error)
}

#[derive(Debug, Default)]
enum Input {
    #[default]
    Stdin,
    File(PathBuf)
}

impl Input {
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

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdin => write!(f, "standard input"),
            Self::File(path) => write!(f, "file `{}`", path.display())
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