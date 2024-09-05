//! Command line interface and example showing how to read and create status lists.
//!
//! # Usage
//!
//! Read a status list from a JWT, JWT-VC claims or Credential:
//! ```console
//! $ cargo run --example status_list -- read -t application/vc+ld+json+jwt examples/files/status-list.jws
//! $ cargo run --example status_list -- read -t application/vc+ld+json examples/files/status-list-credential.jsonld
//! $ cargo run --example status_list -- read -t application/vc+ld+json examples/files/local-status-list-credential.jsonld
//! ```
//!
//! Create a new status list:
//! ```console
//! $ cargo run --example status_list -- create "http://example.org/#statusList" 0 0 1 0
//! ```
use clap::{Parser, Subcommand};
use core::fmt;
use iref::UriBuf;
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::{AnySuite, ProofOptions};
use ssi_dids::{VerificationMethodDIDResolver, DIDJWK};
use ssi_jwk::JWK;
use ssi_status::{
    any::AnyStatusMap, bitstring_status_list, EncodedStatusMap, FromBytes, FromBytesOptions,
    StatusSizeError,
};
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
    SignVcJwt {
        /// Credential filename.
        filename: Option<PathBuf>,

        /// Secret key to sign the JWS.
        #[clap(short, long)]
        key: PathBuf,
    },

    /// Read a status list.
    Read {
        /// Path to a file representing the status list.
        ///
        /// If unspecified, the status list is read from the standard input.
        filename: Option<PathBuf>,

        /// Input media type.
        #[clap(short = 't', long)]
        media_type: String,

        /// Status size in bits.
        status_size: Option<u8>,
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
            Self::SignVcJwt { filename, key } => {
                let source = filename.map(Source::File).unwrap_or_default();
                let bytes = match source.read() {
                    Ok(content) => content,
                    Err(e) => return Err(Error::ReadFile(source, e)),
                };

                let jwk = read_jwk(&key)?;

                let mut header = ssi_jws::Header::default();
                header.algorithm = jwk.algorithm.unwrap();
                header.type_ = Some("vc+ld+json+jwt".to_owned());
                header.content_type = Some("vc+ld+json".to_owned());
                header.key_id = Some(DIDJWK::generate_url(&jwk.to_public()).into_string());

                let signing_bytes = header.encode_signing_bytes(&bytes);
                let signature =
                    ssi_jws::sign_bytes_b64(header.algorithm, &signing_bytes, &jwk).unwrap();

                let jws = ssi_jws::JwsString::from_signing_bytes_and_signature(
                    signing_bytes,
                    signature.into_bytes(),
                )
                .unwrap();

                std::io::stdout().write_all(jws.as_bytes()).unwrap();
                Ok(())
            }
            Self::Read {
                filename,
                media_type,
                status_size,
            } => {
                let source = filename.map(Source::File).unwrap_or_default();
                let bytes = match source.read() {
                    Ok(content) => content,
                    Err(e) => return Err(Error::ReadFile(source, e)),
                };

                let verifier = VerificationParameters::from_resolver(
                    VerificationMethodDIDResolver::new(DIDJWK),
                );
                let status_list = AnyStatusMap::from_bytes_with(
                    &bytes,
                    &media_type,
                    &verifier,
                    FromBytesOptions::ALLOW_UNSECURED,
                )
                .await
                .map_err(|e| Error::FromBytes(source.clone(), e))?
                .decode()
                .map_err(|e| Error::Decode(source, e))?;

                let list: Vec<_> = status_list.iter(status_size)?.collect();

                println!("{}", serde_json::to_string_pretty(&list).unwrap());
                Ok(())
            }
            Self::Create { id, list, key } => {
                let data = create_bitstring_status_list(id.clone(), list, key).await?;
                stdout().write_all(&data).unwrap();
                Ok(())
            }
        }
    }
}

async fn create_bitstring_status_list(
    id: UriBuf,
    list: Vec<StatusValue>,
    key: Option<PathBuf>,
) -> Result<Vec<u8>, Error> {
    let mut status_list = bitstring_status_list::SizedStatusList::new(
        bitstring_status_list::StatusSize::default(),
        bitstring_status_list::TimeToLive::default(),
        // list.into_iter().map(|v| v.0).collect(),
    );

    for v in list {
        status_list.push(v.0).unwrap();
    }

    let credential = bitstring_status_list::BitstringStatusListCredential::new(
        Some(id),
        status_list.to_credential_subject(None, bitstring_status_list::StatusPurpose::Revocation),
    );

    match key {
        Some(path) => {
            use ssi_data_integrity::CryptographicSuite;
            let jwk = read_jwk(&path)?;
            let did = DIDJWK::generate_url(&jwk.to_public());
            let resolver = VerificationMethodDIDResolver::new(DIDJWK);
            let signer = SingleSecretSigner::new(jwk.clone()).into_local();
            let verification_method = ReferenceOrOwned::Reference(did.into());
            let suite = AnySuite::pick(&jwk, Some(&verification_method)).unwrap();
            let params = ProofOptions::from_method(verification_method);
            let vc = suite
                .sign(credential, &resolver, &signer, params)
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

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("could not read from {0}: {1}")]
    ReadFile(Source, io::Error),

    #[error("unable to deserialize {0}: {1}")]
    FromBytes(Source, ssi_status::any::FromBytesError),

    #[error("unable to decode {0}: {1}")]
    Decode(Source, ssi_status::any::DecodeError),

    #[error("unable to read key: {0}")]
    Key(#[from] KeyError),

    #[error(transparent)]
    StatusSize(#[from] StatusSizeError),
}

#[derive(Debug, thiserror::Error)]
enum KeyError {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Default, Clone)]
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
