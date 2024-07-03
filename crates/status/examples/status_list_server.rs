//! Status List server example.
//!
//! This example showcase a simple status list credential server implementation.
//! It serves a single provided status list credential at a given URL.
//!
//! # Usage
//!
//! The credential is read from the standard input or the provided file path.
//! ```console
//! $ cargo run --example status_list_server -- -t application/vc+ld+json examples/files/status-list-credential.jsonld
//! serving /credentials/status/3 at 127.0.0.1:3000...
//! $ cargo run --example status_list_server -- -t application/vc+ld+json examples/files/local-status-list-credential.jsonld
//! serving /#statusList at 127.0.0.1:3000...
//! ```
use clap::Parser;
use core::fmt;
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::CONTENT_TYPE,
    server::conn::http1,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use ssi_claims_core::VerificationParameters;
use ssi_dids::{VerificationMethodDIDResolver, DIDJWK};
use ssi_status::{any::AnyStatusMap, FromBytes, FromBytesOptions};
use std::{
    fs,
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
};
use tokio::net::TcpListener;

#[derive(Parser)]
#[clap(
    name = "status-list-server",
    bin_name = "cargo run --example status_list_server --"
)]
struct Args {
    /// Input status list filename.
    ///
    /// If not provided, read the status list from the standard input.
    filename: Option<PathBuf>,

    /// Input status list media type.
    #[clap(short = 't', long)]
    media_type: String,

    /// URL path, query and fragment where the status list will be served at.
    #[clap(short, long)]
    path: Option<String>,

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

async fn run(args: Args) -> Result<(), Error> {
    let input = args.filename.map(Source::File).unwrap_or_default();
    let bytes = match input.read() {
        Ok(bytes) => bytes,
        Err(e) => return Err(Error::ReadFile(input, e)),
    };

    let verifier =
        VerificationParameters::from_resolver(VerificationMethodDIDResolver::new(DIDJWK));

    let status_list = AnyStatusMap::from_bytes_with(
        &bytes,
        &args.media_type,
        &verifier,
        FromBytesOptions::ALLOW_UNSECURED,
    )
    .await
    .map_err(|e| Error::Decode(input, e))?;

    let path = status_list
        .credential_url()
        .map(|url| {
            format!(
                "{}{}{}",
                url.path(),
                url.query().map(|q| format!("?{q}")).unwrap_or_default(),
                url.fragment().map(|f| format!("#{f}")).unwrap_or_default()
            )
        })
        .or(args.path)
        .ok_or(Error::MissingPath)?;

    let configuration = Arc::new(Configuration {
        path,
        bytes,
        media_type: args.media_type,
    });

    let addr = args
        .addr
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 3000)));

    println!("serving {} at {addr}...", configuration.path);

    let listener = TcpListener::bind(addr).await?;

    let service = Service { configuration };

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);

        let service = service.clone();
        tokio::task::spawn(async move {
            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("failed to serve connection: {e}")
            }
        });
    }
}

struct Configuration {
    path: String,
    bytes: Vec<u8>,
    media_type: String,
}

#[derive(Clone)]
struct Service {
    configuration: Arc<Configuration>,
}

impl hyper::service::Service<Request<Incoming>> for Service {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        println!("serving `{}`", req.uri());
        let response = if req.uri() == self.configuration.path.as_str() {
            Response::builder()
                .header(CONTENT_TYPE, self.configuration.media_type.as_str())
                .body(Full::new(Bytes::from(self.configuration.bytes.clone())))
                .unwrap()
        } else {
            Response::builder()
                .status(404)
                .body(Full::default())
                .unwrap()
        };

        std::future::ready(Ok(response))
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error("unable to read {0}: {1}")]
    ReadFile(Source, io::Error),

    #[error("unable to decode {0}: {1}")]
    Decode(Source, ssi_status::any::FromBytesError),

    #[error("missing serve path")]
    MissingPath,
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
