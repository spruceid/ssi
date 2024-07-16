mod keys;
mod signature;

use std::{
    fs,
    path::{Path, PathBuf},
};

use json_syntax::Parse;
pub use keys::*;
use serde::Deserialize;
pub use signature::*;

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum Test {
    #[serde(rename = "SignatureTest")]
    Signature(SignatureTest),
}

fn test_path(path: impl AsRef<Path>) -> PathBuf {
    let mut result: PathBuf = format!("{}/tests", env!("CARGO_MANIFEST_DIR")).into();
    result.extend(path.as_ref());
    result
}

impl Test {
    pub fn load(path: impl AsRef<Path>) -> Self {
        let content = fs::read_to_string(test_path(path)).unwrap();
        let json = json_syntax::Value::parse_str(&content).unwrap().0;
        json_syntax::from_value(json).unwrap()
    }

    pub async fn run(self) {
        match self {
            Self::Signature(test) => test.run().await,
        }
    }
}
