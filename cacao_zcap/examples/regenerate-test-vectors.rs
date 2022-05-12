use anyhow::{Context, Result};
use cacao_zcap::translation::cacao_to_zcap::cacao_to_zcap;
use cacao_zcap::CapabilityChainItem;
use cacaos::siwe::Message;
use cacaos::siwe_cacao::SignInWithEthereum;
use cacaos::BasicSignature;
use cacaos::{Payload, CACAO};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

fn read_siwe(path: &PathBuf) -> Result<Message> {
    let mut file = File::open(path)?;
    let mut string = String::new();
    file.read_to_string(&mut string)?;
    Message::from_str(&string).context("Unable to parse message")
}

fn read_siwe_sig(path: &PathBuf) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut string = String::new();
    file.read_to_string(&mut string)?;
    let (_base, sig) = multibase::decode(&format!("f{}", &string)).unwrap();
    Ok(sig)
}

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let siwe0_path = crate_dir.join("tests/delegation0.siwe");
    let siwe1_path = crate_dir.join("tests/delegation1.siwe");
    let siwe0_sig_path = crate_dir.join("tests/delegation0.siwe.sig");
    let siwe1_sig_path = crate_dir.join("tests/delegation1.siwe.sig");
    let zcap0_path = crate_dir.join("tests/delegation0-zcap.jsonld");
    let zcap1_path = crate_dir.join("tests/delegation1-zcap.jsonld");

    let siwe0 = read_siwe(&siwe0_path).unwrap();
    let siwe1 = read_siwe(&siwe1_path).unwrap();

    // Build zcap0 from siwe0
    let payload0 = Payload::from(siwe0);
    let sigbytes0 = read_siwe_sig(&siwe0_sig_path).unwrap();
    let sig0 = BasicSignature {
        s: sigbytes0.try_into().unwrap(),
    };
    let cacao0 = CACAO::<SignInWithEthereum>::new(payload0, sig0);
    let zcap0 = cacao_to_zcap(&cacao0).unwrap();
    let zcap0_json = serde_json::to_value(&zcap0).unwrap();
    let mut zcap0_out = File::create(zcap0_path).unwrap();
    serde_json::to_writer_pretty(&mut zcap0_out, &zcap0_json).unwrap();
    write!(zcap0_out, "\n").unwrap();

    // Update siwe1 to embed zcap0.
    // Update previous delegation in resources array
    let parent_capability = CapabilityChainItem::Object(zcap0);
    let mut payload1 = Payload::from(siwe1);
    payload1.resources.pop();
    payload1
        .resources
        .push(parent_capability.as_resource_uri().unwrap());
    let siwe1: Message = payload1.clone().try_into().unwrap();
    let mut siwe1_out = File::create(siwe1_path).unwrap();
    write!(siwe1_out, "{}", siwe1).unwrap();

    // Build zcap1 from siwe1
    let sigbytes1 = read_siwe_sig(&siwe1_sig_path).unwrap();
    let sig1 = BasicSignature {
        s: sigbytes1.try_into().unwrap(),
    };
    let cacao1 = CACAO::<SignInWithEthereum>::new(payload1, sig1);
    let zcap1 = cacao_to_zcap(&cacao1).unwrap();
    let zcap1_json = serde_json::to_value(&zcap1).unwrap();
    let mut zcap1_out = File::create(zcap1_path).unwrap();
    serde_json::to_writer_pretty(&mut zcap1_out, &zcap1_json).unwrap();
    write!(zcap1_out, "\n").unwrap();
}
