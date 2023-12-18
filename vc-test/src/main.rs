use ssi::did::example::DIDExample;
use ssi::jwk::JWTKeys;
use ssi::jwk::JWK;
use ssi::ldp::LinkedDataProofOptions;
use ssi::vc::Credential;
use ssi::vc::Presentation;

fn usage() {
    eprintln!("Usage: ssi-vc-test <generate|generate-presentation> <file>");
}

fn generate(data: String) -> String {
    let doc = Credential::from_json(&data).unwrap();

    serde_json::to_string_pretty(&doc).unwrap()
}

fn take_key(keys: &JWTKeys) -> &JWK {
    if let Some(rs256_key) = &keys.rs256_private_key {
        rs256_key
    } else if let Some(es256k_key) = &keys.es256k_private_key {
        es256k_key
    } else {
        panic!("Missing key");
    }
}

async fn generate_jwt(data: &str, keys: &JWTKeys, aud: &str, sign: bool) -> String {
    let resolver = DIDExample;
    let vc = Credential::from_json_unsigned(data).unwrap();
    let options = LinkedDataProofOptions {
        domain: Some(aud.to_string()),
        checks: None,
        created: None,
        ..Default::default()
    };
    let jwk_opt = if sign { Some(take_key(keys)) } else { None };
    vc.generate_jwt(jwk_opt, &options, &resolver).await.unwrap()
}

fn decode_jwt_unsigned(data: &str) -> String {
    let vc = Credential::from_jwt_unsigned(data).unwrap();
    serde_json::to_string_pretty(&vc).unwrap()
}

fn generate_presentation(data: &str) -> String {
    let vp = Presentation::from_json(data).unwrap();

    serde_json::to_string_pretty(&vp).unwrap()
}

async fn generate_jwt_presentation(data: &str, keys: &JWTKeys, aud: &str) -> String {
    let resolver = DIDExample;
    let vp = Presentation::from_json_unsigned(data).unwrap();
    let options = LinkedDataProofOptions {
        domain: Some(aud.to_string()),
        checks: None,
        created: None,
        proof_purpose: None,
        ..Default::default()
    };
    let jwk = take_key(keys);
    vp.generate_jwt(Some(jwk), &options, &resolver)
        .await
        .unwrap()
}

fn read_file(filename: &str) -> String {
    let mut file = std::fs::File::open(filename).unwrap();
    let mut data = String::new();
    use std::io::Read;
    file.read_to_string(&mut data).unwrap();
    data
}

fn write_out(data: String) {
    use std::io::Write;
    let stdout = std::io::stdout();
    stdout.lock().write_all(data.as_bytes()).unwrap();
}

#[async_std::main]
async fn main() {
    let args = std::env::args();
    let mut cmd: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut jwt_keys: Option<JWTKeys> = None;
    let mut jwt_aud: Option<String> = None;
    let mut jwt_no_jws = false;
    let mut jwt_presentation = false;
    let mut jwt_decode = false;
    let mut args_iter = args;
    let _bin = args_iter.next().unwrap();
    while let Some(arg) = args_iter.next() {
        match (arg.starts_with("--"), arg.as_ref()) {
            (true, "--jwt") => {
                if let Some(jwt_b64) = args_iter.next() {
                    let jwt_json = base64::decode(jwt_b64).unwrap();
                    jwt_keys = Option::Some(serde_json::from_slice(&jwt_json).unwrap());
                }
            }
            (true, "--jwt-aud") => jwt_aud = args_iter.next(),
            (true, "--jwt-no-jws") => jwt_no_jws = true,
            (true, "--jwt-presentation") => jwt_presentation = true,
            (true, "--jwt-decode") => jwt_decode = true,
            (true, _) => panic!("Unexpected option '{arg}'"),
            (false, _) => {
                if cmd.is_none() {
                    cmd = Option::Some(arg);
                } else if filename.is_none() {
                    filename = Option::Some(arg);
                } else {
                    panic!("Unexpected argument '{arg}'");
                }
            }
        }
    }
    if cmd.is_none() || filename.is_none() {
        return usage();
    }

    let cmd_str = cmd.unwrap();
    match cmd_str.as_ref() {
        "generate" => {
            let data: String = read_file(&filename.unwrap());
            let output: String;
            if jwt_decode {
                output = decode_jwt_unsigned(&data);
            } else if let Some(keys) = jwt_keys {
                if let Some(aud) = jwt_aud {
                    output = generate_jwt(&data, &keys, &aud, !jwt_no_jws).await;
                } else {
                    panic!("Expected --jwt-aud with --jwt");
                }
            } else {
                output = generate(data);
            }
            write_out(output);
        }
        "generate-presentation" => {
            let data: String = read_file(&filename.unwrap());
            let output: String;
            if let Some(keys) = jwt_keys {
                if let Some(aud) = jwt_aud {
                    if !jwt_presentation {
                        // vc-test-suite says this is optional, but it seems
                        // to be always used.
                        panic!("Expected --jwt-presentation with --jwt");
                    }
                    output = generate_jwt_presentation(&data, &keys, &aud).await;
                } else {
                    panic!("Expected --jwt-aud with --jwt");
                }
            } else {
                output = generate_presentation(&data);
            }
            write_out(output);
        }
        _ => {
            eprintln!("Unexpected command '{cmd_str}'");
            std::process::exit(1);
        }
    }
}
