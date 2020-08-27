use ssi::jwk::JWTKeys;
use ssi::vc::Contexts;
use ssi::vc::Credential;
use ssi::vc::Presentation;

fn usage() {
    eprintln!("Usage: ssi-vc-test <generate|generate-presentation> <file>");
}

fn generate(data: String) -> String {
    let doc: Credential = serde_json::from_str(&data).unwrap();
    if !doc.type_.contains(&"VerifiableCredential".to_string()) {
        panic!("Missing type VerifiableCredential");
    }
    if doc.issuer.is_none() {
        panic!("Missing issuer");
    }
    if doc.issuance_date.is_none() {
        panic!("Missing issuance date");
    }
    if doc.proof.is_none() {
        panic!("Missing proof");
    }

    let is_zkp = match &doc.proof {
        Some(proofs) => proofs.any(|proof| proof.type_.contains(&"CLSignature2019".to_string())),
        _ => false,
    };
    if is_zkp {
        if doc.credential_schema.is_none() {
            panic!("Missing credential schema for ZKP");
        }
    }

    // work around https://github.com/w3c/vc-test-suite/issues/96
    if doc.type_.len() > 1 {
        if let Contexts::Many(ref context) = doc.context {
            if context.len() == 1 {
                panic!("If there are multiple types, there should be multiple contexts.");
            }
        }
    }

    serde_json::to_string_pretty(&doc).unwrap()
}

fn generate_jwt(data: &String, keys: &JWTKeys, aud: &String, sign: bool) -> String {
    let vc: Credential = serde_json::from_str(data).unwrap();
    if sign {
        vc.encode_sign_jwt(keys, aud).unwrap()
    } else {
        vc.encode_jwt_unsigned(aud).unwrap()
    }
}

fn decode_jwt_unsigned(data: &String) -> String {
    let vc = Credential::from_jwt_unsigned(data).unwrap();
    serde_json::to_string_pretty(&vc).unwrap()
}

fn generate_presentation(data: &String) -> String {
    let doc: Presentation = serde_json::from_str(data).unwrap();
    if !doc.type_.contains(&"VerifiablePresentation".to_string()) {
        panic!("Missing type VerifiablePresentation");
    }

    // note: for JWT, proof may be outside the VC object
    if !doc.proof.is_some() {
        panic!("Missing proof");
    }

    serde_json::to_string_pretty(&doc).unwrap()
}

fn generate_jwt_presentation(data: &String, keys: &JWTKeys, aud: &String) -> String {
    let vp: Presentation = serde_json::from_str(data).unwrap();
    vp.encode_sign_jwt(keys, aud).unwrap()
}

fn read_file(filename: &String) -> String {
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

fn main() {
    let args = std::env::args();
    let mut cmd: Option<String> = None;
    let mut filename: Option<String> = None;
    let mut jwt_keys: Option<JWTKeys> = None;
    let mut jwt_aud: Option<String> = None;
    let mut jwt_no_jws = false;
    let mut jwt_presentation = false;
    let mut jwt_decode = false;
    let mut args_iter = args.into_iter();
    let _bin = args_iter.next().unwrap();
    loop {
        match args_iter.next() {
            Some(arg) => match (arg.starts_with("--"), arg.as_ref()) {
                (true, "--jwt") => match args_iter.next() {
                    Some(jwt_b64) => {
                        let jwt_json = base64::decode(jwt_b64).unwrap();
                        jwt_keys = Option::Some(serde_json::from_slice(&jwt_json).unwrap());
                    }
                    None => {}
                },
                (true, "--jwt-aud") => jwt_aud = args_iter.next(),
                (true, "--jwt-no-jws") => jwt_no_jws = true,
                (true, "--jwt-presentation") => jwt_presentation = true,
                (true, "--jwt-decode") => jwt_decode = true,
                (true, _) => panic!("Unexpected option '{}'", arg),
                (false, _) => {
                    if cmd == None {
                        cmd = Option::Some(arg);
                    } else if filename == None {
                        filename = Option::Some(arg);
                    } else {
                        panic!("Unexpected argument '{}'", arg);
                    }
                }
            },
            None => break,
        }
    }
    if cmd == None || filename == None {
        return usage();
    }
    // work around https://github.com/w3c/vc-test-suite/issues/98
    if filename.as_ref().unwrap().contains("example-015-zkp") {
        jwt_keys = None;
        jwt_aud = None;
        jwt_decode = false;
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
                    output = generate_jwt(&data, &keys, &aud, !jwt_no_jws);
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
                    output = generate_jwt_presentation(&data, &keys, &aud);
                } else {
                    panic!("Expected --jwt-aud with --jwt");
                }
            } else {
                output = generate_presentation(&data);
            }
            write_out(output);
        }
        _ => {
            eprintln!("Unexpected command '{}'", cmd_str);
            std::process::exit(1);
        }
    }
}
