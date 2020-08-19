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

    // work around https://github.com/w3c/vc-test-suite/issues/96
    if doc.type_.len() > 1 {
        if let Contexts::Many(ref context) = doc.context {
            if context.len() == 1 {
                panic!("If there are multiple types, there should be multiple contexts.");
            }
        }
    }

    // @TODO: sign/verify
    return serde_json::to_string_pretty(&doc).unwrap();
}

fn generate_presentation(data: String) -> String {
    let doc: Presentation = serde_json::from_str(&data).unwrap();
    if !doc.type_.contains(&"VerifiablePresentation".to_string()) {
        panic!("Missing type VerifiablePresentation");
    }

    // note: for JWT, proof may be outside the VC object
    if !doc.proof.is_some() {
        panic!("Missing proof");
    }

    // @TODO: sign/verify
    let response = serde_json::to_string_pretty(&doc).unwrap();
    return response;
}

fn read_json(filename: &String) -> String {
    let mut file = match std::fs::File::open(filename) {
        Err(err) => panic!("Unable to open {}: {}", filename, err),
        Ok(file) => file,
    };
    let mut data = String::new();

    use std::io::Read;
    let data = match file.read_to_string(&mut data) {
        Err(err) => panic!("Unable to read {}: {}", filename, err),
        Ok(_) => data,
    };
    // TODO: parse JSON
    data
}

fn write_json(data: String) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match handle.write_all(data.as_bytes()) {
        Err(err) => panic!("Unable to write output: {}", err),
        Ok(_) => {}
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return usage();
    }
    let cmd = &args[1];
    let filename = &args[2];
    match &cmd[..] {
        "generate" => {
            let data: String = read_json(&filename);
            let output: String = generate(data);
            write_json(output);
        }
        "generate-presentation" => {
            let data: String = read_json(&filename);
            let output: String = generate_presentation(data);
            write_json(output);
        }
        _ => {
            eprintln!("Unexpected command '{}'", cmd);
            std::process::exit(1);
        }
    }
}
