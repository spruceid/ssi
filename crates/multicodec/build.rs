use std::{env, fs, io, io::Write, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=src/table.csv");
    let out_dir = env::var_os("OUT_DIR").unwrap();
    if let Err(e) = generate_codecs("src/table.csv", Path::new(&out_dir).join("table.rs")) {
        eprintln!("unable to generate codecs: {e}");
        std::process::exit(1);
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Csv(#[from] csv::Error),

    #[error("missing name field")]
    MissingNameField,

    #[error("missing tag field")]
    MissingTagField,

    #[error("missing code field")]
    MissingCodeField,

    #[error("invalid code `{0}`")]
    InvalidCode(String),

    #[error("missing status field")]
    MissingStatusField,

    #[error("invalid status `{0}`")]
    InvalidStatus(String),

    #[error("missing description field")]
    MissingDescriptionField,
}

fn generate_codecs(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<(), Error> {
    let mut reader = csv::Reader::from_path(input)?;
    let mut f = io::BufWriter::new(fs::File::create(output)?);

    for record in reader.records() {
        let record = record?;
        let mut fields = record.iter();

        let name = fields.next().ok_or(Error::MissingNameField)?.trim();
        let _tag = fields.next().ok_or(Error::MissingTagField)?.trim();
        let code = parse_code(fields.next().ok_or(Error::MissingCodeField)?.trim())?;
        let status = parse_status(fields.next().ok_or(Error::MissingStatusField)?.trim())?;
        let description = fields.next().ok_or(Error::MissingDescriptionField)?.trim();

        let const_name = all_caps(name);

        if !description.is_empty() {
            writeln!(f, "#[doc = \"{description}\"]")?;
        }

        if matches!(status, Status::Deprecated) {
            writeln!(f, "#[deprecated]")?
        }

        writeln!(f, "pub const {const_name}: u64 = {code:#x}u64;")?;
    }

    Ok(())
}

fn parse_code(s: &str) -> Result<u64, Error> {
    u64::from_str_radix(
        s.strip_prefix("0x")
            .ok_or_else(|| Error::InvalidCode(s.to_owned()))?,
        16,
    )
    .map_err(|_| Error::InvalidCode(s.to_owned()))
}

fn parse_status(s: &str) -> Result<Status, Error> {
    match s {
        "draft" => Ok(Status::Draft),
        "permanent" => Ok(Status::Permanent),
        "deprecated" => Ok(Status::Deprecated),
        _ => Err(Error::InvalidStatus(s.to_owned())),
    }
}

enum Status {
    Draft,
    Permanent,
    Deprecated,
}

fn all_caps(s: &str) -> String {
    let mut result = String::new();

    for c in s.chars() {
        if c == '-' {
            result.push('_');
        } else {
            result.push(c.to_uppercase().next().unwrap());
        }
    }

    result
}
