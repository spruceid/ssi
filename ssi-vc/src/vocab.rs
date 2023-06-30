use iref::Iri;
use static_iref::iri;

pub const VERIFIABLE_CREDENTIAL: Iri<'static> =
    iri!("https://www.w3.org/2018/credentials#VerifiableCredential");

pub const PROOF: Iri<'static> = iri!("https://w3id.org/security#proof");
