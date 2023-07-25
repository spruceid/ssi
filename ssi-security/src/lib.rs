use treeldr_rust_macros::tldr;

#[tldr("ssi-vc/src/schema/sec.ttl")]
pub mod schema {
    #[prefix("http://www.w3.org/2002/07/owl#")]
    pub mod owl {}

    #[prefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#")]
    pub mod rdf {}

    #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
    pub mod rdfs {}

    #[prefix("http://www.w3.org/2001/XMLSchema#")]
    pub mod xsd {}

    #[prefix("https://treeldr.org/")]
    pub mod tldr {}

    #[prefix("https://w3id.org/security#")]
    pub mod sec {}
}

pub use schema::sec::*;
