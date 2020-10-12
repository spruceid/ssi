pub mod der;
pub mod did;
pub mod error;
pub mod jwk;
pub mod ldp;
pub mod one_or_many;
pub mod rdf;
pub mod vc;

extern crate pest;
#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate derive_builder;

#[derive(Parser)]
#[grammar = "did.pest"]
pub struct DidParser;

#[cfg(test)]
mod tests {
    use super::*;

    // use pest::error::Error;
    use pest::Parser;

    #[test]
    fn parse_did_components() {
        let input = "did:deadbeef:cafe/sub/path/?p1=v1&p2=v2#frag1";
        let rv = DidParser::parse(Rule::did_url, input);
        match rv {
            Ok(pairs) => {
                //println!("{:#?}", pairs);
                assert_eq!(input, pairs.as_str()); // ensure complete parsing
                let mut pairs_iter = pairs;
                let mut did_url_pairs_iter = pairs_iter.next().unwrap().into_inner();

                // @TODO: check scheme subtokens (method_name, method_specific_id)
                let did_scheme_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::did_scheme, did_scheme_pair.as_rule());
                assert_eq!("did:deadbeef:cafe", did_scheme_pair.as_str());

                // @TODO: check path_abempty subtokens (segment*)
                let path_abempty_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::path_abempty, path_abempty_pair.as_rule());
                assert_eq!("/sub/path/", path_abempty_pair.as_str());

                let query_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::query, query_pair.as_rule());
                assert_eq!("p1=v1&p2=v2", query_pair.as_str());

                let fragment_pair = did_url_pairs_iter.next().unwrap();
                assert_eq!(Rule::fragment, fragment_pair.as_rule());
                assert_eq!("frag1", fragment_pair.as_str());
            }
            Err(e) => panic!("error: {}", e),
        }
    }

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
