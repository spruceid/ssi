#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod caip10;
pub mod caip2;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
