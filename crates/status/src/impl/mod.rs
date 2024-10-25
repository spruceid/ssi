pub mod any;
pub mod bitstring_status_list;
pub mod bitstring_status_list_20240406;
pub mod token_status_list;

pub use flate2::Compression;

/// Status list overflow.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Overflow {
    /// Value is too large.
    #[error("value `{0}` is too large")]
    Value(u8),

    /// Index is out of bounds.
    #[error("index `{0}` is out of bounds")]
    Index(usize),
}
