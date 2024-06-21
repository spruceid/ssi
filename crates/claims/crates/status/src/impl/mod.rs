pub mod any;
pub mod bitstream_status_list;
pub mod token_status_list;

/// Status list overflow.
#[derive(Debug, thiserror::Error)]
pub enum Overflow {
    /// Value is too large.
    #[error("value `{0}` is too large")]
    Value(u8),

    /// Index is out of bounds.
    #[error("index `{0}` is out of bounds")]
    Index(usize),
}
