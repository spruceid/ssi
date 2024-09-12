/// Byte buffer.
///
/// Any type that implements `AsRef<[u8]>` and `Into<Vec<u8>>` such that both
/// implementation yields the same bytes.
///
/// # Safety
///
/// The `Into<Vec<u8>>` **must** return the same bytes as `AsRef<[u8]>`.
pub unsafe trait BytesBuf: AsRef<[u8]> + Into<Vec<u8>> {}

unsafe impl BytesBuf for Vec<u8> {}

unsafe impl BytesBuf for String {}
