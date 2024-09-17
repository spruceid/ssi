/// Checks if the give byte is part of the base64 URL-safe alphabet.
pub const fn is_url_safe_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}
