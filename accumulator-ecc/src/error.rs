#[derive(Clone, Debug)]
pub struct Error {
    pub message: String,
    pub code: usize,
}

impl Error {
    pub fn from_msg(code: usize, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self {
            code: 2,
            message: err.to_string(),
        }
    }
}
