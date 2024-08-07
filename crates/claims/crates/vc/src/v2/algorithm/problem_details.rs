use std::fmt;

use serde::{Serialize, Serializer};

/// [Problem Details](https://www.w3.org/TR/vc-data-model-2.0/#problem-details).
#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type", serialize_with = "serialize_problem_type")]
    problem_type: Box<dyn ProblemType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<i32>,

    title: String,
    detail: String,
}

impl ProblemDetails {
    pub fn new<T: ProblemType>(problem_type: T, title: String, detail: String) -> Self {
        let code = problem_type.code();
        Self {
            problem_type: Box::new(problem_type),
            code: Some(code),
            title,
            detail,
        }
    }

    /// `type` property.
    pub fn r#type(&self) -> &str {
        self.problem_type.url()
    }

    /// `code` property.
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    /// `title` property.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// `detail` property.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

fn serialize_problem_type<S>(
    problem_type: &Box<dyn ProblemType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&problem_type.to_string())
}

/// Problem `type`.
///
/// Implementations can define custom problem types.
pub trait ProblemType: fmt::Display + fmt::Debug + Send + Sync + 'static {
    fn url(&self) -> &'static str;
    fn code(&self) -> i32;
}

/// Predefined `type`s in <https://www.w3.org/TR/vc-data-model-2.0/#problem-details>.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PredefinedProblemType {
    ParsingError,
    CryptographicSecurityError,
    MalformedValueError,
    RangeError,
}

impl ProblemType for PredefinedProblemType {
    fn url(&self) -> &'static str {
        match self {
            PredefinedProblemType::ParsingError => {
                "https://www.w3.org/TR/vc-data-model#PARSING_ERROR"
            }
            PredefinedProblemType::CryptographicSecurityError => {
                "https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR"
            }
            PredefinedProblemType::MalformedValueError => {
                "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR"
            }
            PredefinedProblemType::RangeError => "https://www.w3.org/TR/vc-data-model#RANGE_ERROR",
        }
    }

    fn code(&self) -> i32 {
        match self {
            PredefinedProblemType::ParsingError => -64,
            PredefinedProblemType::CryptographicSecurityError => -65,
            PredefinedProblemType::MalformedValueError => -66,
            PredefinedProblemType::RangeError => -67,
        }
    }
}

impl fmt::Display for PredefinedProblemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_problem_details_parsing_error() {
        let problem = ProblemDetails::new(
            PredefinedProblemType::ParsingError,
            "Parsing Error".to_string(),
            "Failed to parse the request body.".to_string(),
        );
        let json = serde_json::to_string(&problem).expect("Failed to serialize ProblemDetails");
        assert_eq!(
            json,
            r#"{"type":"https://www.w3.org/TR/vc-data-model#PARSING_ERROR","code":-64,"title":"Parsing Error","detail":"Failed to parse the request body."}"#
        );
    }

    #[test]
    fn test_serialize_problem_details_cryptographic_security_error() {
        let problem = ProblemDetails::new(
            PredefinedProblemType::CryptographicSecurityError,
            "Cryptographic Security Error".to_string(),
            "Failed to verify the cryptographic proof.".to_string(),
        );
        let json = serde_json::to_string(&problem).expect("Failed to serialize ProblemDetails");
        assert_eq!(
            json,
            r#"{"type":"https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR","code":-65,"title":"Cryptographic Security Error","detail":"Failed to verify the cryptographic proof."}"#
        );
    }

    #[test]
    fn test_serialize_problem_details_malformed_value_error() {
        let problem = ProblemDetails::new(
            PredefinedProblemType::MalformedValueError,
            "Malformed Value Error".to_string(),
            "The request body contains a malformed value.".to_string(),
        );
        let json = serde_json::to_string(&problem).expect("Failed to serialize ProblemDetails");
        assert_eq!(
            json,
            r#"{"type":"https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR","code":-66,"title":"Malformed Value Error","detail":"The request body contains a malformed value."}"#
        );
    }

    #[test]
    fn test_serialize_problem_details_range_error() {
        let problem = ProblemDetails::new(
            PredefinedProblemType::RangeError,
            "Range Error".to_string(),
            "The request body contains a value out of range.".to_string(),
        );
        let json = serde_json::to_string(&problem).expect("Failed to serialize ProblemDetails");
        assert_eq!(
            json,
            r#"{"type":"https://www.w3.org/TR/vc-data-model#RANGE_ERROR","code":-67,"title":"Range Error","detail":"The request body contains a value out of range."}"#
        );
    }
}
