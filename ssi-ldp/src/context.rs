use crate::URI;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap as Map;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Context {
    URI(URI),
    Object(Map<String, Value>),
}
