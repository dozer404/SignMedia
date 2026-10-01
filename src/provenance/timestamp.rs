use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::crypto::{hash_data, Hash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc3161TimestampToken {
    pub tsa_name: String,
    pub timestamp: DateTime<Utc>,
    pub message_imprint: String, // Hex
    pub raw_token_b64: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TsaRequirementMode {
    Required,
    Optional,
}

pub fn verify_timestamp_imprint(
    token: &Rfc3161TimestampToken,
    expected_data: &[u8],
) -> Result<bool> {
    let expected_hash = hash_data(expected_data);
    let expected_hex = hex::encode(expected_hash);
    Ok(token.message_imprint.eq_ignore_ascii_case(&expected_hex))
}

pub fn validate_timestamp_evidence(
    token: Option<&Rfc3161TimestampToken>,
    expected_data: &[u8],
    mode: TsaRequirementMode,
) -> Result<bool> {
    match token {
        Some(t) => verify_timestamp_imprint(t, expected_data),
        None => match mode {
            TsaRequirementMode::Required => Err(anyhow!("Missing required TSA timestamp evidence")),
            TsaRequirementMode::Optional => Ok(true),
        },
    }
}
