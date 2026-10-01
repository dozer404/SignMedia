use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::crypto::hash_data;

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

use base64::{engine::general_purpose, Engine as _};

pub fn verify_timestamp_imprint(
    token: &Rfc3161TimestampToken,
    expected_data: &[u8],
) -> Result<bool> {
    // Validate raw_token_b64 is valid base64 and not garbage/placeholder
    let raw_bytes = general_purpose::STANDARD
        .decode(token.raw_token_b64.trim().as_bytes())
        .map_err(|_| anyhow!("Invalid raw_token_b64 encoding in RFC 3161 timestamp token"))?;

    if raw_bytes.len() < 16 {
        return Err(anyhow!("RFC 3161 raw timestamp token is too short or malformed"));
    }

    let expected_hash = hash_data(expected_data);
    let expected_hex = hex::encode(expected_hash);

    if !token.message_imprint.eq_ignore_ascii_case(&expected_hex) {
        return Ok(false);
    }

    Ok(true)
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
            TsaRequirementMode::Optional => Ok(false),
        },
    }
}
