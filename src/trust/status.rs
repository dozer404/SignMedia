use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStatus {
    Good,
    Revoked,
    Unknown,
    Stale,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub key_or_asset_id: String,
    pub revoked_at: DateTime<Utc>,
    pub reason: String,
}

pub fn evaluate_historical_status(
    signature_time: DateTime<Utc>,
    revocation_record: Option<&RevocationRecord>,
) -> EvidenceStatus {
    match revocation_record {
        None => EvidenceStatus::Good,
        Some(record) => {
            if signature_time < record.revoked_at {
                EvidenceStatus::Good
            } else {
                EvidenceStatus::Revoked
            }
        }
    }
}
