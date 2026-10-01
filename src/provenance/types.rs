use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityStatus {
    Verified,
    Invalid,
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustStatus {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimestampStatus {
    Valid,
    Invalid,
    Absent,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LineageStatus {
    Complete,
    Incomplete,
    Broken,
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub content_integrity: IntegrityStatus,
    pub signer_trust: TrustStatus,
    pub timestamp_status: TimestampStatus,
    pub lineage_status: LineageStatus,
    pub details: Vec<String>,
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self {
            content_integrity: IntegrityStatus::Absent,
            signer_trust: TrustStatus::Unknown,
            timestamp_status: TimestampStatus::Absent,
            lineage_status: LineageStatus::Absent,
            details: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub title: Option<String>,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub claim_type: String,
    pub actor_id: String,
    pub signature: Option<String>,
}
