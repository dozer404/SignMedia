use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginalWorkDescriptor {
    pub work_id: Uuid,
    pub title: String,
    pub authors: Vec<AuthorMetadata>,
    pub authorship_fingerprint: Option<String>, // Hex encoded BLAKE3 hash of authors
    pub created_at: DateTime<Utc>,
    pub tracks: Vec<TrackMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorMetadata {
    pub author_id: String, // public key hex
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackMetadata {
    pub track_id: u32,
    pub codec: String,
    #[serde(default)]
    pub container_type: Option<String>,
    #[serde(default)]
    pub codec_extradata: Option<String>, // Hex encoded
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub sample_rate: Option<u32>,
    #[serde(default)]
    pub channel_count: Option<u16>,
    #[serde(default)]
    pub timebase_num: Option<u32>,
    #[serde(default)]
    pub timebase_den: Option<u32>,
    pub merkle_root: String,             // Hex encoded
    pub perceptual_hash: Option<String>, // Hex encoded
    pub total_chunks: u64,
    pub chunk_size: u64,
    #[serde(default)]
    pub chunk_index: Vec<TrackChunkIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackChunkIndexEntry {
    pub chunk_index: u64,
    pub pts: Option<i64>,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivativeWorkDescriptor {
    pub derivative_id: Uuid,
    pub original_owd: OriginalWorkDescriptor,
    pub original_signature: String, // Hex
    #[serde(default)]
    pub ancestry: Vec<SignedManifest>,
    pub clipper_id: String, // public key hex
    pub authorship_fingerprint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub clip_mappings: Vec<ClipMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipMapping {
    pub track_id: u32,
    pub start_chunk_index: u64,
    pub end_chunk_index: u64,
    // For each chunk in the clip, we need a proof it was in the original
    pub proofs: Vec<MerkleProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub chunk_index: u64,
    pub hash: String,
    pub path: Vec<ProofStep>,
    pub chunk_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub is_left: bool,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub content: ManifestContent,
    pub signatures: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub signature: String,  // Hex
    pub public_key: String, // Hex
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ManifestContent {
    Original(OriginalWorkDescriptor),
    Derivative(DerivativeWorkDescriptor),
}
