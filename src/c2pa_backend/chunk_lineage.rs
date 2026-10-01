use anyhow::{anyhow, Result};
use c2pa::Builder;
use serde::{Deserialize, Serialize};
use crate::crypto::{verify_proof, Hash};
use crate::models::MerkleProof;

pub const CHUNK_LINEAGE_LABEL: &str = "org.signmedia.chunk-lineage.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkLineageAssertion {
    pub parent_work_id: String,
    pub track_id: u32,
    pub start_chunk_index: u64,
    pub end_chunk_index: u64,
    pub merkle_root: String,
    pub proofs: Vec<MerkleProof>,
}

pub fn add_chunk_lineage_assertion(
    builder: &mut Builder,
    assertion: &ChunkLineageAssertion,
) -> Result<()> {
    builder.add_assertion(CHUNK_LINEAGE_LABEL, assertion)?;
    Ok(())
}

pub fn verify_chunk_lineage_assertion(
    assertion: &ChunkLineageAssertion,
) -> Result<bool> {
    let root_bytes = hex::decode(&assertion.merkle_root)?;
    let root: Hash = root_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid Merkle root length"))?;

    for proof in &assertion.proofs {
        if !verify_proof(root, proof) {
            return Ok(false);
        }
    }

    Ok(true)
}
