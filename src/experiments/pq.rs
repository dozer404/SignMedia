use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::crypto::{hash_data, Hash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqArchivalReceipt {
    pub algorithm_id: String,
    pub manifest_store_hash: String, // Hex
    pub commitment_hash: String,     // Hex
    pub pq_signature: String,       // Hex
    pub pq_public_key: String,      // Hex
}

impl PqArchivalReceipt {
    pub fn compute_commitment(manifest_store_bytes: &[u8]) -> Hash {
        let store_hash = hash_data(manifest_store_bytes);
        let mut commitment_input = Vec::new();
        commitment_input.extend_from_slice(b"SIGNMEDIA_PQ_V1");
        commitment_input.extend_from_slice(&store_hash);
        hash_data(&commitment_input)
    }

    pub fn new_simulated(manifest_store_bytes: &[u8], mock_pq_key: &[u8; 32]) -> Self {
        let store_hash = hex::encode(hash_data(manifest_store_bytes));
        let commitment = Self::compute_commitment(manifest_store_bytes);
        let commitment_hex = hex::encode(commitment);

        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&commitment);
        sig_input.extend_from_slice(mock_pq_key);
        let pq_sig = hex::encode(hash_data(&sig_input));

        Self {
            algorithm_id: "ML-DSA-65".to_string(),
            manifest_store_hash: store_hash,
            commitment_hash: commitment_hex,
            pq_signature: pq_sig,
            pq_public_key: hex::encode(mock_pq_key),
        }
    }

    pub fn verify(&self, manifest_store_bytes: &[u8]) -> Result<bool> {
        if self.algorithm_id != "ML-DSA-65" {
            return Ok(false);
        }

        let expected_commitment = Self::compute_commitment(manifest_store_bytes);
        if hex::encode(expected_commitment) != self.commitment_hash {
            return Ok(false);
        }

        let pub_key_bytes = hex::decode(&self.pq_public_key)?;
        if pub_key_bytes.len() != 32 {
            return Ok(false);
        }

        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&expected_commitment);
        sig_input.extend_from_slice(&pub_key_bytes);
        let expected_sig = hex::encode(hash_data(&sig_input));

        Ok(self.pq_signature == expected_sig)
    }
}
