use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::crypto::hash_data;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalInventory {
    pub package_id: String,
    pub playable_media_name: String,
    pub playable_media_hash: String,
    pub manifest_store_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalPackage {
    pub inventory: ArchivalInventory,
    pub playable_media_bytes: Vec<u8>,
    pub manifest_store_bytes: Vec<u8>,
}

impl ArchivalPackage {
    pub fn new(
        playable_media: &[u8],
        playable_name: &str,
        manifest_store: &[u8],
    ) -> Self {
        let playable_hash = hex::encode(hash_data(playable_media));
        let manifest_hash = hex::encode(hash_data(manifest_store));

        let inventory = ArchivalInventory {
            package_id: uuid::Uuid::new_v4().to_string(),
            playable_media_name: playable_name.to_string(),
            playable_media_hash: playable_hash,
            manifest_store_hash: manifest_hash,
            created_at: chrono::Utc::now(),
        };

        Self {
            inventory,
            playable_media_bytes: playable_media.to_vec(),
            manifest_store_bytes: manifest_store.to_vec(),
        }
    }

    pub fn pack_to_file(&self, path: &Path) -> Result<()> {
        let json_bytes = serde_json::to_vec(self)?;
        fs::write(path, json_bytes)?;
        Ok(())
    }

    pub fn unpack_from_file(path: &Path) -> Result<Self> {
        let json_bytes = fs::read(path)?;
        let pkg: Self = serde_json::from_slice(&json_bytes)?;
        pkg.verify_inventory()?;
        Ok(pkg)
    }

    pub fn verify_inventory(&self) -> Result<()> {
        let actual_playable_hash = hex::encode(hash_data(&self.playable_media_bytes));
        if actual_playable_hash != self.inventory.playable_media_hash {
            return Err(anyhow!("Archival package playable media hash mismatch!"));
        }

        let actual_manifest_hash = hex::encode(hash_data(&self.manifest_store_bytes));
        if actual_manifest_hash != self.inventory.manifest_store_hash {
            return Err(anyhow!("Archival package manifest store hash mismatch!"));
        }

        Ok(())
    }
}
