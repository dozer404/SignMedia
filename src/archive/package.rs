use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use crate::crypto::hash_data;

pub const ARCHIVAL_FORMAT_VERSION: &str = "smed-archive-v1";
pub const MAX_PACKAGE_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100 MB
pub const MAX_OBJECT_SIZE_BYTES: usize = 50 * 1024 * 1024;  // 50 MB

fn default_version() -> String {
    ARCHIVAL_FORMAT_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalInventory {
    #[serde(default = "default_version")]
    pub format_version: String,
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

pub fn validate_object_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Object name cannot be empty"));
    }
    if name.contains('\0') || name.contains('\r') || name.contains('\n') || name.contains('/') || name.contains('\\') {
        return Err(anyhow!("Object name '{}' contains invalid or path separator characters", name));
    }

    let path = Path::new(name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(anyhow!("Object name '{}' attempts path traversal or is an invalid path", name)),
    }
}

pub fn validate_safe_extraction_target(output_dir: &Path, filename: &str) -> Result<PathBuf> {
    validate_object_name(filename)?;
    let target = output_dir.join(filename);

    if let Ok(meta) = fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!("Extraction target '{:?}' is a symlink", target));
        }
    }

    Ok(target)
}

impl ArchivalPackage {
    pub fn new(
        playable_media: &[u8],
        playable_name: &str,
        manifest_store: &[u8],
    ) -> Result<Self> {
        validate_object_name(playable_name)?;
        if playable_name == "manifest_store.c2pa" {
            return Err(anyhow!("Playable media name collides with manifest store name"));
        }
        if playable_media.len() > MAX_OBJECT_SIZE_BYTES || manifest_store.len() > MAX_OBJECT_SIZE_BYTES {
            return Err(anyhow!("Object size exceeds maximum limit"));
        }

        let playable_hash = hex::encode(hash_data(playable_media));
        let manifest_hash = hex::encode(hash_data(manifest_store));

        let inventory = ArchivalInventory {
            format_version: ARCHIVAL_FORMAT_VERSION.to_string(),
            package_id: uuid::Uuid::new_v4().to_string(),
            playable_media_name: playable_name.to_string(),
            playable_media_hash: playable_hash,
            manifest_store_hash: manifest_hash,
            created_at: chrono::Utc::now(),
        };

        Ok(Self {
            inventory,
            playable_media_bytes: playable_media.to_vec(),
            manifest_store_bytes: manifest_store.to_vec(),
        })
    }

    pub fn pack_to_file(&self, path: &Path) -> Result<()> {
        let json_bytes = serde_json::to_vec(self)?;
        if json_bytes.len() as u64 > MAX_PACKAGE_SIZE_BYTES {
            return Err(anyhow!("Package size exceeds maximum limit"));
        }
        fs::write(path, json_bytes)?;
        Ok(())
    }

    pub fn unpack_from_file(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_PACKAGE_SIZE_BYTES {
            return Err(anyhow!("Package file size {:?} exceeds maximum limit", metadata.len()));
        }
        let json_bytes = fs::read(path)?;
        let pkg: Self = serde_json::from_slice(&json_bytes)?;
        pkg.verify_inventory()?;
        Ok(pkg)
    }

    pub fn verify_inventory(&self) -> Result<()> {
        if self.inventory.format_version != ARCHIVAL_FORMAT_VERSION {
            return Err(anyhow!("Unsupported archival format version: {}", self.inventory.format_version));
        }

        validate_object_name(&self.inventory.playable_media_name)?;
        if self.inventory.playable_media_name == "manifest_store.c2pa" {
            return Err(anyhow!("Playable media name collides with manifest_store.c2pa"));
        }

        if self.playable_media_bytes.len() > MAX_OBJECT_SIZE_BYTES || self.manifest_store_bytes.len() > MAX_OBJECT_SIZE_BYTES {
            return Err(anyhow!("Object size exceeds maximum allowable limit"));
        }

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

    pub fn unpack_and_extract(&self, output_dir: &Path) -> Result<()> {
        self.verify_inventory()?;

        let media_target = validate_safe_extraction_target(output_dir, &self.inventory.playable_media_name)?;
        let manifest_target = validate_safe_extraction_target(output_dir, "manifest_store.c2pa")?;

        if let Ok(meta) = fs::symlink_metadata(output_dir) {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("Output directory is a symlink"));
            }
        }

        fs::create_dir_all(output_dir)?;

        fs::write(&media_target, &self.playable_media_bytes)?;
        fs::write(&manifest_target, &self.manifest_store_bytes)?;

        Ok(())
    }
}
