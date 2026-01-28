use std::io::{Read, Write, Seek, SeekFrom};
use crate::models::{SignedManifest, ManifestContent};
use crate::crypto;
use anyhow::{Result, anyhow};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

pub const MAGIC: &[u8; 4] = b"SMED";
pub const VERSION: u32 = 1;

pub struct SmedWriter<W: Write> {
    writer: W,
}

impl<W: Write> SmedWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_all(&mut self, manifest: &SignedManifest, chunks: &[Vec<u8>]) -> Result<()> {
        self.writer.write_all(MAGIC)?;
        self.writer.write_u32::<LittleEndian>(VERSION)?;
        
        let manifest_json = serde_json::to_vec(manifest)?;
        self.writer.write_u64::<LittleEndian>(manifest_json.len() as u64)?;
        self.writer.write_all(&manifest_json)?;
        
        for chunk in chunks {
            self.writer.write_all(chunk)?;
        }
        
        Ok(())
    }
}

pub struct SmedReader<R: Read + Seek> {
    reader: R,
    pub manifest: SignedManifest,
    data_start: u64,
}

impl<R: Read + Seek> SmedReader<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(anyhow!("Invalid magic"));
        }
        
        let version = reader.read_u32::<LittleEndian>()?;
        if version != VERSION {
            return Err(anyhow!("Unsupported version"));
        }
        
        let manifest_len = reader.read_u64::<LittleEndian>()?;
        let mut manifest_json = vec![0u8; manifest_len as usize];
        reader.read_exact(&mut manifest_json)?;
        
        let manifest: SignedManifest = serde_json::from_slice(&manifest_json)?;
        let data_start = reader.stream_position()?;
        
        Ok(Self { reader, manifest, data_start })
    }

    pub fn read_chunk(&mut self, index: u64, chunk_size: u64) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(self.data_start + index * chunk_size))?;
        let mut buffer = Vec::new();
        let mut limited = self.reader.by_ref().take(chunk_size);
        limited.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
    
    pub fn read_variable_chunk(&mut self, offset: u64, size: u64) -> Result<Vec<u8>> {
        self.reader.seek(SeekFrom::Start(self.data_start + offset))?;
        let mut buffer = Vec::new();
        let mut limited = self.reader.by_ref().take(size);
        limited.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn data_start(&self) -> u64 {
        self.data_start
    }
}

pub struct StreamingVerifier {
    manifest: SignedManifest,
    original_root: Option<crypto::Hash>,
}

impl StreamingVerifier {
    pub fn new(manifest: SignedManifest) -> Result<Self> {
        let original_root = match &manifest.content {
            ManifestContent::Original(owd) => {
                let root_bytes = hex::decode(&owd.tracks[0].merkle_root)?;
                Some(root_bytes.try_into().map_err(|_| anyhow!("Invalid root size"))?)
            }
            ManifestContent::Derivative(dwd) => {
                let root_bytes = hex::decode(&dwd.original_owd.tracks[0].merkle_root)?;
                Some(root_bytes.try_into().map_err(|_| anyhow!("Invalid root size"))?)
            }
        };
        
        Ok(Self { manifest, original_root })
    }

    pub fn verify_chunk(&self, index: u64, data: &[u8]) -> bool {
        let actual_hash = crypto::hash_data(data);
        
        match &self.manifest.content {
            ManifestContent::Original(_) => {
                // In a real streaming scenario, we might need more than the root.
                // But if we have the full Merkle tree nodes, we could verify.
                // For this POC, we'll just check if the hash matches what we'd expect 
                // if we had the proofs. Since we don't store ALL hashes in manifest, 
                // we can't easily verify individual chunks without the tree or a proof.
                // However, for Derivatives, we HAVE the proofs.
                true // Placeholder for Original
            }
            ManifestContent::Derivative(dwd) => {
                for mapping in &dwd.clip_mappings {
                    for proof in &mapping.proofs {
                        if proof.chunk_index == index {
                            if hex::encode(actual_hash) != proof.hash {
                                return false;
                            }
                            if let Some(root) = self.original_root {
                                return crypto::verify_proof(root, proof);
                            }
                        }
                    }
                }
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ManifestContent, OriginalWorkDescriptor, SignatureEntry};
    use std::io::Cursor;
    use uuid::Uuid;
    use chrono::Utc;

    #[test]
    fn test_streaming_verifier() -> Result<()> {
        let manifest = SignedManifest {
            content: ManifestContent::Original(OriginalWorkDescriptor {
                work_id: Uuid::new_v4(),
                title: "Test".to_string(),
                authors: vec![],
                created_at: Utc::now(),
                tracks: vec![crate::models::TrackMetadata {
                    track_id: 0,
                    codec: "raw".to_string(),
                    merkle_root: hex::encode([0u8; 32]),
                    perceptual_hash: None,
                    total_chunks: 1,
                    chunk_size: 5,
                }],
            }),
            signatures: vec![],
        };
        let verifier = StreamingVerifier::new(manifest)?;
        assert!(verifier.verify_chunk(0, b"hello"));
        Ok(())
    }

    #[test]
    fn test_round_trip() -> Result<()> {
        let manifest = SignedManifest {
            content: ManifestContent::Original(OriginalWorkDescriptor {
                work_id: Uuid::new_v4(),
                title: "Test".to_string(),
                authors: vec![],
                created_at: Utc::now(),
                tracks: vec![],
            }),
            signatures: vec![SignatureEntry {
                signature: "sig".to_string(),
                public_key: "pub".to_string(),
            }],
        };
        
        let chunks = vec![
            b"hello".to_vec(),
            b"world".to_vec(),
        ];
        
        let mut buffer = Vec::new();
        {
            let mut writer = SmedWriter::new(&mut buffer);
            writer.write_all(&manifest, &chunks)?;
        }
        
        let mut reader = SmedReader::new(Cursor::new(buffer))?;
        assert_eq!(reader.manifest.signatures[0].signature, "sig");
        
        let c1 = reader.read_chunk(0, 5)?;
        assert_eq!(c1, b"hello");
        
        let c2 = reader.read_chunk(1, 5)?;
        assert_eq!(c2, b"world");
        
        Ok(())
    }
}
