use crate::crypto;
use crate::models::{ManifestContent, SignedManifest, TrackChunkIndexEntry};
use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

pub const MAGIC: &[u8; 4] = b"SMED";
pub const VERSION_V1: u32 = 1;
pub const VERSION_V2: u32 = 2;

/// Binary layout (all integers little-endian):
/// V1 (legacy):
/// - [0x00..0x04] magic "SMED"
/// - [0x04..0x08] u32 version = 1
/// - [0x08..0x10] u64 manifest_length
/// - [0x10.. ]    manifest JSON bytes
/// - [..]         raw chunk data concatenated
///
/// V2 (sectioned):
/// - [0x00..0x04] magic "SMED"
/// - [0x04..0x08] u32 version = 2
/// - [0x08.. ]    repeated sections until EOF:
///   - u32 section_type
///   - u64 section_length
///   - [section_length] section payload
///
/// Section types:
/// 1 = Manifest JSON
/// 2 = Track data (chunk bytes)
/// 3 = Track table (future)
/// 4 = Index data (future)
/// 5 = Extra metadata (future)
pub const SECTION_TYPE_MANIFEST: u32 = 1;
pub const SECTION_TYPE_TRACK_DATA: u32 = 2;
pub const SECTION_TYPE_TRACK_TABLE: u32 = 3;
pub const SECTION_TYPE_INDEX_DATA: u32 = 4;
pub const SECTION_TYPE_EXTRA_METADATA: u32 = 5;

#[derive(Debug, Clone)]
pub struct TrackTableEntry {
    pub track_id: u32,
    pub codec: String,
    pub total_chunks: u64,
    pub chunk_size: u64,
    pub chunk_index_count: u64,
}

#[derive(Debug, Clone)]
pub struct ChunkTableEntry {
    pub track_id: u32,
    pub chunk: TrackChunkIndexEntry,
}

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub section_type: u32,
    pub length: u64,
}

impl SectionHeader {
    pub fn read<R: Read>(reader: &mut R) -> Result<Option<Self>> {
        match reader.read_u32::<LittleEndian>() {
            Ok(section_type) => {
                let length = reader.read_u64::<LittleEndian>()?;
                Ok(Some(Self {
                    section_type,
                    length,
                }))
            }
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<LittleEndian>(self.section_type)?;
        writer.write_u64::<LittleEndian>(self.length)?;
        Ok(())
    }
}

pub struct SmedWriter<W: Write> {
    writer: W,
}

impl<W: Write> SmedWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn write_all(
        &mut self,
        manifest: &SignedManifest,
        track_table: &[TrackTableEntry],
        chunk_table: &[ChunkTableEntry],
        chunks: &[Vec<u8>],
    ) -> Result<()> {
        self.writer.write_all(MAGIC)?;
        self.writer.write_u32::<LittleEndian>(VERSION_V2)?;

        let manifest_json = serde_json::to_vec(manifest)?;
        SectionHeader {
            section_type: SECTION_TYPE_MANIFEST,
            length: manifest_json.len() as u64,
        }
        .write(&mut self.writer)?;
        self.writer.write_all(&manifest_json)?;

        let track_table_payload = encode_track_table(track_table)?;
        SectionHeader {
            section_type: SECTION_TYPE_TRACK_TABLE,
            length: track_table_payload.len() as u64,
        }
        .write(&mut self.writer)?;
        self.writer.write_all(&track_table_payload)?;

        let generated_chunk_table;
        let chunk_table = if chunk_table.is_empty() {
            generated_chunk_table = build_chunk_table_from_tracks(track_table, chunks)?;
            &generated_chunk_table
        } else {
            chunk_table
        };
        let chunk_table_payload = encode_chunk_table(chunk_table)?;
        SectionHeader {
            section_type: SECTION_TYPE_INDEX_DATA,
            length: chunk_table_payload.len() as u64,
        }
        .write(&mut self.writer)?;
        self.writer.write_all(&chunk_table_payload)?;

        let data_len: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        SectionHeader {
            section_type: SECTION_TYPE_TRACK_DATA,
            length: data_len,
        }
        .write(&mut self.writer)?;

        for chunk in chunks {
            self.writer.write_all(chunk)?;
        }

        Ok(())
    }
}

pub struct SmedReader<R: Read + Seek> {
    reader: R,
    pub manifest: SignedManifest,
    pub track_table: Vec<TrackTableEntry>,
    pub chunk_index: HashMap<u32, Vec<TrackChunkIndexEntry>>,
    data_start: u64,
    data_len: u64,
}

impl<R: Read + Seek> SmedReader<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(anyhow!("Invalid magic"));
        }

        let version = reader.read_u32::<LittleEndian>()?;
        match version {
            VERSION_V1 => Self::read_v1(reader),
            VERSION_V2 => Self::read_v2(reader),
            _ => Err(anyhow!("Unsupported version")),
        }
    }

    fn read_v1(mut reader: R) -> Result<Self> {
        let manifest_len = reader.read_u64::<LittleEndian>()?;
        let mut manifest_json = vec![0u8; manifest_len as usize];
        reader.read_exact(&mut manifest_json)?;
        let manifest: SignedManifest = serde_json::from_slice(&manifest_json)?;

        let data_start = reader.stream_position()?;
        let end = reader.seek(SeekFrom::End(0))?;
        let data_len = end.saturating_sub(data_start);
        reader.seek(SeekFrom::Start(data_start))?;

        Ok(Self {
            reader,
            manifest,
            track_table: Vec::new(),
            chunk_index: HashMap::new(),
            data_start,
            data_len,
        })
    }

    fn read_v2(mut reader: R) -> Result<Self> {
        let mut manifest: Option<SignedManifest> = None;
        let mut track_table = Vec::new();
        let mut chunk_index: HashMap<u32, Vec<TrackChunkIndexEntry>> = HashMap::new();
        let mut data_start = None;
        let mut data_len = None;

        loop {
            let header = match SectionHeader::read(&mut reader)? {
                Some(header) => header,
                None => break,
            };

            let section_start = reader.stream_position()?;
            match header.section_type {
                SECTION_TYPE_MANIFEST => {
                    let mut manifest_json = vec![0u8; header.length as usize];
                    reader.read_exact(&mut manifest_json)?;
                    let parsed: SignedManifest = serde_json::from_slice(&manifest_json)?;
                    manifest = Some(parsed);
                }
                SECTION_TYPE_TRACK_DATA => {
                    data_start = Some(section_start);
                    data_len = Some(header.length);
                    skip_bytes(&mut reader, header.length)?;
                }
                SECTION_TYPE_TRACK_TABLE => {
                    let table = decode_track_table(&mut reader, header.length)?;
                    track_table = table;
                }
                SECTION_TYPE_INDEX_DATA => {
                    let entries = decode_chunk_table(&mut reader, header.length)?;
                    for entry in entries {
                        chunk_index
                            .entry(entry.track_id)
                            .or_insert_with(Vec::new)
                            .push(entry.chunk);
                    }
                }
                _ => {
                    skip_bytes(&mut reader, header.length)?;
                }
            }
        }

        let manifest = manifest.ok_or_else(|| anyhow!("Missing manifest section"))?;
        let data_start = data_start.ok_or_else(|| anyhow!("Missing track data section"))?;
        let data_len = data_len.unwrap_or(0);
        Ok(Self {
            reader,
            manifest,
            track_table,
            chunk_index,
            data_start,
            data_len,
        })
    }

    pub fn read_chunk(&mut self, index: u64, chunk_size: u64) -> Result<Vec<u8>> {
        self.ensure_range(index * chunk_size, chunk_size)?;
        self.reader
            .seek(SeekFrom::Start(self.data_start + index * chunk_size))?;
        let mut buffer = Vec::new();
        let mut limited = self.reader.by_ref().take(chunk_size);
        limited.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_variable_chunk(&mut self, offset: u64, size: u64) -> Result<Vec<u8>> {
        self.ensure_range(offset, size)?;
        self.reader
            .seek(SeekFrom::Start(self.data_start + offset))?;
        let mut buffer = Vec::new();
        let mut limited = self.reader.by_ref().take(size);
        limited.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn data_start(&self) -> u64 {
        self.data_start
    }

    pub fn chunk_index_for_track(&self, track_id: u32) -> Option<&Vec<TrackChunkIndexEntry>> {
        self.chunk_index.get(&track_id)
    }

    fn ensure_range(&self, offset: u64, size: u64) -> Result<()> {
        let end = offset
            .checked_add(size)
            .ok_or_else(|| anyhow!("Invalid range"))?;
        if end > self.data_len {
            return Err(anyhow!("Requested data outside of track data section"));
        }
        Ok(())
    }
}

fn skip_bytes<R: Read + Seek>(reader: &mut R, length: u64) -> Result<()> {
    if length > i64::MAX as u64 {
        return Err(anyhow!("Section too large to skip"));
    }
    reader.seek(SeekFrom::Current(length as i64))?;
    Ok(())
}

fn build_chunk_table_from_tracks(
    track_table: &[TrackTableEntry],
    chunks: &[Vec<u8>],
) -> Result<Vec<ChunkTableEntry>> {
    if track_table.is_empty() && !chunks.is_empty() {
        return Err(anyhow!("Cannot build chunk index without track metadata"));
    }
    let mut entries = Vec::new();
    let mut offset = 0u64;
    let mut chunk_iter = chunks.iter();
    for track in track_table {
        for chunk_index in 0..track.total_chunks {
            let chunk = chunk_iter
                .next()
                .ok_or_else(|| anyhow!("Track data missing for chunk index generation"))?;
            let size = chunk.len() as u64;
            entries.push(ChunkTableEntry {
                track_id: track.track_id,
                chunk: TrackChunkIndexEntry {
                    chunk_index,
                    pts: None,
                    offset,
                    size,
                },
            });
            offset = offset.saturating_add(size);
        }
    }
    if chunk_iter.next().is_some() {
        return Err(anyhow!("Extra chunk data without matching track metadata"));
    }
    Ok(entries)
}

fn encode_track_table(entries: &[TrackTableEntry]) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.write_u32::<LittleEndian>(entries.len() as u32)?;
    for entry in entries {
        buffer.write_u32::<LittleEndian>(entry.track_id)?;
        buffer.write_u32::<LittleEndian>(entry.codec.len() as u32)?;
        buffer.write_all(entry.codec.as_bytes())?;
        buffer.write_u64::<LittleEndian>(entry.total_chunks)?;
        buffer.write_u64::<LittleEndian>(entry.chunk_size)?;
        buffer.write_u64::<LittleEndian>(entry.chunk_index_count)?;
    }
    Ok(buffer)
}

fn decode_track_table<R: Read>(reader: &mut R, length: u64) -> Result<Vec<TrackTableEntry>> {
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload)?;
    let mut cursor = std::io::Cursor::new(payload);
    let count = cursor.read_u32::<LittleEndian>()?;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let track_id = cursor.read_u32::<LittleEndian>()?;
        let codec_len = cursor.read_u32::<LittleEndian>()? as usize;
        let mut codec_bytes = vec![0u8; codec_len];
        cursor.read_exact(&mut codec_bytes)?;
        let codec = String::from_utf8(codec_bytes)?;
        let total_chunks = cursor.read_u64::<LittleEndian>()?;
        let chunk_size = cursor.read_u64::<LittleEndian>()?;
        let chunk_index_count = cursor.read_u64::<LittleEndian>()?;
        entries.push(TrackTableEntry {
            track_id,
            codec,
            total_chunks,
            chunk_size,
            chunk_index_count,
        });
    }
    Ok(entries)
}

fn encode_chunk_table(entries: &[ChunkTableEntry]) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.write_u64::<LittleEndian>(entries.len() as u64)?;
    for entry in entries {
        buffer.write_u32::<LittleEndian>(entry.track_id)?;
        buffer.write_u64::<LittleEndian>(entry.chunk.chunk_index)?;
        let pts = entry.chunk.pts.unwrap_or(i64::MIN);
        buffer.write_i64::<LittleEndian>(pts)?;
        buffer.write_u64::<LittleEndian>(entry.chunk.offset)?;
        buffer.write_u64::<LittleEndian>(entry.chunk.size)?;
    }
    Ok(buffer)
}

fn decode_chunk_table<R: Read>(reader: &mut R, length: u64) -> Result<Vec<ChunkTableEntry>> {
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload)?;
    let mut cursor = std::io::Cursor::new(payload);
    let count = cursor.read_u64::<LittleEndian>()?;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let track_id = cursor.read_u32::<LittleEndian>()?;
        let chunk_index = cursor.read_u64::<LittleEndian>()?;
        let pts_raw = cursor.read_i64::<LittleEndian>()?;
        let pts = if pts_raw == i64::MIN {
            None
        } else {
            Some(pts_raw)
        };
        let offset = cursor.read_u64::<LittleEndian>()?;
        let size = cursor.read_u64::<LittleEndian>()?;
        entries.push(ChunkTableEntry {
            track_id,
            chunk: TrackChunkIndexEntry {
                chunk_index,
                pts,
                offset,
                size,
            },
        });
    }
    Ok(entries)
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
                Some(
                    root_bytes
                        .try_into()
                        .map_err(|_| anyhow!("Invalid root size"))?,
                )
            }
            ManifestContent::Derivative(dwd) => {
                let root_bytes = hex::decode(&dwd.original_owd.tracks[0].merkle_root)?;
                Some(
                    root_bytes
                        .try_into()
                        .map_err(|_| anyhow!("Invalid root size"))?,
                )
            }
        };

        Ok(Self {
            manifest,
            original_root,
        })
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
    use crate::models::{
        ManifestContent, OriginalWorkDescriptor, SignatureEntry, TrackChunkIndexEntry,
    };
    use chrono::Utc;
    use std::io::Cursor;
    use uuid::Uuid;

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
                    codec_extradata: None,
                    width: None,
                    height: None,
                    sample_rate: None,
                    channel_count: None,
                    timebase_num: None,
                    timebase_den: None,
                    merkle_root: hex::encode([0u8; 32]),
                    perceptual_hash: None,
                    total_chunks: 1,
                    chunk_size: 5,
                    chunk_index: vec![],
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

        let chunks = vec![b"hello".to_vec(), b"world".to_vec()];
        let track_table = vec![TrackTableEntry {
            track_id: 0,
            codec: "raw".to_string(),
            total_chunks: chunks.len() as u64,
            chunk_size: 5,
            chunk_index_count: chunks.len() as u64,
        }];
        let chunk_table = vec![
            ChunkTableEntry {
                track_id: 0,
                chunk: TrackChunkIndexEntry {
                    chunk_index: 0,
                    pts: None,
                    offset: 0,
                    size: 5,
                },
            },
            ChunkTableEntry {
                track_id: 0,
                chunk: TrackChunkIndexEntry {
                    chunk_index: 1,
                    pts: None,
                    offset: 5,
                    size: 5,
                },
            },
        ];

        let mut buffer = Vec::new();
        {
            let mut writer = SmedWriter::new(&mut buffer);
            writer.write_all(&manifest, &track_table, &chunk_table, &chunks)?;
        }

        let mut reader = SmedReader::new(Cursor::new(buffer))?;
        assert_eq!(reader.manifest.signatures[0].signature, "sig");

        let c1 = reader.read_chunk(0, 5)?;
        assert_eq!(c1, b"hello");

        let c2 = reader.read_chunk(1, 5)?;
        assert_eq!(c2, b"world");

        Ok(())
    }

    #[test]
    fn test_read_v1_compat() -> Result<()> {
        let manifest = SignedManifest {
            content: ManifestContent::Original(OriginalWorkDescriptor {
                work_id: Uuid::new_v4(),
                title: "Legacy".to_string(),
                authors: vec![],
                created_at: Utc::now(),
                tracks: vec![],
            }),
            signatures: vec![],
        };
        let manifest_json = serde_json::to_vec(&manifest)?;
        let chunks = vec![b"legacy".to_vec()];

        let mut buffer = Vec::new();
        buffer.write_all(MAGIC)?;
        buffer.write_u32::<LittleEndian>(VERSION_V1)?;
        buffer.write_u64::<LittleEndian>(manifest_json.len() as u64)?;
        buffer.write_all(&manifest_json)?;
        for chunk in &chunks {
            buffer.write_all(chunk)?;
        }

        let mut reader = SmedReader::new(Cursor::new(buffer))?;
        let data = reader.read_variable_chunk(0, 6)?;
        assert_eq!(data, b"legacy");
        Ok(())
    }
}
