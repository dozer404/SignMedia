use signmedia::container::{ChunkTableEntry, SectionHeader, SmedReader, SmedWriter, TrackTableEntry, MAGIC, SECTION_TYPE_MANIFEST, VERSION_V1, VERSION_V2};
use signmedia::crypto::{compute_authorship_fingerprint, hash_data, sign, generate_keypair};
use signmedia::models::{
    AuthorMetadata, ManifestContent, OriginalWorkDescriptor, SignatureEntry, SignedManifest,
    TrackChunkIndexEntry, TrackMetadata,
};
use chrono::Utc;
use std::io::{Cursor, Read, Write};

#[test]
fn test_legacy_v1_fixture_decode() -> anyhow::Result<()> {
    let keypair = generate_keypair();
    let author_pubkey = hex::encode(keypair.verifying_key().to_bytes());
    let author = AuthorMetadata {
        author_id: author_pubkey.clone(),
        name: "Legacy Author".to_string(),
        role: "author".to_string(),
    };
    let fingerprint = compute_authorship_fingerprint(&[author.clone()]);

    let owd = OriginalWorkDescriptor {
        work_id: uuid::Uuid::nil(),
        title: "Legacy v1 Asset".to_string(),
        authors: vec![author],
        authorship_fingerprint: Some(fingerprint),
        created_at: Utc::now(),
        tracks: vec![TrackMetadata {
            track_id: 0,
            codec: "raw".to_string(),
            container_type: None,
            codec_extradata: None,
            width: None,
            height: None,
            sample_rate: None,
            channel_count: None,
            timebase_num: Some(1),
            timebase_den: Some(30),
            merkle_root: hex::encode(hash_data(b"chunk1")),
            perceptual_hash: None,
            total_chunks: 1,
            chunk_size: 6,
            chunk_index: vec![],
        }],
    };

    let content = ManifestContent::Original(owd);
    let content_json = serde_json::to_vec(&content)?;
    let content_hash = hash_data(&content_json);
    let sig = sign(&content_hash, &keypair);

    let manifest = SignedManifest {
        content,
        signatures: vec![SignatureEntry {
            signature: hex::encode(sig.to_bytes()),
            public_key: author_pubkey,
            display_name: Some("Legacy Author".to_string()),
        }],
    };

    let manifest_json = serde_json::to_vec(&manifest)?;
    let chunk_data = b"chunk1";

    let mut v1_buf = Vec::new();
    v1_buf.write_all(MAGIC)?;
    v1_buf.write_all(&(VERSION_V1.to_le_bytes()))?;
    v1_buf.write_all(&((manifest_json.len() as u64).to_le_bytes()))?;
    v1_buf.write_all(&manifest_json)?;
    v1_buf.write_all(chunk_data)?;

    let mut reader = SmedReader::new(Cursor::new(v1_buf))?;
    assert_eq!(reader.manifest.signatures.len(), 1);
    let read_chunk = reader.read_variable_chunk(0, 6)?;
    assert_eq!(read_chunk, b"chunk1");

    Ok(())
}

#[test]
fn test_legacy_v2_unknown_section_handling() -> anyhow::Result<()> {
    let manifest = SignedManifest {
        content: ManifestContent::Original(OriginalWorkDescriptor {
            work_id: uuid::Uuid::nil(),
            title: "Unknown Section Test".to_string(),
            authors: vec![],
            authorship_fingerprint: None,
            created_at: Utc::now(),
            tracks: vec![],
        }),
        signatures: vec![],
    };

    let manifest_json = serde_json::to_vec(&manifest)?;

    let mut buf = Vec::new();
    buf.write_all(MAGIC)?;
    buf.write_all(&(VERSION_V2.to_le_bytes()))?;

    // Write Unknown Section type 999
    SectionHeader {
        section_type: 999,
        length: 12,
    }
    .write(&mut buf)?;
    buf.write_all(b"UNKNOWN_DATA")?;

    // Write Manifest Section
    SectionHeader {
        section_type: SECTION_TYPE_MANIFEST,
        length: manifest_json.len() as u64,
    }
    .write(&mut buf)?;
    buf.write_all(&manifest_json)?;

    // Write Track Data Section
    SectionHeader {
        section_type: signmedia::container::SECTION_TYPE_TRACK_DATA,
        length: 4,
    }
    .write(&mut buf)?;
    buf.write_all(b"DATA")?;

    let reader = SmedReader::new(Cursor::new(buf))?;
    assert_eq!(reader.manifest.signatures.len(), 0);
    Ok(())
}
