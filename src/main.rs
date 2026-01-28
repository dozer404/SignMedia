use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use signmedia::container::{ChunkTableEntry, SmedReader, SmedWriter, TrackTableEntry};
use signmedia::crypto::{self, MerkleTree};
use signmedia::models::{
    ManifestContent, OriginalWorkDescriptor, SignedManifest, TrackChunkIndexEntry, TrackMetadata,
};
use std::fs;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "smtool")]
#[command(about = "SignMedia CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair
    GenKey {
        /// Path to save the private key
        #[arg(short, long, default_value = "key.priv")]
        output: PathBuf,
    },
    /// Sign a media file and create a .smed container
    Sign {
        /// Input media file
        #[arg(short, long)]
        input: PathBuf,
        /// Private key file
        #[arg(short, long)]
        key: PathBuf,
        /// Output .smed file
        #[arg(short, long)]
        output: PathBuf,
        /// Title of the work
        #[arg(short, long, default_value = "Untitled")]
        title: String,
        /// Maximum chunk size in bytes (used as a cap for packet-based chunking)
        #[arg(short, long, default_value_t = 1048576)] // 1MB
        chunk_size: u64,
    },
    /// Verify a .smed file
    Verify {
        /// Input .smed file
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Create a clip from a .smed file
    Clip {
        /// Input .smed file
        #[arg(short, long)]
        input: PathBuf,
        /// Private key file (for the clipper)
        #[arg(short, long)]
        key: PathBuf,
        /// Output .smed file
        #[arg(short, long)]
        output: PathBuf,
        /// Start chunk index
        #[arg(long)]
        start: u64,
        /// End chunk index (exclusive)
        #[arg(long)]
        end: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey { output } => {
            let signing_key = crypto::generate_keypair();
            fs::write(&output, signing_key.to_bytes())?;
            println!("Key saved to {:?}", output);
            println!(
                "Public key (hex): {}",
                hex::encode(signing_key.verifying_key().to_bytes())
            );
        }
        Commands::Sign {
            input,
            key,
            output,
            title,
            chunk_size,
        } => {
            sign_command(input, key, output, title, chunk_size)?;
        }
        Commands::Verify { input } => {
            verify_command(input)?;
        }
        Commands::Clip {
            input,
            key,
            output,
            start,
            end,
        } => {
            clip_command(input, key, output, start, end)?;
        }
    }

    Ok(())
}

fn hash_manifest_content(content: &ManifestContent) -> Result<crypto::Hash> {
    let json = serde_json::to_vec(content)?;
    Ok(crypto::hash_data(&json))
}

fn verify_manifest_signatures(manifest: &SignedManifest, content_name: &str) -> Result<()> {
    let content_hash = hash_manifest_content(&manifest.content)?;
    for sig_entry in &manifest.signatures {
        let pubkey_bytes = hex::decode(&sig_entry.public_key).context("Invalid public key hex")?;
        let verifying_key = VerifyingKey::from_bytes(
            &pubkey_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid public key size"))?,
        )
        .context("Failed to create verifying key")?;

        let sig_bytes = hex::decode(&sig_entry.signature).context("Invalid signature hex")?;
        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| anyhow!("Invalid signature size"))?,
        );

        if !crypto::verify_signature(&content_hash, &signature, &verifying_key) {
            return Err(anyhow!(
                "Signature verification failed for key {}",
                sig_entry.public_key
            ));
        }
        println!(
            "Signature verified for {} (Key: {})",
            content_name, sig_entry.public_key
        );
    }
    Ok(())
}

fn verify_original_signature(owd: &OriginalWorkDescriptor, signature_hex: &str) -> Result<()> {
    let original_owd_json = serde_json::to_vec(owd)?;
    let original_owd_hash = crypto::hash_data(&original_owd_json);
    let orig_pubkey_bytes = hex::decode(&owd.authors[0].author_id)?;
    let orig_verifying_key = VerifyingKey::from_bytes(
        &orig_pubkey_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid original public key size"))?,
    )
    .context("Failed to create original verifying key")?;
    let orig_sig_bytes = hex::decode(signature_hex)?;
    let orig_signature = Signature::from_bytes(
        &orig_sig_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid original signature size"))?,
    );

    if !crypto::verify_signature(&original_owd_hash, &orig_signature, &orig_verifying_key) {
        return Err(anyhow!("Original author signature verification failed"));
    }
    Ok(())
}

fn sign_command(
    input: PathBuf,
    key_path: PathBuf,
    output: PathBuf,
    title: String,
    max_chunk_size: u64,
) -> Result<()> {
    let key_bytes = fs::read(key_path).context("Failed to read key file")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid key size"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let file = fs::File::open(&input).context("Failed to open input file")?;
    let mut reader = BufReader::new(file);

    let mut chunks = Vec::new();
    let mut chunk_hashes = Vec::new();
    let mut first_chunk_data = None;
    let chunked = chunk_media(&mut reader, max_chunk_size)?;
    let mut chunk_index = Vec::with_capacity(chunked.len());
    let mut chunk_table = Vec::with_capacity(chunked.len());
    let mut offset = 0u64;
    for (index, chunk) in chunked.into_iter().enumerate() {
        let size = chunk.data.len() as u64;
        if first_chunk_data.is_none() {
            first_chunk_data = Some(chunk.data.clone());
        }
        chunk_hashes.push(crypto::hash_data(&chunk.data));
        chunk_index.push(TrackChunkIndexEntry {
            chunk_index: index as u64,
            pts: chunk.pts,
            offset,
            size,
        });
        chunk_table.push(ChunkTableEntry {
            track_id: 0,
            chunk: TrackChunkIndexEntry {
                chunk_index: index as u64,
                pts: chunk.pts,
                offset,
                size,
            },
        });
        offset += size;
        chunks.push(chunk.data);
    }

    let tree = MerkleTree::new(chunk_hashes);
    let root = tree.root();

    let p_hash = first_chunk_data.and_then(|data| crypto::compute_perceptual_hash(&data));

    let owd = OriginalWorkDescriptor {
        work_id: Uuid::new_v4(),
        title,
        authors: vec![signmedia::models::AuthorMetadata {
            author_id: hex::encode(signing_key.verifying_key().to_bytes()),
            name: "Default Author".to_string(),
            role: "Creator".to_string(),
        }],
        created_at: Utc::now(),
        tracks: vec![TrackMetadata {
            track_id: 0,
            codec: "raw".to_string(),
            merkle_root: hex::encode(root),
            perceptual_hash: p_hash,
            total_chunks: chunks.len() as u64,
            chunk_size: max_chunk_size,
            chunk_index,
        }],
    };

    let owd_json = serde_json::to_vec(&owd)?;
    let owd_hash = crypto::hash_data(&owd_json);

    let signature = crypto::sign(&owd_hash, &signing_key);

    let manifest = SignedManifest {
        content: ManifestContent::Original(owd),
        signatures: vec![signmedia::models::SignatureEntry {
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        }],
    };

    let out_file = fs::File::create(&output).context("Failed to create output file")?;
    let mut writer = SmedWriter::new(out_file);
    let track_table = vec![TrackTableEntry {
        track_id: 0,
        codec: "raw".to_string(),
        total_chunks: chunks.len() as u64,
        chunk_size: max_chunk_size,
        chunk_index_count: chunks.len() as u64,
    }];
    writer.write_all(&manifest, &track_table, &chunk_table, &chunks)?;

    println!("Successfully signed and saved to {:?}", output);
    Ok(())
}

fn verify_command(input: PathBuf) -> Result<()> {
    let file = fs::File::open(&input).context("Failed to open file")?;
    let file_len = file.metadata()?.len();
    let mut reader = SmedReader::new(file).context("Failed to initialize SmedReader")?;

    let manifest = reader.manifest.clone();

    let content_name = match &manifest.content {
        ManifestContent::Original(_) => "Original Work",
        ManifestContent::Derivative(_) => "Derivative Work",
    };

    verify_manifest_signatures(&manifest, content_name)?;

    match &manifest.content {
        ManifestContent::Original(owd) => {
            println!("Authors:");
            for author in &owd.authors {
                println!(
                    " - {} ({}, Key: {})",
                    author.name, author.role, author.author_id
                );
            }
            for track in &owd.tracks {
                println!("Verifying integrity for track {}...", track.track_id);
                if let Some(p_hash) = &track.perceptual_hash {
                    println!("Track Perceptual Hash (Watermark): {}", p_hash);
                }
                let mut chunk_hashes = Vec::new();
                // For v1, we assume sequential storage of tracks.
                // Since there's only one track, it's easy.
                let mut entries = track.chunk_index.clone();
                if entries.is_empty() {
                    let data_size = file_len - reader.data_start();
                    for i in 0..track.total_chunks {
                        let offset = i * track.chunk_size;
                        let size = if offset + track.chunk_size > data_size {
                            data_size - offset
                        } else {
                            track.chunk_size
                        };
                        entries.push(TrackChunkIndexEntry {
                            chunk_index: i,
                            pts: None,
                            offset,
                            size,
                        });
                    }
                } else {
                    entries.sort_by_key(|entry| entry.chunk_index);
                }
                for entry in entries {
                    let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
                    chunk_hashes.push(crypto::hash_data(&chunk));
                }
                let tree = MerkleTree::new(chunk_hashes);
                if hex::encode(tree.root()) != track.merkle_root {
                    return Err(anyhow!("Merkle root mismatch for track {}", track.track_id));
                }
                println!(
                    "Track {} ({} chunks) integrity verified.",
                    track.track_id, track.total_chunks
                );
            }
        }
        ManifestContent::Derivative(dwd) => {
            println!("Verifying provenance chain...");
            println!("Original Authors:");
            for author in &dwd.original_owd.authors {
                println!(
                    " - {} ({}, Key: {})",
                    author.name, author.role, author.author_id
                );
            }
            // 1. Verify original author signature
            verify_original_signature(&dwd.original_owd, &dwd.original_signature)?;
            println!(
                "Original author signature verified for: {}",
                dwd.original_owd.title
            );

            // 2. Verify ancestry chain signatures and consistency
            if !dwd.ancestry.is_empty() {
                println!(
                    "Verifying ancestry chain ({} entries)...",
                    dwd.ancestry.len()
                );
            }
            for (index, ancestor_manifest) in dwd.ancestry.iter().enumerate() {
                let ancestor_label = format!("Ancestor Manifest {}", index + 1);
                verify_manifest_signatures(ancestor_manifest, &ancestor_label)?;
                match &ancestor_manifest.content {
                    ManifestContent::Original(ancestor_owd) => {
                        if ancestor_owd.work_id != dwd.original_owd.work_id {
                            return Err(anyhow!("Ancestry original work ID mismatch"));
                        }
                    }
                    ManifestContent::Derivative(ancestor_dwd) => {
                        if ancestor_dwd.original_owd.work_id != dwd.original_owd.work_id {
                            return Err(anyhow!("Ancestry derivative work ID mismatch"));
                        }
                        verify_original_signature(
                            &ancestor_dwd.original_owd,
                            &ancestor_dwd.original_signature,
                        )?;
                    }
                }
            }

            // 3. Verify clip integrity and Merkle proofs
            println!("Verifying clip integrity and Merkle proofs against original root...");
            let original_root: crypto::Hash = hex::decode(&dwd.original_owd.tracks[0].merkle_root)?
                .try_into()
                .map_err(|_| anyhow!("Invalid original root"))?;

            let mut current_offset = 0;
            let mut consumed_bytes = 0u64;
            for mapping in &dwd.clip_mappings {
                let chunk_lookup = reader
                    .chunk_index_for_track(mapping.track_id)
                    .map(|entries| {
                        let mut lookup = std::collections::HashMap::new();
                        for entry in entries {
                            lookup.insert(entry.chunk_index, entry);
                        }
                        lookup
                    });
                println!(
                    "Verifying clip mapping for track {} (chunks {} to {})...",
                    mapping.track_id, mapping.start_chunk_index, mapping.end_chunk_index
                );

                for proof in &mapping.proofs {
                    let chunk_size = if let Some(lookup) = &chunk_lookup {
                        let entry = lookup
                            .get(&proof.chunk_index)
                            .context("Missing chunk index entry for proof")?;
                        let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
                        let size = entry.size;
                        let actual_hash = crypto::hash_data(&chunk);
                        if hex::encode(actual_hash) != proof.hash {
                            return Err(anyhow!(
                                "Integrity mismatch for chunk {}",
                                proof.chunk_index
                            ));
                        }

                        if !crypto::verify_proof(original_root, proof) {
                            return Err(anyhow!(
                                "Merkle proof verification failed for chunk {}",
                                proof.chunk_index
                            ));
                        }
                        current_offset += size;
                        consumed_bytes += size;
                        continue;
                    } else {
                        proof.chunk_size
                    };

                    let chunk = reader.read_variable_chunk(current_offset, chunk_size)?;
                    let actual_hash = crypto::hash_data(&chunk);
                    if hex::encode(actual_hash) != proof.hash {
                        return Err(anyhow!(
                            "Integrity mismatch for chunk {}",
                            proof.chunk_index
                        ));
                    }

                    if !crypto::verify_proof(original_root, proof) {
                        return Err(anyhow!(
                            "Merkle proof verification failed for chunk {}",
                            proof.chunk_index
                        ));
                    }
                    current_offset += chunk_size;
                    consumed_bytes += chunk_size;
                }
            }
            if reader.data_start() + consumed_bytes != file_len {
                return Err(anyhow!("Extra data found at the end of the file"));
            }
            println!("Derivative provenance and integrity verified successfully.");
        }
    }

    Ok(())
}

fn clip_command(
    input: PathBuf,
    key_path: PathBuf,
    output: PathBuf,
    start: u64,
    end: u64,
) -> Result<()> {
    let key_bytes = fs::read(key_path).context("Failed to read key file")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid key size"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let file = fs::File::open(&input).context("Failed to open input file")?;
    let file_len = file.metadata()?.len();
    let mut reader = SmedReader::new(file).context("Failed to initialize SmedReader")?;

    let original_manifest = reader.manifest.clone();
    let mut ancestry = Vec::new();
    let (original_owd, original_signature, source_mapping, source_proofs) =
        match &original_manifest.content {
            ManifestContent::Original(owd) => (
                owd.clone(),
                original_manifest.signatures[0].signature.clone(),
                None,
                None,
            ),
            ManifestContent::Derivative(dwd) => {
                ancestry.extend(dwd.ancestry.clone());
                ancestry.push(original_manifest.clone());
                let mapping = dwd
                    .clip_mappings
                    .get(0)
                    .context("Missing clip mapping in derivative input")?;
                let proofs = mapping.proofs.clone();
                (
                    dwd.original_owd.clone(),
                    dwd.original_signature.clone(),
                    Some(mapping.clone()),
                    Some(proofs),
                )
            }
        };

    let (track_id, total_chunks, chunk_size_orig, track_index) = {
        let track = &original_owd.tracks[0];
        (
            track.track_id,
            track.total_chunks,
            track.chunk_size,
            track.chunk_index.clone(),
        )
    };

    let mut clip_chunks = Vec::new();
    let mut proofs = Vec::new();
    if let (Some(mapping), Some(existing_proofs)) = (source_mapping, source_proofs) {
        if end > existing_proofs.len() as u64 {
            return Err(anyhow!("End index out of bounds for derivative input"));
        }
        if start >= end {
            return Err(anyhow!("Start index must be less than end index"));
        }
        let data_size = file_len - reader.data_start();
        let mut current_offset = 0;
        let chunk_lookup = reader
            .chunk_index_for_track(mapping.track_id)
            .map(|entries| {
                let mut lookup = std::collections::HashMap::new();
                for entry in entries {
                    lookup.insert(entry.chunk_index, entry);
                }
                lookup
            });
        for (index, proof) in existing_proofs.iter().enumerate() {
            let proof_index = index as u64;
            if proof_index >= start && proof_index < end {
                let chunk = if let Some(lookup) = &chunk_lookup {
                    let entry = lookup
                        .get(&proof.chunk_index)
                        .context("Missing chunk index entry for proof")?;
                    if entry.offset + entry.size > data_size {
                        return Err(anyhow!(
                            "Unexpected end of data while reading derivative chunks"
                        ));
                    }
                    reader.read_variable_chunk(entry.offset, entry.size)?
                } else {
                    let size = proof.chunk_size;
                    if current_offset + size > data_size {
                        return Err(anyhow!(
                            "Unexpected end of data while reading derivative chunks"
                        ));
                    }
                    reader.read_variable_chunk(current_offset, size)?
                };
                clip_chunks.push(chunk);
                proofs.push(proof.clone());
            }
            if chunk_lookup.is_none() {
                current_offset += proof.chunk_size;
            }
        }
        if proofs.is_empty() {
            return Err(anyhow!("No chunks selected for derivative clip"));
        }
        let first_index = proofs
            .first()
            .map(|proof| proof.chunk_index)
            .unwrap_or(mapping.start_chunk_index);
        let last_index = proofs
            .last()
            .map(|proof| proof.chunk_index)
            .unwrap_or(mapping.end_chunk_index.saturating_sub(1));
        let start = first_index;
        let end = last_index + 1;
        let dwd = signmedia::models::DerivativeWorkDescriptor {
            derivative_id: Uuid::new_v4(),
            original_owd,
            original_signature,
            ancestry,
            clipper_id: hex::encode(signing_key.verifying_key().to_bytes()),
            created_at: Utc::now(),
            clip_mappings: vec![signmedia::models::ClipMapping {
                track_id: mapping.track_id,
                start_chunk_index: start,
                end_chunk_index: end,
                proofs,
            }],
        };

        let dwd_json = serde_json::to_vec(&dwd)?;
        let dwd_hash = crypto::hash_data(&dwd_json);
        let signature = crypto::sign(&dwd_hash, &signing_key);

        let manifest = SignedManifest {
            content: ManifestContent::Derivative(dwd),
            signatures: vec![signmedia::models::SignatureEntry {
                signature: hex::encode(signature.to_bytes()),
                public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            }],
        };

        let (track_table, chunk_table) =
            build_track_tables(mapping.track_id, &proofs, &clip_chunks)?;
        let out_file = fs::File::create(&output)?;
        let mut writer = SmedWriter::new(out_file);
        writer.write_all(&manifest, &track_table, &chunk_table, &clip_chunks)?;

        println!("Successfully created clip: {:?}", output);
        return Ok(());
    }

    if end > total_chunks {
        return Err(anyhow!("End index out of bounds"));
    }
    if start >= end {
        return Err(anyhow!("Start index must be less than end index"));
    }

    println!("Extracting original chunks and reconstructing Merkle tree...");
    let mut original_hashes = Vec::new();
    let entries = if track_index.is_empty() {
        let data_size = file_len - reader.data_start();
        (0..total_chunks)
            .map(|i| {
                let offset = i * chunk_size_orig;
                let size = if offset + chunk_size_orig > data_size {
                    data_size - offset
                } else {
                    chunk_size_orig
                };
                TrackChunkIndexEntry {
                    chunk_index: i,
                    pts: None,
                    offset,
                    size,
                }
            })
            .collect::<Vec<_>>()
    } else {
        let mut entries = track_index;
        entries.sort_by_key(|entry| entry.chunk_index);
        entries
    };
    for entry in &entries {
        let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
        original_hashes.push(crypto::hash_data(&chunk));
    }
    let original_tree = MerkleTree::new(original_hashes);

    for entry in entries
        .iter()
        .filter(|entry| entry.chunk_index >= start && entry.chunk_index < end)
    {
        let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
        clip_chunks.push(chunk);
        let mut proof = original_tree.generate_proof(entry.chunk_index as usize);
        proof.chunk_size = entry.size;
        proofs.push(proof);
    }

    let dwd = signmedia::models::DerivativeWorkDescriptor {
        derivative_id: Uuid::new_v4(),
        original_owd,
        original_signature,
        ancestry,
        clipper_id: hex::encode(signing_key.verifying_key().to_bytes()),
        created_at: Utc::now(),
        clip_mappings: vec![signmedia::models::ClipMapping {
            track_id,
            start_chunk_index: start,
            end_chunk_index: end,
            proofs,
        }],
    };

    let dwd_json = serde_json::to_vec(&dwd)?;
    let dwd_hash = crypto::hash_data(&dwd_json);
    let signature = crypto::sign(&dwd_hash, &signing_key);

    let manifest = SignedManifest {
        content: ManifestContent::Derivative(dwd),
        signatures: vec![signmedia::models::SignatureEntry {
            signature: hex::encode(signature.to_bytes()),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        }],
    };

    let (track_table, chunk_table) = build_track_tables(track_id, &proofs, &clip_chunks)?;
    let out_file = fs::File::create(&output)?;
    let mut writer = SmedWriter::new(out_file);
    writer.write_all(&manifest, &track_table, &chunk_table, &clip_chunks)?;

    println!("Successfully created clip: {:?}", output);
    Ok(())
}

struct ChunkWithMeta {
    data: Vec<u8>,
    pts: Option<i64>,
}

fn chunk_media(reader: &mut impl Read, max_chunk_size: u64) -> Result<Vec<ChunkWithMeta>> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    if let Some(frames) = parse_adts_frames(&data) {
        return Ok(group_adts_frames(&data, &frames, max_chunk_size));
    }
    if let Some(nals) = parse_annexb_nals(&data) {
        return Ok(group_nals(&data, &nals, max_chunk_size));
    }
    Ok(fallback_chunking(&data, max_chunk_size))
}

fn parse_adts_frames(data: &[u8]) -> Option<Vec<(usize, usize, i64)>> {
    let sample_rates = [
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
    ];
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut pts_us = 0i64;
    let mut sample_rate = None;
    while offset + 7 <= data.len() {
        if data[offset] != 0xFF || (data[offset + 1] & 0xF0) != 0xF0 {
            return None;
        }
        let protection_absent = data[offset + 1] & 0x01;
        let header_len = if protection_absent == 1 { 7 } else { 9 };
        let frame_length = (((data[offset + 3] & 0x03) as usize) << 11)
            | ((data[offset + 4] as usize) << 3)
            | ((data[offset + 5] & 0xE0) as usize >> 5);
        if frame_length < header_len || offset + frame_length > data.len() {
            return None;
        }
        let sample_rate_index = ((data[offset + 2] & 0x3C) >> 2) as usize;
        let sr = sample_rates.get(sample_rate_index).copied()?;
        sample_rate.get_or_insert(sr);
        if sample_rate != Some(sr) {
            return None;
        }
        frames.push((offset, frame_length, pts_us));
        pts_us += (1_000_000i64 * 1024) / sr as i64;
        offset += frame_length;
    }
    if offset != data.len() || frames.is_empty() {
        None
    } else {
        Some(frames)
    }
}

fn group_adts_frames(
    data: &[u8],
    frames: &[(usize, usize, i64)],
    max_chunk_size: u64,
) -> Vec<ChunkWithMeta> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_pts = None;
    for (start, length, pts) in frames {
        if !current.is_empty() && current.len() as u64 + *length as u64 > max_chunk_size {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: current_pts,
            });
            current_pts = None;
        }
        if current.is_empty() {
            current_pts = Some(*pts);
        }
        current.extend_from_slice(&data[*start..start + length]);
    }
    if !current.is_empty() {
        chunks.push(ChunkWithMeta {
            data: current,
            pts: current_pts,
        });
    }
    chunks
}

fn parse_annexb_nals(data: &[u8]) -> Option<Vec<(usize, usize, bool)>> {
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            starts.push((i, 3));
            i += 3;
            continue;
        }
        if i + 4 <= data.len()
            && data[i] == 0
            && data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] == 1
        {
            starts.push((i, 4));
            i += 4;
            continue;
        }
        i += 1;
    }
    if starts.len() < 2 {
        return None;
    }
    let mut nals = Vec::new();
    for idx in 0..starts.len() {
        let (start, code_len) = starts[idx];
        let end = if idx + 1 < starts.len() {
            starts[idx + 1].0
        } else {
            data.len()
        };
        if start + code_len >= end {
            continue;
        }
        let nal_type = data[start + code_len] & 0x1F;
        let is_idr = nal_type == 5;
        nals.push((start, end, is_idr));
    }
    if nals.is_empty() {
        None
    } else {
        Some(nals)
    }
}

fn group_nals(
    data: &[u8],
    nals: &[(usize, usize, bool)],
    max_chunk_size: u64,
) -> Vec<ChunkWithMeta> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for (start, end, is_idr) in nals {
        let nal_len = end - start;
        if *is_idr && !current.is_empty() {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: None,
            });
        }
        if !current.is_empty() && current.len() as u64 + nal_len as u64 > max_chunk_size {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: None,
            });
        }
        current.extend_from_slice(&data[*start..*end]);
    }
    if !current.is_empty() {
        chunks.push(ChunkWithMeta {
            data: current,
            pts: None,
        });
    }
    chunks
}

fn fallback_chunking(data: &[u8], max_chunk_size: u64) -> Vec<ChunkWithMeta> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    let chunk_size = max_chunk_size as usize;
    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        chunks.push(ChunkWithMeta {
            data: data[offset..end].to_vec(),
            pts: None,
        });
        offset = end;
    }
    chunks
}

fn build_track_tables(
    track_id: u32,
    proofs: &[signmedia::models::MerkleProof],
    chunks: &[Vec<u8>],
) -> Result<(Vec<TrackTableEntry>, Vec<ChunkTableEntry>)> {
    let mut chunk_table = Vec::with_capacity(chunks.len());
    let mut offset = 0u64;
    for (index, chunk) in chunks.iter().enumerate() {
        let size = chunk.len() as u64;
        let chunk_index = proofs
            .get(index)
            .map(|proof| proof.chunk_index)
            .unwrap_or(index as u64);
        chunk_table.push(ChunkTableEntry {
            track_id,
            chunk: TrackChunkIndexEntry {
                chunk_index,
                pts: None,
                offset,
                size,
            },
        });
        offset += size;
    }
    let track_table = vec![TrackTableEntry {
        track_id,
        codec: "raw".to_string(),
        total_chunks: chunks.len() as u64,
        chunk_size: chunks
            .iter()
            .map(|chunk| chunk.len() as u64)
            .max()
            .unwrap_or(0),
        chunk_index_count: chunks.len() as u64,
    }];
    Ok((track_table, chunk_table))
}
