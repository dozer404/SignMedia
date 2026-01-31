use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use signmedia::codec;
use signmedia::container::{ChunkTableEntry, SmedReader, SmedWriter, TrackTableEntry};
use signmedia::crypto::{self, MerkleTree};
use signmedia::models::{
    ManifestContent, OriginalWorkDescriptor, SignedManifest, TrackChunkIndexEntry, TrackMetadata,
};
use signmedia::timecode;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
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
        /// Path to save the private key (binary)
        #[arg(short = 'o', long = "private", default_value = "key.priv")]
        private: PathBuf,
        /// Path to save the public key (hex-encoded)
        #[arg(short = 'p', long = "public")]
        public: Option<PathBuf>,
    },
    /// Sign one or more media files and create a .smed container
    Sign {
        /// Input media files
        #[arg(short, long, required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,
        /// Private key file
        #[arg(short, long)]
        key: PathBuf,
        /// Output .smed file
        #[arg(short, long)]
        output: PathBuf,
        /// Title of the work
        #[arg(short, long, default_value = "Untitled")]
        title: String,
        /// Display name for the original author
        #[arg(long, default_value = "Default Author")]
        author_name: String,
        /// Role for the author: original or derivative
        #[arg(long, default_value = "original")]
        author_role: String,
        /// Maximum chunk size in bytes (used as a cap for packet-based chunking)
        #[arg(short, long, default_value_t = 1048576)] // 1MB
        chunk_size: u64,
    },
    /// Create a clip from a .smed file
    Clip {
        /// Input .smed file
        #[arg(short, long)]
        input: PathBuf,
        /// Private key file (for the clipper)
        #[arg(short, long)]
        key: PathBuf,
        /// Display name for the clipper
        #[arg(long)]
        clipper_name: Option<String>,
        /// Output .smed file
        #[arg(short, long)]
        output: PathBuf,
        /// Start chunk index
        #[arg(long)]
        start: Option<u64>,
        /// End chunk index (exclusive)
        #[arg(long)]
        end: Option<u64>,
        /// Start time in seconds
        #[arg(long)]
        start_time: Option<f64>,
        /// End time in seconds
        #[arg(long)]
        end_time: Option<f64>,
        /// Track ID to clip (defaults to 0)
        #[arg(long, default_value_t = 0)]
        track: u32,
    },
    /// Extract tracks from a .smed file into a container (MP4/MKV/WEBM)
    Extract {
        /// Input .smed file
        #[arg(short, long)]
        input: PathBuf,
        /// Output container file (.mp4 or .mkv)
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Show information and verify cryptographic integrity of a .smed file
    #[command(name = "verify-smed", alias = "VERIFY-SMED")]
    VerifySmed {
        /// Input .smed file
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Verify embedded SignMedia metadata in an extracted container
    VerifyMetadata {
        /// Input media file (.mp4 or .mkv)
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey {
            private,
            public,
        } => {
            let signing_key = crypto::generate_keypair();
            let pub_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

            fs::write(&private, signing_key.to_bytes())
                .with_context(|| format!("Failed to write private key to {:?}", private))?;
            println!("Private key saved to {:?}", private);

            if let Some(pub_path) = public {
                fs::write(&pub_path, &pub_key_hex)
                    .with_context(|| format!("Failed to write public key to {:?}", pub_path))?;
                println!("Public key saved to {:?}", pub_path);
            }

            println!("Public key (hex): {}", pub_key_hex);
        }
        Commands::Sign {
            inputs,
            key,
            output,
            title,
            author_name,
            author_role,
            chunk_size,
        } => {
            sign_command(
                inputs,
                key,
                output,
                title,
                author_name,
                author_role,
                chunk_size,
            )?;
        }
        Commands::Clip {
            input,
            key,
            clipper_name,
            output,
            start,
            end,
            start_time,
            end_time,
            track,
        } => {
            clip_command(
                input,
                key,
                clipper_name,
                output,
                start,
                end,
                start_time,
                end_time,
                track,
            )?;
        }
        Commands::Extract { input, output } => {
            extract_command(input, output)?;
        }
        Commands::VerifySmed { input } => {
            verify_smed_command(input)?;
        }
        Commands::VerifyMetadata { input } => {
            verify_metadata_command(input)?;
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
    let mut ttp_verified = false;
    let ttp_pubkey = crypto::get_ttp_public_key();
    for sig_entry in &manifest.signatures {
        if sig_entry.public_key == ttp_pubkey {
            ttp_verified = true;
        }
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

    if !ttp_verified {
        return Err(anyhow!(
            "Missing Trusted Third Party (TTP) signature for {}!",
            content_name
        ));
    }
    println!(
        "Trusted Third Party (TTP) oversight verified for {}.",
        content_name
    );

    Ok(())
}

fn verify_original_signature(owd: &OriginalWorkDescriptor, signature_hex: &str) -> Result<()> {
    let content = ManifestContent::Original(owd.clone());
    let original_owd_hash = hash_manifest_content(&content)?;
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

fn build_sequential_entries(
    total_chunks: u64,
    chunk_size: u64,
    data_size: u64,
) -> Vec<TrackChunkIndexEntry> {
    (0..total_chunks)
        .map(|i| {
            let offset = i * chunk_size;
            let size = if offset + chunk_size > data_size {
                data_size.saturating_sub(offset)
            } else {
                chunk_size
            };
            TrackChunkIndexEntry {
                chunk_index: i,
                pts: None,
                offset,
                size,
            }
        })
        .collect()
}

fn resolve_track_entries<R: Read + Seek>(
    reader: &SmedReader<R>,
    track: &TrackMetadata,
    file_len: u64,
) -> Vec<TrackChunkIndexEntry> {
    if let Some(entries) = reader.chunk_index_for_track(track.track_id) {
        if !entries.is_empty() {
            return entries.clone();
        }
    }
    if !track.chunk_index.is_empty() {
        return track.chunk_index.clone();
    }
    let data_size = file_len - reader.data_start();
    build_sequential_entries(track.total_chunks, track.chunk_size, data_size)
}

fn open_smed_reader(input: &PathBuf) -> Result<SmedReader<fs::File>> {
    let file = fs::File::open(input).with_context(|| format!("Failed to open file {:?}", input))?;
    SmedReader::new(file).map_err(|e| {
        if e.to_string().contains("Invalid magic") {
            anyhow!(
                "'{}' is not a valid SignMedia (.smed) container. If you are trying to verify an extracted and tagged media file, use 'verify-metadata' instead.",
                input.display()
            )
        } else {
            e.context("Failed to initialize SmedReader")
        }
    })
}

fn find_idr_start<R: Read + Seek>(
    reader: &mut SmedReader<R>,
    entries: &[TrackChunkIndexEntry],
    start: u64,
) -> Result<u64> {
    if entries.is_empty() {
        return Err(anyhow!("No chunk entries available for keyframe search"));
    }
    let start_index = start.min(entries.len().saturating_sub(1) as u64);
    for idx in (0..=start_index).rev() {
        let entry = entries.get(idx as usize).context("Missing chunk entry")?;
        let data = reader.read_variable_chunk(entry.offset, entry.size)?;
        if let Some(info) = codec::parse_annexb_nals(&data) {
            if info.nals.iter().any(|nal| nal.is_idr) {
                return Ok(idx);
            }
        }
    }
    Err(anyhow!(
        "Unable to locate a keyframe chunk before the requested clip start"
    ))
}

fn sign_command(
    inputs: Vec<PathBuf>,
    key_path: PathBuf,
    output: PathBuf,
    title: String,
    author_name: String,
    author_role: String,
    max_chunk_size: u64,
) -> Result<()> {
    let key_bytes = fs::read(key_path).context("Failed to read key file")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid key size"))?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let mut all_chunks = Vec::new();
    let mut track_metadata = Vec::new();
    let mut track_table = Vec::new();
    let mut chunk_table = Vec::with_capacity(inputs.len() * 10); // heuristic
    let mut global_offset = 0u64;
    let mut next_track_id = 0u32;

    for input in inputs.iter() {
        let file =
            fs::File::open(input).context(format!("Failed to open input file {:?}", input))?;
        let mut reader = BufReader::new(file);

        let chunked_tracks = codec::chunk_media_tracks(&mut reader, max_chunk_size)?;

        for track in chunked_tracks {
            let track_id = next_track_id;
            next_track_id = next_track_id.saturating_add(1);

            let mut current_track_chunks = Vec::new();
            let mut chunk_hashes = Vec::new();
            let mut first_chunk_data = None;
            let mut track_chunk_index = Vec::with_capacity(track.chunks.len());

            for (index, chunk) in track.chunks.into_iter().enumerate() {
                let size = chunk.data.len() as u64;
                if first_chunk_data.is_none() {
                    first_chunk_data = Some(chunk.data.clone());
                }
                chunk_hashes.push(crypto::hash_data(&chunk.data));
                let entry = TrackChunkIndexEntry {
                    chunk_index: index as u64,
                    pts: chunk.pts,
                    offset: global_offset,
                    size,
                };
                track_chunk_index.push(entry.clone());
                chunk_table.push(ChunkTableEntry {
                    track_id,
                    chunk: entry,
                });
                global_offset += size;
                current_track_chunks.push(chunk.data);
            }

            let tree = MerkleTree::new(chunk_hashes);
            let root = tree.root();
            let p_hash = first_chunk_data.and_then(|data| crypto::compute_perceptual_hash(&data));

            track_metadata.push(TrackMetadata {
                track_id,
                codec: track.playback.codec.clone(),
                container_type: track.playback.container_type.clone(),
                codec_extradata: track
                    .playback
                    .codec_extradata
                    .as_ref()
                    .map(|data| hex::encode(data)),
                width: track.playback.width,
                height: track.playback.height,
                sample_rate: track.playback.sample_rate,
                channel_count: track.playback.channels,
                timebase_num: track.playback.timebase_num,
                timebase_den: track.playback.timebase_den,
                merkle_root: hex::encode(root),
                perceptual_hash: p_hash,
                total_chunks: current_track_chunks.len() as u64,
                chunk_size: max_chunk_size,
                chunk_index: track_chunk_index,
            });

            track_table.push(TrackTableEntry {
                track_id,
                codec: track.playback.codec,
                total_chunks: current_track_chunks.len() as u64,
                chunk_size: max_chunk_size,
                chunk_index_count: current_track_chunks.len() as u64,
            });

            all_chunks.extend(current_track_chunks);
        }
    }

    let normalized_role = author_role.to_ascii_lowercase();
    if normalized_role != "original" && normalized_role != "derivative" {
        return Err(anyhow!(
            "Invalid author role: {} (expected \"original\" or \"derivative\")",
            author_role
        ));
    }

    let authors = vec![signmedia::models::AuthorMetadata {
        author_id: hex::encode(signing_key.verifying_key().to_bytes()),
        name: author_name,
        role: normalized_role,
    }];
    let author_display_name = authors.get(0).map(|author| author.name.clone());

    let authorship_fingerprint = Some(crypto::compute_authorship_fingerprint(&authors));

    let owd = OriginalWorkDescriptor {
        work_id: Uuid::new_v4(),
        title,
        authors,
        authorship_fingerprint,
        created_at: Utc::now(),
        tracks: track_metadata,
    };

    let content = ManifestContent::Original(owd);
    let content_hash = hash_manifest_content(&content)?;

    let author_signature = crypto::sign(&content_hash, &signing_key);

    // Attempt to get the TTP signer from environment
    let ttp_signer = crypto::get_ttp_signing_key()?;
    let ttp_signature = crypto::sign_with_ttp(&content_hash, &ttp_signer);

    let manifest = SignedManifest {
        content,
        signatures: vec![
            signmedia::models::SignatureEntry {
                signature: hex::encode(author_signature.to_bytes()),
                public_key: hex::encode(signing_key.verifying_key().to_bytes()),
                display_name: author_display_name,
            },
            signmedia::models::SignatureEntry {
                signature: hex::encode(ttp_signature.to_bytes()),
                public_key: crypto::get_ttp_public_key(),
                display_name: Some(ttp_display_name()),
            },
        ],
    };

    let out_file = fs::File::create(&output).context("Failed to create output file")?;
    let mut writer = SmedWriter::new(out_file);
    writer.write_all(&manifest, &track_table, &chunk_table, &all_chunks)?;

    println!("Successfully signed and saved to {:?}", output);
    Ok(())
}

fn verify_smed_integrity<R: Read + Seek>(reader: &mut SmedReader<R>, file_len: u64) -> Result<()> {
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
            if let Some(fp) = &owd.authorship_fingerprint {
                println!("Authorship Fingerprint: {}", fp);
            }

            // Fingerprint check
            if let Some(expected_fingerprint) = &owd.authorship_fingerprint {
                let actual_fingerprint = crypto::compute_authorship_fingerprint(&owd.authors);
                if expected_fingerprint != &actual_fingerprint {
                    return Err(anyhow!("CRITICAL: Authorship metadata mismatch with fingerprint! Evidence of tampering."));
                }
                println!("Authorship fingerprint verified.");
            } else {
                println!("Warning: No authorship fingerprint found in metadata.");
            }

            for track in &owd.tracks {
                println!("Verifying integrity for track {}...", track.track_id);
                if let Some(p_hash) = &track.perceptual_hash {
                    println!("Track Perceptual Hash (Watermark): {}", p_hash);
                }
                let mut chunk_hashes = Vec::new();
                // Prefer container chunk index for fast seeking; fall back to manifest or sequential.
                let mut entries = resolve_track_entries(&reader, track, file_len);
                entries.sort_by_key(|entry| entry.chunk_index);
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
            // Fingerprint check
            if let Some(expected_fingerprint) = &dwd.authorship_fingerprint {
                let actual_fingerprint = crypto::compute_derivative_fingerprint(&dwd.clipper_id);
                if expected_fingerprint != &actual_fingerprint {
                    return Err(anyhow!("CRITICAL: Derivative authorship metadata mismatch with fingerprint! Evidence of tampering."));
                }
                println!("Derivative authorship fingerprint verified.");
            } else {
                println!("Warning: No derivative authorship fingerprint found in metadata.");
            }

            println!("\n[PROVENANCE CHAIN]");
            println!("  (Original: {})", dwd.original_owd.title);
            for (i, ancestor) in dwd.ancestry.iter().enumerate() {
                let id = match &ancestor.content {
                    ManifestContent::Original(o) => o.work_id.to_string(),
                    ManifestContent::Derivative(d) => d.derivative_id.to_string(),
                };
                println!("     │");
                println!("     ▼");
                println!("  (Ancestor {}: {})", i + 1, id);
            }
            println!("     │");
            println!("     ▼");
            println!("  (Current: {})\n", dwd.derivative_id);

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
            println!("\nVerifying clip integrity and Merkle proofs against original root...");

            let mut current_offset = 0;
            let mut consumed_bytes = 0u64;
            for mapping in &dwd.clip_mappings {
                let original_track = dwd
                    .original_owd
                    .tracks
                    .iter()
                    .find(|t| t.track_id == mapping.track_id)
                    .context(format!(
                        "Original track {} not found for mapping",
                        mapping.track_id
                    ))?;

                let original_root: crypto::Hash = hex::decode(&original_track.merkle_root)?
                    .try_into()
                    .map_err(|_| anyhow!("Invalid original root"))?;

                let chunk_lookup = reader
                    .chunk_index_for_track(mapping.track_id)
                    .map(|entries| {
                        let mut lookup = std::collections::HashMap::new();
                        for entry in entries {
                            lookup.insert(entry.chunk_index, entry.clone());
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

fn print_smed_info<R: Read + Seek>(reader: &SmedReader<R>, input: &PathBuf) -> Result<()> {
    println!("--- SignMedia File Information ---");
    println!("File: {:?}", input);

    let manifest = &reader.manifest;
    let track_map: HashMap<u32, &TrackMetadata> = match &manifest.content {
        ManifestContent::Original(owd) => owd.tracks.iter().map(|t| (t.track_id, t)).collect(),
        ManifestContent::Derivative(dwd) => dwd
            .original_owd
            .tracks
            .iter()
            .map(|t| (t.track_id, t))
            .collect(),
    };
    match &manifest.content {
        ManifestContent::Original(owd) => {
            println!("Type: Original Work");
            println!("Title: {}", owd.title);
            println!("Work ID: {}", owd.work_id);
            println!("Created: {}", owd.created_at);
            println!("Authors:");
            for author in &owd.authors {
                println!(
                    "  - {} ({}, ID: {})",
                    author.name, author.role, author.author_id
                );
            }
            println!("Tracks: {}", owd.tracks.len());
            for track in &owd.tracks {
                println!(
                    "  Track {} ({}): Codec: {}, Chunks: {}, Root: {}",
                    track.track_id,
                    track_type_label(track),
                    track.codec,
                    track.total_chunks,
                    track.merkle_root
                );
            }
        }
        ManifestContent::Derivative(dwd) => {
            println!("Type: Derivative Work");
            println!("Derivative ID: {}", dwd.derivative_id);
            println!("Clipper ID: {}", dwd.clipper_id);
            println!("Created: {}", dwd.created_at);
            println!("Original Work:");
            println!("  Title: {}", dwd.original_owd.title);
            println!("  Work ID: {}", dwd.original_owd.work_id);
            println!("  Authors:");
            for author in &dwd.original_owd.authors {
                println!("    - {} ({})", author.name, author.role);
            }
            if let Some(fp) = &dwd.authorship_fingerprint {
                println!("  Derivative Fingerprint: {}", fp);
            }
            println!("Ancestry: {} levels", dwd.ancestry.len());
            println!("Clip Mappings: {}", dwd.clip_mappings.len());
            for mapping in &dwd.clip_mappings {
                let label = track_map
                    .get(&mapping.track_id)
                    .map(|track| track_type_label(track))
                    .unwrap_or("Unknown");
                println!(
                    "  Track {} ({}): Chunks {}..{}",
                    mapping.track_id, label, mapping.start_chunk_index, mapping.end_chunk_index
                );
            }
        }
    }

    if !reader.track_table.is_empty() {
        println!("Container Track Table:");
        for entry in &reader.track_table {
            let label = track_map
                .get(&entry.track_id)
                .map(|track| track_type_label(track))
                .unwrap_or("Unknown");
            println!(
                "  Track {} ({}): Codec: {}, Total Chunks: {}",
                entry.track_id, label, entry.codec, entry.total_chunks
            );
        }
    }

    let mut author_key_names: HashMap<String, String> = HashMap::new();
    match &manifest.content {
        ManifestContent::Original(owd) => {
            for author in &owd.authors {
                author_key_names.insert(author.author_id.clone(), author.name.clone());
            }
        }
        ManifestContent::Derivative(dwd) => {
            let clipper_name = manifest
                .signatures
                .iter()
                .find(|sig| sig.public_key == dwd.clipper_id)
                .and_then(|sig| sig.display_name.clone())
                .and_then(|name| {
                    let trimmed = name.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                });
            let label = clipper_name.unwrap_or_else(|| "Clipper".to_string());
            author_key_names.insert(dwd.clipper_id.clone(), label);
        }
    }

    println!("Signatures: {}", manifest.signatures.len());
    let ttp_key = crypto::get_ttp_public_key();
    for sig in &manifest.signatures {
        let label = if sig.public_key == ttp_key {
            let ttp_name = sig
                .display_name
                .clone()
                .unwrap_or_else(|| "Trusted Third Party".to_string());
            if ttp_name == "Trusted Third Party" {
                "TTP Key".to_string()
            } else {
                format!("TTP Key ({})", ttp_name)
            }
        } else if let Some(name) = author_key_names.get(&sig.public_key) {
            if name.is_empty() {
                "Author Key".to_string()
            } else {
                format!("Author Key ({})", name)
            }
        } else if let Some(name) = &sig.display_name {
            format!("Author Key ({})", name)
        } else {
            "Author Key".to_string()
        };
        println!("  - {}: {}", label, sig.public_key);
    }

    Ok(())
}

fn verify_metadata_command(input: PathBuf) -> Result<()> {
    let output = std::process::Command::new("ffprobe")
        .args(["-v", "quiet", "-print_format", "json", "-show_format"])
        .arg(&input)
        .output()
        .context("Failed to invoke ffprobe")?;
    if !output.status.success() {
        if input.extension().map_or(false, |ext| ext == "smed") {
            return Err(anyhow!("ffprobe failed to read '{}'. This appears to be a .smed container; use 'VERIFY-SMED' instead.", input.display()));
        }
        return Err(anyhow!(
            "ffprobe failed with status {}. Ensure the input is a valid media file.",
            output.status
        ));
    }

    #[derive(serde::Deserialize)]
    struct FfprobeFormat {
        tags: Option<HashMap<String, String>>,
    }
    #[derive(serde::Deserialize)]
    struct FfprobeOutput {
        format: Option<FfprobeFormat>,
    }

    let parsed: FfprobeOutput =
        serde_json::from_slice(&output.stdout).context("Failed to parse ffprobe JSON")?;
    let tags = parsed
        .format
        .and_then(|fmt| fmt.tags)
        .ok_or_else(|| anyhow!("No metadata tags found in container"))?;

    let mut normalized = HashMap::new();
    for (key, value) in tags {
        normalized.insert(key.to_ascii_lowercase(), value);
    }

    let manifest_b64 = normalized.get("smed.manifest_b64").ok_or_else(|| {
        let mut msg = format!(
            "No SignMedia metadata found in '{}'. This file has not been tagged.",
            input.display()
        );
        if input.extension().map_or(false, |ext| ext == "smed") {
            msg.push_str("\nThis appears to be a .smed container. Use 'VERIFY-SMED' instead.");
        } else {
            msg.push_str("\nUse 'sign' to create a .smed container or 'extract' to create a tagged media file from a .smed container.");
        }
        anyhow!(msg)
    })?.to_string();
    let manifest_bytes = general_purpose::STANDARD
        .decode(manifest_b64.as_bytes())
        .context("Failed to decode smed.manifest_b64")?;

    let manifest_hash = hex::encode(crypto::hash_data(&manifest_bytes));
    let parsed_manifest: SignedManifest =
        serde_json::from_slice(&manifest_bytes).context("Failed to parse SignedManifest JSON")?;
    let content_hash = hex::encode(hash_manifest_content(&parsed_manifest.content)?);

    let mut mismatches = Vec::new();

    if let Some(expected) = normalized.get("smed.manifest_hash") {
        if expected.to_ascii_lowercase() != manifest_hash {
            mismatches.push(format!(
                "smed.manifest_hash mismatch (expected {}, got {})",
                expected, manifest_hash
            ));
        }
    } else {
        mismatches.push("Missing smed.manifest_hash tag".to_string());
    }

    if let Some(expected) = normalized.get("smed.content_hash") {
        if expected.to_ascii_lowercase() != content_hash {
            mismatches.push(format!(
                "smed.content_hash mismatch (expected {}, got {})",
                expected, content_hash
            ));
        }
    } else {
        mismatches.push("Missing smed.content_hash tag".to_string());
    }

    let (expected_work_id, label) = match &parsed_manifest.content {
        ManifestContent::Original(owd) => (owd.work_id.to_string(), "smed.work_id"),
        ManifestContent::Derivative(dwd) => (
            dwd.original_owd.work_id.to_string(),
            "smed.original_work_id",
        ),
    };
    if let Some(tag_value) = normalized.get(label) {
        if tag_value != &expected_work_id {
            mismatches.push(format!(
                "{} mismatch (expected {}, got {})",
                label, tag_value, expected_work_id
            ));
        }
    } else if let Some(tag_value) = normalized.get("smed.work_id") {
        if tag_value != &expected_work_id {
            mismatches.push(format!(
                "smed.work_id mismatch (expected {}, got {})",
                tag_value, expected_work_id
            ));
        }
    } else if let Some(tag_value) = normalized.get("smed.original_work_id") {
        if tag_value != &expected_work_id {
            mismatches.push(format!(
                "smed.original_work_id mismatch (expected {}, got {})",
                tag_value, expected_work_id
            ));
        }
    } else {
        mismatches.push("Missing work id tag (smed.work_id or smed.original_work_id)".to_string());
    }

    if mismatches.is_empty() {
        println!("Metadata verification OK");
        println!("Manifest hash: {}", manifest_hash);
        println!("Content hash: {}", content_hash);
        println!("Work ID: {}", expected_work_id);
        Ok(())
    } else {
        Err(anyhow!(
            "Metadata verification failed: {}",
            mismatches.join("; ")
        ))
    }
}

struct ExtractTrackOutput {
    format: String,
    path: PathBuf,
    timebase_num: Option<u32>,
    timebase_den: Option<u32>,
    codec: String,
}

fn ttp_display_name() -> String {
    std::env::var("SMED_TTP_NAME").unwrap_or_else(|_| "Trusted Third Party".to_string())
}

fn derive_ttp_display_name(
    manifest: &SignedManifest,
    author_names: &HashSet<String>,
) -> Option<String> {
    let ttp_key = crypto::get_ttp_public_key();
    if let Some(entry) = manifest
        .signatures
        .iter()
        .find(|entry| entry.public_key == ttp_key)
        .and_then(|entry| entry.display_name.clone())
    {
        return Some(entry);
    }

    let mut candidates = Vec::new();
    for entry in &manifest.signatures {
        if let Some(name) = &entry.display_name {
            if !author_names.contains(name) {
                candidates.push(name.clone());
            }
        }
    }

    if candidates.len() == 1 {
        return Some(candidates.remove(0));
    }

    let fallback = ttp_display_name();
    if fallback.is_empty() {
        None
    } else {
        Some(fallback)
    }
}

fn build_extract_metadata(manifest: &SignedManifest) -> Result<Vec<(String, String)>> {
    let mut metadata = Vec::new();

    let manifest_json = serde_json::to_vec(manifest)?;
    let manifest_hash = crypto::hash_data(&manifest_json);
    let content_hash = hash_manifest_content(&manifest.content)?;

    metadata.push((
        "smed.manifest_b64".to_string(),
        general_purpose::STANDARD.encode(&manifest_json),
    ));
    metadata.push(("smed.manifest_hash".to_string(), hex::encode(manifest_hash)));
    metadata.push(("smed.content_hash".to_string(), hex::encode(content_hash)));
    metadata.push((
        "smed.signature_count".to_string(),
        manifest.signatures.len().to_string(),
    ));

    let mut author_names = HashSet::new();
    match &manifest.content {
        ManifestContent::Original(owd) => {
            metadata.push(("smed.type".to_string(), "original".to_string()));
            metadata.push(("smed.work_id".to_string(), owd.work_id.to_string()));
            metadata.push(("smed.title".to_string(), owd.title.clone()));
            metadata.push(("smed.created_at".to_string(), owd.created_at.to_rfc3339()));
            metadata.push((
                "smed.author_count".to_string(),
                owd.authors.len().to_string(),
            ));
            metadata.push(("smed.track_count".to_string(), owd.tracks.len().to_string()));
            if let Some(fp) = &owd.authorship_fingerprint {
                metadata.push(("smed.authorship_fingerprint".to_string(), fp.clone()));
            }
            if !owd.authors.is_empty() {
                let names: Vec<String> = owd
                    .authors
                    .iter()
                    .map(|author| author.name.clone())
                    .collect();
                for name in &names {
                    author_names.insert(name.clone());
                }
                metadata.push(("smed.author_names".to_string(), names.join(", ")));
            }
        }
        ManifestContent::Derivative(dwd) => {
            metadata.push(("smed.type".to_string(), "derivative".to_string()));
            metadata.push((
                "smed.derivative_id".to_string(),
                dwd.derivative_id.to_string(),
            ));
            metadata.push((
                "smed.original_work_id".to_string(),
                dwd.original_owd.work_id.to_string(),
            ));
            metadata.push((
                "smed.original_title".to_string(),
                dwd.original_owd.title.clone(),
            ));
            metadata.push(("smed.clipper_id".to_string(), dwd.clipper_id.clone()));
            metadata.push(("smed.created_at".to_string(), dwd.created_at.to_rfc3339()));
            metadata.push((
                "smed.ancestry_count".to_string(),
                dwd.ancestry.len().to_string(),
            ));
            metadata.push((
                "smed.clip_mapping_count".to_string(),
                dwd.clip_mappings.len().to_string(),
            ));
            if let Some(fp) = &dwd.authorship_fingerprint {
                metadata.push(("smed.derivative_fingerprint".to_string(), fp.clone()));
            }
            if let Some(fp) = &dwd.original_owd.authorship_fingerprint {
                metadata.push((
                    "smed.original_authorship_fingerprint".to_string(),
                    fp.clone(),
                ));
            }
            if !dwd.original_owd.authors.is_empty() {
                let names: Vec<String> = dwd
                    .original_owd
                    .authors
                    .iter()
                    .map(|author| author.name.clone())
                    .collect();
                for name in &names {
                    author_names.insert(name.clone());
                }
                metadata.push(("smed.author_names".to_string(), names.join(", ")));
            }
        }
    }

    if let Some(ttp_name) = derive_ttp_display_name(manifest, &author_names) {
        metadata.push(("smed.ttp_name".to_string(), ttp_name));
    }

    Ok(metadata)
}

fn extract_raw_track_passthrough(
    reader: &mut SmedReader<fs::File>,
    track: &TrackMetadata,
    file_len: u64,
    track_count: usize,
    output: &PathBuf,
) -> Result<()> {
    let mut entries = resolve_chunk_entries(reader, track, file_len, track_count)?;
    entries.sort_by_key(|entry| entry.offset);

    let mut writer =
        BufWriter::new(fs::File::create(output).context("Failed to create output file")?);
    for entry in entries {
        let data = reader.read_variable_chunk(entry.offset, entry.size)?;
        writer.write_all(&data)?;
    }
    writer.flush()?;
    Ok(())
}

fn output_ext_matches_container(output_ext: &str, container_type: &str) -> bool {
    let output_ext = output_ext.to_ascii_lowercase();
    let container_type = container_type.to_ascii_lowercase();
    match container_type.as_str() {
        "jpg" | "jpeg" => matches!(output_ext.as_str(), "jpg" | "jpeg"),
        "heic" | "heif" => matches!(output_ext.as_str(), "heic" | "heif"),
        "png" | "gif" | "webp" => output_ext == container_type,
        _ => output_ext == container_type,
    }
}

fn track_type_label(track: &TrackMetadata) -> &'static str {
    let codec = track.codec.to_ascii_lowercase();
    if let Some(container_type) = track.container_type.as_deref() {
        let container_type = container_type.to_ascii_lowercase();
        if matches!(
            container_type.as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "heif"
        ) {
            return "Image";
        }
    }
    if track.width.is_some()
        || track.height.is_some()
        || matches!(
            codec.as_str(),
            "h264" | "h265" | "hevc" | "av1" | "vp9" | "vp8" | "mpeg4" | "mpeg2video"
        )
    {
        return "Video";
    }
    if track.sample_rate.is_some()
        || track.channel_count.is_some()
        || matches!(
            codec.as_str(),
            "aac" | "opus" | "flac" | "mp3" | "vorbis" | "pcm" | "alac"
        )
    {
        return "Audio";
    }
    "Unknown"
}

fn verify_smed_command(input: PathBuf) -> Result<()> {
    let file_len = fs::metadata(&input)?.len();
    let mut reader = open_smed_reader(&input)?;

    print_smed_info(&reader, &input)?;
    println!("\n--- Cryptographic Verification ---");
    verify_smed_integrity(&mut reader, file_len)?;

    Ok(())
}

fn extract_command(input: PathBuf, output: PathBuf) -> Result<()> {
    let file_len = fs::metadata(&input)?.len();
    let mut reader = open_smed_reader(&input)?;

    let tracks = match &reader.manifest.content {
        ManifestContent::Original(owd) => owd.tracks.clone(),
        ManifestContent::Derivative(dwd) => dwd.original_owd.tracks.clone(),
    };
    let mut tracks_by_id = HashMap::new();
    for track in tracks {
        tracks_by_id.insert(track.track_id, track);
    }

    let mut track_ids: Vec<u32> = if !reader.track_table.is_empty() {
        reader
            .track_table
            .iter()
            .map(|entry| entry.track_id)
            .collect()
    } else if !reader.chunk_index.is_empty() {
        reader.chunk_index.keys().copied().collect()
    } else {
        tracks_by_id.keys().copied().collect()
    };
    track_ids.sort_unstable();
    track_ids.dedup();

    if track_ids.is_empty() {
        return Err(anyhow!("No tracks found in the .smed file"));
    }

    let output_ext = output
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default();
    let is_mux_container = matches!(output_ext.as_str(), "mkv" | "mp4" | "webm");
    if !is_mux_container {
        if track_ids.len() != 1 {
            return Err(anyhow!(
                "Unsupported output container: {:?} (expected .mp4, .mkv, or .webm)",
                output
            ));
        }
        let track = tracks_by_id
            .get(&track_ids[0])
            .context(format!("Missing track metadata for track {}", track_ids[0]))?;
        if !track.codec.eq_ignore_ascii_case("raw") {
            return Err(anyhow!(
                "Unsupported output container: {:?} (expected .mp4, .mkv, or .webm)",
                output
            ));
        }
        let Some(container_type) = track.container_type.as_deref() else {
            return Err(anyhow!(
                "Unsupported output container: {:?} (expected .mp4, .mkv, or .webm)",
                output
            ));
        };
        if !output_ext_matches_container(&output_ext, container_type) {
            return Err(anyhow!(
                "Track {} is a raw {} container; output extension .{} does not match",
                track.track_id,
                container_type,
                output_ext
            ));
        }
    }

    let metadata = build_extract_metadata(&reader.manifest)?;

    if track_ids.len() == 1 {
        let track_id = track_ids[0];
        let track = tracks_by_id
            .get(&track_id)
            .context(format!("Missing track metadata for track {}", track_id))?;
        if track.codec.eq_ignore_ascii_case("raw") {
            let Some(container_type) = track.container_type.as_deref() else {
                return Err(anyhow!(
                    "Track {} is raw with an unknown container type; cannot extract without conversion",
                    track_id
                ));
            };
            if !output_ext_matches_container(&output_ext, container_type) {
                return Err(anyhow!(
                    "Track {} is a raw {} container; output extension .{} does not match",
                    track_id,
                    container_type,
                    output_ext
                ));
            }
            extract_raw_track_passthrough(&mut reader, track, file_len, track_ids.len(), &output)?;
            println!("Extracted container written to {:?}", output);
            return Ok(());
        }
    }

    for track_id in &track_ids {
        let track = tracks_by_id
            .get(track_id)
            .context(format!("Missing track metadata for track {}", track_id))?;
        if track.codec.eq_ignore_ascii_case("raw") {
            return Err(anyhow!(
                "Track {} is raw and cannot be muxed; re-sign with demuxable inputs or extract a single matching container",
                track_id
            ));
        }
    }

    let temp_dir = std::env::temp_dir().join(format!("smed-extract-{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).context("Failed to create temp directory")?;

    let mut track_outputs = Vec::new();
    for track_id in &track_ids {
        let track = tracks_by_id
            .get(track_id)
            .context(format!("Missing track metadata for track {}", track_id))?;
        let mut entries = resolve_chunk_entries(&reader, track, file_len, track_ids.len())?;
        entries.sort_by_key(|entry| entry.offset);

        let format = match codec::codec_to_ffmpeg_format(&track.codec) {
            Some(format) => format.to_string(),
            None => {
                return Err(anyhow!(
                    "Unsupported codec {} for container extraction",
                    track.codec
                ))
            }
        };

        let track_path = temp_dir.join(format!("track-{}-{}.bin", track_id, track.codec));
        let mut writer = BufWriter::new(
            fs::File::create(&track_path).context("Failed to create extracted track file")?,
        );
        if matches!(track.codec.as_str(), "h264" | "h265" | "hevc") {
            if let Some(extradata) = &track.codec_extradata {
                let bytes = hex::decode(extradata).context("Failed to decode codec extradata")?;
                if !bytes.is_empty() {
                    let mut already_prefixed = false;
                    if let Some(first_entry) = entries.first() {
                        // Check if the first chunk already starts with this exact extradata
                        let first_chunk_prefix = reader.read_variable_chunk(
                            first_entry.offset,
                            first_entry.size.min(bytes.len() as u64),
                        )?;
                        if first_chunk_prefix == bytes {
                            already_prefixed = true;
                        }
                    }
                    if !already_prefixed {
                        writer.write_all(&bytes)?;
                    }
                }
            }
        }

        for entry in entries {
            let data = reader.read_variable_chunk(entry.offset, entry.size)?;
            writer.write_all(&data)?;
        }
        writer.flush()?;

        track_outputs.push(ExtractTrackOutput {
            format,
            path: track_path,
            timebase_num: track.timebase_num,
            timebase_den: track.timebase_den,
            codec: track.codec.clone(),
        });
    }

    mux_tracks_with_ffmpeg(&track_outputs, &output, &metadata, &output_ext)?;

    for output in &track_outputs {
        let _ = fs::remove_file(&output.path);
    }
    let _ = fs::remove_dir(&temp_dir);

    println!("Extracted container written to {:?}", output);
    Ok(())
}

fn resolve_chunk_entries(
    reader: &SmedReader<fs::File>,
    track: &TrackMetadata,
    file_len: u64,
    track_count: usize,
) -> Result<Vec<TrackChunkIndexEntry>> {
    if let Some(entries) = reader.chunk_index_for_track(track.track_id) {
        return Ok(entries.clone());
    }
    if !track.chunk_index.is_empty() {
        return Ok(track.chunk_index.clone());
    }
    if track_count == 1 {
        let data_size = file_len.saturating_sub(reader.data_start());
        return Ok(build_sequential_entries(
            track.total_chunks,
            track.chunk_size,
            data_size,
        ));
    }
    Err(anyhow!(
        "Missing chunk index data for track {}",
        track.track_id
    ))
}

fn mux_tracks_with_ffmpeg(
    tracks: &[ExtractTrackOutput],
    output: &PathBuf,
    metadata: &[(String, String)],
    output_ext: &str,
) -> Result<()> {
    let mut command = std::process::Command::new("ffmpeg");
    command.arg("-y");
    command.arg("-fflags").arg("+genpts");
    command.arg("-avoid_negative_ts").arg("make_zero");

    for track in tracks {
        if let (Some(num), Some(den)) = (track.timebase_num, track.timebase_den) {
            if num > 0 && den > 0 && matches!(track.codec.as_str(), "h264" | "h265" | "hevc") {
                command.arg("-r").arg(format!("{}/{}", den, num));
            }
        }
        command.arg("-f").arg(&track.format);
        command.arg("-i").arg(&track.path);
    }
    if output_ext == "mp4" {
        command.arg("-movflags").arg("use_metadata_tags");
    }
    for (key, value) in metadata {
        command.arg("-metadata").arg(format!("{}={}", key, value));
    }
    command.arg("-c").arg("copy").arg(output);
    let status = command
        .status()
        .context("Failed to invoke ffmpeg for muxing")?;
    if !status.success() {
        return Err(anyhow!("ffmpeg failed with status {}", status));
    }
    Ok(())
}

fn clip_command(
    input: PathBuf,
    key_path: PathBuf,
    clipper_name: Option<String>,
    output: PathBuf,
    start: Option<u64>,
    end: Option<u64>,
    start_time: Option<f64>,
    end_time: Option<f64>,
    track_id_to_clip: u32,
) -> Result<()> {
    let key_bytes = fs::read(key_path).context("Failed to read key file")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid key size"))?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let clipper_display_name = clipper_name.and_then(|name| {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    let file_len = fs::metadata(&input)?.len();
    let mut reader = open_smed_reader(&input)?;

    let original_manifest = reader.manifest.clone();

    // Enforce TTP oversight for clipping
    verify_manifest_signatures(&original_manifest, "Input manifest for clipping")?;
    let mut ancestry = Vec::new();
    let (original_owd, original_signature, input_mappings) = match &original_manifest.content {
        ManifestContent::Original(owd) => (
            owd.clone(),
            original_manifest.signatures[0].signature.clone(),
            None,
        ),
        ManifestContent::Derivative(dwd) => {
            ancestry.extend(dwd.ancestry.clone());
            ancestry.push(original_manifest.clone());
            (
                dwd.original_owd.clone(),
                dwd.original_signature.clone(),
                Some(&dwd.clip_mappings),
            )
        }
    };

    let ref_track = original_owd
        .tracks
        .iter()
        .find(|t| t.track_id == track_id_to_clip)
        .context(format!(
            "Track {} not found in original work",
            track_id_to_clip
        ))?
        .clone();
    if ref_track.codec.eq_ignore_ascii_case("raw") {
        return Err(anyhow!(
            "Track {} uses codec \"raw\"; clipping opaque containers is unsupported.",
            ref_track.track_id
        ));
    }

    let ref_entries = resolve_track_entries(&reader, &ref_track, file_len);
    let (mut target_start_time, target_end_time) =
        if let (Some(st), Some(et)) = (start_time, end_time) {
            (st, et)
        } else if let (Some(s), Some(e)) = (start, end) {
            timecode::chunk_range_to_time_range(&ref_track, &ref_entries, s, e)
                .context("Failed to determine time range from chunk range")?
        } else if start_time.is_some() || end_time.is_some() {
            let (s, e) =
                timecode::time_range_to_chunk_range(&ref_track, &ref_entries, start_time, end_time)
                    .context("Failed to determine chunk range for partial time range")?;
            timecode::chunk_range_to_time_range(&ref_track, &ref_entries, s, e)
                .context("Failed to resolve absolute time range")?
        } else {
            return Err(anyhow!(
                "Must provide either --start/--end or --start-time/--end-time"
            ));
        };

    // IDR adjustment: find the earliest IDR start across all video tracks
    let mut min_adjusted_start_time = target_start_time;
    for track in &original_owd.tracks {
        if matches!(track.codec.as_str(), "h264" | "h265" | "hevc") {
            let track_entries = resolve_track_entries(&reader, track, file_len);
            if track_entries.is_empty() {
                continue;
            }
            if let Some((s, _)) = timecode::time_range_to_chunk_range(
                track,
                &track_entries,
                Some(target_start_time),
                Some(target_end_time),
            ) {
                if let Ok(adjusted_start_chunk) = find_idr_start(&mut reader, &track_entries, s) {
                    if let Some((chunk_time, _)) = timecode::chunk_range_to_time_range(
                        track,
                        &track_entries,
                        adjusted_start_chunk,
                        adjusted_start_chunk + 1,
                    ) {
                        if chunk_time < min_adjusted_start_time {
                            min_adjusted_start_time = chunk_time;
                        }
                    }
                }
            }
        }
    }
    target_start_time = min_adjusted_start_time;

    let mut track_clip_results = Vec::new();
    let mut final_clip_mappings = Vec::new();

    for track in &original_owd.tracks {
        let track_entries = resolve_track_entries(&reader, track, file_len);
        if track_entries.is_empty() {
            continue;
        }

        let range = timecode::time_range_to_chunk_range(
            track,
            &track_entries,
            Some(target_start_time),
            Some(target_end_time),
        );
        let (s, e) = match range {
            Some(r) => r,
            None => continue,
        };

        let mut clip_chunks = Vec::new();
        let mut proofs = Vec::new();

        if let Some(mappings) = input_mappings {
            let mapping = mappings.iter().find(|m| m.track_id == track.track_id);
            if let Some(m) = mapping {
                let proof_map: HashMap<u64, &signmedia::models::MerkleProof> =
                    m.proofs.iter().map(|p| (p.chunk_index, p)).collect();
                for entry in &track_entries {
                    if entry.chunk_index >= s && entry.chunk_index < e {
                        let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
                        let proof = proof_map.get(&entry.chunk_index).context(format!(
                            "Missing proof for chunk {} in track {}",
                            entry.chunk_index, track.track_id
                        ))?;
                        clip_chunks.push(chunk);
                        proofs.push((*proof).clone());
                    }
                }
            }
        } else {
            let mut original_hashes = Vec::new();
            let mut sorted_entries = track_entries.clone();
            sorted_entries.sort_by_key(|entry| entry.chunk_index);
            for entry in &sorted_entries {
                let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
                original_hashes.push(crypto::hash_data(&chunk));
            }
            let tree = MerkleTree::new(original_hashes);

            for entry in &track_entries {
                if entry.chunk_index >= s && entry.chunk_index < e {
                    let chunk = reader.read_variable_chunk(entry.offset, entry.size)?;
                    let mut proof = tree.generate_proof(entry.chunk_index as usize, entry.pts);
                    proof.chunk_size = entry.size;
                    clip_chunks.push(chunk);
                    proofs.push(proof);
                }
            }
        }

        if !clip_chunks.is_empty() {
            final_clip_mappings.push(signmedia::models::ClipMapping {
                track_id: track.track_id,
                start_chunk_index: s,
                end_chunk_index: e,
                proofs: proofs.clone(),
            });
            track_clip_results.push(TrackClipData {
                track_id: track.track_id,
                codec: track.codec.clone(),
                proofs,
                chunks: clip_chunks,
            });
        }
    }

    if track_clip_results.is_empty() {
        return Err(anyhow!("No chunks selected for clip across any tracks"));
    }

    let clipper_id = hex::encode(signing_key.verifying_key().to_bytes());
    let authorship_fingerprint = Some(crypto::compute_derivative_fingerprint(&clipper_id));
    let final_track_count = final_clip_mappings.len();
    let dwd = signmedia::models::DerivativeWorkDescriptor {
        derivative_id: Uuid::new_v4(),
        original_owd,
        original_signature,
        ancestry,
        clipper_id,
        authorship_fingerprint,
        created_at: Utc::now(),
        clip_mappings: final_clip_mappings,
    };

    let content = ManifestContent::Derivative(dwd);
    let content_hash = hash_manifest_content(&content)?;
    let author_signature = crypto::sign(&content_hash, &signing_key);

    let ttp_signer = crypto::get_ttp_signing_key()?;
    let ttp_signature = crypto::sign_with_ttp(&content_hash, &ttp_signer);
    let manifest = SignedManifest {
        content,
        signatures: vec![
            signmedia::models::SignatureEntry {
                signature: hex::encode(author_signature.to_bytes()),
                public_key: hex::encode(signing_key.verifying_key().to_bytes()),
                display_name: clipper_display_name,
            },
            signmedia::models::SignatureEntry {
                signature: hex::encode(ttp_signature.to_bytes()),
                public_key: crypto::get_ttp_public_key(),
                display_name: Some(ttp_display_name()),
            },
        ],
    };

    let (track_table, chunk_table) = build_track_tables(&track_clip_results)?;
    let all_chunks: Vec<Vec<u8>> = track_clip_results
        .into_iter()
        .flat_map(|res| res.chunks)
        .collect();

    let out_file = fs::File::create(&output).context("Failed to create output file")?;
    let mut writer = SmedWriter::new(out_file);
    writer.write_all(&manifest, &track_table, &chunk_table, &all_chunks)?;

    println!(
        "Successfully created clip with {} tracks: {:?}",
        final_track_count, output
    );
    Ok(())
}

struct TrackClipData {
    track_id: u32,
    codec: String,
    proofs: Vec<signmedia::models::MerkleProof>,
    chunks: Vec<Vec<u8>>,
}

fn build_track_tables(
    tracks_data: &[TrackClipData],
) -> Result<(Vec<TrackTableEntry>, Vec<ChunkTableEntry>)> {
    let mut track_table = Vec::new();
    let mut chunk_table = Vec::new();
    let mut current_offset = 0u64;

    for data in tracks_data {
        for (index, chunk) in data.chunks.iter().enumerate() {
            let size = chunk.len() as u64;
            let proof = &data.proofs[index];
            chunk_table.push(ChunkTableEntry {
                track_id: data.track_id,
                chunk: TrackChunkIndexEntry {
                    chunk_index: proof.chunk_index,
                    pts: proof.pts,
                    offset: current_offset,
                    size,
                },
            });
            current_offset += size;
        }

        let max_chunk_size = data
            .chunks
            .iter()
            .map(|chunk| chunk.len() as u64)
            .max()
            .unwrap_or(0);
        track_table.push(TrackTableEntry {
            track_id: data.track_id,
            codec: data.codec.clone(),
            total_chunks: data.chunks.len() as u64,
            chunk_size: max_chunk_size,
            chunk_index_count: data.chunks.len() as u64,
        });
    }
    Ok((track_table, chunk_table))
}
