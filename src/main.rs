use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use signmedia::container::{ChunkTableEntry, SmedReader, SmedWriter, TrackTableEntry};
use signmedia::codec;
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
        /// Path to save the private key
        #[arg(short, long, default_value = "key.priv")]
        output: PathBuf,
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
    /// Show information about a .smed file
    Info {
        /// Input .smed file
        #[arg(short, long)]
        input: PathBuf,
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
        Commands::Verify { input } => {
            verify_command(input)?;
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
        Commands::Info { input } => {
            info_command(input)?;
        }
        Commands::Extract { input, output } => {
            extract_command(input, output)?;
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

    for (track_idx, input) in inputs.iter().enumerate() {
        let track_id = track_idx as u32;
        let file =
            fs::File::open(input).context(format!("Failed to open input file {:?}", input))?;
        let mut reader = BufReader::new(file);

        let mut current_track_chunks = Vec::new();
        let mut chunk_hashes = Vec::new();
        let mut first_chunk_data = None;
        let (chunked, playback_info) = codec::chunk_media(&mut reader, max_chunk_size)?;
        let mut track_chunk_index = Vec::with_capacity(chunked.len());

        for (index, chunk) in chunked.into_iter().enumerate() {
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
            codec: playback_info.codec.clone(),
            container_type: playback_info.container_type.clone(),
            codec_extradata: playback_info
                .codec_extradata
                .as_ref()
                .map(|data| hex::encode(data)),
            width: playback_info.width,
            height: playback_info.height,
            sample_rate: playback_info.sample_rate,
            channel_count: playback_info.channels,
            timebase_num: playback_info.timebase_num,
            timebase_den: playback_info.timebase_den,
            merkle_root: hex::encode(root),
            perceptual_hash: p_hash,
            total_chunks: current_track_chunks.len() as u64,
            chunk_size: max_chunk_size,
            chunk_index: track_chunk_index,
        });

        track_table.push(TrackTableEntry {
            track_id,
            codec: playback_info.codec,
            total_chunks: current_track_chunks.len() as u64,
            chunk_size: max_chunk_size,
            chunk_index_count: current_track_chunks.len() as u64,
        });

        all_chunks.extend(current_track_chunks);
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

fn info_command(input: PathBuf) -> Result<()> {
    let file = fs::File::open(&input).context("Failed to open file")?;
    let reader = SmedReader::new(file).context("Failed to initialize SmedReader")?;

    println!("--- SignMedia File Information ---");
    println!("File: {:?}", input);

    let manifest = &reader.manifest;
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
                    "  Track {}: Codec: {}, Chunks: {}, Root: {}",
                    track.track_id, track.codec, track.total_chunks, track.merkle_root
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
                println!(
                    "  Track {}: Chunks {}..{}",
                    mapping.track_id, mapping.start_chunk_index, mapping.end_chunk_index
                );
            }
        }
    }

    if !reader.track_table.is_empty() {
        println!("Container Track Table:");
        for entry in &reader.track_table {
            println!(
                "  Track {}: Codec: {}, Total Chunks: {}",
                entry.track_id, entry.codec, entry.total_chunks
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
        return Err(anyhow!("ffprobe failed with status {}", output.status));
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

    let manifest_b64 = normalized
        .get("smed.manifest_b64")
        .ok_or_else(|| anyhow!("Missing smed.manifest_b64 tag"))?
        .to_string();
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

fn extract_command(input: PathBuf, output: PathBuf) -> Result<()> {
    let file = fs::File::open(&input).context("Failed to open file")?;
    let file_len = file.metadata()?.len();
    let mut reader = SmedReader::new(file).context("Failed to initialize SmedReader")?;

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
    if output_ext != "mkv" && output_ext != "mp4" && output_ext != "webm" {
        return Err(anyhow!(
            "Unsupported output container: {:?} (expected .mp4, .mkv, or .webm)",
            output
        ));
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
            if output_ext != container_type {
                return Err(anyhow!(
                    "Track {} is a raw {} container; output extension .{} does not match",
                    track_id,
                    container_type,
                    output_ext
                ));
            }
            extract_raw_track_passthrough(
                &mut reader,
                track,
                file_len,
                track_ids.len(),
                &output,
            )?;
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
                let bytes = hex::decode(extradata)
                    .context("Failed to decode codec extradata")?;
                if !bytes.is_empty() {
                    writer.write_all(&bytes)?;
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
    for track in tracks {
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

    let file = fs::File::open(&input).context("Failed to open input file")?;
    let file_len = file.metadata()?.len();
    let mut reader = SmedReader::new(file).context("Failed to initialize SmedReader")?;

    let original_manifest = reader.manifest.clone();

    // Enforce TTP oversight for clipping
    verify_manifest_signatures(&original_manifest, "Input manifest for clipping")?;
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

    let track = original_owd
        .tracks
        .iter()
        .find(|t| t.track_id == track_id_to_clip)
        .context(format!(
            "Track {} not found in original work",
            track_id_to_clip
        ))?
        .clone();
    if track.codec.eq_ignore_ascii_case("raw") {
        return Err(anyhow!(
            "Track {} uses codec \"raw\"; clipping opaque containers is unsupported. Re-sign the input with a demuxable container (MP4/MKV/WEBM) or provide an elementary stream (H.264/H.265/AAC) so the track has a real codec.",
            track.track_id
        ));
    }
    let track_id = track.track_id;
    let total_chunks = track.total_chunks;
    let track_entries = resolve_track_entries(&reader, &track, file_len);
    let time_range = if start_time.is_some() || end_time.is_some() {
        timecode::time_range_to_chunk_range(&track, &track_entries, start_time, end_time)
    } else {
        None
    };
    let (start, end) = if let Some((start, end)) = time_range {
        (start, end)
    } else {
        let start = start.ok_or_else(|| {
            anyhow!("--start is required when timestamps are unavailable for this track")
        })?;
        let end = end.ok_or_else(|| {
            anyhow!("--end is required when timestamps are unavailable for this track")
        })?;
        (start, end)
    };

    let mut clip_chunks = Vec::new();
    let mut proofs = Vec::new();
    if let (Some(mapping), Some(existing_proofs)) = (source_mapping, source_proofs) {
        if start >= end {
            return Err(anyhow!("Start index must be less than end index"));
        }
        if time_range.is_none() && end > existing_proofs.len() as u64 {
            return Err(anyhow!("End index out of bounds for derivative input"));
        }
        let data_size = file_len - reader.data_start();
        let mut current_offset = 0;
        let chunk_lookup = reader
            .chunk_index_for_track(mapping.track_id)
            .map(|entries| {
                let mut lookup = std::collections::HashMap::new();
                for entry in entries {
                    lookup.insert(entry.chunk_index, entry.clone());
                }
                lookup
            });
        for (index, proof) in existing_proofs.iter().enumerate() {
            let proof_index = index as u64;
            let proof_chunk_index = proof.chunk_index;
            let in_range = if time_range.is_some() {
                proof_chunk_index >= start && proof_chunk_index < end
            } else {
                proof_index >= start && proof_index < end
            };
            if in_range {
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
        let clipper_id = hex::encode(signing_key.verifying_key().to_bytes());
        let authorship_fingerprint = Some(crypto::compute_derivative_fingerprint(&clipper_id));
        let dwd = signmedia::models::DerivativeWorkDescriptor {
            derivative_id: Uuid::new_v4(),
            original_owd,
            original_signature,
            ancestry,
            clipper_id,
            authorship_fingerprint,
            created_at: Utc::now(),
            clip_mappings: vec![signmedia::models::ClipMapping {
                track_id: mapping.track_id,
                start_chunk_index: start,
                end_chunk_index: end,
                proofs: proofs.clone(),
            }],
        };

        let content = ManifestContent::Derivative(dwd);
        let content_hash = hash_manifest_content(&content)?;
        let signature = crypto::sign(&content_hash, &signing_key);

        let ttp_signer = crypto::get_ttp_signing_key()?;
        let ttp_signature = crypto::sign_with_ttp(&content_hash, &ttp_signer);
        let manifest = SignedManifest {
            content,
            signatures: vec![
                signmedia::models::SignatureEntry {
                    signature: hex::encode(signature.to_bytes()),
                    public_key: hex::encode(signing_key.verifying_key().to_bytes()),
                    display_name: clipper_display_name.clone(),
                },
                signmedia::models::SignatureEntry {
                    signature: hex::encode(ttp_signature.to_bytes()),
                    public_key: crypto::get_ttp_public_key(),
                    display_name: Some(ttp_display_name()),
                },
            ],
        };

        let (track_table, chunk_table) =
            build_track_tables(mapping.track_id, track.codec.clone(), &proofs, &clip_chunks)?;
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
    let mut entries = track_entries;
    entries.sort_by_key(|entry| entry.chunk_index);
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

    let clipper_id = hex::encode(signing_key.verifying_key().to_bytes());
    let authorship_fingerprint = Some(crypto::compute_derivative_fingerprint(&clipper_id));
    let dwd = signmedia::models::DerivativeWorkDescriptor {
        derivative_id: Uuid::new_v4(),
        original_owd,
        original_signature,
        ancestry,
        clipper_id,
        authorship_fingerprint,
        created_at: Utc::now(),
        clip_mappings: vec![signmedia::models::ClipMapping {
            track_id,
            start_chunk_index: start,
            end_chunk_index: end,
            proofs: proofs.clone(),
        }],
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
                display_name: clipper_display_name.clone(),
            },
            signmedia::models::SignatureEntry {
                signature: hex::encode(ttp_signature.to_bytes()),
                public_key: crypto::get_ttp_public_key(),
                display_name: Some(ttp_display_name()),
            },
        ],
    };

    let (track_table, chunk_table) =
        build_track_tables(track_id, track.codec.clone(), &proofs, &clip_chunks)?;
    let out_file = fs::File::create(&output)?;
    let mut writer = SmedWriter::new(out_file);
    writer.write_all(&manifest, &track_table, &chunk_table, &clip_chunks)?;

    println!("Successfully created clip: {:?}", output);
    Ok(())
}

fn build_track_tables(
    track_id: u32,
    codec: String,
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
        codec,
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
