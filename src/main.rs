use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
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
    /// Extract tracks from a .smed file into a container (MP4/MKV)
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
            output,
            start,
            end,
            start_time,
            end_time,
            track,
        } => {
            clip_command(input, key, output, start, end, start_time, end_time, track)?;
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
        let (chunked, playback_info) = chunk_media(&mut reader, max_chunk_size)?;
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
            author_key_names.insert(dwd.clipper_id.clone(), "Clipper".to_string());
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
    if output_ext != "mkv" && output_ext != "mp4" {
        return Err(anyhow!(
            "Unsupported output container: {:?} (expected .mp4 or .mkv)",
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
            let temp_dir = std::env::temp_dir().join(format!("smed-extract-{}", Uuid::new_v4()));
            fs::create_dir_all(&temp_dir).context("Failed to create temp directory")?;
            let temp_path = temp_dir.join(format!("raw-track.{}", output_ext));
            extract_raw_track_passthrough(
                &mut reader,
                track,
                file_len,
                track_ids.len(),
                &temp_path,
            )?;
            let remux_result =
                remux_container_with_ffmpeg(&temp_path, &output, &metadata, &output_ext);
            let _ = fs::remove_file(&temp_path);
            let _ = fs::remove_dir(&temp_dir);
            remux_result?;
            println!("Extracted container written to {:?}", output);
            return Ok(());
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

        let format = match codec_to_ffmpeg_format(&track.codec) {
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

fn codec_to_ffmpeg_format(codec: &str) -> Option<&'static str> {
    match codec {
        "h264" => Some("h264"),
        "aac" => Some("adts"),
        _ => None,
    }
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

fn remux_container_with_ffmpeg(
    input: &PathBuf,
    output: &PathBuf,
    metadata: &[(String, String)],
    output_ext: &str,
) -> Result<()> {
    let mut command = std::process::Command::new("ffmpeg");
    command.arg("-y");
    command.arg("-i").arg(input);
    if output_ext == "mp4" {
        command.arg("-movflags").arg("use_metadata_tags");
    }
    for (key, value) in metadata {
        command.arg("-metadata").arg(format!("{}={}", key, value));
    }
    command.arg("-c").arg("copy").arg(output);
    let status = command
        .status()
        .context("Failed to invoke ffmpeg for container remux")?;
    if !status.success() {
        return Err(anyhow!("ffmpeg failed with status {}", status));
    }
    Ok(())
}

fn clip_command(
    input: PathBuf,
    key_path: PathBuf,
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
                    display_name: None,
                },
                signmedia::models::SignatureEntry {
                    signature: hex::encode(ttp_signature.to_bytes()),
                    public_key: crypto::get_ttp_public_key(),
                    display_name: Some(ttp_display_name()),
                },
            ],
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
                display_name: None,
            },
            signmedia::models::SignatureEntry {
                signature: hex::encode(ttp_signature.to_bytes()),
                public_key: crypto::get_ttp_public_key(),
                display_name: Some(ttp_display_name()),
            },
        ],
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

struct TrackPlaybackInfo {
    codec: String,
    codec_extradata: Option<Vec<u8>>,
    width: Option<u32>,
    height: Option<u32>,
    sample_rate: Option<u32>,
    channels: Option<u16>,
    timebase_num: Option<u32>,
    timebase_den: Option<u32>,
}

fn chunk_media(
    reader: &mut impl Read,
    max_chunk_size: u64,
) -> Result<(Vec<ChunkWithMeta>, TrackPlaybackInfo)> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    if let Some(info) = parse_adts_frames(&data) {
        let chunks = group_adts_frames(&data, &info.frames, max_chunk_size);
        let codec_extradata = build_aac_extradata(
            info.audio_object_type,
            info.sample_rate_index,
            info.channel_config,
        );
        return Ok((
            chunks,
            TrackPlaybackInfo {
                codec: "aac".to_string(),
                codec_extradata: Some(codec_extradata),
                width: None,
                height: None,
                sample_rate: Some(info.sample_rate),
                channels: info.channel_config.and_then(|channels| {
                    if channels == 0 {
                        None
                    } else {
                        Some(channels)
                    }
                }),
                timebase_num: Some(1),
                timebase_den: Some(1_000_000),
            },
        ));
    }
    if let Some(info) = parse_annexb_nals(&data) {
        let chunks = group_nals(&data, &info.nals, max_chunk_size);
        return Ok((
            chunks,
            TrackPlaybackInfo {
                codec: "h264".to_string(),
                codec_extradata: info.codec_extradata,
                width: info.width,
                height: info.height,
                sample_rate: None,
                channels: None,
                timebase_num: info.timebase_num,
                timebase_den: info.timebase_den,
            },
        ));
    }
    Ok((
        fallback_chunking(&data, max_chunk_size),
        TrackPlaybackInfo {
            codec: "raw".to_string(),
            codec_extradata: None,
            width: None,
            height: None,
            sample_rate: None,
            channels: None,
            timebase_num: None,
            timebase_den: None,
        },
    ))
}

struct AdtsParseInfo {
    frames: Vec<(usize, usize, i64)>,
    sample_rate: u32,
    sample_rate_index: u8,
    channel_config: Option<u16>,
    audio_object_type: u8,
}

fn parse_adts_frames(data: &[u8]) -> Option<AdtsParseInfo> {
    let sample_rates = [
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
    ];
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut pts_us = 0i64;
    let mut sample_rate = None;
    let mut sample_rate_index = None;
    let mut channel_config = None;
    let mut audio_object_type = None;
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
        let profile = (data[offset + 2] & 0xC0) >> 6;
        let audio_object = profile + 1;
        let sr_index = ((data[offset + 2] & 0x3C) >> 2) as usize;
        let sr = sample_rates.get(sr_index).copied()?;
        let channel_cfg =
            (((data[offset + 2] & 0x01) as u16) << 2) | (((data[offset + 3] & 0xC0) as u16) >> 6);
        sample_rate_index.get_or_insert(sr_index as u8);
        sample_rate.get_or_insert(sr);
        if sample_rate != Some(sr) {
            return None;
        }
        channel_config.get_or_insert(channel_cfg);
        if channel_config != Some(channel_cfg) {
            return None;
        }
        audio_object_type.get_or_insert(audio_object);
        if audio_object_type != Some(audio_object) {
            return None;
        }
        frames.push((offset, frame_length, pts_us));
        pts_us += (1_000_000i64 * 1024) / sr as i64;
        offset += frame_length;
    }
    if offset != data.len() || frames.is_empty() {
        None
    } else {
        Some(AdtsParseInfo {
            frames,
            sample_rate: sample_rate?,
            sample_rate_index: sample_rate_index?,
            channel_config,
            audio_object_type: audio_object_type?,
        })
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

struct AnnexbParseInfo {
    nals: Vec<AnnexbNal>,
    codec_extradata: Option<Vec<u8>>,
    width: Option<u32>,
    height: Option<u32>,
    timebase_num: Option<u32>,
    timebase_den: Option<u32>,
}

struct AnnexbNal {
    start: usize,
    end: usize,
    is_idr: bool,
    pts: Option<i64>,
}

fn parse_annexb_nals(data: &[u8]) -> Option<AnnexbParseInfo> {
    if looks_like_isobmff(data) {
        return None;
    }
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
    let mut sps = None;
    let mut pps = None;
    let mut current_pts = 0i64;
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
        if (1..=5).contains(&nal_type) {
            let pts = current_pts;
            current_pts = current_pts.saturating_add(1);
            nals.push(AnnexbNal {
                start,
                end,
                is_idr,
                pts: Some(pts),
            });
        } else {
            nals.push(AnnexbNal {
                start,
                end,
                is_idr,
                pts: Some(current_pts),
            });
        }
        match nal_type {
            7 => {
                if sps.is_none() {
                    sps = Some(data[start + code_len..end].to_vec());
                }
            }
            8 => {
                if pps.is_none() {
                    pps = Some(data[start + code_len..end].to_vec());
                }
            }
            _ => {}
        }
    }
    if nals.is_empty() {
        None
    } else {
        let (codec_extradata, width, height, timebase_num, timebase_den) =
            match (sps.as_deref(), pps.as_deref()) {
                (Some(sps_bytes), Some(pps_bytes)) => {
                    let extradata = build_avcc_extradata(sps_bytes, pps_bytes);
                    let (width, height) = parse_h264_sps_dimensions(sps_bytes).unwrap_or((0, 0));
                    let timing = parse_h264_sps_timing(sps_bytes);
                    let (timebase_num, timebase_den) = timing
                        .map(|(num, den)| (Some(num), Some(den)))
                        .unwrap_or((None, None));
                    (
                        Some(extradata),
                        if width == 0 { None } else { Some(width) },
                        if height == 0 { None } else { Some(height) },
                        timebase_num,
                        timebase_den,
                    )
                }
                _ => (None, None, None, None, None),
            };
        Some(AnnexbParseInfo {
            nals,
            codec_extradata,
            width,
            height,
            timebase_num,
            timebase_den,
        })
    }
}

fn looks_like_isobmff(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let box_type = &data[4..8];
    if !box_type.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    if matches!(
        box_type,
        b"ftyp"
            | b"moov"
            | b"moof"
            | b"mdat"
            | b"free"
            | b"skip"
            | b"wide"
            | b"uuid"
            | b"jumb"
            | b"meta"
    ) {
        return true;
    }
    let scan_len = data.len().min(4096);
    let mut offset = 0usize;
    while offset + 8 <= scan_len {
        let size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let kind = &data[offset + 4..offset + 8];
        if matches!(
            kind,
            b"ftyp" | b"moov" | b"moof" | b"mdat" | b"jumb" | b"meta"
        ) {
            return true;
        }
        if size < 8 || size > scan_len - offset {
            break;
        }
        offset += size;
    }
    false
}

fn group_nals(data: &[u8], nals: &[AnnexbNal], max_chunk_size: u64) -> Vec<ChunkWithMeta> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_pts = None;
    for nal in nals {
        let nal_len = nal.end - nal.start;
        if nal.is_idr && !current.is_empty() {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: current_pts.take(),
            });
        }
        if !current.is_empty() && current.len() as u64 + nal_len as u64 > max_chunk_size {
            chunks.push(ChunkWithMeta {
                data: std::mem::take(&mut current),
                pts: current_pts.take(),
            });
        }
        if current.is_empty() {
            current_pts = nal.pts;
        }
        current.extend_from_slice(&data[nal.start..nal.end]);
    }
    if !current.is_empty() {
        chunks.push(ChunkWithMeta {
            data: current,
            pts: current_pts,
        });
    }
    chunks
}

fn build_aac_extradata(
    audio_object_type: u8,
    sample_rate_index: u8,
    channel_config: Option<u16>,
) -> Vec<u8> {
    let channel_config = channel_config.unwrap_or(0) as u8;
    let packed = ((audio_object_type & 0x1F) as u16) << 11
        | ((sample_rate_index & 0x0F) as u16) << 7
        | ((channel_config & 0x0F) as u16) << 3;
    vec![(packed >> 8) as u8, packed as u8]
}

fn build_avcc_extradata(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let profile_idc = sps.get(1).copied().unwrap_or(0);
    let compatibility = sps.get(2).copied().unwrap_or(0);
    let level_idc = sps.get(3).copied().unwrap_or(0);
    let mut extradata = Vec::new();
    extradata.push(1); // configurationVersion
    extradata.push(profile_idc);
    extradata.push(compatibility);
    extradata.push(level_idc);
    extradata.push(0xFF); // lengthSizeMinusOne (4 bytes)
    extradata.push(0xE1); // numOfSequenceParameterSets = 1
    extradata.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    extradata.extend_from_slice(sps);
    extradata.push(1); // numOfPictureParameterSets = 1
    extradata.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    extradata.extend_from_slice(pps);
    extradata
}

fn parse_h264_sps_dimensions(sps: &[u8]) -> Option<(u32, u32)> {
    if sps.len() < 4 {
        return None;
    }
    let rbsp = remove_emulation_prevention_bytes(&sps[1..]);
    let mut reader = BitReader::new(&rbsp);
    let profile_idc = reader.read_bits(8)? as u8;
    reader.read_bits(8)?;
    reader.read_bits(8)?;
    reader.read_ue()?;
    let mut chroma_format_idc = 1u32;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134
    ) {
        chroma_format_idc = reader.read_ue()?;
        if chroma_format_idc == 3 {
            reader.read_bits(1)?;
        }
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_bits(1)?;
        let seq_scaling_matrix_present_flag = reader.read_bits(1)?;
        if seq_scaling_matrix_present_flag == 1 {
            let scaling_list_count = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..scaling_list_count {
                let scaling_list_present = reader.read_bits(1)?;
                if scaling_list_present == 1 {
                    skip_scaling_list(&mut reader, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    reader.read_ue()?;
    let pic_order_cnt_type = reader.read_ue()?;
    if pic_order_cnt_type == 0 {
        reader.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        reader.read_bits(1)?;
        reader.read_se()?;
        reader.read_se()?;
        let num_ref_frames_in_pic_order_cnt_cycle = reader.read_ue()?;
        for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
            reader.read_se()?;
        }
    }
    reader.read_ue()?;
    reader.read_bits(1)?;
    let pic_width_in_mbs_minus1 = reader.read_ue()?;
    let pic_height_in_map_units_minus1 = reader.read_ue()?;
    let frame_mbs_only_flag = reader.read_bits(1)?;
    if frame_mbs_only_flag == 0 {
        reader.read_bits(1)?;
    }
    reader.read_bits(1)?;
    let frame_cropping_flag = reader.read_bits(1)?;
    let mut frame_crop_left = 0u32;
    let mut frame_crop_right = 0u32;
    let mut frame_crop_top = 0u32;
    let mut frame_crop_bottom = 0u32;
    if frame_cropping_flag == 1 {
        frame_crop_left = reader.read_ue()?;
        frame_crop_right = reader.read_ue()?;
        frame_crop_top = reader.read_ue()?;
        frame_crop_bottom = reader.read_ue()?;
    }
    let width = (pic_width_in_mbs_minus1 + 1) * 16;
    let mut height = (pic_height_in_map_units_minus1 + 1) * 16;
    if frame_mbs_only_flag == 0 {
        height *= 2;
    }
    let crop_unit_x = match chroma_format_idc {
        0 | 3 => 1,
        _ => 2,
    };
    let crop_unit_y = match chroma_format_idc {
        0 | 3 => 2 - frame_mbs_only_flag,
        _ => 2 * (2 - frame_mbs_only_flag),
    };
    let width = width.saturating_sub((frame_crop_left + frame_crop_right) * crop_unit_x);
    let height = height.saturating_sub((frame_crop_top + frame_crop_bottom) * crop_unit_y);
    Some((width, height))
}

fn parse_h264_sps_timing(sps: &[u8]) -> Option<(u32, u32)> {
    if sps.len() < 4 {
        return None;
    }
    let rbsp = remove_emulation_prevention_bytes(&sps[1..]);
    let mut reader = BitReader::new(&rbsp);
    let profile_idc = reader.read_bits(8)? as u8;
    reader.read_bits(8)?;
    reader.read_bits(8)?;
    reader.read_ue()?;
    let mut chroma_format_idc = 1u32;
    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134
    ) {
        chroma_format_idc = reader.read_ue()?;
        if chroma_format_idc == 3 {
            reader.read_bits(1)?;
        }
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_bits(1)?;
        let seq_scaling_matrix_present_flag = reader.read_bits(1)?;
        if seq_scaling_matrix_present_flag == 1 {
            let scaling_list_count = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..scaling_list_count {
                let scaling_list_present = reader.read_bits(1)?;
                if scaling_list_present == 1 {
                    skip_scaling_list(&mut reader, if i < 6 { 16 } else { 64 })?;
                }
            }
        }
    }
    reader.read_ue()?;
    let pic_order_cnt_type = reader.read_ue()?;
    if pic_order_cnt_type == 0 {
        reader.read_ue()?;
    } else if pic_order_cnt_type == 1 {
        reader.read_bits(1)?;
        reader.read_se()?;
        reader.read_se()?;
        let num_ref_frames_in_pic_order_cnt_cycle = reader.read_ue()?;
        for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
            reader.read_se()?;
        }
    }
    reader.read_ue()?;
    reader.read_bits(1)?;
    reader.read_ue()?;
    reader.read_ue()?;
    let frame_mbs_only_flag = reader.read_bits(1)?;
    if frame_mbs_only_flag == 0 {
        reader.read_bits(1)?;
    }
    reader.read_bits(1)?;
    let frame_cropping_flag = reader.read_bits(1)?;
    if frame_cropping_flag == 1 {
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_ue()?;
        reader.read_ue()?;
    }
    let vui_parameters_present_flag = reader.read_bits(1)?;
    if vui_parameters_present_flag == 0 {
        return None;
    }
    let aspect_ratio_info_present_flag = reader.read_bits(1)?;
    if aspect_ratio_info_present_flag == 1 {
        let aspect_ratio_idc = reader.read_bits(8)?;
        if aspect_ratio_idc == 255 {
            reader.read_bits(16)?;
            reader.read_bits(16)?;
        }
    }
    let overscan_info_present_flag = reader.read_bits(1)?;
    if overscan_info_present_flag == 1 {
        reader.read_bits(1)?;
    }
    let video_signal_type_present_flag = reader.read_bits(1)?;
    if video_signal_type_present_flag == 1 {
        reader.read_bits(3)?;
        reader.read_bits(1)?;
        let colour_description_present_flag = reader.read_bits(1)?;
        if colour_description_present_flag == 1 {
            reader.read_bits(8)?;
            reader.read_bits(8)?;
            reader.read_bits(8)?;
        }
    }
    let chroma_loc_info_present_flag = reader.read_bits(1)?;
    if chroma_loc_info_present_flag == 1 {
        reader.read_ue()?;
        reader.read_ue()?;
    }
    let timing_info_present_flag = reader.read_bits(1)?;
    if timing_info_present_flag == 0 {
        return None;
    }
    let num_units_in_tick = reader.read_bits(32)?;
    let time_scale = reader.read_bits(32)?;
    let _fixed_frame_rate_flag = reader.read_bits(1)?;
    if num_units_in_tick == 0 || time_scale == 0 {
        return None;
    }
    let timebase_num = num_units_in_tick.saturating_mul(2);
    Some((timebase_num, time_scale))
}

fn remove_emulation_prevention_bytes(data: &[u8]) -> Vec<u8> {
    let mut cleaned = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + 2 < data.len() && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 3 {
            cleaned.push(0);
            cleaned.push(0);
            i += 3;
            continue;
        }
        cleaned.push(data[i]);
        i += 1;
    }
    cleaned
}

struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn read_bits(&mut self, count: usize) -> Option<u32> {
        let mut value = 0u32;
        for _ in 0..count {
            value <<= 1;
            value |= self.read_bit()? as u32;
        }
        Some(value)
    }

    fn read_bit(&mut self) -> Option<u8> {
        let byte_pos = self.bit_pos / 8;
        if byte_pos >= self.data.len() {
            return None;
        }
        let bit_offset = 7 - (self.bit_pos % 8);
        let bit = (self.data[byte_pos] >> bit_offset) & 1;
        self.bit_pos += 1;
        Some(bit)
    }

    fn read_ue(&mut self) -> Option<u32> {
        let mut zeros = 0usize;
        while self.read_bit()? == 0 {
            zeros += 1;
        }
        let mut value = 0u32;
        if zeros > 0 {
            value = self.read_bits(zeros)?;
        }
        Some((1u32 << zeros) - 1 + value)
    }

    fn read_se(&mut self) -> Option<i32> {
        let code_num = self.read_ue()? as i32;
        let sign = if code_num % 2 == 0 { -1 } else { 1 };
        Some(((code_num + 1) / 2) * sign)
    }
}

fn skip_scaling_list(reader: &mut BitReader<'_>, size: usize) -> Option<()> {
    let mut last_scale = 8i32;
    let mut next_scale = 8i32;
    for _ in 0..size {
        if next_scale != 0 {
            let delta_scale = reader.read_se()?;
            next_scale = (last_scale + delta_scale + 256) % 256;
        }
        last_scale = if next_scale == 0 {
            last_scale
        } else {
            next_scale
        };
    }
    Some(())
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
