use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use signmedia::container::{SmedReader, SmedWriter};
use signmedia::crypto::{self, MerkleTree};
use signmedia::models::{ManifestContent, OriginalWorkDescriptor, SignedManifest, TrackMetadata};
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
        /// Chunk size in bytes
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
    chunk_size: u64,
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

    loop {
        let mut buffer = vec![0u8; chunk_size as usize];
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        buffer.truncate(n);
        if first_chunk_data.is_none() {
            first_chunk_data = Some(buffer.clone());
        }
        chunk_hashes.push(crypto::hash_data(&buffer));
        chunks.push(buffer);
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
            chunk_size,
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
    writer.write_all(&manifest, &chunks)?;

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
                let data_size = file_len - reader.data_start();
                for i in 0..track.total_chunks {
                    let offset = i * track.chunk_size;
                    let size = if offset + track.chunk_size > data_size {
                        data_size - offset
                    } else {
                        track.chunk_size
                    };
                    let chunk = reader.read_variable_chunk(offset, size)?;
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
            for mapping in &dwd.clip_mappings {
                println!(
                    "Verifying clip mapping for track {} (chunks {} to {})...",
                    mapping.track_id, mapping.start_chunk_index, mapping.end_chunk_index
                );

                for proof in &mapping.proofs {
                    let chunk = reader.read_variable_chunk(current_offset, proof.chunk_size)?;
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
                    current_offset += proof.chunk_size;
                }
            }
            if reader.data_start() + current_offset != file_len {
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

    let (track_id, total_chunks, chunk_size_orig) = {
        let track = &original_owd.tracks[0];
        (track.track_id, track.total_chunks, track.chunk_size)
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
        for (index, proof) in existing_proofs.iter().enumerate() {
            let proof_index = index as u64;
            let size = proof.chunk_size;
            if current_offset + size > data_size {
                return Err(anyhow!(
                    "Unexpected end of data while reading derivative chunks"
                ));
            }
            if proof_index >= start && proof_index < end {
                let chunk = reader.read_variable_chunk(current_offset, size)?;
                clip_chunks.push(chunk);
                proofs.push(proof.clone());
            }
            current_offset += size;
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

        let out_file = fs::File::create(&output)?;
        let mut writer = SmedWriter::new(out_file);
        writer.write_all(&manifest, &clip_chunks)?;

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
    let data_size = file_len - reader.data_start();
    for i in 0..total_chunks {
        let offset = i * chunk_size_orig;
        let size = if offset + chunk_size_orig > data_size {
            data_size - offset
        } else {
            chunk_size_orig
        };
        let chunk = reader.read_variable_chunk(offset, size)?;
        original_hashes.push(crypto::hash_data(&chunk));
    }
    let original_tree = MerkleTree::new(original_hashes);

    for i in start..end {
        let offset = i * chunk_size_orig;
        let size = if offset + chunk_size_orig > data_size {
            data_size - offset
        } else {
            chunk_size_orig
        };
        let chunk = reader.read_variable_chunk(offset, size)?;
        clip_chunks.push(chunk);
        let mut proof = original_tree.generate_proof(i as usize);
        proof.chunk_size = size;
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

    let out_file = fs::File::create(&output)?;
    let mut writer = SmedWriter::new(out_file);
    writer.write_all(&manifest, &clip_chunks)?;

    println!("Successfully created clip: {:?}", output);
    Ok(())
}
