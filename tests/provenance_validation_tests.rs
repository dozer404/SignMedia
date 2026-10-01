use signmedia::crypto::{generate_keypair, hash_data, sign};
use signmedia::models::{
    AuthorMetadata, ManifestContent, OriginalWorkDescriptor, SignatureEntry, SignedManifest,
};
use signmedia::provenance::{validate_signed_manifest, IntegrityStatus};
use chrono::Utc;

#[test]
fn test_provenance_validation_valid_and_invalid() -> anyhow::Result<()> {
    let keypair = generate_keypair();
    let author_pubkey = hex::encode(keypair.verifying_key().to_bytes());

    let owd = OriginalWorkDescriptor {
        work_id: uuid::Uuid::new_v4(),
        title: "Test Asset".to_string(),
        authors: vec![AuthorMetadata {
            author_id: author_pubkey.clone(),
            name: "Alice".to_string(),
            role: "author".to_string(),
        }],
        authorship_fingerprint: None,
        created_at: Utc::now(),
        tracks: vec![],
    };

    let content = ManifestContent::Original(owd);
    let content_json = serde_json::to_vec(&content)?;
    let content_hash = hash_data(&content_json);
    let sig = sign(&content_hash, &keypair);

    let mut manifest = SignedManifest {
        content,
        signatures: vec![SignatureEntry {
            signature: hex::encode(sig.to_bytes()),
            public_key: author_pubkey,
            display_name: Some("Alice".to_string()),
        }],
    };

    let report = validate_signed_manifest(&manifest);
    assert_eq!(report.content_integrity, IntegrityStatus::Verified);

    // One valid signature plus a malformed second signature must fail verification
    let mut manifest_with_malformed_second_sig = manifest.clone();
    manifest_with_malformed_second_sig.signatures.push(SignatureEntry {
        signature: "invalid_hex_signature".to_string(),
        public_key: hex::encode([1u8; 32]),
        display_name: Some("Bob".to_string()),
    });
    let report2 = validate_signed_manifest(&manifest_with_malformed_second_sig);
    assert_eq!(report2.content_integrity, IntegrityStatus::Invalid);

    // Tamper signature
    manifest.signatures[0].signature = hex::encode([0u8; 64]);
    let tampered_report = validate_signed_manifest(&manifest);
    assert_eq!(tampered_report.content_integrity, IntegrityStatus::Invalid);

    Ok(())
}
