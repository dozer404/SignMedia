use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use signmedia::crypto;
use signmedia::models::{
    AuthorMetadata, ManifestContent, OriginalWorkDescriptor, SignatureEntry, SignedManifest,
};
use uuid::Uuid;

#[test]
fn test_multi_signature_and_fingerprint() {
    let author_key = crypto::generate_keypair();
    let ttp_key = crypto::generate_keypair(); // We'll use a fresh one for this test

    let authors = vec![AuthorMetadata {
        author_id: hex::encode(author_key.verifying_key().to_bytes()),
        name: "Test Author".to_string(),
        role: "Creator".to_string(),
    }];

    let fingerprint = crypto::compute_authorship_fingerprint(&authors);

    let owd = OriginalWorkDescriptor {
        work_id: Uuid::new_v4(),
        title: "Test Work".to_string(),
        authors: authors.clone(),
        authorship_fingerprint: Some(fingerprint),
        created_at: Utc::now(),
        tracks: vec![],
    };

    let content = ManifestContent::Original(owd.clone());
    let content_json = serde_json::to_vec(&content).unwrap();
    let content_hash = crypto::hash_data(&content_json);

    let author_sig = crypto::sign(&content_hash, &author_key);
    let ttp_sig = crypto::sign(&content_hash, &ttp_key);

    let manifest = SignedManifest {
        content: content.clone(),
        signatures: vec![
            SignatureEntry {
                signature: hex::encode(author_sig.to_bytes()),
                public_key: hex::encode(author_key.verifying_key().to_bytes()),
                display_name: None,
            },
            SignatureEntry {
                signature: hex::encode(ttp_sig.to_bytes()),
                public_key: hex::encode(ttp_key.verifying_key().to_bytes()),
                display_name: None,
            },
        ],
    };

    // 1. Verify signatures manually (simulating what verify_command does)
    for sig_entry in &manifest.signatures {
        let pubkey_bytes = hex::decode(&sig_entry.public_key).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap()).unwrap();
        let sig_bytes = hex::decode(&sig_entry.signature).unwrap();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        assert!(crypto::verify_signature(
            &content_hash,
            &signature,
            &verifying_key
        ));
    }

    // 2. Verify fingerprint
    let actual_fingerprint = crypto::compute_authorship_fingerprint(&owd.authors);
    assert_eq!(
        owd.authorship_fingerprint.as_ref().unwrap(),
        &actual_fingerprint
    );

    // 3. Tamper with author name
    let mut tampered_owd = owd.clone();
    tampered_owd.authors[0].name = "Tampered Author".to_string();
    let tampered_actual_fingerprint = crypto::compute_authorship_fingerprint(&tampered_owd.authors);
    assert_ne!(
        owd.authorship_fingerprint.as_ref().unwrap(),
        &tampered_actual_fingerprint
    );
}

#[test]
fn test_derivative_fingerprint() {
    let clipper_key = crypto::generate_keypair();
    let clipper_id = hex::encode(clipper_key.verifying_key().to_bytes());
    let fingerprint = crypto::compute_derivative_fingerprint(&clipper_id);

    assert_ne!(fingerprint, "");
    assert_eq!(
        fingerprint,
        crypto::compute_derivative_fingerprint(&clipper_id)
    );
}
