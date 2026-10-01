use signmedia::c2pa_backend::{build_c2pa_manifest_for_dwd, build_c2pa_manifest_for_owd};
use signmedia::models::{AuthorMetadata, DerivativeWorkDescriptor, OriginalWorkDescriptor};
use chrono::Utc;
use uuid::Uuid;

#[test]
fn test_c2pa_mapping_owd_dwd() -> anyhow::Result<()> {
    let owd = OriginalWorkDescriptor {
        work_id: Uuid::new_v4(),
        title: "Original Media".to_string(),
        authors: vec![AuthorMetadata {
            author_id: "author_key".to_string(),
            name: "Alice".to_string(),
            role: "author".to_string(),
        }],
        authorship_fingerprint: None,
        created_at: Utc::now(),
        tracks: vec![],
    };

    let builder_owd = build_c2pa_manifest_for_owd(&owd)?;

    let dwd = DerivativeWorkDescriptor {
        derivative_id: Uuid::new_v4(),
        original_owd: owd,
        original_signature: "sig123".to_string(),
        ancestry: vec![],
        clipper_id: "clipper_key".to_string(),
        authorship_fingerprint: None,
        created_at: Utc::now(),
        clip_mappings: vec![],
    };

    let builder_dwd = build_c2pa_manifest_for_dwd(&dwd, None)?;

    Ok(())
}
