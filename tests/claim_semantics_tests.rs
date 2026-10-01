use signmedia::crypto::{compute_authorship_fingerprint, compute_authorship_fingerprint_v2};
use signmedia::models::AuthorMetadata;
use signmedia::provenance::{
    ActorRef, AuthorshipClaim, CaptureClaim, EditClaim, PublicationClaim,
};
use chrono::Utc;

#[test]
fn test_typed_claims_semantics() {
    let actor = ActorRef {
        key_id: "key_123".to_string(),
        display_name: Some("Alice".to_string()),
        role: "author".to_string(),
    };

    let capture = CaptureClaim {
        actor: actor.clone(),
        captured_at: Utc::now(),
        device_info: Some("Camera X".to_string()),
    };

    let authorship = AuthorshipClaim {
        author: actor.clone(),
        statement: Some("Original creation".to_string()),
    };

    let edit = EditClaim {
        editor: actor.clone(),
        edit_action: "clip".to_string(),
    };

    let publication = PublicationClaim {
        publisher: actor,
        publication_url: Some("https://example.com/asset".to_string()),
    };

    assert_eq!(capture.actor.key_id, "key_123");
    assert_eq!(authorship.author.role, "author");
    assert_eq!(edit.edit_action, "clip");
    assert_eq!(
        publication.publication_url.as_deref(),
        Some("https://example.com/asset")
    );
}

#[test]
fn test_fingerprint_v2_field_boundaries() {
    let author_a = vec![
        AuthorMetadata {
            author_id: "a".to_string(),
            name: "bc".to_string(),
            role: "author".to_string(),
        },
    ];
    let author_b = vec![
        AuthorMetadata {
            author_id: "ab".to_string(),
            name: "c".to_string(),
            role: "author".to_string(),
        },
    ];

    // Legacy fingerprint has collision between "a" + "bc" and "ab" + "c"
    assert_eq!(
        compute_authorship_fingerprint(&author_a),
        compute_authorship_fingerprint(&author_b)
    );

    // v2 fingerprint differentiates field boundaries
    assert_ne!(
        compute_authorship_fingerprint_v2(&author_a),
        compute_authorship_fingerprint_v2(&author_b)
    );

    // Test delimiter collision in name/role fields (R10)
    let author_delim1 = vec![AuthorMetadata {
        author_id: "key_1".to_string(),
        name: "a\x1fb".to_string(),
        role: "c".to_string(),
    }];
    let author_delim2 = vec![AuthorMetadata {
        author_id: "key_1".to_string(),
        name: "a".to_string(),
        role: "b\x1fc".to_string(),
    }];

    assert_ne!(
        compute_authorship_fingerprint_v2(&author_delim1),
        compute_authorship_fingerprint_v2(&author_delim2)
    );
}
