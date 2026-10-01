use signmedia::crypto::{MerkleTreeV2, verify_proof_v2};
use signmedia::models::{MerkleProof, ProofStep};

#[test]
fn test_merkle_v2_domain_separation_and_validation() {
    let chunks: Vec<&[u8]> = vec![b"chunk1", b"chunk2", b"chunk3"];
    let tree = MerkleTreeV2::new(0, &chunks);
    let root = tree.root();

    assert_ne!(root, [0u8; 32]);

    let invalid_proof = MerkleProof {
        chunk_index: 0,
        hash: "invalid_hex".to_string(),
        path: vec![],
        chunk_size: 6,
        pts: None,
    };
    assert!(!verify_proof_v2(root, &invalid_proof));

    let oversized_path_proof = MerkleProof {
        chunk_index: 0,
        hash: hex::encode([1u8; 32]),
        path: vec![
            ProofStep {
                is_left: false,
                hash: hex::encode([2u8; 32]),
            };
            65
        ],
        chunk_size: 6,
        pts: None,
    };
    assert!(!verify_proof_v2(root, &oversized_path_proof));
}

#[test]
fn test_merkle_v2_empty_tree() {
    let chunks: Vec<&[u8]> = vec![];
    let tree = MerkleTreeV2::new(0, &chunks);
    let root = tree.root();
    assert_ne!(root, [0u8; 32]);
}
