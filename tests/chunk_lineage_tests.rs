use signmedia::c2pa_backend::{
    add_chunk_lineage_assertion, verify_chunk_lineage_assertion, ChunkLineageAssertion,
};
use signmedia::crypto::{hash_data, MerkleTree};
use c2pa::Builder;

#[test]
fn test_chunk_lineage_assertion_roundtrip() -> anyhow::Result<()> {
    let leaves = vec![hash_data(b"chunk0"), hash_data(b"chunk1")];
    let tree = MerkleTree::new(leaves);
    let root = tree.root();
    let proof0 = tree.generate_proof(0, None);

    let assertion = ChunkLineageAssertion {
        parent_work_id: uuid::Uuid::nil().to_string(),
        track_id: 0,
        start_chunk_index: 0,
        end_chunk_index: 1,
        merkle_root: hex::encode(root),
        proofs: vec![proof0],
    };

    assert!(verify_chunk_lineage_assertion(&assertion)?);

    let mut builder = Builder::from_json(r#"{"claim_generator": "SignMedia/0.1.0"}"#)?;
    add_chunk_lineage_assertion(&mut builder, &assertion)?;

    Ok(())
}
