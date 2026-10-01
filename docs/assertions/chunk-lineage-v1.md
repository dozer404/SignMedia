# SignMedia Chunk Lineage Assertion (org.signmedia.chunk-lineage.v1)

This specification defines the namespaced C2PA assertion `org.signmedia.chunk-lineage.v1` for embedding fine-grained media chunk Merkle proofs and timeline range mappings into standard C2PA Content Credentials.

## 1. Namespace
- **Label**: `org.signmedia.chunk-lineage.v1`
- **JSON Schema**: `schemas/chunk-lineage-v1.json`

## 2. Structure
- `parent_work_id`: `String` (UUID of original work)
- `track_id`: `u32` (Track index)
- `start_chunk_index`: `u64`
- `end_chunk_index`: `u64`
- `merkle_root`: `String` (Hex encoded Merkle root of original track)
- `proofs`: `Array` of Merkle proof objects
