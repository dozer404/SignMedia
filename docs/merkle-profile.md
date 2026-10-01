# SignMedia Hardened Merkle Profile Specification (v2)

This document specifies the hardened Merkle Tree construction (`v2`) for SignMedia chunk commitments.

## 1. Domain Separation
To prevent second-preimage and leaf-vs-internal-node confusion attacks, `v2` enforces cryptographic domain prefixes:

- **Leaf Hash**:
  $$\text{LeafHash} = \text{BLAKE3}(\text{0x00} \parallel \text{track\_id (u32-LE)} \parallel \text{chunk\_index (u64-LE)} \parallel \text{chunk\_bytes})$$
- **Internal Node Hash**:
  $$\text{InternalHash} = \text{BLAKE3}(\text{0x01} \parallel \text{left\_child\_hash} \parallel \text{right\_child\_hash})$$
- **Empty Tree Root**:
  $$\text{EmptyRoot} = \text{BLAKE3}(\text{0x02} \parallel \text{"EMPTY\_TREE"})$$

## 2. Odd-Node Rule
If a level contains an odd number of nodes:
- The last node is promoted to the next level by hashing with a fixed prefix:
  $$\text{PromotedNode} = \text{BLAKE3}(\text{0x03} \parallel \text{node\_hash})$$

## 3. Proof Hardening and Validation Rules
1. **Hash Length Verification**: All proof hashes MUST decode to exactly 32 bytes; malformed hex inputs immediately fail proof verification without silent zero-padding.
2. **Path Depth Bounding**: Proof paths exceeding 64 levels MUST be rejected.
3. **Strict Range Checks**: Chunk index MUST be less than leaf count.
