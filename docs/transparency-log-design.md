# SignMedia Transparency Log Design

This document specifies the append-only transparency log architecture for SignMedia claims and revocations.

## Architecture
- **Merkle Tree Log**: All published manifests and revocation entries are appended to a binary BLAKE3 Merkle tree log.
- **Inclusion Proofs**: Clients verify log inclusion via standard Merkle audit paths.
- **Consistency Proofs**: Log servers provide consistency proofs between tree size $N_1$ and $N_2$.
