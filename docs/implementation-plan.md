# SignMedia Standards Alignment Implementation Plan

This document outlines the step-by-step technical plan to evolve SignMedia into a C2PA-compliant provenance engine with chunk-level lineage, configurable trust, decoded visual fingerprinting, archival packaging, capture attestation, and experimental post-quantum evidence.

## Execution Phases & Dependency Mapping

1. **Phase 0 (#22)**: Freeze SMED v1/v2 & Publish Format Specification
2. **Phase 1 (#23)**: Introduce Format-Independent Provenance Model & Shared Validation
3. **Phase 9 (#24)**: Separate Capture, Authorship, Edit, and Publication Claims
4. **Phase 11 (#25)**: Version & Harden Chunk Commitments & Merkle Verification
5. **Phase 2 (#26)**: Integrate Official C2PA Rust SDK & CLI Commands (`c2pa-sign`, `c2pa-verify`, `inspect`)
6. **Phase 5 (#27)**: Configurable Credentials & Trust Policy
7. **Phase 3 (#28)**: Map OWD/DWD Lineage into C2PA Ingredients & Actions
8. **Phase 4 (#29)**: Define & Verify SignMedia C2PA Chunk-Lineage Assertion
9. **Phase 6 (#30)**: Validated RFC 3161 Timestamp Evidence & Optional Capture Bounds
10. **Phase 7 (#31)**: Certificate/Evidence Revocation & Historical Validation Policy
11. **Phase 10 (#32)**: Decoded-Content Visual Fingerprints
12. **Phase 13 (#33)**: Archival Package (.smed Profile)
13. **Phase 8 (#34)**: Capture Attestation Profiles & Hardware Prototype
14. **Phase 12 (#35)**: Supplemental Post-Quantum Archival Evidence
15. **Phase 14 (#36)**: Interoperability/Conformance Suite & Submission Readiness
