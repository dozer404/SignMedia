# SignMedia C2PA Integration Profile

## Supported Specification & SDK
- **C2PA Specification Target**: C2PA v2.3
- **Rust SDK**: `c2pa` crate v0.36
- **MSRV**: Rust 1.75+
- **Crypto Backends**: OpenSSL / Ring (Standard C2PA COSE signatures)

## Supported File Formats
- **Images**: JPEG, PNG
- **Video**: MP4 / BMFF (ISO Base Media File Format)
- **Unsupported/Experimental**: WebM / MKV (C2PA hard-binding not supported natively by c2pa-rs for WebM container embedding)

## CLI Commands
- `c2pa-sign`: Inject/embed a C2PA Content Credentials manifest into JPEG, PNG, or MP4.
- `c2pa-verify`: Verify embedded C2PA Content Credentials and display manifest report.
- `inspect`: Detailed inspection of C2PA manifest store, assertions, and signatures.
