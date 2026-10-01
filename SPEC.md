# SignMedia (.smed) Format Specification

## Version 1 and Version 2 Specification

This specification defines the physical layout, serialization, schema, and cryptographic conventions for SignMedia (`.smed`) v1 and v2 containers.

---

## 1. Binary Container Layout

All integer fields in header and section structures are stored in **little-endian** byte order.

### 1.1 Header

| Offset (Bytes) | Field Name | Type | Description |
| --- | --- | --- | --- |
| `0x00 .. 0x04` | `magic` | `[u8; 4]` | Fixed ASCII magic bytes: `b"SMED"` (`0x53 0x4D 0x45 0x44`) |
| `0x04 .. 0x08` | `version` | `u32` | Container version (`1` for Legacy v1, `2` for Sectioned v2) |

---

### 1.2 Legacy Container (Version 1)

In Version 1, the manifest JSON is written immediately after the header length, followed directly by concatenated media chunks.

```
+-------------------+-------------------+-------------------+-----------------------+
| Magic ("SMED")    | Version (u32 = 1) | Manifest Len (u64)| SignedManifest (JSON) | ... Track Payload
+-------------------+-------------------+-------------------+-----------------------+
```

1. **Manifest Length**: `u64` (little-endian) representing the byte count of the UTF-8 JSON payload.
2. **Manifest Payload**: JSON serialization of `SignedManifest`.
3. **Track Payload Data**: Concatenated raw binary chunk data without section framing.

---

### 1.3 Sectioned Container (Version 2)

Version 2 defines a repeated stream of section headers and payload blocks following the magic and version header.

```
+-------------------+-------------------+-------------------+--------------------+ ...
| Magic ("SMED")    | Version (u32 = 2) | Section Header    | Section Payload    |
+-------------------+-------------------+-------------------+--------------------+
```

#### Section Header Format

| Field Name | Type | Description |
| --- | --- | --- |
| `section_type` | `u32` | Identifier for payload structure |
| `length` | `u64` | Byte length of payload |

#### Defined Section Types

| Type ID | Name | Description |
| --- | --- | --- |
| `1` | `MANIFEST` | `SignedManifest` serialized as UTF-8 JSON |
| `2` | `TRACK_DATA` | Concatenated raw media chunk binary payloads |
| `3` | `TRACK_TABLE` | Binary table defining tracks and chunk metadata |
| `4` | `INDEX_DATA` | Binary index mapping chunks to byte offsets and PTS |
| `5` | `EXTRA_METADATA` | Reserved for supplemental metadata |

#### Standard Section Writer Order
1. Section 1 (`MANIFEST`)
2. Section 3 (`TRACK_TABLE`)
3. Section 4 (`INDEX_DATA`)
4. Section 2 (`TRACK_DATA`)

Unknown sections (`type > 5` or unhandled) MUST be skipped by readers using the payload `length`.

---

## 2. Binary Metadata Payload Encoding

### 2.1 Track Table Payload (Section Type 3)

| Field Name | Type | Description |
| --- | --- | --- |
| `count` | `u32` | Number of track entries |
| *Repeated per track*: | | |
| `track_id` | `u32` | Unique track identifier |
| `codec_len` | `u32` | Byte length of UTF-8 codec name |
| `codec` | `[u8; codec_len]` | UTF-8 codec string (e.g., `"H264"`, `"H265"`, `"AAC"`, `"raw"`) |
| `total_chunks` | `u64` | Total number of chunks in track |
| `chunk_size` | `u64` | Fixed chunk size in bytes (or 0 for variable) |
| `chunk_index_count` | `u64` | Number of indexed chunk entries |

### 2.2 Index Data Payload (Section Type 4)

| Field Name | Type | Description |
| --- | --- | --- |
| `count` | `u64` | Number of index entries |
| *Repeated per chunk*: | | |
| `track_id` | `u32` | Track identifier |
| `chunk_index` | `u64` | Zero-based chunk index within track |
| `pts` | `i64` | Presentation Time Stamp (or `i64::MIN` if None) |
| `offset` | `u64` | Byte offset relative to start of `TRACK_DATA` payload |
| `size` | `u64` | Byte length of chunk |

---

## 3. Manifest JSON Schemas & Signatures

### 3.1 Serialization
- Manifests are formatted as UTF-8 JSON using `serde_json`.
- `ManifestContent` is tagged using `"type"`: `"Original"` or `"Derivative"`.

### 3.2 Signature Input & Calculation
Signature input bytes are computed as:
$$\text{SignatureInput} = \text{BLAKE3}(\text{serde\_json::to\_vec}(\text{content}))$$

For each required signer (Author, Clipper, TTP), an Ed25519 signature is computed over the 32-byte `SignatureInput`.

### 3.3 Authorship Fingerprint
Authorship fingerprints are computed as:
$$\text{AuthorshipFingerprint} = \text{hex}(\text{BLAKE3}(\text{concat}(\text{author\_id}, \text{name}, \text{role})))$$

---

## 4. Cryptographic Chunking & Merkle Trees (Legacy Profile v1)

1. **Leaf Hashes**: Each leaf is $\text{BLAKE3}(\text{chunk\_bytes})$.
2. **Internal Nodes**: $\text{BLAKE3}(\text{left\_hash} \parallel \text{right\_hash})$.
3. **Odd Leaves**: An odd node at any level is promoted to the parent level without rehashing.
4. **Empty Roots**: An empty leaf array produces a root of 32 zero bytes (`[0u8; 32]`).
