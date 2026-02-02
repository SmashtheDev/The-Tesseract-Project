# TESSERACT Vault Format Specification

This document provides a byte-level specification of the TESSERACT vault format, including the header, keystore, blob, and metadata file formats.

**Version:** 1.0
**Last Updated:** January 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Directory Structure](#2-directory-structure)
3. [Vault Header Format](#3-vault-header-format)
4. [Keystore Format](#4-keystore-format)
5. [Blob Format](#5-blob-format)
6. [Metadata Format](#6-metadata-format)
7. [Streaming Format](#7-streaming-format)
8. [Security Considerations](#8-security-considerations)
9. [Version Compatibility](#9-version-compatibility)

---

## 1. Overview

A TESSERACT vault is a directory structure containing encrypted files, metadata, and key material. The format is designed for:

- **Security**: AES-256-GCM authenticated encryption with per-file keys
- **Portability**: Self-contained structure that can reside on removable media
- **Integrity**: HMAC-SHA256 verification of all critical structures
- **Performance**: Fixed-size header (512 bytes) for efficient I/O

### Byte Ordering

All multi-byte integers are stored in **little-endian** format unless otherwise specified.

### Encoding

- UUIDs: 128-bit (16 bytes) in binary form (UUID bytes, not hex string)
- Timestamps: 64-bit unsigned Unix epoch (seconds since 1970-01-01 00:00:00 UTC)
- Strings: UTF-8 encoded, length-prefixed in bincode serialization

---

## 2. Directory Structure

```
vault/
├── vault.header              # 512-byte encrypted header
├── .keystores/               # Per-level encrypted key bundles
│   ├── L0.keys.enc           # Level 0 keystore
│   ├── L1.keys.enc           # Level 1 keystore
│   └── L2.keys.enc           # Level 2 keystore
├── .blobs/                   # Encrypted file contents
│   ├── {uuid1}.blob
│   └── {uuid2}.blob
├── .metadata/                # Encrypted file metadata
│   ├── {uuid1}.meta
│   └── {uuid2}.meta
├── .levels/                  # Access level configuration
│   └── levels.enc            # Encrypted level definitions
└── .recovery/                # Recovery key material (optional)
    └── recovery.blob         # Encrypted master key for recovery
```

### Directory Permissions

All directories should have restrictive permissions:
- Unix: `0700` (owner read/write/execute only)
- Windows: ACL restricted to current user

---

## 3. Vault Header Format

The vault header is a fixed-size 512-byte structure stored in `vault.header`.

### 3.1 Header Layout

| Offset | Size    | Field                | Description                              |
|--------|---------|----------------------|------------------------------------------|
| 0      | 8       | `magic`              | Magic bytes: `TESSERAC` (ASCII)          |
| 8      | 2       | `version`            | Format version (major, minor)            |
| 10     | 16      | `salt`               | Argon2id salt for key derivation         |
| 26     | 48      | `encrypted_master_key` | AES-256-GCM encrypted MK (32 + 16 tag) |
| 74     | 12      | `master_key_nonce`   | Nonce for master key encryption          |
| 86     | 4       | `attempt_counter`    | Failed authentication attempts           |
| 90     | 8       | `lockout_until`      | Unix timestamp for lockout expiry        |
| 98     | 8       | `created_at`         | Unix timestamp of vault creation         |
| 106    | 8       | `last_modified`      | Unix timestamp of last modification      |
| 114    | 32      | `hmac_tag`           | HMAC-SHA256 over bytes [0..114]          |
| 146    | 366     | `reserved`           | Reserved for future use (zeroed)         |

**Total size: 512 bytes**

### 3.2 Field Details

#### Magic Bytes (8 bytes)
```
Offset 0-7: 0x54 0x45 0x53 0x53 0x45 0x52 0x41 0x43 ("TESSERAC")
```
Used to identify valid TESSERACT vault files. If these bytes don't match, the file is not a valid vault header.

#### Version (2 bytes)
```
Offset 8:  major version (1 byte, currently 0x01)
Offset 9:  minor version (1 byte, currently 0x00)
```
Version compatibility is based on major version only. Minor version changes are backwards-compatible.

#### Salt (16 bytes)
```
Offset 10-25: Random 128-bit salt for Argon2id
```
Used with the password to derive the encryption key and HMAC key for the header.

#### Encrypted Master Key (48 bytes)
```
Offset 26-73: AES-256-GCM ciphertext (32 bytes) + authentication tag (16 bytes)
```
Contains the 256-bit master key encrypted with a key derived from the user's password.

**Key Derivation:**
```
encryption_key = Argon2id(password, salt XOR 0x01, m=65536, t=3, p=4)
hmac_key = Argon2id(password, salt XOR 0x02, m=65536, t=3, p=4)
```

**Encryption:**
```
encrypted_master_key = AES-256-GCM.Encrypt(
    key = encryption_key,
    nonce = master_key_nonce,
    plaintext = master_key,
    aad = "TESSERACT_MK_V1"
)
```

#### Master Key Nonce (12 bytes)
```
Offset 74-85: 96-bit nonce for AES-256-GCM
```
Randomly generated during vault creation. Never reused.

#### Attempt Counter (4 bytes)
```
Offset 86-89: 32-bit unsigned integer, little-endian
```
Incremented on each failed authentication attempt. Reset to 0 on successful authentication.

#### Lockout Until (8 bytes)
```
Offset 90-97: 64-bit unsigned Unix timestamp, little-endian
```
If current time < lockout_until, authentication attempts are blocked. Set to 0 when not locked out.

#### Created At (8 bytes)
```
Offset 98-105: 64-bit unsigned Unix timestamp, little-endian
```
Set once during vault creation, never modified.

#### Last Modified (8 bytes)
```
Offset 106-113: 64-bit unsigned Unix timestamp, little-endian
```
Updated whenever the vault structure changes (files added/removed, passwords changed).

#### HMAC Tag (32 bytes)
```
Offset 114-145: HMAC-SHA256 tag
```
Computed over bytes [0..114] using the HMAC key derived from the password.

**Verification:**
```
expected = HMAC-SHA256(hmac_key, header[0..114])
if expected != header[114..146]:
    return IntegrityError
```

#### Reserved (366 bytes)
```
Offset 146-511: Zero-filled, reserved for future extensions
```

---

## 4. Keystore Format

Each access level has its own keystore file: `.keystores/L{n}.keys.enc`

### 4.1 Keystore Layout

| Offset | Size      | Field             | Description                           |
|--------|-----------|-------------------|---------------------------------------|
| 0      | 2         | `version`         | Keystore format version               |
| 2      | 4         | `level_id`        | Access level identifier               |
| 6      | 48        | `encrypted_kek`   | KEK encrypted with ALK (32 + 16 tag)  |
| 54     | 12        | `kek_nonce`       | Nonce for KEK encryption              |
| 66     | 4         | `dek_count`       | Number of DEK entries                 |
| 70     | variable  | `dek_entries`     | Array of DEK entries                  |
| -32    | 32        | `hmac_tag`        | HMAC-SHA256 over all preceding data   |

**Fixed header size: 70 bytes**
**DEK entry size: 76 bytes each**
**Total size: 70 + (76 * dek_count) + 32 bytes**

### 4.2 Field Details

#### Version (2 bytes)
```
Offset 0: major version (1 byte, currently 0x01)
Offset 1: minor version (1 byte, currently 0x00)
```

#### Level ID (4 bytes)
```
Offset 2-5: 32-bit unsigned integer, little-endian
```
Identifies which access level this keystore belongs to (0, 1, 2, ...).

#### Encrypted KEK (48 bytes)
```
Offset 6-53: AES-256-GCM ciphertext (32 bytes) + tag (16 bytes)
```
The Key Encryption Key (KEK) encrypted with the Access Level Key (ALK).

**ALK Derivation:**
```
alk = Argon2id(level_password, level_salt, m=65536, t=3, p=4)
```

**KEK Encryption:**
```
encrypted_kek = AES-256-GCM.Encrypt(
    key = alk,
    nonce = kek_nonce,
    plaintext = kek,
    aad = level_id as bytes
)
```

#### KEK Nonce (12 bytes)
```
Offset 54-65: 96-bit nonce for AES-256-GCM
```

#### DEK Count (4 bytes)
```
Offset 66-69: 32-bit unsigned integer, little-endian
```
Number of DEK entries following this field.

### 4.3 DEK Entry Format

Each DEK entry is 76 bytes:

| Offset | Size | Field           | Description                          |
|--------|------|-----------------|--------------------------------------|
| 0      | 16   | `file_uuid`     | UUID of the file                     |
| 16     | 48   | `encrypted_dek` | DEK encrypted with KEK (32 + 16 tag) |
| 64     | 12   | `dek_nonce`     | Nonce for DEK encryption             |

**DEK Encryption:**
```
encrypted_dek = AES-256-GCM.Encrypt(
    key = kek,
    nonce = dek_nonce,
    plaintext = dek,
    aad = file_uuid as bytes
)
```

**DEK Ordering:**
DEK entries are sorted by UUID (binary comparison) for deterministic HMAC computation.

### 4.4 HMAC Tag (32 bytes)

Located at the end of the file:
```
hmac_tag = HMAC-SHA256(hmac_key, keystore[0..len-32])
```
Where `hmac_key` is derived from the level password similarly to the ALK.

---

## 5. Blob Format

Encrypted file contents are stored in `.blobs/{uuid}.blob`.

### 5.1 Blob Layout

```
+---------------+----------------------+----------+
| Nonce (12 B)  | Ciphertext (variable)| Tag (16B)|
+---------------+----------------------+----------+
```

| Offset | Size     | Field        | Description                    |
|--------|----------|--------------|--------------------------------|
| 0      | 12       | `nonce`      | AES-256-GCM nonce              |
| 12     | variable | `ciphertext` | Encrypted file content         |
| -16    | 16       | `tag`        | GCM authentication tag         |

**Minimum size: 28 bytes** (12 nonce + 0 content + 16 tag)

### 5.2 Encryption

```
blob_content = AES-256-GCM.Encrypt(
    key = dek,
    nonce = nonce,
    plaintext = file_content,
    aad = file_uuid as bytes
)
```

The AAD binds the blob to a specific file UUID, preventing blob substitution attacks.

### 5.3 File Naming

Blob files are named using the lowercase hyphenated UUID format:
```
550e8400-e29b-41d4-a716-446655440000.blob
```

---

## 6. Metadata Format

Encrypted file metadata is stored in `.metadata/{uuid}.meta`.

### 6.1 Metadata Layout

```
+------------+----------------------+----------+
| Nonce(12B) | Ciphertext (variable)| Tag(16B) |
+------------+----------------------+----------+
```

| Offset | Size     | Field        | Description                    |
|--------|----------|--------------|--------------------------------|
| 0      | 12       | `nonce`      | AES-256-GCM nonce              |
| 12     | variable | `ciphertext` | Encrypted bincode data         |
| -16    | 16       | `tag`        | GCM authentication tag         |

### 6.2 Plaintext Structure (bincode serialized)

The ciphertext contains a bincode-serialized `MetadataPlaintext` structure:

```rust
struct MetadataPlaintext {
    name: String,           // Original filename
    path: String,           // Virtual path in vault
    access_level: u32,      // Access level assignment
    size: u64,              // Original file size in bytes
    created_at: u64,        // File creation timestamp
    modified_at: u64,       // File modification timestamp
    blob_uuid: Uuid,        // Reference to blob file
}
```

### 6.3 Encryption

```
metadata_content = AES-256-GCM.Encrypt(
    key = kek,  // Level's KEK, not the file's DEK
    nonce = nonce,
    plaintext = bincode::serialize(metadata_plaintext),
    aad = file_uuid as bytes
)
```

### 6.4 File Naming

Metadata files use the same UUID as their corresponding blob:
```
550e8400-e29b-41d4-a716-446655440000.meta
```

---

## 7. Streaming Format

For large files, TESSERACT uses a streaming format that encrypts in chunks.

### 7.1 Stream File Layout

```
+--------+---------+-----------+------------+---------+---------+-----+
| Header |  Chunk  |  Chunk    |   Chunk    |  Chunk  |  Chunk  | ... |
| (21 B) |    0    |     1     |     2      |    3    |   ...   |     |
+--------+---------+-----------+------------+---------+---------+-----+
```

### 7.2 Stream Header (21 bytes)

| Offset | Size | Field        | Description                       |
|--------|------|--------------|-----------------------------------|
| 0      | 4    | `magic`      | Magic bytes: `TESS` (ASCII)       |
| 4      | 1    | `version`    | Stream format version (currently 1)|
| 5      | 12   | `base_nonce` | Base nonce for chunk derivation   |
| 17     | 4    | `chunk_size` | Chunk size in bytes, little-endian|

### 7.3 Chunk Format

Each chunk is encrypted independently:

| Offset | Size          | Field         | Description                    |
|--------|---------------|---------------|--------------------------------|
| 0      | chunk_size    | `ciphertext`  | Encrypted chunk data           |
| -16    | 16            | `tag`         | GCM authentication tag         |

**Chunk sizes:**
- Default: 1 MiB (1,048,576 bytes)
- Minimum: 4 KiB (4,096 bytes)
- Maximum: 64 MiB (67,108,864 bytes)

### 7.4 Chunk Nonce Derivation

Each chunk uses a unique nonce derived from the base nonce:

```
chunk_nonce = base_nonce XOR (chunk_index as little-endian u64, padded to 12 bytes)
```

Example for chunk 5:
```
base_nonce:  [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]
counter:     [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
chunk_nonce: [0x04, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]
```

### 7.5 Chunk AAD

Each chunk includes authenticated additional data:

```
chunk_aad = file_uuid (16 bytes) || chunk_index (8 bytes, LE) || is_final (1 byte)
```

| Offset | Size | Field         | Description                     |
|--------|------|---------------|---------------------------------|
| 0      | 16   | `file_uuid`   | File UUID                       |
| 16     | 8    | `chunk_index` | 64-bit chunk index, LE          |
| 24     | 1    | `is_final`    | 0x01 if last chunk, 0x00 otherwise |

This prevents:
- Chunk substitution between files (UUID binding)
- Chunk reordering attacks (index binding)
- Truncation attacks (final flag binding)

---

## 8. Security Considerations

### 8.1 Nonce Management

- All nonces are 96-bit (12 bytes) for AES-256-GCM
- Nonces are generated using OS CSPRNG (`getrandom`)
- Each encryption operation uses a unique nonce
- Streaming format derives chunk nonces from a base nonce

### 8.2 Key Hierarchy

```
Password
    │
    ▼
┌────────────────────────┐
│ Argon2id (m=64MB, t=3) │
└────────────────────────┘
    │
    ├── XOR salt with 0x01 ──► Encryption Key ──► Decrypt Master Key
    │
    └── XOR salt with 0x02 ──► HMAC Key ──► Verify Header Integrity
            │
            ▼
        Master Key
            │
            ├──► ALK (Level 0) ──► Unwrap KEK ──► Unwrap DEKs
            ├──► ALK (Level 1) ──► Unwrap KEK ──► Unwrap DEKs
            └──► ALK (Level 2) ──► Unwrap KEK ──► Unwrap DEKs
```

### 8.3 Integrity Verification Order

1. Verify magic bytes
2. Check version compatibility
3. Verify HMAC tag over header
4. Only then attempt decryption

### 8.4 Atomic Operations

File operations should be atomic:
- Write to temporary file
- Verify write integrity
- Rename to final location
- On failure, clean up temporary file

---

## 9. Version Compatibility

### 9.1 Current Versions

| Structure | Major | Minor | Description           |
|-----------|-------|-------|-----------------------|
| Header    | 1     | 0     | Initial release       |
| Keystore  | 1     | 0     | Initial release       |
| Streaming | 1     | -     | Single-byte version   |

### 9.2 Compatibility Rules

- **Major version change**: Breaking change, incompatible format
- **Minor version change**: Backwards-compatible additions

An implementation MUST:
- Refuse to open vaults with incompatible major version
- Accept vaults with same major version but different minor version
- Preserve unknown fields in reserved areas when modifying

### 9.3 Migration Strategy

Future major version upgrades should:
1. Provide a migration tool
2. Create backup before migration
3. Verify integrity after migration
4. Support rollback on failure

---

## Appendix A: Constants Reference

| Constant             | Value     | Description                     |
|----------------------|-----------|---------------------------------|
| `HEADER_SIZE`        | 512       | Total vault header size         |
| `MAGIC_BYTES`        | "TESSERAC"| 8-byte magic identifier         |
| `SALT_SIZE`          | 16        | Argon2id salt size              |
| `KEY_SIZE`           | 32        | AES-256 key size                |
| `NONCE_SIZE`         | 12        | AES-GCM nonce size              |
| `TAG_SIZE`           | 16        | AES-GCM tag size                |
| `HMAC_SIZE`          | 32        | HMAC-SHA256 output size         |
| `UUID_SIZE`          | 16        | UUID binary size                |
| `ENCRYPTED_KEY_SIZE` | 48        | Encrypted key (32 + 16 tag)     |
| `DEK_ENTRY_SIZE`     | 76        | Size of each DEK entry          |
| `DEFAULT_CHUNK_SIZE` | 1,048,576 | Default streaming chunk (1 MiB) |
| `MIN_CHUNK_SIZE`     | 4,096     | Minimum chunk size (4 KiB)      |
| `MAX_CHUNK_SIZE`     | 67,108,864| Maximum chunk size (64 MiB)     |

---

## Appendix B: Example Hex Dumps

### B.1 Valid Vault Header (first 64 bytes)

```
00000000  54 45 53 53 45 52 41 43  01 00 a1 b2 c3 d4 e5 f6  |TESSERAC........|
00000010  07 08 09 0a 0b 0c 0d 0e  0f 10 [encrypted master  |................|
00000020  key continues for 48 bytes total, then nonce...]  |................|
00000030  [nonce 12 bytes] [attempt_counter 4 bytes] [lock]  |................|
```

### B.2 DEK Entry (76 bytes)

```
00000000  55 0e 84 00 e2 9b 41 d4  a7 16 44 66 55 44 00 00  |U.....A...DfUD..|  <- UUID
00000010  [encrypted DEK - 48 bytes containing ciphertext   |................|
00000020  and authentication tag..........................]  |................|
00000030  [nonce - 12 bytes...............................]  |............|      <- Nonce
```

---

*End of Vault Format Specification*
