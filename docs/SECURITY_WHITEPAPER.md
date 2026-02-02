# TESSERACT Security Whitepaper

**Version**: 1.0
**Date**: January 2026
**Classification**: Technical Security Documentation

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Security Objectives](#security-objectives)
3. [Threat Model](#threat-model)
4. [Cryptographic Design](#cryptographic-design)
5. [Key Hierarchy](#key-hierarchy)
6. [Vault Format Specification](#vault-format-specification)
7. [Authentication and Access Control](#authentication-and-access-control)
8. [Security Mitigations](#security-mitigations)
9. [Implementation Security](#implementation-security)
10. [Security Testing](#security-testing)
11. [Compliance Considerations](#compliance-considerations)
12. [References](#references)

---

## Executive Summary

TESSERACT is a portable removable storage encryption application designed for enterprise and government classified data protection. It employs a defense-in-depth approach using:

- **AES-256-GCM** for authenticated encryption of all data
- **Argon2id** for password-based key derivation (memory-hard)
- **Four-tier key hierarchy** for cryptographic separation
- **Multi-level access control** for compartmentalized data access
- **BIP39 recovery keys** for disaster recovery

All cryptographic primitives follow NIST recommendations and IETF RFCs, with implementations validated against official test vectors.

---

## Security Objectives

### Primary Goals

| Goal | Description | Implementation |
|------|-------------|----------------|
| **Confidentiality** | Protect data from unauthorized disclosure | AES-256-GCM encryption for all content and metadata |
| **Integrity** | Detect any unauthorized modification | HMAC-SHA256 and GCM authentication tags |
| **Authenticity** | Verify data origin and prevent forgery | Authenticated encryption with AAD binding |
| **Availability** | Ensure authorized users can access data | Recovery key mechanism, robust error handling |

### Secondary Goals

- **Plausible Deniability**: Hidden volumes not implemented (out of scope)
- **Key Escrow Resistance**: Recovery keys controlled solely by user
- **Portability**: Single executable, no installation required
- **Cross-Platform**: Identical security guarantees on Windows, Linux, macOS

---

## Threat Model

### Assumed Adversary Capabilities

#### Tier 1: Casual Attacker
- Physical access to unattended USB drive
- No specialized hardware or cryptographic expertise
- **Mitigation**: Encryption at rest, auto-lock on idle

#### Tier 2: Determined Attacker
- Forensic tools and disk imaging capability
- Offline password cracking resources (GPU clusters)
- **Mitigation**: Argon2id with 64 MiB memory, no plaintext metadata leakage

#### Tier 3: Advanced Persistent Threat
- Access to compromised endpoints
- Memory forensics capability
- **Mitigation**: Secure memory handling, key zeroization on lock

### Attack Vectors and Mitigations

| Attack Vector | Threat | Mitigation |
|---------------|--------|------------|
| **Brute-force password attack** | Offline dictionary/rainbow table attack | Argon2id with 64 MiB memory, 3 iterations, 4 lanes (~1s derivation) |
| **Ciphertext tampering** | Modify encrypted data undetected | GCM authentication tags on all data |
| **Header tampering** | Modify vault metadata | HMAC-SHA256 integrity verification before decryption |
| **Nonce reuse** | Complete GCM security failure | NonceRegistry collision detection, counter-based streaming nonces |
| **Keystore manipulation** | Access unauthorized files | Level-bound AAD, HMAC integrity verification |
| **Memory extraction** | Cold boot attack, RAM dump | zeroize crate, mlock/VirtualLock, session key wiping |
| **File enumeration** | Discover vault contents without decryption | All filenames/paths encrypted, UUID-only external naming |
| **Timing attacks** | Password verification timing leak | Constant-time comparison for all sensitive comparisons |
| **Side-channel attacks** | Cache timing, power analysis | AES-NI hardware acceleration (resistant), Argon2id (memory-hard) |
| **USB removal during write** | Data corruption | Atomic file operations, integrity verification on open |

### Out of Scope

The following threats are explicitly not addressed:

- Keylogger/malware on the host system
- Hardware tampering (evil maid attacks)
- Rubber-hose cryptanalysis (coercion)
- Quantum computing attacks (AES-256 is quantum-resistant)

---

## Cryptographic Design

### Algorithm Selection

| Purpose | Algorithm | Standard | Parameters |
|---------|-----------|----------|------------|
| **Symmetric Encryption** | AES-256-GCM | NIST SP 800-38D | 256-bit key, 96-bit nonce, 128-bit tag |
| **Key Derivation** | Argon2id | RFC 9106 | 64 MiB memory, t=3, p=4, version 1.3 |
| **Integrity** | HMAC-SHA256 | RFC 4231, FIPS 198-1 | 256-bit key, 256-bit tag |
| **Random Generation** | OS CSPRNG | Platform-specific | getrandom (Linux), CryptGenRandom (Windows) |
| **Recovery Key** | BIP39 | BIP-0039 | 256-bit entropy, 24-word mnemonic |

### AES-256-GCM Details

**Rationale**: AES-256-GCM provides authenticated encryption with associated data (AEAD), combining confidentiality and integrity in a single primitive. The 256-bit key provides 128-bit security against quantum attacks (Grover's algorithm).

**Security Properties**:
- IND-CPA (Indistinguishability under Chosen Plaintext Attack)
- INT-CTXT (Integrity of Ciphertext)
- Up to 2^32 blocks per nonce (safe for files up to 64 GiB per nonce)

**Nonce Management**:
- 96-bit (12-byte) nonces as recommended by NIST
- Randomly generated for each encryption operation
- NonceRegistry prevents collision within a session
- Streaming mode: `base_nonce XOR counter` derivation

**Ciphertext Format**:
```
[ciphertext (variable)][authentication tag (16 bytes)]
```

### Argon2id Key Derivation

**Rationale**: Argon2id is the winner of the Password Hashing Competition (2015) and recommended by OWASP. The hybrid variant combines:
- Argon2i: Resistant to side-channel attacks
- Argon2d: Resistant to GPU/ASIC attacks

**Default Parameters**:
```
Memory:      65,536 KiB (64 MiB)
Iterations:  3
Parallelism: 4 lanes
Output:      32 bytes (256 bits)
Version:     0x13 (1.3)
```

**Security Analysis**:
| Parameter | Effect | Chosen Value |
|-----------|--------|--------------|
| Memory cost | Higher = more GPU-resistant | 64 MiB (exceeds typical GPU memory bandwidth) |
| Time cost | Higher = slower derivation | 3 (balances security and usability) |
| Parallelism | Matches CPU cores | 4 (typical desktop) |

**Performance Target**: 0.5 - 2 seconds on typical hardware

### HMAC-SHA256

**Usage**: Header and keystore integrity verification

**Key Derivation**: Separate HMAC key derived from password:
```
HMAC_key = Argon2id(password, salt XOR 0x02, params)
```

The XOR with 0x02 provides domain separation from the encryption key (XOR 0x01).

---

## Key Hierarchy

TESSERACT implements a four-tier key hierarchy providing cryptographic separation between access levels and files.

### Key Types

```
                    ┌──────────────────────┐
                    │   Master Password    │
                    │    (User Input)      │
                    └──────────┬───────────┘
                               │ Argon2id
                               ▼
                    ┌──────────────────────┐
                    │   Master Key (MK)    │◄─── Recovery Key (backup path)
                    │      256 bits        │
                    └──────────┬───────────┘
                               │ Encrypted in header
                               ▼
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Level Password  │  │ Level Password  │  │ Level Password  │
│    Level 1      │  │    Level 2      │  │    Level 3      │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │ Argon2id           │ Argon2id           │ Argon2id
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  ALK Level 1    │  │  ALK Level 2    │  │  ALK Level 3    │
│  (Access Level  │  │  (Access Level  │  │  (Access Level  │
│      Key)       │  │      Key)       │  │      Key)       │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │ Wraps              │ Wraps              │ Wraps
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  KEK Level 1    │  │  KEK Level 2    │  │  KEK Level 3    │
│(Key Encryption  │  │(Key Encryption  │  │(Key Encryption  │
│      Key)       │  │      Key)       │  │      Key)       │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │ Wraps              │ Wraps              │ Wraps
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  File DEKs      │  │  File DEKs      │  │  File DEKs      │
│(Data Encryption │  │(Data Encryption │  │(Data Encryption │
│     Keys)       │  │     Keys)       │  │     Keys)       │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Key Descriptions

| Key Type | Size | Generation | Storage | Purpose |
|----------|------|------------|---------|---------|
| **Master Password** | Variable | User input | Never stored | Derives MK |
| **Master Key (MK)** | 256 bits | Random | Encrypted in header | Root of key hierarchy |
| **Recovery Key** | 256 bits | Random | User backup only | Alternative MK decryption |
| **Access Level Key (ALK)** | 256 bits | Derived (Argon2id) | Never stored | Wraps KEK |
| **Key Encryption Key (KEK)** | 256 bits | Random | Wrapped by ALK | Wraps file DEKs |
| **Data Encryption Key (DEK)** | 256 bits | Random | Wrapped by KEK | Encrypts file content |

### Key Wrapping

All key wrapping uses AES-256-GCM with Additional Authenticated Data (AAD) for binding:

| Wrapped Key | Wrapper Key | AAD |
|-------------|-------------|-----|
| Master Key | Password-derived key | Salt |
| KEK | ALK | Level ID (4 bytes) |
| DEK | KEK | File UUID (16 bytes) |

**Format**: `[encrypted key (32 bytes)][GCM tag (16 bytes)]` = 48 bytes

### Hierarchical Access Mode

Level N password unlocks all levels from 1 to N:

| Entered Password | Accessible Levels |
|------------------|-------------------|
| Level 1 | L1 only |
| Level 2 | L1, L2 |
| Level 3 | L1, L2, L3 |

---

## Vault Format Specification

### Directory Structure

```
vault/
├── vault.header          # 512 bytes, encrypted vault metadata
├── .keystores/           # Per-level encrypted key bundles
│   ├── L1.keys.enc
│   ├── L2.keys.enc
│   └── L3.keys.enc
├── .blobs/               # Encrypted file content
│   ├── {uuid}.blob
│   └── ...
├── .metadata/            # Encrypted file metadata
│   ├── {uuid}.meta
│   └── ...
└── .levels/              # Access level configuration
    └── levels.enc
```

### Vault Header Format (512 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | magic | Magic bytes: `TESSERAC` |
| 8 | 2 | version | Format version (major.minor) |
| 10 | 16 | salt | Argon2 salt for key derivation |
| 26 | 48 | encrypted_master_key | AES-256-GCM encrypted MK (32) + tag (16) |
| 74 | 12 | master_key_nonce | Nonce used for MK encryption |
| 86 | 4 | attempt_counter | Failed authentication attempts |
| 90 | 8 | lockout_until | Unix timestamp for lockout expiry |
| 98 | 8 | created_at | Unix timestamp of vault creation |
| 106 | 8 | last_modified | Unix timestamp of last modification |
| 114 | 32 | hmac_tag | HMAC-SHA256 over bytes 0-113 |
| 146 | 350 | reserved | Reserved for future use (zeroed) |
| 496 | 16 | recovery_nonce | Nonce for recovery key encryption |

**Security Notes**:
- HMAC verified before any decryption attempt
- Attempt counter survives application restarts
- Reserved space allows format evolution without breaking compatibility

### Keystore Format

```
┌─────────────────────────────────────────────────────────┐
│ version (2B) │ level_id (4B) │ encrypted_kek (48B)     │
├─────────────────────────────────────────────────────────┤
│ kek_nonce (12B) │ dek_count (4B) │ DEK entries...      │
├─────────────────────────────────────────────────────────┤
│ hmac_tag (32B)                                          │
└─────────────────────────────────────────────────────────┘
```

**DEK Entry Format** (76 bytes each):
| Offset | Size | Field |
|--------|------|-------|
| 0 | 16 | file_uuid |
| 16 | 48 | encrypted_dek (32 + 16 tag) |
| 64 | 12 | dek_nonce |

**Security Notes**:
- KEK wrapped with ALK, never stored in plaintext
- Each DEK wrapped individually with unique nonce
- HMAC covers all keystore data for integrity
- DEK entries sorted by UUID for deterministic HMAC

### Blob Format

```
┌──────────────┬─────────────────────┬────────────┐
│ Nonce (12B)  │ Ciphertext (var)    │ Tag (16B)  │
└──────────────┴─────────────────────┴────────────┘
```

**Filename**: `{uuid}.blob` (lowercase hex UUID)

**AAD**: File UUID (16 bytes) - binds ciphertext to specific file

**Maximum File Size**: 64 GiB per blob (GCM block limit)

### Metadata Format

```
┌──────────────┬─────────────────────┬────────────┐
│ Nonce (12B)  │ Encrypted bincode   │ Tag (16B)  │
└──────────────┴─────────────────────┴────────────┘
```

**Plaintext Structure** (before encryption):
```rust
struct MetadataPlaintext {
    name: String,           // Original filename
    path: String,           // Virtual path in vault
    access_level: u32,      // Owning access level
    size: u64,              // Original file size
    created_at: u64,        // Unix timestamp
    modified_at: u64,       // Unix timestamp
    blob_uuid: Uuid,        // Reference to blob file
}
```

**Security Notes**:
- All sensitive metadata encrypted, zero plaintext leakage
- AAD: File UUID for authenticated binding
- Access level hidden from external observation

### Streaming Format (Large Files)

```
┌───────────────────────────────────────────────────────┐
│ Header (21B)                                           │
│ ┌──────────┬─────────┬──────────────┬────────────┐    │
│ │TESS (4B) │Ver (1B) │Base Nonce(12)│ChunkSize(4)│    │
│ └──────────┴─────────┴──────────────┴────────────┘    │
├───────────────────────────────────────────────────────┤
│ Chunk 0: [encrypted data][tag (16B)]                   │
│ Chunk 1: [encrypted data][tag (16B)]                   │
│ ...                                                    │
│ Chunk N: [encrypted data][tag (16B)] (final chunk)     │
└───────────────────────────────────────────────────────┘
```

**Chunk Nonce Derivation**:
```
chunk_nonce = base_nonce XOR (chunk_index as little-endian bytes)
```

**Chunk AAD** (25 bytes):
```
[file_uuid (16B)][chunk_index (8B)][is_final (1B)]
```

**Security Notes**:
- Unique nonce per chunk via counter derivation
- AAD prevents chunk reordering attacks
- Final flag prevents truncation attacks
- Default chunk size: 1 MiB (configurable 4 KiB - 64 MiB)

---

## Authentication and Access Control

### Password Verification Flow

```
1. Read vault.header
2. Verify HMAC-SHA256 integrity (reject if tampered)
3. Check lockout_until timestamp
4. If locked out, return error with remaining time
5. Derive encryption key: Argon2id(password, salt XOR 0x01)
6. Derive HMAC key: Argon2id(password, salt XOR 0x02)
7. Attempt decrypt of encrypted_master_key with GCM
8. If GCM tag verification fails:
   a. Increment attempt_counter
   b. Calculate backoff delay: min(2^attempts, 3600) seconds
   c. If attempts >= 10, set lockout_until = now + 900 seconds
   d. Write updated header
   e. Return AuthenticationFailed error
9. If successful:
   a. Reset attempt_counter to 0
   b. Write updated header
   c. Return session with decrypted master key
```

### Exponential Backoff

| Attempts | Delay |
|----------|-------|
| 1 | 2 seconds |
| 2 | 4 seconds |
| 3 | 8 seconds |
| 4 | 16 seconds |
| 5 | 32 seconds |
| 6 | 64 seconds |
| 7 | 128 seconds |
| 8 | 256 seconds |
| 9 | 512 seconds |
| 10+ | 900 seconds (15-minute lockout) |

**Maximum Delay**: 3600 seconds (1 hour) for extreme cases

### Recovery Key Authentication

```
1. User enters 24-word mnemonic or base64 string
2. Parse and validate BIP39 mnemonic (checksum verification)
3. Extract 256-bit recovery key
4. Decrypt recovery blob from header using recovery key
5. If successful, obtain master key
6. User can reset any level password using master key
```

---

## Security Mitigations

### Memory Protection

| Mechanism | Implementation | Purpose |
|-----------|----------------|---------|
| **Automatic Zeroization** | `zeroize` crate with `ZeroizeOnDrop` | Clear keys when out of scope |
| **Memory Locking** | `mlock` (Unix) / `VirtualLock` (Windows) | Prevent swapping to disk |
| **Secure Containers** | `SecureBytes`, `SecureKey`, `SecureNonce` | Type-safe key handling |

### Timing Attack Prevention

- **Constant-time comparison** for all password/key verification
- **XOR accumulation pattern** for HMAC tag verification
- **No early returns** on byte mismatches

### Nonce Uniqueness

| Context | Mechanism |
|---------|-----------|
| Session operations | `NonceRegistry` with `RwLock<HashSet>` collision detection |
| Streaming encryption | Counter-based derivation from base nonce |
| File operations | Fresh random nonce per encryption |

**Test Coverage**: Zero collisions verified across 1,000,000 nonce generations

### USB Removal Protection

- **Atomic file operations** using temporary file + rename
- **Integrity verification** on vault open detects corruption
- **Pending write flush** before unmount

---

## Implementation Security

### Language Choice: Rust

Rust provides:
- Memory safety without garbage collection
- No null pointer dereferences
- No buffer overflows
- No use-after-free

### Dependency Selection

| Crate | Purpose | Audit Status |
|-------|---------|--------------|
| `aes-gcm` | AES-256-GCM | RustCrypto, widely reviewed |
| `argon2` | Key derivation | RustCrypto implementation |
| `hmac` / `sha2` | HMAC-SHA256 | RustCrypto, NIST validated |
| `zeroize` | Secure memory clearing | RustCrypto, audited |
| `getrandom` | OS CSPRNG | Cross-platform, well-maintained |
| `bip39` | Mnemonic generation | Bitcoin standard library |

### Test Vector Validation

All cryptographic implementations validated against official test vectors:

| Algorithm | Standard | Vectors |
|-----------|----------|---------|
| AES-256-GCM | NIST SP 800-38D | 8 test vectors |
| Argon2id | RFC 9106 | 1 official vector |
| HMAC-SHA256 | RFC 4231 | 7 test vectors (Cases 1-7) |

---

## Security Testing

### Automated Tests

| Test Type | Coverage |
|-----------|----------|
| Unit tests | >90% crypto module coverage |
| Nonce stress test | 1,000,000 nonces, zero collisions |
| Metadata encryption test | Hex dump verification, zero plaintext |
| Tamper detection | All components: header, keystore, blob, metadata |
| Cross-platform | Windows, Linux, macOS in CI |

### Manual Review Checklist

- [ ] No plaintext keys in memory after lock
- [ ] No plaintext file content on disk after import
- [ ] Backoff delays enforced after failed auth
- [ ] Recovery key cannot be extracted from vault
- [ ] Level separation prevents unauthorized access

---

## Compliance Considerations

### Standards Alignment

| Standard | Alignment |
|----------|-----------|
| **NIST SP 800-38D** | AES-GCM parameters |
| **NIST SP 800-132** | Password-based key derivation |
| **RFC 9106** | Argon2 implementation |
| **RFC 4231** | HMAC-SHA256 |
| **BIP-0039** | Recovery key mnemonic |
| **OWASP** | Password hashing recommendations |

### Regulatory Notes

TESSERACT is designed to support compliance with:
- GDPR (data protection by design)
- HIPAA (encryption at rest)
- PCI-DSS (cryptographic controls)

**Disclaimer**: Compliance depends on deployment context and organizational controls beyond TESSERACT itself.

---

## References

1. NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
2. RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
3. RFC 4231: Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512
4. BIP-0039: Mnemonic code for generating deterministic keys
5. OWASP Password Storage Cheat Sheet
6. FIPS 197: Advanced Encryption Standard (AES)
7. FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)

---

*This document is intended for security auditors and technical reviewers evaluating TESSERACT's cryptographic design.*
