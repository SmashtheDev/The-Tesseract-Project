//! Blob storage for encrypted file content.
//!
//! Each file in the vault is stored as an encrypted blob with UUID-based naming.
//! Blobs are stored in the `.blobs/` directory within the vault.
//!
//! # Blob Format
//!
//! ```text
//! +---------------+-------------------+----------+
//! | Nonce (12B)   | Ciphertext (var)  | Tag (16B)|
//! +---------------+-------------------+----------+
//! ```
//!
//! - **Nonce**: 96-bit (12-byte) nonce for AES-256-GCM
//! - **Ciphertext**: Encrypted file content (variable length)
//! - **Tag**: 128-bit (16-byte) GCM authentication tag
//!
//! # File Naming
//!
//! Blobs are named using their UUID in lowercase hex format:
//! `{uuid}.blob` (e.g., `550e8400-e29b-41d4-a716-446655440000.blob`)
//!
//! # Security
//!
//! - Each blob uses a unique nonce
//! - File UUID is used as Additional Authenticated Data (AAD)
//! - Authentication tag ensures integrity and authenticity
//!
//! # Example
//!
//! ```ignore
//! use tesseract_core::blob::{BlobStorage, write_blob, read_blob};
//! use uuid::Uuid;
//!
//! let file_uuid = Uuid::new_v4();
//! let dek = [0x42u8; 32]; // Data Encryption Key
//! let plaintext = b"Secret file content";
//!
//! // Write blob
//! let blob_path = write_blob(&vault_path, file_uuid, &dek, plaintext)?;
//!
//! // Read blob
//! let decrypted = read_blob(&vault_path, file_uuid, &dek)?;
//! assert_eq!(decrypted, plaintext);
//! ```

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use tesseract_crypto::aes::{encrypt, decrypt, NONCE_LENGTH, TAG_LENGTH, KEY_LENGTH};
use tesseract_crypto::random::generate_nonce;

use crate::VaultError;

// ============================================
// Constants
// ============================================

/// Directory name for blob storage within the vault.
pub const BLOBS_DIR: &str = ".blobs";

/// File extension for blob files.
pub const BLOB_EXTENSION: &str = "blob";

/// Minimum blob size: nonce + tag (empty file)
pub const MIN_BLOB_SIZE: usize = NONCE_LENGTH + TAG_LENGTH;

/// Size of the nonce prefix in a blob
pub const BLOB_NONCE_SIZE: usize = NONCE_LENGTH;

/// Size of the authentication tag at the end of encrypted data
pub const BLOB_TAG_SIZE: usize = TAG_LENGTH;

// ============================================
// Blob Header (informational only)
// ============================================

/// Represents the structure of a blob file.
///
/// The blob format is:
/// - Bytes 0-11: Nonce (12 bytes)
/// - Bytes 12-N: Ciphertext (variable, includes 16-byte tag at end)
///
/// Note: This struct is for documentation and helper methods.
/// The actual blob format is just raw bytes.
#[derive(Debug, Clone)]
pub struct BlobInfo {
    /// File UUID (used for naming and AAD)
    pub file_uuid: Uuid,
    /// Nonce used for encryption (12 bytes)
    pub nonce: [u8; NONCE_LENGTH],
    /// Size of the encrypted content (ciphertext + tag)
    pub encrypted_size: usize,
    /// Size of the original plaintext
    pub plaintext_size: usize,
}

impl BlobInfo {
    /// Creates blob info from metadata.
    pub fn new(file_uuid: Uuid, nonce: [u8; NONCE_LENGTH], encrypted_size: usize) -> Self {
        // Plaintext size is encrypted size minus the tag
        let plaintext_size = encrypted_size.saturating_sub(TAG_LENGTH);
        Self {
            file_uuid,
            nonce,
            encrypted_size,
            plaintext_size,
        }
    }

    /// Returns the total blob file size (nonce + ciphertext + tag).
    pub fn blob_size(&self) -> usize {
        NONCE_LENGTH + self.encrypted_size
    }
}

// ============================================
// Path Utilities
// ============================================

/// Returns the path to the blobs directory within a vault.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
///
/// # Returns
///
/// Path to `.blobs/` directory
pub fn blobs_dir(vault_path: &Path) -> PathBuf {
    vault_path.join(BLOBS_DIR)
}

/// Returns the path to a specific blob file.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Returns
///
/// Path to the blob file (e.g., `.blobs/550e8400-e29b-41d4-a716-446655440000.blob`)
pub fn blob_path(vault_path: &Path, file_uuid: Uuid) -> PathBuf {
    let filename = format!("{}.{}", file_uuid.hyphenated().to_string(), BLOB_EXTENSION);
    blobs_dir(vault_path).join(filename)
}

/// Ensures the blobs directory exists.
///
/// Creates the `.blobs/` directory if it doesn't exist.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
///
/// # Errors
///
/// Returns `VaultError::IoError` if directory creation fails.
pub fn ensure_blobs_dir(vault_path: &Path) -> Result<(), VaultError> {
    let dir = blobs_dir(vault_path);
    fs::create_dir_all(&dir)?;
    Ok(())
}

// ============================================
// Blob Write Operations
// ============================================

/// Writes encrypted file content as a blob.
///
/// Creates a new blob file with the format:
/// `[nonce:12][ciphertext:*][tag:16]`
///
/// The file UUID is used as Additional Authenticated Data (AAD) to bind
/// the encrypted content to this specific file.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID for the file (used for naming and AAD)
/// * `dek` - Data Encryption Key (32-byte AES-256 key)
/// * `plaintext` - Content to encrypt
///
/// # Returns
///
/// Path to the created blob file.
///
/// # Errors
///
/// * `VaultError::CryptoError` - If encryption fails
/// * `VaultError::IoError` - If file creation fails
///
/// # Security
///
/// - Generates a unique nonce for each blob
/// - Uses file UUID as AAD for authenticated binding
/// - Atomic write not implemented in this basic version (see US-030 for streaming)
pub fn write_blob(
    vault_path: &Path,
    file_uuid: Uuid,
    dek: &[u8],
    plaintext: &[u8],
) -> Result<PathBuf, VaultError> {
    // Validate key length
    if dek.len() != KEY_LENGTH {
        return Err(VaultError::CryptoError(
            tesseract_crypto::CryptoError::InvalidKeyLength {
                expected: KEY_LENGTH,
                actual: dek.len(),
            }
        ));
    }

    // Ensure blobs directory exists
    ensure_blobs_dir(vault_path)?;

    // Generate a unique nonce
    let nonce = generate_nonce().map_err(VaultError::CryptoError)?;

    // Use file UUID as AAD (as raw 16 bytes)
    let aad = file_uuid.as_bytes();

    // Encrypt the content
    let ciphertext = encrypt(dek, &nonce, plaintext, aad)?;

    // Build blob: [nonce:12][ciphertext+tag:*]
    let mut blob_data = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    blob_data.extend_from_slice(&nonce);
    blob_data.extend_from_slice(&ciphertext);

    // Write to file
    let path = blob_path(vault_path, file_uuid);
    let mut file = File::create(&path)?;
    file.write_all(&blob_data)?;
    file.sync_all()?; // Ensure data is flushed to disk

    Ok(path)
}

/// Writes a blob with a specific nonce (for testing or deterministic operations).
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID for the file
/// * `dek` - Data Encryption Key (32-byte AES-256 key)
/// * `nonce` - Specific nonce to use (12 bytes)
/// * `plaintext` - Content to encrypt
///
/// # Security Warning
///
/// This function should only be used for testing. In production, use [`write_blob`]
/// which generates a unique nonce for each operation.
pub fn write_blob_with_nonce(
    vault_path: &Path,
    file_uuid: Uuid,
    dek: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
) -> Result<PathBuf, VaultError> {
    // Validate key length
    if dek.len() != KEY_LENGTH {
        return Err(VaultError::CryptoError(
            tesseract_crypto::CryptoError::InvalidKeyLength {
                expected: KEY_LENGTH,
                actual: dek.len(),
            }
        ));
    }

    // Ensure blobs directory exists
    ensure_blobs_dir(vault_path)?;

    // Use file UUID as AAD (as raw 16 bytes)
    let aad = file_uuid.as_bytes();

    // Encrypt the content
    let ciphertext = encrypt(dek, nonce, plaintext, aad)?;

    // Build blob: [nonce:12][ciphertext+tag:*]
    let mut blob_data = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    blob_data.extend_from_slice(nonce);
    blob_data.extend_from_slice(&ciphertext);

    // Write to file
    let path = blob_path(vault_path, file_uuid);
    let mut file = File::create(&path)?;
    file.write_all(&blob_data)?;
    file.sync_all()?;

    Ok(path)
}

// ============================================
// Blob Read Operations
// ============================================

/// Reads and decrypts a blob file.
///
/// Reads the blob file, extracts the nonce, and decrypts the content.
/// The file UUID is verified as part of AAD during decryption.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file to read
/// * `dek` - Data Encryption Key (32-byte AES-256 key)
///
/// # Returns
///
/// Decrypted file content.
///
/// # Errors
///
/// * `VaultError::FileNotFound` - If the blob file doesn't exist
/// * `VaultError::InvalidFormat` - If the blob is too small or malformed
/// * `VaultError::CryptoError` - If decryption fails (wrong key, tampered content, etc.)
/// * `VaultError::IoError` - If file read fails
pub fn read_blob(
    vault_path: &Path,
    file_uuid: Uuid,
    dek: &[u8],
) -> Result<Vec<u8>, VaultError> {
    // Validate key length
    if dek.len() != KEY_LENGTH {
        return Err(VaultError::CryptoError(
            tesseract_crypto::CryptoError::InvalidKeyLength {
                expected: KEY_LENGTH,
                actual: dek.len(),
            }
        ));
    }

    // Get blob path
    let path = blob_path(vault_path, file_uuid);

    // Check if file exists
    if !path.exists() {
        return Err(VaultError::FileNotFound(file_uuid.to_string()));
    }

    // Read blob data
    let mut file = File::open(&path)?;
    let mut blob_data = Vec::new();
    file.read_to_end(&mut blob_data)?;

    // Validate minimum size
    if blob_data.len() < MIN_BLOB_SIZE {
        return Err(VaultError::InvalidFormat(
            format!("Blob too small: {} bytes (minimum {})", blob_data.len(), MIN_BLOB_SIZE)
        ));
    }

    // Extract nonce and ciphertext
    let nonce = &blob_data[0..NONCE_LENGTH];
    let ciphertext = &blob_data[NONCE_LENGTH..];

    // Use file UUID as AAD
    let aad = file_uuid.as_bytes();

    // Decrypt
    let plaintext = decrypt(dek, nonce, ciphertext, aad)?;

    Ok(plaintext)
}

/// Reads blob info without decrypting the content.
///
/// Useful for getting metadata about a blob without loading and decrypting
/// the entire file.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Returns
///
/// Information about the blob (sizes, nonce).
///
/// # Errors
///
/// * `VaultError::FileNotFound` - If the blob file doesn't exist
/// * `VaultError::InvalidFormat` - If the blob is too small
/// * `VaultError::IoError` - If file read fails
pub fn read_blob_info(
    vault_path: &Path,
    file_uuid: Uuid,
) -> Result<BlobInfo, VaultError> {
    let path = blob_path(vault_path, file_uuid);

    if !path.exists() {
        return Err(VaultError::FileNotFound(file_uuid.to_string()));
    }

    // Get file size
    let metadata = fs::metadata(&path)?;
    let file_size = metadata.len() as usize;

    if file_size < MIN_BLOB_SIZE {
        return Err(VaultError::InvalidFormat(
            format!("Blob too small: {} bytes (minimum {})", file_size, MIN_BLOB_SIZE)
        ));
    }

    // Read just the nonce (first 12 bytes)
    let mut file = File::open(&path)?;
    let mut nonce = [0u8; NONCE_LENGTH];
    file.read_exact(&mut nonce)?;

    // Encrypted size is total size minus nonce
    let encrypted_size = file_size - NONCE_LENGTH;

    Ok(BlobInfo::new(file_uuid, nonce, encrypted_size))
}

// ============================================
// Blob Delete Operations
// ============================================

/// Deletes a blob file.
///
/// Removes the blob file from the `.blobs/` directory.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file to delete
///
/// # Returns
///
/// `Ok(())` if the file was deleted or didn't exist.
///
/// # Errors
///
/// * `VaultError::IoError` - If deletion fails
pub fn delete_blob(vault_path: &Path, file_uuid: Uuid) -> Result<(), VaultError> {
    let path = blob_path(vault_path, file_uuid);

    if path.exists() {
        fs::remove_file(&path)?;
    }

    Ok(())
}

/// Checks if a blob exists.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file to check
///
/// # Returns
///
/// `true` if the blob file exists, `false` otherwise.
pub fn blob_exists(vault_path: &Path, file_uuid: Uuid) -> bool {
    blob_path(vault_path, file_uuid).exists()
}

// ============================================
// Blob Listing
// ============================================

/// Lists all blob UUIDs in the vault.
///
/// Scans the `.blobs/` directory and returns all valid blob UUIDs.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
///
/// # Returns
///
/// Vector of UUIDs for all blobs in the vault.
///
/// # Note
///
/// Invalid blob filenames are silently skipped.
pub fn list_blobs(vault_path: &Path) -> Result<Vec<Uuid>, VaultError> {
    let dir = blobs_dir(vault_path);

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut uuids = Vec::new();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        // Check if it's a file with .blob extension
        if path.is_file() {
            if let Some(stem) = path.file_stem() {
                if let Some(stem_str) = stem.to_str() {
                    // Try to parse as UUID
                    if let Ok(uuid) = Uuid::parse_str(stem_str) {
                        // Verify extension
                        if path.extension().and_then(|e| e.to_str()) == Some(BLOB_EXTENSION) {
                            uuids.push(uuid);
                        }
                    }
                }
            }
        }
    }

    Ok(uuids)
}

// ============================================
// Blob Verification
// ============================================

/// Verifies blob integrity without fully decrypting.
///
/// This performs a full decryption to verify the authentication tag,
/// but discards the plaintext. Use this to check if a blob is valid
/// and the key is correct.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
/// * `dek` - Data Encryption Key
///
/// # Returns
///
/// `Ok(())` if the blob is valid and can be decrypted.
/// `Err(...)` if the blob is corrupted, tampered, or the key is wrong.
pub fn verify_blob(vault_path: &Path, file_uuid: Uuid, dek: &[u8]) -> Result<(), VaultError> {
    // Just try to read - if it succeeds, the blob is valid
    read_blob(vault_path, file_uuid, dek)?;
    Ok(())
}

// ============================================
// Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper to create a temporary vault directory
    fn create_temp_vault() -> TempDir {
        TempDir::new().expect("Failed to create temp directory")
    }

    /// Generate a test DEK
    fn test_dek() -> [u8; KEY_LENGTH] {
        [0x42u8; KEY_LENGTH]
    }

    // ==========================================
    // Path Utilities Tests
    // ==========================================

    #[test]
    fn test_blobs_dir() {
        let vault = PathBuf::from("/tmp/vault");
        let dir = blobs_dir(&vault);
        assert_eq!(dir, PathBuf::from("/tmp/vault/.blobs"));
    }

    #[test]
    fn test_blob_path() {
        let vault = PathBuf::from("/tmp/vault");
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = blob_path(&vault, uuid);
        assert_eq!(
            path,
            PathBuf::from("/tmp/vault/.blobs/550e8400-e29b-41d4-a716-446655440000.blob")
        );
    }

    #[test]
    fn test_ensure_blobs_dir() {
        let vault = create_temp_vault();
        ensure_blobs_dir(vault.path()).expect("Should create blobs directory");
        assert!(blobs_dir(vault.path()).exists());
    }

    // ==========================================
    // Write and Read Tests
    // ==========================================

    #[test]
    fn test_write_and_read_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"Hello, TESSERACT!";

        // Write blob
        let path = write_blob(vault.path(), uuid, &dek, plaintext)
            .expect("Should write blob");
        assert!(path.exists());

        // Read blob
        let decrypted = read_blob(vault.path(), uuid, &dek)
            .expect("Should read blob");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_write_empty_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"";

        // Write empty blob
        let path = write_blob(vault.path(), uuid, &dek, plaintext)
            .expect("Should write empty blob");

        // Check blob size (nonce + tag only)
        let metadata = fs::metadata(&path).expect("Should get metadata");
        assert_eq!(metadata.len() as usize, MIN_BLOB_SIZE);

        // Read back
        let decrypted = read_blob(vault.path(), uuid, &dek)
            .expect("Should read empty blob");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_write_large_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = vec![0xABu8; 1_000_000]; // 1MB

        // Write large blob
        write_blob(vault.path(), uuid, &dek, &plaintext)
            .expect("Should write large blob");

        // Read back
        let decrypted = read_blob(vault.path(), uuid, &dek)
            .expect("Should read large blob");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_write_blob_with_specific_nonce() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Deterministic test";

        // Write with specific nonce
        write_blob_with_nonce(vault.path(), uuid, &dek, &nonce, plaintext)
            .expect("Should write blob with specific nonce");

        // Read blob data and verify nonce
        let path = blob_path(vault.path(), uuid);
        let blob_data = fs::read(&path).expect("Should read blob file");
        assert_eq!(&blob_data[0..NONCE_LENGTH], &nonce);

        // Verify decryption works
        let decrypted = read_blob(vault.path(), uuid, &dek)
            .expect("Should decrypt");
        assert_eq!(decrypted, plaintext);
    }

    // ==========================================
    // Error Handling Tests
    // ==========================================

    #[test]
    fn test_read_nonexistent_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();

        let result = read_blob(vault.path(), uuid, &dek);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_read_with_wrong_key() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let wrong_dek = [0x43u8; KEY_LENGTH];
        let plaintext = b"Secret data";

        // Write with correct key
        write_blob(vault.path(), uuid, &dek, plaintext)
            .expect("Should write blob");

        // Try to read with wrong key
        let result = read_blob(vault.path(), uuid, &wrong_dek);
        assert!(matches!(result, Err(VaultError::CryptoError(_))));
    }

    #[test]
    fn test_read_tampered_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"Secret data";

        // Write blob
        let path = write_blob(vault.path(), uuid, &dek, plaintext)
            .expect("Should write blob");

        // Tamper with blob content
        let mut blob_data = fs::read(&path).expect("Should read blob");
        blob_data[NONCE_LENGTH] ^= 0xFF; // Flip a bit in ciphertext
        fs::write(&path, &blob_data).expect("Should write tampered blob");

        // Try to read
        let result = read_blob(vault.path(), uuid, &dek);
        assert!(matches!(result, Err(VaultError::CryptoError(_))));
    }

    #[test]
    fn test_read_with_wrong_uuid_fails() {
        let vault = create_temp_vault();
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"Secret data";

        // Write blob with uuid1
        write_blob(vault.path(), uuid1, &dek, plaintext)
            .expect("Should write blob");

        // Copy blob to uuid2's location
        let path1 = blob_path(vault.path(), uuid1);
        let path2 = blob_path(vault.path(), uuid2);
        fs::copy(&path1, &path2).expect("Should copy blob");

        // Try to read uuid2's blob - should fail because AAD (UUID) doesn't match
        let result = read_blob(vault.path(), uuid2, &dek);
        assert!(matches!(result, Err(VaultError::CryptoError(_))));
    }

    #[test]
    fn test_invalid_key_length() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let short_dek = [0x42u8; 16]; // Too short
        let plaintext = b"test";

        let result = write_blob(vault.path(), uuid, &short_dek, plaintext);
        assert!(matches!(result, Err(VaultError::CryptoError(
            tesseract_crypto::CryptoError::InvalidKeyLength { expected: 32, actual: 16 }
        ))));
    }

    #[test]
    fn test_read_truncated_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();

        // Create blob directory
        ensure_blobs_dir(vault.path()).expect("Should create blobs dir");

        // Write truncated blob (less than minimum size)
        let path = blob_path(vault.path(), uuid);
        let truncated = vec![0u8; MIN_BLOB_SIZE - 1];
        fs::write(&path, &truncated).expect("Should write truncated blob");

        // Try to read
        let result = read_blob(vault.path(), uuid, &dek);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    // ==========================================
    // BlobInfo Tests
    // ==========================================

    #[test]
    fn test_blob_info() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"Hello, TESSERACT!";

        // Write blob
        write_blob(vault.path(), uuid, &dek, plaintext)
            .expect("Should write blob");

        // Read info
        let info = read_blob_info(vault.path(), uuid)
            .expect("Should read blob info");

        assert_eq!(info.file_uuid, uuid);
        assert_eq!(info.plaintext_size, plaintext.len());
        assert_eq!(info.encrypted_size, plaintext.len() + TAG_LENGTH);
        assert_eq!(info.blob_size(), NONCE_LENGTH + plaintext.len() + TAG_LENGTH);
    }

    #[test]
    fn test_blob_info_nonexistent() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();

        let result = read_blob_info(vault.path(), uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    // ==========================================
    // Delete Tests
    // ==========================================

    #[test]
    fn test_delete_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"To be deleted";

        // Write blob
        write_blob(vault.path(), uuid, &dek, plaintext)
            .expect("Should write blob");
        assert!(blob_exists(vault.path(), uuid));

        // Delete blob
        delete_blob(vault.path(), uuid)
            .expect("Should delete blob");
        assert!(!blob_exists(vault.path(), uuid));
    }

    #[test]
    fn test_delete_nonexistent_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();

        // Should not error on nonexistent blob
        delete_blob(vault.path(), uuid)
            .expect("Should not error on nonexistent blob");
    }

    // ==========================================
    // Listing Tests
    // ==========================================

    #[test]
    fn test_list_blobs() {
        let vault = create_temp_vault();
        let dek = test_dek();

        // Create multiple blobs
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();
        let uuid3 = Uuid::new_v4();

        write_blob(vault.path(), uuid1, &dek, b"file1").unwrap();
        write_blob(vault.path(), uuid2, &dek, b"file2").unwrap();
        write_blob(vault.path(), uuid3, &dek, b"file3").unwrap();

        // List blobs
        let uuids = list_blobs(vault.path()).expect("Should list blobs");
        assert_eq!(uuids.len(), 3);
        assert!(uuids.contains(&uuid1));
        assert!(uuids.contains(&uuid2));
        assert!(uuids.contains(&uuid3));
    }

    #[test]
    fn test_list_blobs_empty() {
        let vault = create_temp_vault();

        // List empty vault
        let uuids = list_blobs(vault.path()).expect("Should list blobs");
        assert!(uuids.is_empty());
    }

    #[test]
    fn test_list_blobs_ignores_invalid_files() {
        let vault = create_temp_vault();
        let dek = test_dek();

        // Create valid blob
        let uuid = Uuid::new_v4();
        write_blob(vault.path(), uuid, &dek, b"valid").unwrap();

        // Create invalid files in blobs directory
        let blobs = blobs_dir(vault.path());
        fs::write(blobs.join("not-a-uuid.blob"), b"garbage").unwrap();
        fs::write(blobs.join("random.txt"), b"text file").unwrap();
        fs::create_dir(blobs.join("subdir")).unwrap();

        // List should only return valid blob
        let uuids = list_blobs(vault.path()).expect("Should list blobs");
        assert_eq!(uuids.len(), 1);
        assert!(uuids.contains(&uuid));
    }

    // ==========================================
    // Verification Tests
    // ==========================================

    #[test]
    fn test_verify_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"Verify me";

        // Write blob
        write_blob(vault.path(), uuid, &dek, plaintext).unwrap();

        // Verify should succeed
        verify_blob(vault.path(), uuid, &dek)
            .expect("Should verify blob");
    }

    #[test]
    fn test_verify_blob_with_wrong_key() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let wrong_dek = [0x43u8; KEY_LENGTH];
        let plaintext = b"Verify me";

        // Write blob
        write_blob(vault.path(), uuid, &dek, plaintext).unwrap();

        // Verify with wrong key should fail
        let result = verify_blob(vault.path(), uuid, &wrong_dek);
        assert!(matches!(result, Err(VaultError::CryptoError(_))));
    }

    // ==========================================
    // Format Tests
    // ==========================================

    #[test]
    fn test_blob_format_structure() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Format test";

        // Write with known nonce
        let path = write_blob_with_nonce(vault.path(), uuid, &dek, &nonce, plaintext)
            .expect("Should write blob");

        // Read raw blob data
        let blob_data = fs::read(&path).expect("Should read blob");

        // Verify format: [nonce:12][ciphertext:*][tag:16]
        // Total size: 12 + plaintext.len() + 16
        assert_eq!(blob_data.len(), NONCE_LENGTH + plaintext.len() + TAG_LENGTH);

        // First 12 bytes are nonce
        assert_eq!(&blob_data[0..NONCE_LENGTH], &nonce);

        // Last 16 bytes are tag (can't verify exact value, but size is correct)
        let _tag = &blob_data[blob_data.len() - TAG_LENGTH..];
    }

    #[test]
    fn test_nonce_uniqueness() {
        let vault = create_temp_vault();
        let dek = test_dek();
        let plaintext = b"Same content";

        // Write multiple blobs with same content
        let mut nonces = Vec::new();
        for _ in 0..100 {
            let uuid = Uuid::new_v4();
            write_blob(vault.path(), uuid, &dek, plaintext).unwrap();

            // Read nonce from blob
            let info = read_blob_info(vault.path(), uuid).unwrap();
            nonces.push(info.nonce);
        }

        // All nonces should be unique
        let unique_nonces: std::collections::HashSet<_> = nonces.iter().collect();
        assert_eq!(unique_nonces.len(), nonces.len(), "All nonces should be unique");
    }

    // ==========================================
    // Edge Cases
    // ==========================================

    #[test]
    fn test_overwrite_existing_blob() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext1 = b"Original content";
        let plaintext2 = b"Updated content";

        // Write first blob
        write_blob(vault.path(), uuid, &dek, plaintext1).unwrap();
        let content1 = read_blob(vault.path(), uuid, &dek).unwrap();
        assert_eq!(content1, plaintext1);

        // Overwrite with new content
        write_blob(vault.path(), uuid, &dek, plaintext2).unwrap();
        let content2 = read_blob(vault.path(), uuid, &dek).unwrap();
        assert_eq!(content2, plaintext2);
    }

    #[test]
    fn test_blob_with_binary_content() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();

        // Binary content with all possible byte values
        let plaintext: Vec<u8> = (0..=255).collect();

        write_blob(vault.path(), uuid, &dek, &plaintext).unwrap();
        let decrypted = read_blob(vault.path(), uuid, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_blob_with_null_bytes() {
        let vault = create_temp_vault();
        let uuid = Uuid::new_v4();
        let dek = test_dek();
        let plaintext = b"Hello\0World\0\0\0";

        write_blob(vault.path(), uuid, &dek, plaintext).unwrap();
        let decrypted = read_blob(vault.path(), uuid, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // ==========================================
    // Constants Tests
    // ==========================================

    #[test]
    fn test_constants() {
        assert_eq!(BLOB_NONCE_SIZE, 12);
        assert_eq!(BLOB_TAG_SIZE, 16);
        assert_eq!(MIN_BLOB_SIZE, 12 + 16); // nonce + tag
        assert_eq!(BLOB_EXTENSION, "blob");
        assert_eq!(BLOBS_DIR, ".blobs");
    }
}
