//! Encrypted metadata storage.
//!
//! Stores encrypted file metadata including names, paths, and timestamps.
//! All sensitive information (filenames, paths) is encrypted with the level-specific
//! KEK (Key Encryption Key) to ensure no plaintext leakage.
//!
//! # Metadata Directory Structure
//!
//! ```text
//! vault/
//! └── .metadata/
//!     ├── 550e8400-e29b-41d4-a716-446655440000.meta
//!     └── 6ba7b810-9dad-11d1-80b4-00c04fd430c8.meta
//! ```
//!
//! # Encrypted Metadata Format
//!
//! ```text
//! +------------+-------------------+----------+
//! | Nonce(12B) | Ciphertext (var)  | Tag(16B) |
//! +------------+-------------------+----------+
//! ```
//!
//! The ciphertext contains the bincode-serialized `MetadataPlaintext` structure.
//!
//! # Security
//!
//! - Filenames and paths are encrypted, never stored in plaintext
//! - Each metadata file uses a unique nonce
//! - File UUID is used as AAD (Additional Authenticated Data)
//! - Access level is stored encrypted to prevent level enumeration
//! - Timestamps are also encrypted to prevent timing analysis
//!
//! # Example
//!
//! ```ignore
//! use tesseract_core::metadata::{FileMetadata, write_metadata, read_metadata};
//! use uuid::Uuid;
//!
//! let file_uuid = Uuid::new_v4();
//! let kek = [0x42u8; 32];
//! let metadata = FileMetadata::new(
//!     file_uuid,
//!     "secret_document.txt".to_string(),
//!     "/confidential/secret_document.txt".to_string(),
//!     2, // Access level
//!     1024, // File size
//!     file_uuid, // Blob reference
//! );
//!
//! // Write encrypted metadata
//! write_metadata(&vault_path, &metadata, &kek)?;
//!
//! // Read and decrypt metadata
//! let decrypted = read_metadata(&vault_path, file_uuid, &kek)?;
//! assert_eq!(decrypted.plaintext.name, "secret_document.txt");
//! ```

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use tesseract_crypto::aes::{decrypt, encrypt, KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH};
use tesseract_crypto::random::generate_nonce;

use crate::VaultError;

// ============================================
// Constants
// ============================================

/// Directory name for metadata storage within the vault.
pub const METADATA_DIR: &str = ".metadata";

/// File extension for metadata files.
pub const METADATA_EXTENSION: &str = "meta";

/// Minimum metadata file size: nonce + tag (empty serialized data)
pub const MIN_METADATA_SIZE: usize = NONCE_LENGTH + TAG_LENGTH;

/// Size of the nonce prefix in a metadata file
pub const METADATA_NONCE_SIZE: usize = NONCE_LENGTH;

/// Size of the authentication tag
pub const METADATA_TAG_SIZE: usize = TAG_LENGTH;

// ============================================
// Plaintext Metadata Structure
// ============================================

/// The plaintext metadata structure that gets encrypted.
///
/// This structure contains all sensitive file information that must
/// be protected. It is serialized with bincode before encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataPlaintext {
    /// Original file name (encrypted)
    pub name: String,

    /// Virtual path within the vault (encrypted)
    pub path: String,

    /// Access level required to view this file
    pub access_level: u32,

    /// File creation timestamp (Unix epoch seconds)
    pub created_at: u64,

    /// Last modification timestamp (Unix epoch seconds)
    pub modified_at: u64,

    /// File size in bytes
    pub size: u64,

    /// UUID of the associated blob file
    pub blob_ref: Uuid,
}

impl MetadataPlaintext {
    /// Creates a new plaintext metadata entry.
    ///
    /// # Arguments
    ///
    /// * `name` - Original filename
    /// * `path` - Virtual path within the vault
    /// * `access_level` - Required access level
    /// * `size` - File size in bytes
    /// * `blob_ref` - UUID of the associated blob
    pub fn new(
        name: String,
        path: String,
        access_level: u32,
        size: u64,
        blob_ref: Uuid,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            name,
            path,
            access_level,
            created_at: now,
            modified_at: now,
            size,
            blob_ref,
        }
    }

    /// Creates metadata with specific timestamps.
    ///
    /// Useful for testing or importing files with preserved timestamps.
    pub fn with_timestamps(
        name: String,
        path: String,
        access_level: u32,
        created_at: u64,
        modified_at: u64,
        size: u64,
        blob_ref: Uuid,
    ) -> Self {
        Self {
            name,
            path,
            access_level,
            created_at,
            modified_at,
            size,
            blob_ref,
        }
    }

    /// Returns the filename without the path.
    pub fn filename(&self) -> &str {
        self.path
            .rsplit('/')
            .next()
            .unwrap_or(&self.name)
    }

    /// Returns the parent directory path.
    pub fn parent_path(&self) -> &str {
        self.path
            .rfind('/')
            .map(|idx| &self.path[..idx])
            .unwrap_or("/")
    }

    /// Updates the modified timestamp to now.
    pub fn touch(&mut self) {
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(self.modified_at);
    }

    /// Serializes the metadata to bincode bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self)
            .map_err(|e| VaultError::SerializationError(e.to_string()))
    }

    /// Deserializes metadata from bincode bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, VaultError> {
        bincode::deserialize(bytes)
            .map_err(|e| VaultError::SerializationError(e.to_string()))
    }
}

// ============================================
// Encrypted Metadata Handle
// ============================================

/// Represents encrypted file metadata.
///
/// This structure contains the file UUID and the decrypted plaintext
/// metadata after successful decryption.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// File UUID (used for naming and AAD)
    pub uuid: Uuid,

    /// Decrypted metadata content
    pub plaintext: MetadataPlaintext,
}

impl FileMetadata {
    /// Creates a new file metadata entry.
    ///
    /// # Arguments
    ///
    /// * `uuid` - Unique file identifier
    /// * `name` - Original filename
    /// * `path` - Virtual path within the vault
    /// * `access_level` - Required access level
    /// * `size` - File size in bytes
    /// * `blob_ref` - UUID of the associated blob
    pub fn new(
        uuid: Uuid,
        name: String,
        path: String,
        access_level: u32,
        size: u64,
        blob_ref: Uuid,
    ) -> Self {
        Self {
            uuid,
            plaintext: MetadataPlaintext::new(name, path, access_level, size, blob_ref),
        }
    }

    /// Creates a new file metadata entry from an existing plaintext.
    ///
    /// # Arguments
    ///
    /// * `uuid` - Unique file identifier
    /// * `plaintext` - Pre-constructed metadata plaintext
    pub fn from_plaintext(uuid: Uuid, plaintext: MetadataPlaintext) -> Self {
        Self { uuid, plaintext }
    }

    /// Creates metadata with specific timestamps.
    pub fn with_timestamps(
        uuid: Uuid,
        name: String,
        path: String,
        access_level: u32,
        created_at: u64,
        modified_at: u64,
        size: u64,
        blob_ref: Uuid,
    ) -> Self {
        Self {
            uuid,
            plaintext: MetadataPlaintext::with_timestamps(
                name,
                path,
                access_level,
                created_at,
                modified_at,
                size,
                blob_ref,
            ),
        }
    }

    /// Convenience accessor for the file name.
    pub fn name(&self) -> &str {
        &self.plaintext.name
    }

    /// Convenience accessor for the virtual path.
    pub fn path(&self) -> &str {
        &self.plaintext.path
    }

    /// Convenience accessor for the access level.
    pub fn access_level(&self) -> u32 {
        self.plaintext.access_level
    }

    /// Convenience accessor for the file size.
    pub fn size(&self) -> u64 {
        self.plaintext.size
    }

    /// Convenience accessor for the blob reference.
    pub fn blob_ref(&self) -> Uuid {
        self.plaintext.blob_ref
    }

    /// Convenience accessor for created timestamp.
    pub fn created_at(&self) -> u64 {
        self.plaintext.created_at
    }

    /// Convenience accessor for modified timestamp.
    pub fn modified_at(&self) -> u64 {
        self.plaintext.modified_at
    }
}

// ============================================
// Metadata Info Structure
// ============================================

/// Information about an encrypted metadata file (without decryption).
#[derive(Debug, Clone)]
pub struct MetadataInfo {
    /// File UUID
    pub file_uuid: Uuid,
    /// Nonce used for encryption
    pub nonce: [u8; NONCE_LENGTH],
    /// Size of the encrypted content
    pub encrypted_size: usize,
}

impl MetadataInfo {
    /// Creates metadata info from raw components.
    pub fn new(file_uuid: Uuid, nonce: [u8; NONCE_LENGTH], encrypted_size: usize) -> Self {
        Self {
            file_uuid,
            nonce,
            encrypted_size,
        }
    }

    /// Returns the total file size on disk.
    pub fn file_size(&self) -> usize {
        NONCE_LENGTH + self.encrypted_size
    }
}

// ============================================
// Path Utilities
// ============================================

/// Returns the path to the metadata directory within a vault.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
///
/// # Returns
///
/// Path to `.metadata/` directory
pub fn metadata_dir(vault_path: &Path) -> PathBuf {
    vault_path.join(METADATA_DIR)
}

/// Returns the path to a specific metadata file.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Returns
///
/// Path to the metadata file (e.g., `.metadata/550e8400-e29b-41d4-a716-446655440000.meta`)
pub fn metadata_path(vault_path: &Path, file_uuid: Uuid) -> PathBuf {
    let filename = format!("{}.{}", file_uuid.hyphenated(), METADATA_EXTENSION);
    metadata_dir(vault_path).join(filename)
}

/// Ensures the metadata directory exists.
///
/// Creates the `.metadata/` directory if it doesn't exist.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
///
/// # Errors
///
/// Returns `VaultError::IoError` if directory creation fails.
pub fn ensure_metadata_dir(vault_path: &Path) -> Result<(), VaultError> {
    let dir = metadata_dir(vault_path);
    fs::create_dir_all(&dir)?;
    Ok(())
}

/// Checks if a metadata file exists for a given UUID.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Returns
///
/// `true` if the metadata file exists, `false` otherwise
pub fn metadata_exists(vault_path: &Path, file_uuid: Uuid) -> bool {
    metadata_path(vault_path, file_uuid).exists()
}

// ============================================
// Metadata Write Operations
// ============================================

/// Writes encrypted file metadata.
///
/// Encrypts the metadata with the provided KEK and writes it to the
/// `.metadata/` directory.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `metadata` - File metadata to encrypt and store
/// * `kek` - Key Encryption Key (32-byte AES-256 key)
///
/// # Returns
///
/// Path to the created metadata file.
///
/// # Errors
///
/// * `VaultError::CryptoError` - If encryption fails
/// * `VaultError::IoError` - If file creation fails
/// * `VaultError::SerializationError` - If serialization fails
///
/// # Security
///
/// - Generates a unique nonce for each metadata file
/// - Uses file UUID as AAD for authenticated binding
pub fn write_metadata(
    vault_path: &Path,
    metadata: &FileMetadata,
    kek: &[u8; KEY_LENGTH],
) -> Result<PathBuf, VaultError> {
    let nonce = generate_nonce()?;
    write_metadata_with_nonce(vault_path, metadata, kek, &nonce)
}

/// Writes encrypted metadata with a specific nonce.
///
/// This is primarily for testing to ensure deterministic output.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `metadata` - File metadata to encrypt and store
/// * `kek` - Key Encryption Key (32-byte AES-256 key)
/// * `nonce` - Specific nonce to use
///
/// # Returns
///
/// Path to the created metadata file.
pub fn write_metadata_with_nonce(
    vault_path: &Path,
    metadata: &FileMetadata,
    kek: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
) -> Result<PathBuf, VaultError> {
    // Ensure metadata directory exists
    ensure_metadata_dir(vault_path)?;

    // Serialize the plaintext metadata
    let plaintext = metadata.plaintext.serialize()?;

    // Use file UUID as AAD to bind metadata to specific file
    let aad = metadata.uuid.as_bytes();

    // Encrypt the serialized metadata
    let ciphertext = encrypt(kek, nonce, &plaintext, aad)?;

    // Construct the file path
    let path = metadata_path(vault_path, metadata.uuid);

    // Write: [nonce][ciphertext (includes tag)]
    let mut file = File::create(&path)?;
    file.write_all(nonce)?;
    file.write_all(&ciphertext)?;
    file.sync_all()?;

    Ok(path)
}

// ============================================
// Metadata Read Operations
// ============================================

/// Reads and decrypts file metadata.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
/// * `kek` - Key Encryption Key (32-byte AES-256 key)
///
/// # Returns
///
/// Decrypted file metadata.
///
/// # Errors
///
/// * `VaultError::FileNotFound` - If metadata file doesn't exist
/// * `VaultError::CryptoError` - If decryption fails (wrong key or tampered)
/// * `VaultError::IoError` - If file read fails
/// * `VaultError::SerializationError` - If deserialization fails
pub fn read_metadata(
    vault_path: &Path,
    file_uuid: Uuid,
    kek: &[u8; KEY_LENGTH],
) -> Result<FileMetadata, VaultError> {
    let path = metadata_path(vault_path, file_uuid);

    if !path.exists() {
        return Err(VaultError::FileNotFound(file_uuid.to_string()));
    }

    // Read the entire file
    let mut file = File::open(&path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Validate minimum size
    if buffer.len() < MIN_METADATA_SIZE {
        return Err(VaultError::InvalidFormat(format!(
            "Metadata file too small: {} bytes (minimum {})",
            buffer.len(),
            MIN_METADATA_SIZE
        )));
    }

    // Extract nonce (first 12 bytes)
    let nonce: [u8; NONCE_LENGTH] = buffer[..NONCE_LENGTH]
        .try_into()
        .map_err(|_| VaultError::InvalidFormat("Invalid nonce in metadata".to_string()))?;

    // Extract ciphertext (rest of file)
    let ciphertext = &buffer[NONCE_LENGTH..];

    // Use file UUID as AAD
    let aad = file_uuid.as_bytes();

    // Decrypt
    let plaintext_bytes = decrypt(kek, &nonce, ciphertext, aad)?;

    // Deserialize
    let plaintext = MetadataPlaintext::deserialize(&plaintext_bytes)?;

    Ok(FileMetadata {
        uuid: file_uuid,
        plaintext,
    })
}

/// Reads metadata info without decryption.
///
/// This allows checking metadata existence and size without
/// needing the decryption key.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Returns
///
/// Metadata info (nonce, encrypted size).
///
/// # Errors
///
/// * `VaultError::FileNotFound` - If metadata file doesn't exist
/// * `VaultError::IoError` - If file read fails
/// * `VaultError::InvalidFormat` - If file format is invalid
pub fn read_metadata_info(
    vault_path: &Path,
    file_uuid: Uuid,
) -> Result<MetadataInfo, VaultError> {
    let path = metadata_path(vault_path, file_uuid);

    if !path.exists() {
        return Err(VaultError::FileNotFound(file_uuid.to_string()));
    }

    // Read just the header
    let mut file = File::open(&path)?;
    let file_size = file.metadata()?.len() as usize;

    if file_size < MIN_METADATA_SIZE {
        return Err(VaultError::InvalidFormat(format!(
            "Metadata file too small: {} bytes",
            file_size
        )));
    }

    let mut nonce = [0u8; NONCE_LENGTH];
    file.read_exact(&mut nonce)?;

    let encrypted_size = file_size - NONCE_LENGTH;

    Ok(MetadataInfo::new(file_uuid, nonce, encrypted_size))
}

// ============================================
// Metadata Delete Operations
// ============================================

/// Deletes a metadata file.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Errors
///
/// * `VaultError::FileNotFound` - If metadata file doesn't exist
/// * `VaultError::IoError` - If deletion fails
pub fn delete_metadata(vault_path: &Path, file_uuid: Uuid) -> Result<(), VaultError> {
    let path = metadata_path(vault_path, file_uuid);

    if !path.exists() {
        return Err(VaultError::FileNotFound(file_uuid.to_string()));
    }

    fs::remove_file(&path)?;
    Ok(())
}

// ============================================
// Metadata List Operations
// ============================================

/// Lists all metadata file UUIDs in the vault.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
///
/// # Returns
///
/// Vector of file UUIDs that have metadata entries.
///
/// # Errors
///
/// * `VaultError::IoError` - If directory reading fails
pub fn list_metadata(vault_path: &Path) -> Result<Vec<Uuid>, VaultError> {
    let dir = metadata_dir(vault_path);

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut uuids = Vec::new();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(ext) = path.extension() {
            if ext == METADATA_EXTENSION {
                if let Some(stem) = path.file_stem() {
                    if let Some(stem_str) = stem.to_str() {
                        if let Ok(uuid) = Uuid::parse_str(stem_str) {
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
// Metadata Update Operations
// ============================================

/// Updates file metadata (re-encrypts with new values).
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `metadata` - Updated file metadata
/// * `kek` - Key Encryption Key
///
/// # Returns
///
/// Path to the updated metadata file.
///
/// # Errors
///
/// Returns errors if re-encryption or writing fails.
pub fn update_metadata(
    vault_path: &Path,
    metadata: &FileMetadata,
    kek: &[u8; KEY_LENGTH],
) -> Result<PathBuf, VaultError> {
    // Simply re-write with a new nonce
    write_metadata(vault_path, metadata, kek)
}

/// Renames a file in metadata.
///
/// Reads existing metadata, updates the name, and re-encrypts.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file to rename
/// * `new_name` - New filename
/// * `kek` - Key Encryption Key
///
/// # Returns
///
/// Updated file metadata.
pub fn rename_file(
    vault_path: &Path,
    file_uuid: Uuid,
    new_name: String,
    kek: &[u8; KEY_LENGTH],
) -> Result<FileMetadata, VaultError> {
    let mut metadata = read_metadata(vault_path, file_uuid, kek)?;

    // Update path to reflect new name
    let parent = metadata.plaintext.parent_path().to_string();
    metadata.plaintext.name = new_name.clone();
    metadata.plaintext.path = if parent == "/" {
        format!("/{}", new_name)
    } else {
        format!("{}/{}", parent, new_name)
    };
    metadata.plaintext.touch();

    update_metadata(vault_path, &metadata, kek)?;

    Ok(metadata)
}

/// Moves a file to a new path in metadata.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file to move
/// * `new_path` - New virtual path
/// * `kek` - Key Encryption Key
///
/// # Returns
///
/// Updated file metadata.
pub fn move_file(
    vault_path: &Path,
    file_uuid: Uuid,
    new_path: String,
    kek: &[u8; KEY_LENGTH],
) -> Result<FileMetadata, VaultError> {
    let mut metadata = read_metadata(vault_path, file_uuid, kek)?;

    // Extract new name from path
    let new_name = new_path
        .rsplit('/')
        .next()
        .unwrap_or(&metadata.plaintext.name)
        .to_string();

    metadata.plaintext.name = new_name;
    metadata.plaintext.path = new_path;
    metadata.plaintext.touch();

    update_metadata(vault_path, &metadata, kek)?;

    Ok(metadata)
}

/// Changes the access level of a file.
///
/// Note: This only updates metadata. The caller is responsible for
/// re-wrapping the DEK with the new level's KEK.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
/// * `new_level` - New access level
/// * `kek` - Key Encryption Key (must have access to current level)
///
/// # Returns
///
/// Updated file metadata.
pub fn change_access_level(
    vault_path: &Path,
    file_uuid: Uuid,
    new_level: u32,
    kek: &[u8; KEY_LENGTH],
) -> Result<FileMetadata, VaultError> {
    let mut metadata = read_metadata(vault_path, file_uuid, kek)?;

    metadata.plaintext.access_level = new_level;
    metadata.plaintext.touch();

    update_metadata(vault_path, &metadata, kek)?;

    Ok(metadata)
}

// ============================================
// Verification Utilities
// ============================================

/// Verifies metadata integrity without returning contents.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
/// * `kek` - Key Encryption Key
///
/// # Returns
///
/// `Ok(())` if metadata decrypts and deserializes successfully.
pub fn verify_metadata(
    vault_path: &Path,
    file_uuid: Uuid,
    kek: &[u8; KEY_LENGTH],
) -> Result<(), VaultError> {
    read_metadata(vault_path, file_uuid, kek)?;
    Ok(())
}

/// Scans raw bytes for plaintext patterns.
///
/// This is a security audit helper to verify no plaintext leakage.
///
/// # Arguments
///
/// * `data` - Raw bytes to scan
/// * `patterns` - Patterns to search for
///
/// # Returns
///
/// `true` if any pattern is found, `false` otherwise.
pub fn contains_plaintext_patterns(data: &[u8], patterns: &[&str]) -> bool {
    for pattern in patterns {
        let pattern_bytes = pattern.as_bytes();
        if data.windows(pattern_bytes.len()).any(|w| w == pattern_bytes) {
            return true;
        }
    }
    false
}

/// Reads raw metadata file bytes for security auditing.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `file_uuid` - UUID of the file
///
/// # Returns
///
/// Raw bytes of the metadata file.
pub fn read_raw_metadata(vault_path: &Path, file_uuid: Uuid) -> Result<Vec<u8>, VaultError> {
    let path = metadata_path(vault_path, file_uuid);

    if !path.exists() {
        return Err(VaultError::FileNotFound(file_uuid.to_string()));
    }

    let mut file = File::open(&path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    Ok(buffer)
}

// ============================================
// Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tesseract_crypto::random::{generate_key, generate_uuid};

    // ============================================
    // Path Utility Tests
    // ============================================

    #[test]
    fn test_metadata_dir() {
        let vault = Path::new("/vault");
        assert_eq!(metadata_dir(vault), PathBuf::from("/vault/.metadata"));
    }

    #[test]
    fn test_metadata_path() {
        let vault = Path::new("/vault");
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let path = metadata_path(vault, uuid);
        assert_eq!(
            path,
            PathBuf::from("/vault/.metadata/550e8400-e29b-41d4-a716-446655440000.meta")
        );
    }

    #[test]
    fn test_ensure_metadata_dir() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();

        assert!(!metadata_dir(vault_path).exists());
        ensure_metadata_dir(vault_path).unwrap();
        assert!(metadata_dir(vault_path).exists());
    }

    #[test]
    fn test_metadata_exists() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        assert!(!metadata_exists(vault_path, file_uuid));

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek).unwrap();

        assert!(metadata_exists(vault_path, file_uuid));
    }

    // ============================================
    // MetadataPlaintext Tests
    // ============================================

    #[test]
    fn test_metadata_plaintext_new() {
        let blob_ref = generate_uuid().unwrap();
        let plaintext = MetadataPlaintext::new(
            "secret.txt".to_string(),
            "/documents/secret.txt".to_string(),
            2,
            1024,
            blob_ref,
        );

        assert_eq!(plaintext.name, "secret.txt");
        assert_eq!(plaintext.path, "/documents/secret.txt");
        assert_eq!(plaintext.access_level, 2);
        assert_eq!(plaintext.size, 1024);
        assert_eq!(plaintext.blob_ref, blob_ref);
        assert!(plaintext.created_at > 0);
        assert_eq!(plaintext.created_at, plaintext.modified_at);
    }

    #[test]
    fn test_metadata_plaintext_with_timestamps() {
        let blob_ref = generate_uuid().unwrap();
        let plaintext = MetadataPlaintext::with_timestamps(
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            1000,
            2000,
            512,
            blob_ref,
        );

        assert_eq!(plaintext.created_at, 1000);
        assert_eq!(plaintext.modified_at, 2000);
    }

    #[test]
    fn test_metadata_plaintext_filename() {
        let blob_ref = generate_uuid().unwrap();
        let plaintext = MetadataPlaintext::new(
            "file.pdf".to_string(),
            "/a/b/c/file.pdf".to_string(),
            1,
            100,
            blob_ref,
        );

        assert_eq!(plaintext.filename(), "file.pdf");
    }

    #[test]
    fn test_metadata_plaintext_parent_path() {
        let blob_ref = generate_uuid().unwrap();

        let plaintext1 = MetadataPlaintext::new(
            "file.pdf".to_string(),
            "/a/b/c/file.pdf".to_string(),
            1,
            100,
            blob_ref,
        );
        assert_eq!(plaintext1.parent_path(), "/a/b/c");

        let plaintext2 = MetadataPlaintext::new(
            "root.txt".to_string(),
            "/root.txt".to_string(),
            1,
            100,
            blob_ref,
        );
        assert_eq!(plaintext2.parent_path(), "");
    }

    #[test]
    fn test_metadata_plaintext_touch() {
        let blob_ref = generate_uuid().unwrap();
        let mut plaintext = MetadataPlaintext::with_timestamps(
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            1000,
            1000,
            100,
            blob_ref,
        );

        let old_modified = plaintext.modified_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        plaintext.touch();

        assert!(plaintext.modified_at >= old_modified);
    }

    #[test]
    fn test_metadata_plaintext_serialization() {
        let blob_ref = generate_uuid().unwrap();
        let plaintext = MetadataPlaintext::with_timestamps(
            "test.txt".to_string(),
            "/folder/test.txt".to_string(),
            3,
            1000,
            2000,
            4096,
            blob_ref,
        );

        let serialized = plaintext.serialize().unwrap();
        let deserialized = MetadataPlaintext::deserialize(&serialized).unwrap();

        assert_eq!(plaintext, deserialized);
    }

    // ============================================
    // FileMetadata Tests
    // ============================================

    #[test]
    fn test_file_metadata_new() {
        let uuid = generate_uuid().unwrap();
        let blob_ref = generate_uuid().unwrap();

        let metadata = FileMetadata::new(
            uuid,
            "secret.txt".to_string(),
            "/documents/secret.txt".to_string(),
            2,
            1024,
            blob_ref,
        );

        assert_eq!(metadata.uuid, uuid);
        assert_eq!(metadata.name(), "secret.txt");
        assert_eq!(metadata.path(), "/documents/secret.txt");
        assert_eq!(metadata.access_level(), 2);
        assert_eq!(metadata.size(), 1024);
        assert_eq!(metadata.blob_ref(), blob_ref);
    }

    #[test]
    fn test_file_metadata_with_timestamps() {
        let uuid = generate_uuid().unwrap();
        let blob_ref = generate_uuid().unwrap();

        let metadata = FileMetadata::with_timestamps(
            uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            1000,
            2000,
            512,
            blob_ref,
        );

        assert_eq!(metadata.created_at(), 1000);
        assert_eq!(metadata.modified_at(), 2000);
    }

    // ============================================
    // Write/Read Roundtrip Tests
    // ============================================

    #[test]
    fn test_write_read_roundtrip() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();
        let blob_ref = generate_uuid().unwrap();

        let original = FileMetadata::new(
            file_uuid,
            "confidential.doc".to_string(),
            "/secrets/confidential.doc".to_string(),
            3,
            65536,
            blob_ref,
        );

        // Write
        let path = write_metadata(vault_path, &original, &kek).unwrap();
        assert!(path.exists());

        // Read
        let decrypted = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(decrypted.uuid, original.uuid);
        assert_eq!(decrypted.name(), original.name());
        assert_eq!(decrypted.path(), original.path());
        assert_eq!(decrypted.access_level(), original.access_level());
        assert_eq!(decrypted.size(), original.size());
        assert_eq!(decrypted.blob_ref(), original.blob_ref());
    }

    #[test]
    fn test_write_read_empty_strings() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let original = FileMetadata::new(
            file_uuid,
            "".to_string(),
            "".to_string(),
            0,
            0,
            file_uuid,
        );

        write_metadata(vault_path, &original, &kek).unwrap();
        let decrypted = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(decrypted.name(), "");
        assert_eq!(decrypted.path(), "");
    }

    #[test]
    fn test_write_read_unicode() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let original = FileMetadata::new(
            file_uuid,
            "文件名_🔐.txt".to_string(),
            "/目录/文件名_🔐.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &original, &kek).unwrap();
        let decrypted = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(decrypted.name(), "文件名_🔐.txt");
        assert_eq!(decrypted.path(), "/目录/文件名_🔐.txt");
    }

    #[test]
    fn test_write_read_long_path() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let long_name = "a".repeat(255);
        let long_path = format!("/{}/{}/{}", "dir".repeat(50), "subdir".repeat(50), long_name);

        let original = FileMetadata::new(
            file_uuid,
            long_name.clone(),
            long_path.clone(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &original, &kek).unwrap();
        let decrypted = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(decrypted.name(), long_name);
        assert_eq!(decrypted.path(), long_path);
    }

    // ============================================
    // Error Handling Tests
    // ============================================

    #[test]
    fn test_read_nonexistent_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let result = read_metadata(vault_path, file_uuid, &kek);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_read_wrong_key() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek1 = generate_key().unwrap();
        let kek2 = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek1).unwrap();
        let result = read_metadata(vault_path, file_uuid, &kek2);

        assert!(result.is_err());
    }

    #[test]
    fn test_read_wrong_uuid_aad_mismatch() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let other_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        // Rename the file to have a different UUID
        let src = metadata_path(vault_path, file_uuid);
        let dst = metadata_path(vault_path, other_uuid);
        fs::rename(src, dst).unwrap();

        // Reading with the wrong UUID should fail (AAD mismatch)
        let result = read_metadata(vault_path, other_uuid, &kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_tampered_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        // Tamper with the file
        let path = metadata_path(vault_path, file_uuid);
        let mut data = fs::read(&path).unwrap();
        if let Some(byte) = data.get_mut(NONCE_LENGTH + 5) {
            *byte ^= 0xFF;
        }
        fs::write(&path, &data).unwrap();

        let result = read_metadata(vault_path, file_uuid, &kek);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_truncated_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        // Truncate the file
        let path = metadata_path(vault_path, file_uuid);
        let data = fs::read(&path).unwrap();
        fs::write(&path, &data[..10]).unwrap();

        let result = read_metadata(vault_path, file_uuid, &kek);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    // ============================================
    // Delete Tests
    // ============================================

    #[test]
    fn test_delete_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();
        assert!(metadata_exists(vault_path, file_uuid));

        delete_metadata(vault_path, file_uuid).unwrap();
        assert!(!metadata_exists(vault_path, file_uuid));
    }

    #[test]
    fn test_delete_nonexistent_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();

        let result = delete_metadata(vault_path, file_uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    // ============================================
    // List Tests
    // ============================================

    #[test]
    fn test_list_metadata_empty() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();

        let uuids = list_metadata(vault_path).unwrap();
        assert!(uuids.is_empty());
    }

    #[test]
    fn test_list_metadata_multiple() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let kek = generate_key().unwrap();

        let mut expected_uuids = Vec::new();
        for i in 0..5 {
            let file_uuid = generate_uuid().unwrap();
            expected_uuids.push(file_uuid);

            let metadata = FileMetadata::new(
                file_uuid,
                format!("file{}.txt", i),
                format!("/file{}.txt", i),
                1,
                100,
                file_uuid,
            );
            write_metadata(vault_path, &metadata, &kek).unwrap();
        }

        let listed = list_metadata(vault_path).unwrap();
        assert_eq!(listed.len(), 5);

        for uuid in expected_uuids {
            assert!(listed.contains(&uuid));
        }
    }

    #[test]
    fn test_list_ignores_invalid_files() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let kek = generate_key().unwrap();
        let file_uuid = generate_uuid().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek).unwrap();

        // Add some invalid files
        let meta_dir = metadata_dir(vault_path);
        fs::write(meta_dir.join("not-a-uuid.meta"), "invalid").unwrap();
        fs::write(meta_dir.join("12345.txt"), "wrong extension").unwrap();
        fs::write(meta_dir.join("readme.md"), "not a meta file").unwrap();

        let listed = list_metadata(vault_path).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed.contains(&file_uuid));
    }

    // ============================================
    // MetadataInfo Tests
    // ============================================

    #[test]
    fn test_read_metadata_info() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        let info = read_metadata_info(vault_path, file_uuid).unwrap();
        assert_eq!(info.file_uuid, file_uuid);
        assert!(info.encrypted_size > 0);
        assert_eq!(info.file_size(), NONCE_LENGTH + info.encrypted_size);
    }

    // ============================================
    // Update Tests
    // ============================================

    #[test]
    fn test_rename_file() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "original.txt".to_string(),
            "/folder/original.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek).unwrap();

        let renamed = rename_file(vault_path, file_uuid, "renamed.txt".to_string(), &kek).unwrap();

        assert_eq!(renamed.name(), "renamed.txt");
        assert_eq!(renamed.path(), "/folder/renamed.txt");
    }

    #[test]
    fn test_move_file() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "file.txt".to_string(),
            "/old/path/file.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek).unwrap();

        let moved = move_file(vault_path, file_uuid, "/new/location/moved.txt".to_string(), &kek).unwrap();

        assert_eq!(moved.name(), "moved.txt");
        assert_eq!(moved.path(), "/new/location/moved.txt");
    }

    #[test]
    fn test_change_access_level() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "file.txt".to_string(),
            "/file.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek).unwrap();

        let changed = change_access_level(vault_path, file_uuid, 3, &kek).unwrap();

        assert_eq!(changed.access_level(), 3);
    }

    // ============================================
    // Verification Tests
    // ============================================

    #[test]
    fn test_verify_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek).unwrap();

        assert!(verify_metadata(vault_path, file_uuid, &kek).is_ok());
    }

    #[test]
    fn test_verify_metadata_fails_with_wrong_key() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek1 = generate_key().unwrap();
        let kek2 = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &metadata, &kek1).unwrap();

        assert!(verify_metadata(vault_path, file_uuid, &kek2).is_err());
    }

    // ============================================
    // Plaintext Leakage Tests (Security Critical)
    // ============================================

    #[test]
    fn test_no_plaintext_filename_leakage() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let secret_name = "TOP_SECRET_CONFIDENTIAL.doc";
        let metadata = FileMetadata::new(
            file_uuid,
            secret_name.to_string(),
            format!("/classified/{}", secret_name),
            3,
            1024,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        // Read raw bytes
        let raw_bytes = read_raw_metadata(vault_path, file_uuid).unwrap();

        // Search for plaintext patterns
        assert!(
            !contains_plaintext_patterns(&raw_bytes, &[secret_name]),
            "Plaintext filename found in encrypted metadata!"
        );
    }

    #[test]
    fn test_no_plaintext_path_leakage() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let secret_path = "/sensitive/documents/nuclear_codes";
        let metadata = FileMetadata::new(
            file_uuid,
            "codes.txt".to_string(),
            format!("{}/codes.txt", secret_path),
            3,
            1024,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        let raw_bytes = read_raw_metadata(vault_path, file_uuid).unwrap();

        assert!(
            !contains_plaintext_patterns(&raw_bytes, &["sensitive", "documents", "nuclear", "codes"]),
            "Plaintext path components found in encrypted metadata!"
        );
    }

    #[test]
    fn test_comprehensive_no_plaintext_leakage() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let kek = generate_key().unwrap();

        // Create multiple files with various sensitive names
        let test_cases = vec![
            ("bank_account_password.txt", "/finances/bank_account_password.txt"),
            ("social_security_number.doc", "/personal/ssn/social_security_number.doc"),
            ("private_keys.pem", "/crypto/.ssh/private_keys.pem"),
            ("secret_recipe.pdf", "/business/trade_secrets/secret_recipe.pdf"),
        ];

        let mut all_raw_bytes = Vec::new();

        for (name, path) in &test_cases {
            let file_uuid = generate_uuid().unwrap();
            let metadata = FileMetadata::new(
                file_uuid,
                name.to_string(),
                path.to_string(),
                2,
                512,
                file_uuid,
            );
            write_metadata(vault_path, &metadata, &kek).unwrap();

            let raw = read_raw_metadata(vault_path, file_uuid).unwrap();
            all_raw_bytes.extend(raw);
        }

        // Check that none of the sensitive terms appear
        let sensitive_terms = vec![
            "bank", "account", "password", "social", "security", "number",
            "private", "keys", "secret", "recipe", "finances", "personal",
            "ssn", "crypto", "ssh", "business", "trade_secrets",
        ];

        for term in &sensitive_terms {
            assert!(
                !contains_plaintext_patterns(&all_raw_bytes, &[term]),
                "Found plaintext term '{}' in encrypted metadata!",
                term
            );
        }
    }

    #[test]
    fn test_hex_dump_shows_no_plaintext() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let very_distinctive_name = "ZZZZZ_UNIQUE_MARKER_12345_YYYYY";
        let metadata = FileMetadata::new(
            file_uuid,
            very_distinctive_name.to_string(),
            format!("/{}", very_distinctive_name),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();

        // Read the entire metadata directory
        let meta_dir = metadata_dir(vault_path);
        let mut all_bytes = Vec::new();

        for entry in fs::read_dir(&meta_dir).unwrap() {
            let entry = entry.unwrap();
            let content = fs::read(entry.path()).unwrap();
            all_bytes.extend(content);
        }

        // Convert to hex and search
        let hex_string: String = all_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        // The distinctive marker should NOT appear in plaintext
        assert!(
            !all_bytes.windows(very_distinctive_name.len()).any(|w| w == very_distinctive_name.as_bytes()),
            "Found plaintext marker in raw bytes!"
        );

        // Also check the ASCII representation
        let ascii_string: String = all_bytes.iter()
            .map(|&b| if b.is_ascii_alphanumeric() { b as char } else { '.' })
            .collect();

        assert!(
            !ascii_string.contains("UNIQUE_MARKER"),
            "Found plaintext in ASCII representation of encrypted metadata!"
        );
    }

    // ============================================
    // Nonce Uniqueness Tests
    // ============================================

    #[test]
    fn test_unique_nonces_for_each_write() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let kek = generate_key().unwrap();

        let mut nonces = std::collections::HashSet::new();

        for _ in 0..100 {
            let file_uuid = generate_uuid().unwrap();
            let metadata = FileMetadata::new(
                file_uuid,
                "test.txt".to_string(),
                "/test.txt".to_string(),
                1,
                100,
                file_uuid,
            );
            write_metadata(vault_path, &metadata, &kek).unwrap();

            let info = read_metadata_info(vault_path, file_uuid).unwrap();
            let inserted = nonces.insert(info.nonce);
            assert!(inserted, "Duplicate nonce detected!");
        }
    }

    // ============================================
    // Overwrite Tests
    // ============================================

    #[test]
    fn test_overwrite_metadata() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        // Write initial
        let initial = FileMetadata::new(
            file_uuid,
            "original.txt".to_string(),
            "/original.txt".to_string(),
            1,
            100,
            file_uuid,
        );
        write_metadata(vault_path, &initial, &kek).unwrap();

        // Overwrite
        let updated = FileMetadata::new(
            file_uuid,
            "updated.txt".to_string(),
            "/updated.txt".to_string(),
            2,
            200,
            file_uuid,
        );
        write_metadata(vault_path, &updated, &kek).unwrap();

        // Verify new content
        let read = read_metadata(vault_path, file_uuid, &kek).unwrap();
        assert_eq!(read.name(), "updated.txt");
        assert_eq!(read.access_level(), 2);
        assert_eq!(read.size(), 200);
    }

    // ============================================
    // Edge Case Tests
    // ============================================

    #[test]
    fn test_special_characters_in_name() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let special_name = "file with spaces & symbols! @#$%^.txt";
        let metadata = FileMetadata::new(
            file_uuid,
            special_name.to_string(),
            format!("/path to/{}", special_name),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();
        let read = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(read.name(), special_name);
    }

    #[test]
    fn test_null_bytes_in_content() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        // Name with embedded null (unusual but should work)
        let name_with_null = "file\x00name.txt";
        let metadata = FileMetadata::new(
            file_uuid,
            name_with_null.to_string(),
            format!("/{}", name_with_null),
            1,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();
        let read = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(read.name(), name_with_null);
    }

    #[test]
    fn test_max_access_level() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "test.txt".to_string(),
            "/test.txt".to_string(),
            u32::MAX,
            100,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();
        let read = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(read.access_level(), u32::MAX);
    }

    #[test]
    fn test_max_file_size() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let file_uuid = generate_uuid().unwrap();
        let kek = generate_key().unwrap();

        let metadata = FileMetadata::new(
            file_uuid,
            "huge.bin".to_string(),
            "/huge.bin".to_string(),
            1,
            u64::MAX,
            file_uuid,
        );

        write_metadata(vault_path, &metadata, &kek).unwrap();
        let read = read_metadata(vault_path, file_uuid, &kek).unwrap();

        assert_eq!(read.size(), u64::MAX);
    }

    // ============================================
    // Directory Listing Helper Tests
    // ============================================

    #[test]
    fn test_list_files_by_path() {
        let temp = TempDir::new().unwrap();
        let vault_path = temp.path();
        let kek = generate_key().unwrap();

        // Create files in different directories
        let files = vec![
            ("/documents/file1.txt", 1),
            ("/documents/file2.txt", 1),
            ("/images/photo.jpg", 2),
            ("/images/vacation/beach.png", 2),
            ("/root.txt", 1),
        ];

        for (path, level) in &files {
            let file_uuid = generate_uuid().unwrap();
            let name = path.rsplit('/').next().unwrap_or("unknown");
            let metadata = FileMetadata::new(
                file_uuid,
                name.to_string(),
                path.to_string(),
                *level,
                100,
                file_uuid,
            );
            write_metadata(vault_path, &metadata, &kek).unwrap();
        }

        // List all and verify we can read them all
        let uuids = list_metadata(vault_path).unwrap();
        assert_eq!(uuids.len(), 5);

        // Verify each can be read
        for uuid in uuids {
            let metadata = read_metadata(vault_path, uuid, &kek).unwrap();
            assert!(!metadata.name().is_empty());
        }
    }
}
