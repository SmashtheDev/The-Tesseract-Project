//! File operations.
//!
//! Provides import, export, delete, rename, move, and listing operations for vault files.
//!
//! # File Import
//!
//! The import process:
//! 1. Generate a unique UUID for the file
//! 2. Generate a unique DEK (Data Encryption Key) for the file
//! 3. Encrypt the file content to a blob with the DEK
//! 4. Create encrypted metadata with the level's KEK
//! 5. Wrap the DEK with the level's KEK and store in keystore
//! 6. Persist the updated keystore
//!
//! # File Export
//!
//! The export process:
//! 1. Locate the file's DEK in the appropriate level keystore
//! 2. Verify the session has access to the file's access level
//! 3. Read and decrypt the metadata to get file information
//! 4. Decrypt the DEK using the level's KEK
//! 5. Read and decrypt the blob using the DEK
//! 6. Write the decrypted content to the destination
//!
//! # File Deletion
//!
//! The deletion process:
//! 1. Locate the file's DEK entry in the appropriate level keystore
//! 2. Verify the session has access to the file's access level
//! 3. Remove the encrypted blob from .blobs/
//! 4. Remove the encrypted metadata from .metadata/
//! 5. Remove the DEK entry from the keystore
//! 6. Persist the updated keystore
//!
//! # File Rename and Move
//!
//! The rename/move process:
//! 1. Locate the file's DEK entry to find the access level
//! 2. Verify the session has access to the file's level
//! 3. Read and decrypt the current metadata
//! 4. Update the name and/or path in the metadata
//! 5. Re-encrypt and persist the updated metadata
//!
//! Note: Only metadata is modified; the encrypted blob remains unchanged.
//! The file's access level is preserved.
//!
//! # Directory Listing
//!
//! The listing process returns files accessible at the current session level:
//! 1. Iterate through all accessible keystores
//! 2. For each file UUID in the keystores, read and decrypt metadata
//! 3. Filter files by virtual path if specified
//! 4. Return FileEntry structs with decrypted metadata
//!
//! Virtual directories are supported - files can have paths like "/docs/reports/file.txt"
//! and listing "/docs" will show "reports" as a subdirectory and any files directly
//! in "/docs".
//!
//! # Examples
//!
//! ## Import a file
//!
//! ```ignore
//! use tesseract_core::files::import_file;
//! use tesseract_core::session::open_vault;
//!
//! let mut session = open_vault("/vault", b"password", None)?;
//! let file_uuid = import_file(
//!     &mut session,
//!     "/path/to/document.pdf",
//!     "/docs/document.pdf",
//!     2, // Access level
//! )?;
//! ```
//!
//! ## Export a file
//!
//! ```ignore
//! use tesseract_core::files::{export_file, export_to_bytes};
//! use tesseract_core::session::open_vault;
//!
//! let session = open_vault("/vault", b"password", None)?;
//!
//! // Export to filesystem
//! export_file(&session, file_uuid, "/path/to/output.pdf")?;
//!
//! // Or export to memory
//! let (content, metadata) = export_to_bytes(&session, file_uuid)?;
//! println!("Original filename: {}", metadata.plaintext.name);
//! ```

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write as IoWrite};
use std::path::Path;

use uuid::Uuid;

use crate::blob::{delete_blob, read_blob, write_blob};
use crate::error::VaultError;
use crate::keystore::{unwrap_dek, wrap_dek, DekEntry};
use crate::metadata::{delete_metadata, read_metadata, write_metadata, FileMetadata, MetadataPlaintext};
use crate::session::{SessionState, VaultSession};
use tesseract_crypto::random::{generate_key, generate_uuid};

// ============================================================================
// Directory Listing Types
// ============================================================================

/// Entry type for items in a directory listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    /// Regular file.
    File,
    /// Virtual directory (container for other files).
    Directory,
}

/// A file or directory entry returned from directory listing.
///
/// This structure contains all the information needed to display a file
/// or directory in a file browser view.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Entry name (file or directory name without path).
    pub name: String,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Last modification timestamp (Unix epoch seconds).
    pub modified_time: u64,
    /// Type of entry (file or directory).
    pub entry_type: EntryType,
    /// Access level required to access this entry.
    pub access_level: u32,
    /// File UUID (None for virtual directories).
    pub uuid: Option<Uuid>,
}

impl FileEntry {
    /// Creates a new file entry.
    pub fn new_file(
        name: String,
        size: u64,
        modified_time: u64,
        access_level: u32,
        uuid: Uuid,
    ) -> Self {
        Self {
            name,
            size,
            modified_time,
            entry_type: EntryType::File,
            access_level,
            uuid: Some(uuid),
        }
    }

    /// Creates a new directory entry.
    ///
    /// Directories are virtual containers derived from file paths.
    /// They have no UUID and size is 0.
    ///
    /// # Arguments
    ///
    /// * `name` - Directory name
    /// * `access_level` - The minimum access level of files within this directory
    /// * `modified_time` - Last modification timestamp (Unix epoch seconds), typically 0 for virtual directories
    pub fn new_directory(name: String, access_level: u32, modified_time: u64) -> Self {
        Self {
            name,
            size: 0,
            modified_time,
            entry_type: EntryType::Directory,
            access_level,
            uuid: None,
        }
    }

    /// Returns true if this entry is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.entry_type == EntryType::Directory
    }

    /// Returns true if this entry is a file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.entry_type == EntryType::File
    }
}

/// Imports a file from the filesystem into the vault.
///
/// This function reads a file from the source path, encrypts it with a newly
/// generated DEK (Data Encryption Key), stores the encrypted content as a blob,
/// creates encrypted metadata, and stores the wrapped DEK in the level's keystore.
///
/// # Arguments
///
/// * `session` - Mutable reference to an active vault session
/// * `source` - Path to the source file on the filesystem
/// * `dest_path` - Virtual path within the vault (e.g., "/documents/secret.pdf")
/// * `level` - Access level to assign to the file
///
/// # Returns
///
/// The UUID of the newly imported file on success.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::AccessDenied` - Level is not accessible in current session
/// * `VaultError::IoError` - Failed to read source file or write vault files
/// * `VaultError::CryptoError` - Encryption operation failed
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::import_file;
///
/// let file_uuid = import_file(
///     &mut session,
///     "/home/user/secret.txt",
///     "/confidential/secret.txt",
///     2,
/// )?;
/// println!("Imported file with UUID: {}", file_uuid);
/// ```
pub fn import_file<P: AsRef<Path>>(
    session: &mut VaultSession,
    source: P,
    dest_path: &str,
    level: u32,
) -> Result<Uuid, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Verify level is accessible
    if !session.can_access_level(level) {
        return Err(VaultError::AccessDenied);
    }

    // Get the KEK for the target level
    let kek = session.get_kek_copy(level)?;
    let hmac_key = session
        .get_unlocked_keystore(level)
        .ok_or(VaultError::AccessDenied)?
        .hmac_key()
        .clone();

    // Read source file
    let source_path = source.as_ref();
    let mut file = File::open(source_path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    // Get file size
    let file_size = plaintext.len() as u64;

    // Extract filename from source path
    let filename = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();

    // Generate unique identifiers
    let file_uuid = generate_uuid().map_err(|e| VaultError::CryptoError(e))?;
    let dek = generate_key().map_err(|e| VaultError::CryptoError(e))?;

    // Write encrypted blob
    write_blob(session.vault_path(), file_uuid, &dek, &plaintext)?;

    // Create and write encrypted metadata
    let metadata_plaintext = MetadataPlaintext::new(
        filename,
        dest_path.to_string(),
        level,
        file_size,
        file_uuid, // blob_ref points to itself
    );
    let metadata = FileMetadata::from_plaintext(file_uuid, metadata_plaintext);
    write_metadata(session.vault_path(), &metadata, &kek)?;

    // Wrap DEK with level's KEK and add to keystore
    let (encrypted_dek, dek_nonce) = wrap_dek(&dek, &kek, &file_uuid)?;
    let dek_entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);

    // Add DEK entry to keystore
    {
        let unlocked_ks = session
            .get_unlocked_keystore_mut(level)
            .ok_or(VaultError::AccessDenied)?;
        unlocked_ks.keystore_mut().add_dek_entry(dek_entry);
        unlocked_ks.keystore_mut().compute_hmac(&hmac_key);
    }

    // Persist updated keystore
    session.persist_keystore(level)?;

    Ok(file_uuid)
}

/// Imports raw bytes into the vault as a file.
///
/// Similar to [`import_file`], but takes raw bytes instead of reading from
/// a filesystem path. Useful for in-memory data or when you already have
/// the file content loaded.
///
/// # Arguments
///
/// * `session` - Mutable reference to an active vault session
/// * `content` - Raw bytes to store as the file content
/// * `filename` - Name for the file
/// * `dest_path` - Virtual path within the vault
/// * `level` - Access level to assign to the file
///
/// # Returns
///
/// The UUID of the newly imported file on success.
///
/// # Errors
///
/// Same as [`import_file`].
pub fn import_bytes(
    session: &mut VaultSession,
    content: &[u8],
    filename: &str,
    dest_path: &str,
    level: u32,
) -> Result<Uuid, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Verify level is accessible
    if !session.can_access_level(level) {
        return Err(VaultError::AccessDenied);
    }

    // Get the KEK for the target level
    let kek = session.get_kek_copy(level)?;
    let hmac_key = session
        .get_unlocked_keystore(level)
        .ok_or(VaultError::AccessDenied)?
        .hmac_key()
        .clone();

    // Get file size
    let file_size = content.len() as u64;

    // Generate unique identifiers
    let file_uuid = generate_uuid().map_err(|e| VaultError::CryptoError(e))?;
    let dek = generate_key().map_err(|e| VaultError::CryptoError(e))?;

    // Write encrypted blob
    write_blob(session.vault_path(), file_uuid, &dek, content)?;

    // Create and write encrypted metadata
    let metadata_plaintext = MetadataPlaintext::new(
        filename.to_string(),
        dest_path.to_string(),
        level,
        file_size,
        file_uuid,
    );
    let metadata = FileMetadata::from_plaintext(file_uuid, metadata_plaintext);
    write_metadata(session.vault_path(), &metadata, &kek)?;

    // Wrap DEK with level's KEK and add to keystore
    let (encrypted_dek, dek_nonce) = wrap_dek(&dek, &kek, &file_uuid)?;
    let dek_entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);

    // Add DEK entry to keystore
    {
        let unlocked_ks = session
            .get_unlocked_keystore_mut(level)
            .ok_or(VaultError::AccessDenied)?;
        unlocked_ks.keystore_mut().add_dek_entry(dek_entry);
        unlocked_ks.keystore_mut().compute_hmac(&hmac_key);
    }

    // Persist updated keystore
    session.persist_keystore(level)?;

    Ok(file_uuid)
}

// ============================================================================
// File Export Operations
// ============================================================================

/// Exports a file from the vault to the filesystem.
///
/// This function reads an encrypted file from the vault, decrypts it using the
/// file's DEK, and writes the plaintext content to the destination path. The
/// original filename from metadata is preserved unless the destination specifies
/// a different name.
///
/// # Arguments
///
/// * `session` - Reference to an active vault session
/// * `file_uuid` - UUID of the file to export
/// * `dest` - Destination path on the filesystem
///
/// # Returns
///
/// The path where the file was written on success.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::FileNotFound` - File UUID not found in any accessible keystore
/// * `VaultError::AccessDenied` - File's access level is not accessible in current session
/// * `VaultError::IoError` - Failed to write destination file
/// * `VaultError::CryptoError` - Decryption operation failed
///
/// # Security
///
/// The function verifies that the current session has access to the file's
/// access level before attempting decryption. This ensures that users cannot
/// export files above their clearance level.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::export_file;
///
/// let dest_path = export_file(
///     &session,
///     file_uuid,
///     "/home/user/exported_file.txt",
/// )?;
/// println!("Exported to: {:?}", dest_path);
/// ```
pub fn export_file<P: AsRef<Path>>(
    session: &VaultSession,
    file_uuid: Uuid,
    dest: P,
) -> Result<std::path::PathBuf, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Export to bytes first (handles all access control and decryption)
    let (plaintext, metadata) = export_to_bytes(session, file_uuid)?;

    // Write to destination
    let dest_path = dest.as_ref();
    let mut file = File::create(dest_path)?;
    file.write_all(&plaintext)?;
    file.sync_all()?;

    Ok(dest_path.to_path_buf())
}

/// Exports a file from the vault to an in-memory buffer.
///
/// This function reads an encrypted file from the vault and decrypts it,
/// returning both the plaintext content and the file's metadata. This is
/// useful for in-memory processing or when you need access to metadata
/// like the original filename.
///
/// # Arguments
///
/// * `session` - Reference to an active vault session
/// * `file_uuid` - UUID of the file to export
///
/// # Returns
///
/// A tuple of (plaintext_bytes, metadata) on success.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::FileNotFound` - File UUID not found in any accessible keystore
/// * `VaultError::AccessDenied` - File's access level is not accessible in current session
/// * `VaultError::CryptoError` - Decryption operation failed
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::export_to_bytes;
///
/// let (content, metadata) = export_to_bytes(&session, file_uuid)?;
/// println!("Original filename: {}", metadata.plaintext.name);
/// println!("Content size: {} bytes", content.len());
/// ```
pub fn export_to_bytes(
    session: &VaultSession,
    file_uuid: Uuid,
) -> Result<(Vec<u8>, FileMetadata), VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Find which level this file belongs to by searching keystores
    let mut file_level: Option<u32> = None;
    for level in 1..=3 {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            if unlocked_ks.keystore().has_dek_entry(&file_uuid) {
                file_level = Some(level);
                break;
            }
        }
    }

    let level = file_level.ok_or_else(|| VaultError::FileNotFound(file_uuid.to_string()))?;

    // Get the KEK for this level
    let kek = session.get_kek_copy(level)?;

    // Read and decrypt metadata to get access level and verify it matches
    let metadata = read_metadata(session.vault_path(), file_uuid, &kek)?;

    // Verify the session can access this file's level
    let file_access_level = metadata.plaintext.access_level;
    if !session.can_access_level(file_access_level) {
        return Err(VaultError::AccessDenied);
    }

    // Get the DEK from the keystore
    let unlocked_ks = session
        .get_unlocked_keystore(level)
        .ok_or(VaultError::AccessDenied)?;
    let dek = unlocked_ks
        .keystore()
        .decrypt_file_dek(&file_uuid, unlocked_ks.kek())?;

    // Read and decrypt the blob
    let plaintext = read_blob(session.vault_path(), file_uuid, &dek)?;

    Ok((plaintext, metadata))
}

/// Exports a file from the vault using its original filename.
///
/// This is a convenience function that exports a file to a directory,
/// preserving the original filename from the vault metadata.
///
/// # Arguments
///
/// * `session` - Reference to an active vault session
/// * `file_uuid` - UUID of the file to export
/// * `dest_dir` - Destination directory on the filesystem
///
/// # Returns
///
/// The full path where the file was written on success.
///
/// # Errors
///
/// Same as [`export_file`], plus:
/// * `VaultError::IoError` - If the destination directory doesn't exist
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::export_file_with_original_name;
///
/// let dest_path = export_file_with_original_name(
///     &session,
///     file_uuid,
///     "/home/user/exports/",
/// )?;
/// // If original filename was "secret.txt", dest_path will be "/home/user/exports/secret.txt"
/// ```
pub fn export_file_with_original_name<P: AsRef<Path>>(
    session: &VaultSession,
    file_uuid: Uuid,
    dest_dir: P,
) -> Result<std::path::PathBuf, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Export to bytes to get metadata
    let (plaintext, metadata) = export_to_bytes(session, file_uuid)?;

    // Construct destination path with original filename
    let dest_path = dest_dir.as_ref().join(&metadata.plaintext.name);

    // Write to destination
    let mut file = File::create(&dest_path)?;
    file.write_all(&plaintext)?;
    file.sync_all()?;

    Ok(dest_path)
}

// ============================================================================
// File Deletion Operations
// ============================================================================

/// Deletes a file from the vault.
///
/// This function removes all traces of a file from the vault:
/// - The encrypted blob from .blobs/
/// - The encrypted metadata from .metadata/
/// - The DEK entry from the level's keystore
///
/// # Arguments
///
/// * `session` - Mutable reference to an active vault session
/// * `file_uuid` - UUID of the file to delete
///
/// # Returns
///
/// `Ok(())` on successful deletion.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::FileNotFound` - File UUID not found in any accessible keystore
/// * `VaultError::AccessDenied` - File's access level is not accessible in current session
/// * `VaultError::IoError` - Failed to delete blob or metadata files
///
/// # Security
///
/// The function verifies that the current session has access to the file's
/// access level before attempting deletion. This ensures that users cannot
/// delete files above their clearance level.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::delete_file;
///
/// delete_file(&mut session, file_uuid)?;
/// println!("File deleted successfully");
/// ```
pub fn delete_file(
    session: &mut VaultSession,
    file_uuid: Uuid,
) -> Result<(), VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Find which level this file belongs to by searching keystores
    let mut file_level: Option<u32> = None;
    for level in 1..=3 {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            if unlocked_ks.keystore().has_dek_entry(&file_uuid) {
                file_level = Some(level);
                break;
            }
        }
    }

    let level = file_level.ok_or_else(|| VaultError::FileNotFound(file_uuid.to_string()))?;

    // Verify the session can access this file's level
    if !session.can_access_level(level) {
        return Err(VaultError::AccessDenied);
    }

    // Get HMAC key for keystore recomputation
    let hmac_key = session
        .get_unlocked_keystore(level)
        .ok_or(VaultError::AccessDenied)?
        .hmac_key()
        .clone();

    // Delete the blob file
    delete_blob(session.vault_path(), file_uuid)?;

    // Delete the metadata file
    delete_metadata(session.vault_path(), file_uuid)?;

    // Remove the DEK entry from the keystore
    {
        let unlocked_ks = session
            .get_unlocked_keystore_mut(level)
            .ok_or(VaultError::AccessDenied)?;
        unlocked_ks.keystore_mut().remove_dek_entry(&file_uuid);
        unlocked_ks.keystore_mut().compute_hmac(&hmac_key);
    }

    // Persist the updated keystore
    session.persist_keystore(level)?;

    Ok(())
}

// ============================================================================
// File Rename and Move Operations
// ============================================================================

/// Renames a file in the vault.
///
/// This function changes the filename while keeping it in the same virtual
/// directory. Only the metadata is updated; the encrypted blob remains unchanged.
///
/// # Arguments
///
/// * `session` - Mutable reference to an active vault session
/// * `file_uuid` - UUID of the file to rename
/// * `new_name` - New filename (just the name, not a full path)
///
/// # Returns
///
/// The updated file metadata on success.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::FileNotFound` - File UUID not found in any accessible keystore
/// * `VaultError::AccessDenied` - File's access level is not accessible in current session
/// * `VaultError::IoError` - Failed to write updated metadata
/// * `VaultError::CryptoError` - Re-encryption failed
///
/// # Security
///
/// The function verifies that the current session has access to the file's
/// access level before attempting the rename. The file's access level and
/// encrypted content are not modified.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::rename_file;
///
/// let updated = rename_file(&mut session, file_uuid, "new_name.txt")?;
/// println!("Renamed to: {}", updated.name());
/// ```
pub fn rename_file(
    session: &mut VaultSession,
    file_uuid: Uuid,
    new_name: &str,
) -> Result<crate::metadata::FileMetadata, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Find which level this file belongs to by searching keystores
    let mut file_level: Option<u32> = None;
    for level in 1..=3 {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            if unlocked_ks.keystore().has_dek_entry(&file_uuid) {
                file_level = Some(level);
                break;
            }
        }
    }

    let level = file_level.ok_or_else(|| VaultError::FileNotFound(file_uuid.to_string()))?;

    // Verify the session can access this file's level
    if !session.can_access_level(level) {
        return Err(VaultError::AccessDenied);
    }

    // Get the KEK for this level
    let kek = session.get_kek_copy(level)?;

    // Use the metadata module's rename function
    let updated = crate::metadata::rename_file(
        session.vault_path(),
        file_uuid,
        new_name.to_string(),
        &kek,
    )?;

    Ok(updated)
}

/// Moves a file to a new virtual path in the vault.
///
/// This function changes the file's virtual path (including directory and filename).
/// Only the metadata is updated; the encrypted blob remains unchanged.
///
/// # Arguments
///
/// * `session` - Mutable reference to an active vault session
/// * `file_uuid` - UUID of the file to move
/// * `new_path` - New virtual path (e.g., "/new/location/file.txt")
///
/// # Returns
///
/// The updated file metadata on success.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::FileNotFound` - File UUID not found in any accessible keystore
/// * `VaultError::AccessDenied` - File's access level is not accessible in current session
/// * `VaultError::IoError` - Failed to write updated metadata
/// * `VaultError::CryptoError` - Re-encryption failed
///
/// # Security
///
/// The function verifies that the current session has access to the file's
/// access level before attempting the move. The file's access level and
/// encrypted content are not modified.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::move_file;
///
/// let updated = move_file(&mut session, file_uuid, "/archive/2026/document.pdf")?;
/// println!("Moved to: {}", updated.path());
/// ```
pub fn move_file(
    session: &mut VaultSession,
    file_uuid: Uuid,
    new_path: &str,
) -> Result<crate::metadata::FileMetadata, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Find which level this file belongs to by searching keystores
    let mut file_level: Option<u32> = None;
    for level in 1..=3 {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            if unlocked_ks.keystore().has_dek_entry(&file_uuid) {
                file_level = Some(level);
                break;
            }
        }
    }

    let level = file_level.ok_or_else(|| VaultError::FileNotFound(file_uuid.to_string()))?;

    // Verify the session can access this file's level
    if !session.can_access_level(level) {
        return Err(VaultError::AccessDenied);
    }

    // Get the KEK for this level
    let kek = session.get_kek_copy(level)?;

    // Use the metadata module's move function
    let updated = crate::metadata::move_file(
        session.vault_path(),
        file_uuid,
        new_path.to_string(),
        &kek,
    )?;

    Ok(updated)
}

// ============================================================================
// Access Level Operations
// ============================================================================

/// Changes the access level of a file in the vault.
///
/// This function moves a file from its current access level to a new target level.
/// This involves:
/// 1. Reading the file's DEK from the current level's keystore
/// 2. Adding the DEK to the target level's keystore (re-encrypted with target KEK)
/// 3. Updating the file's metadata to reflect the new access level
/// 4. Removing the DEK from the original level's keystore
///
/// # Arguments
///
/// * `session` - Mutable reference to an active vault session
/// * `file_uuid` - UUID of the file to modify
/// * `target_level` - New access level (1, 2, or 3)
///
/// # Returns
///
/// The updated file metadata on success.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
/// * `VaultError::FileNotFound` - File UUID not found in any accessible keystore
/// * `VaultError::AccessDenied` - Cannot access source or target level
/// * `VaultError::IoError` - Failed to update files
/// * `VaultError::CryptoError` - Re-encryption failed
///
/// # Security
///
/// Both the source and target levels must be accessible in the current session.
/// The DEK is re-encrypted with the target level's KEK.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::set_access_level;
///
/// // Promote a file from L1 to L2
/// let updated = set_access_level(&mut session, file_uuid, 2)?;
/// println!("File now at L{}", updated.plaintext.access_level);
/// ```
pub fn set_access_level(
    session: &mut VaultSession,
    file_uuid: Uuid,
    target_level: u32,
) -> Result<crate::metadata::FileMetadata, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Validate target level
    if target_level < 1 || target_level > 3 {
        return Err(VaultError::InvalidData(format!(
            "Invalid access level: {}. Must be 1, 2, or 3.",
            target_level
        )));
    }

    // Find which level this file currently belongs to
    let mut current_level: Option<u32> = None;
    for level in 1..=3 {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            if unlocked_ks.keystore().has_dek_entry(&file_uuid) {
                current_level = Some(level);
                break;
            }
        }
    }

    let source_level = current_level.ok_or_else(|| {
        VaultError::FileNotFound(file_uuid.to_string())
    })?;

    // If already at target level, no-op
    if source_level == target_level {
        let kek = session.get_kek_copy(source_level)?;
        return crate::metadata::read_metadata(session.vault_path(), file_uuid, &kek);
    }

    // Verify session can access both source and target levels
    if !session.can_access_level(source_level) {
        return Err(VaultError::AccessDenied);
    }
    if !session.can_access_level(target_level) {
        return Err(VaultError::AccessDenied);
    }

    // Get KEKs for both levels
    let source_kek = session.get_kek_copy(source_level)?;
    let target_kek = session.get_kek_copy(target_level)?;

    // Get the DEK from source keystore
    let dek = {
        let source_ks = session
            .get_unlocked_keystore(source_level)
            .ok_or(VaultError::AccessDenied)?;
        let entry = source_ks
            .keystore()
            .get_dek_entry(&file_uuid)
            .ok_or(VaultError::FileNotFound(file_uuid.to_string()))?;
        unwrap_dek(entry.encrypted_dek(), entry.dek_nonce(), &source_kek, &file_uuid)?
    };

    // Add DEK to target keystore
    {
        let target_hmac_key = session
            .get_unlocked_keystore(target_level)
            .ok_or(VaultError::AccessDenied)?
            .hmac_key()
            .clone();

        let target_ks = session
            .get_unlocked_keystore_mut(target_level)
            .ok_or(VaultError::AccessDenied)?;

        // Wrap DEK with target KEK and create entry
        let (encrypted_dek, dek_nonce) = wrap_dek(&dek, &target_kek, &file_uuid)?;
        let dek_entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);
        target_ks.keystore_mut().add_dek_entry(dek_entry);
        target_ks.keystore_mut().compute_hmac(&target_hmac_key);
    }

    // Persist target keystore
    session.persist_keystore(target_level)?;

    // Remove DEK from source keystore
    {
        let source_hmac_key = session
            .get_unlocked_keystore(source_level)
            .ok_or(VaultError::AccessDenied)?
            .hmac_key()
            .clone();

        let source_ks = session
            .get_unlocked_keystore_mut(source_level)
            .ok_or(VaultError::AccessDenied)?;

        source_ks.keystore_mut().remove_dek_entry(&file_uuid);
        source_ks.keystore_mut().compute_hmac(&source_hmac_key);
    }

    // Persist source keystore
    session.persist_keystore(source_level)?;

    // Update metadata with new access level
    let updated = crate::metadata::change_access_level(
        session.vault_path(),
        file_uuid,
        target_level,
        &target_kek,
    )?;

    Ok(updated)
}

// ============================================================================
// Directory Listing Operations
// ============================================================================

/// Lists files and directories at a specified virtual path.
///
/// This function returns all files and virtual subdirectories visible at the
/// given path, filtered by the session's accessible levels. Virtual directories
/// are derived from file paths - if a file exists at "/docs/reports/file.txt",
/// listing "/" will show "docs" as a directory.
///
/// # Arguments
///
/// * `session` - Reference to an active vault session
/// * `path` - Virtual path to list (e.g., "/" or "/docs/reports")
///
/// # Returns
///
/// A vector of [`FileEntry`] items (files and directories) visible at the path.
/// The entries are sorted with directories first, then files, both alphabetically.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
///
/// # Security
///
/// Only files at accessible levels are returned. Files at higher levels than
/// the session's access are not visible in listings.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::list_files;
///
/// let entries = list_files(&session, "/")?;
/// for entry in entries {
///     if entry.is_directory() {
///         println!("📁 {}/", entry.name);
///     } else {
///         println!("📄 {} ({} bytes)", entry.name, entry.size);
///     }
/// }
/// ```
pub fn list_files(
    session: &VaultSession,
    path: &str,
) -> Result<Vec<FileEntry>, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    // Normalize the path (ensure it starts with "/" and has no trailing slash except for root)
    let normalized_path = normalize_path(path);

    let mut files: Vec<FileEntry> = Vec::new();
    let mut subdirs: HashSet<(String, u32)> = HashSet::new();

    // Iterate through all accessible levels
    for level in session.accessible_levels() {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            let kek = match session.get_kek_copy(level) {
                Ok(k) => k,
                Err(_) => continue,
            };

            // Iterate through all file UUIDs in this keystore
            for (file_uuid, _dek_entry) in unlocked_ks.keystore().dek_entries() {
                // Read and decrypt metadata
                let metadata = match read_metadata(session.vault_path(), *file_uuid, &kek) {
                    Ok(m) => m,
                    Err(_) => continue, // Skip files with unreadable metadata
                };

                let file_path = &metadata.plaintext.path;
                let file_level = metadata.plaintext.access_level;

                // Check if this file is directly in the requested directory
                // or if it's in a subdirectory
                if let Some(relative) = get_relative_path(file_path, &normalized_path) {
                    if relative.is_empty() {
                        // This file's path exactly matches a directory entry - shouldn't happen
                        // as files have names, but handle gracefully
                        continue;
                    }

                    if let Some((first_component, has_more)) = split_first_component(&relative) {
                        if has_more {
                            // This is a subdirectory
                            subdirs.insert((first_component.to_string(), file_level));
                        } else {
                            // This is a file directly in this directory
                            files.push(FileEntry::new_file(
                                metadata.plaintext.name.clone(),
                                metadata.plaintext.size,
                                metadata.plaintext.modified_at,
                                file_level,
                                *file_uuid,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Convert subdirectories to entries
    // For directories, we use the minimum access level of all files within
    // Virtual directories have modified_time=0 since they don't exist on disk
    let mut dir_entries: Vec<FileEntry> = subdirs
        .into_iter()
        .map(|(name, level)| FileEntry::new_directory(name, level, 0))
        .collect();

    // Sort: directories first (alphabetically), then files (alphabetically)
    dir_entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    // Combine directories first, then files
    let mut result = dir_entries;
    result.append(&mut files);

    Ok(result)
}

/// Lists all files in the vault across all accessible levels.
///
/// This is a convenience function that returns all files without path filtering.
/// Useful for building a complete file index or search functionality.
///
/// # Arguments
///
/// * `session` - Reference to an active vault session
///
/// # Returns
///
/// A vector of all [`FileEntry`] items (files only, no directories).
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
///
/// # Example
///
/// ```ignore
/// use tesseract_core::files::list_all_files;
///
/// let files = list_all_files(&session)?;
/// println!("Total files in vault: {}", files.len());
/// ```
pub fn list_all_files(session: &VaultSession) -> Result<Vec<FileEntry>, VaultError> {
    // Check session state
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    let mut files: Vec<FileEntry> = Vec::new();

    // Iterate through all accessible levels
    for level in session.accessible_levels() {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            let kek = match session.get_kek_copy(level) {
                Ok(k) => k,
                Err(_) => continue,
            };

            // Iterate through all file UUIDs in this keystore
            for (file_uuid, _dek_entry) in unlocked_ks.keystore().dek_entries() {
                // Read and decrypt metadata
                let metadata = match read_metadata(session.vault_path(), *file_uuid, &kek) {
                    Ok(m) => m,
                    Err(_) => continue, // Skip files with unreadable metadata
                };

                files.push(FileEntry::new_file(
                    metadata.plaintext.name.clone(),
                    metadata.plaintext.size,
                    metadata.plaintext.modified_at,
                    metadata.plaintext.access_level,
                    *file_uuid,
                ));
            }
        }
    }

    // Sort alphabetically by name
    files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Ok(files)
}

/// Returns the total count of files accessible in the current session.
///
/// # Arguments
///
/// * `session` - Reference to an active vault session
///
/// # Returns
///
/// The count of files accessible at the session's levels.
///
/// # Errors
///
/// * `VaultError::VaultLocked` - Session has been locked
pub fn file_count(session: &VaultSession) -> Result<usize, VaultError> {
    if session.state() == SessionState::Locked {
        return Err(VaultError::VaultLocked);
    }

    let mut count = 0;
    for level in session.accessible_levels() {
        if let Some(unlocked_ks) = session.get_unlocked_keystore(level) {
            count += unlocked_ks.keystore().dek_count();
        }
    }

    Ok(count)
}

// ============================================================================
// Path Utility Functions
// ============================================================================

/// Normalizes a virtual path to a consistent format.
///
/// - Ensures the path starts with "/"
/// - Removes trailing slashes (except for root "/")
fn normalize_path(path: &str) -> String {
    let mut normalized = path.trim().to_string();

    // Ensure starts with /
    if !normalized.starts_with('/') {
        normalized = format!("/{}", normalized);
    }

    // Remove trailing slash (except for root)
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }

    normalized
}

/// Gets the relative path from a base directory to a file path.
///
/// Returns `Some(relative)` if `file_path` is under `base_path`, where
/// `relative` is the remaining path after the base (without leading slash).
/// Returns `None` if the file is not under the base path.
fn get_relative_path(file_path: &str, base_path: &str) -> Option<String> {
    let normalized_file = normalize_path(file_path);
    let normalized_base = normalize_path(base_path);

    if normalized_base == "/" {
        // Root directory: return everything after the first /
        if normalized_file.len() > 1 {
            return Some(normalized_file[1..].to_string());
        } else {
            return None; // File path is just "/"
        }
    }

    // Check if file is under the base directory
    if normalized_file.starts_with(&normalized_base) {
        let remainder = &normalized_file[normalized_base.len()..];
        if remainder.is_empty() {
            // File path equals base path exactly (shouldn't happen for files)
            return Some(String::new());
        }
        if remainder.starts_with('/') {
            // Strip leading slash from remainder
            return Some(remainder[1..].to_string());
        }
    }

    None
}

/// Splits a path into its first component and whether there are more components.
///
/// For example:
/// - "docs/reports/file.txt" -> Some(("docs", true))
/// - "file.txt" -> Some(("file.txt", false))
/// - "" -> None
fn split_first_component(path: &str) -> Option<(&str, bool)> {
    if path.is_empty() {
        return None;
    }

    match path.find('/') {
        Some(idx) => Some((&path[..idx], true)),
        None => Some((path, false)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{blob_exists, read_blob};
    use crate::keystore::unwrap_dek;
    use crate::metadata::{metadata_exists, read_metadata};
    use crate::session::open_vault;
    use crate::vault::{create_vault, VaultConfig};
    use std::io::Write;
    use tempfile::TempDir;
    use tesseract_crypto::kdf::Argon2Params;

    /// Helper to create a test vault with minimal security for fast tests.
    fn create_test_vault() -> (TempDir, std::path::PathBuf) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("test_vault");

        let config = VaultConfig::default().with_argon2_params(Argon2Params::minimal());
        create_vault(&vault_path, b"test password", Some(config)).expect("Failed to create vault");

        (temp_dir, vault_path)
    }

    /// Helper to create a temp file with content.
    fn create_temp_file(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
        let file_path = dir.path().join(name);
        let mut file = File::create(&file_path).expect("Failed to create temp file");
        file.write_all(content).expect("Failed to write temp file");
        file_path
    }

    // ============================================================================
    // US-025: File Import Tests
    // ============================================================================

    #[test]
    fn test_import_file_success() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "secret.txt", b"Top secret content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/docs/secret.txt", 1)
            .expect("Import should succeed");

        // Verify UUID was returned
        assert!(!file_uuid.is_nil());

        // Verify DEK was added to keystore
        let ks = session.get_unlocked_keystore(1).unwrap();
        assert!(ks.keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_import_file_content_preserved() {
        let (temp_dir, vault_path) = create_test_vault();
        let original_content = b"This is the original content that should be preserved.";
        let source_path = create_temp_file(&temp_dir, "document.pdf", original_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/docs/document.pdf", 2)
            .expect("Import should succeed");

        // Get DEK from keystore and decrypt blob
        let ks = session.get_unlocked_keystore(2).unwrap();
        let dek_entry = ks.keystore().get_dek_entry(&file_uuid).unwrap();
        let dek = unwrap_dek(
            dek_entry.encrypted_dek(),
            dek_entry.dek_nonce(),
            ks.kek(),
            &file_uuid,
        )
        .expect("DEK unwrap should succeed");

        let decrypted = read_blob(&vault_path, file_uuid, &dek).expect("Read blob should succeed");
        assert_eq!(decrypted, original_content);
    }

    #[test]
    fn test_import_file_metadata_created() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "report.txt", b"Annual report");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/reports/annual.txt", 1)
            .expect("Import should succeed");

        // Read and verify metadata
        let kek = session.get_kek_copy(1).unwrap();
        let metadata = read_metadata(&vault_path, file_uuid, &kek).expect("Read metadata should succeed");

        assert_eq!(metadata.plaintext.name, "report.txt");
        assert_eq!(metadata.plaintext.path, "/reports/annual.txt");
        assert_eq!(metadata.plaintext.access_level, 1);
        assert_eq!(metadata.plaintext.size, 13); // "Annual report" = 13 bytes
        assert_eq!(metadata.plaintext.blob_ref, file_uuid);
    }

    #[test]
    fn test_import_file_to_different_levels() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import files at each level
        let file1_path = create_temp_file(&temp_dir, "level1.txt", b"Level 1 file");
        let file2_path = create_temp_file(&temp_dir, "level2.txt", b"Level 2 file");
        let file3_path = create_temp_file(&temp_dir, "level3.txt", b"Level 3 file");

        let uuid1 = import_file(&mut session, &file1_path, "/l1/file.txt", 1).expect("L1 import");
        let uuid2 = import_file(&mut session, &file2_path, "/l2/file.txt", 2).expect("L2 import");
        let uuid3 = import_file(&mut session, &file3_path, "/l3/file.txt", 3).expect("L3 import");

        // Each file in correct keystore
        assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&uuid1));
        assert!(session.get_unlocked_keystore(2).unwrap().keystore().has_dek_entry(&uuid2));
        assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&uuid3));

        // Files not in wrong keystores
        assert!(!session.get_unlocked_keystore(2).unwrap().keystore().has_dek_entry(&uuid1));
        assert!(!session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&uuid1));
    }

    #[test]
    fn test_import_file_locked_session_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "file.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        session.lock();

        let result = import_file(&mut session, &source_path, "/file.txt", 1);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_import_file_inaccessible_level_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "file.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Level 99 doesn't exist
        let result = import_file(&mut session, &source_path, "/file.txt", 99);
        assert!(matches!(result, Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_import_file_nonexistent_source_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let result = import_file(&mut session, "/nonexistent/file.txt", "/file.txt", 1);
        assert!(matches!(result, Err(VaultError::IoError(_))));
    }

    #[test]
    fn test_import_file_persists_across_session() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "persistent.txt", b"Persistent data");

        let file_uuid = {
            let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            import_file(&mut session, &source_path, "/data/persistent.txt", 1)
                .expect("Import should succeed")
        };

        // Reopen vault
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        // File should still exist
        assert!(session2.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_import_file_unique_uuids() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let mut uuids = std::collections::HashSet::new();
        for i in 0..10 {
            let path = create_temp_file(&temp_dir, &format!("file{}.txt", i), b"content");
            let uuid = import_file(&mut session, &path, &format!("/file{}.txt", i), 1)
                .expect("Import should succeed");
            assert!(uuids.insert(uuid), "UUID should be unique");
        }
    }

    #[test]
    fn test_import_file_unique_deks() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import two files
        let path1 = create_temp_file(&temp_dir, "file1.txt", b"content1");
        let path2 = create_temp_file(&temp_dir, "file2.txt", b"content2");

        let uuid1 = import_file(&mut session, &path1, "/file1.txt", 1).expect("Import 1");
        let uuid2 = import_file(&mut session, &path2, "/file2.txt", 1).expect("Import 2");

        // Get DEKs
        let ks = session.get_unlocked_keystore(1).unwrap();
        let entry1 = ks.keystore().get_dek_entry(&uuid1).unwrap();
        let entry2 = ks.keystore().get_dek_entry(&uuid2).unwrap();

        let dek1 = unwrap_dek(entry1.encrypted_dek(), entry1.dek_nonce(), ks.kek(), &uuid1)
            .expect("Unwrap 1");
        let dek2 = unwrap_dek(entry2.encrypted_dek(), entry2.dek_nonce(), ks.kek(), &uuid2)
            .expect("Unwrap 2");

        // DEKs should be different
        assert_ne!(dek1, dek2);
    }

    #[test]
    fn test_import_file_empty_file() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "empty.txt", b"");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/empty.txt", 1)
            .expect("Empty file import should succeed");

        // Verify size is 0
        let kek = session.get_kek_copy(1).unwrap();
        let metadata = read_metadata(&vault_path, file_uuid, &kek).unwrap();
        assert_eq!(metadata.plaintext.size, 0);

        // Verify content is empty
        let ks = session.get_unlocked_keystore(1).unwrap();
        let entry = ks.keystore().get_dek_entry(&file_uuid).unwrap();
        let dek = unwrap_dek(entry.encrypted_dek(), entry.dek_nonce(), ks.kek(), &file_uuid).unwrap();
        let content = read_blob(&vault_path, file_uuid, &dek).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn test_import_file_large_file() {
        let (temp_dir, vault_path) = create_test_vault();

        // Create a 1MB file
        let large_content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let source_path = create_temp_file(&temp_dir, "large.bin", &large_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/large.bin", 2)
            .expect("Large file import should succeed");

        // Verify content roundtrip
        let ks = session.get_unlocked_keystore(2).unwrap();
        let entry = ks.keystore().get_dek_entry(&file_uuid).unwrap();
        let dek = unwrap_dek(entry.encrypted_dek(), entry.dek_nonce(), ks.kek(), &file_uuid).unwrap();
        let decrypted = read_blob(&vault_path, file_uuid, &dek).unwrap();

        assert_eq!(decrypted.len(), large_content.len());
        assert_eq!(decrypted, large_content);
    }

    #[test]
    fn test_import_file_unicode_filename() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "文档.txt", b"Unicode content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/文档/报告.txt", 1)
            .expect("Unicode import should succeed");

        let kek = session.get_kek_copy(1).unwrap();
        let metadata = read_metadata(&vault_path, file_uuid, &kek).unwrap();
        assert_eq!(metadata.plaintext.name, "文档.txt");
        assert_eq!(metadata.plaintext.path, "/文档/报告.txt");
    }

    #[test]
    fn test_import_file_binary_content() {
        let (temp_dir, vault_path) = create_test_vault();

        // Binary content with all byte values
        let binary_content: Vec<u8> = (0u8..=255).collect();
        let source_path = create_temp_file(&temp_dir, "binary.bin", &binary_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/binary.bin", 1)
            .expect("Binary import should succeed");

        // Verify content
        let ks = session.get_unlocked_keystore(1).unwrap();
        let entry = ks.keystore().get_dek_entry(&file_uuid).unwrap();
        let dek = unwrap_dek(entry.encrypted_dek(), entry.dek_nonce(), ks.kek(), &file_uuid).unwrap();
        let decrypted = read_blob(&vault_path, file_uuid, &dek).unwrap();
        assert_eq!(decrypted, binary_content);
    }

    // ============================================================================
    // import_bytes Tests
    // ============================================================================

    #[test]
    fn test_import_bytes_success() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let content = b"In-memory content";
        let file_uuid = import_bytes(&mut session, content, "memory.txt", "/data/memory.txt", 1)
            .expect("Import bytes should succeed");

        // Verify metadata
        let kek = session.get_kek_copy(1).unwrap();
        let metadata = read_metadata(&vault_path, file_uuid, &kek).unwrap();
        assert_eq!(metadata.plaintext.name, "memory.txt");
        assert_eq!(metadata.plaintext.path, "/data/memory.txt");
        assert_eq!(metadata.plaintext.size, content.len() as u64);

        // Verify content
        let ks = session.get_unlocked_keystore(1).unwrap();
        let entry = ks.keystore().get_dek_entry(&file_uuid).unwrap();
        let dek = unwrap_dek(entry.encrypted_dek(), entry.dek_nonce(), ks.kek(), &file_uuid).unwrap();
        let decrypted = read_blob(&vault_path, file_uuid, &dek).unwrap();
        assert_eq!(decrypted, content);
    }

    #[test]
    fn test_import_bytes_empty() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_bytes(&mut session, b"", "empty.txt", "/empty.txt", 1)
            .expect("Empty import should succeed");

        let kek = session.get_kek_copy(1).unwrap();
        let metadata = read_metadata(&vault_path, file_uuid, &kek).unwrap();
        assert_eq!(metadata.plaintext.size, 0);
    }

    #[test]
    fn test_import_bytes_locked_session_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        session.lock();

        let result = import_bytes(&mut session, b"content", "file.txt", "/file.txt", 1);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_import_bytes_inaccessible_level_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let result = import_bytes(&mut session, b"content", "file.txt", "/file.txt", 99);
        assert!(matches!(result, Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_multiple_imports_in_sequence() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import 20 files in sequence
        for i in 0..20 {
            let path = create_temp_file(&temp_dir, &format!("seq{}.txt", i), format!("content {}", i).as_bytes());
            import_file(&mut session, &path, &format!("/seq/{}.txt", i), (i % 3) as u32 + 1)
                .expect("Sequential import should succeed");
        }

        // Verify counts in each keystore
        let l1_count = session.get_unlocked_keystore(1).unwrap().keystore().dek_count();
        let l2_count = session.get_unlocked_keystore(2).unwrap().keystore().dek_count();
        let l3_count = session.get_unlocked_keystore(3).unwrap().keystore().dek_count();

        // 20 files distributed across 3 levels: 7, 7, 6
        assert_eq!(l1_count + l2_count + l3_count, 20);
    }

    // ============================================================================
    // US-026: File Export Tests
    // ============================================================================

    #[test]
    fn test_export_file_success() {
        let (temp_dir, vault_path) = create_test_vault();
        let original_content = b"This is the original content for export test.";
        let source_path = create_temp_file(&temp_dir, "export_test.txt", original_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import a file
        let file_uuid = import_file(&mut session, &source_path, "/docs/export_test.txt", 1)
            .expect("Import should succeed");

        // Export to a new location
        let export_dest = temp_dir.path().join("exported.txt");
        let result_path = export_file(&session, file_uuid, &export_dest)
            .expect("Export should succeed");

        assert_eq!(result_path, export_dest);

        // Verify content matches
        let mut exported_content = Vec::new();
        File::open(&export_dest)
            .expect("Should open exported file")
            .read_to_end(&mut exported_content)
            .expect("Should read exported file");

        assert_eq!(exported_content, original_content);
    }

    #[test]
    fn test_export_to_bytes_success() {
        let (temp_dir, vault_path) = create_test_vault();
        let original_content = b"Content for export_to_bytes test";
        let source_path = create_temp_file(&temp_dir, "bytes_test.txt", original_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/data/bytes_test.txt", 2)
            .expect("Import should succeed");

        let (content, metadata) = export_to_bytes(&session, file_uuid)
            .expect("Export to bytes should succeed");

        assert_eq!(content, original_content);
        assert_eq!(metadata.plaintext.name, "bytes_test.txt");
        assert_eq!(metadata.plaintext.path, "/data/bytes_test.txt");
        assert_eq!(metadata.plaintext.access_level, 2);
        assert_eq!(metadata.plaintext.size, original_content.len() as u64);
    }

    #[test]
    fn test_export_file_with_original_name() {
        let (temp_dir, vault_path) = create_test_vault();
        let original_content = b"Original name test content";
        let source_path = create_temp_file(&temp_dir, "original_名前.txt", original_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/保密/original_名前.txt", 1)
            .expect("Import should succeed");

        // Create export directory
        let export_dir = temp_dir.path().join("exports");
        std::fs::create_dir_all(&export_dir).expect("Create export dir");

        let result_path = export_file_with_original_name(&session, file_uuid, &export_dir)
            .expect("Export with original name should succeed");

        // Should preserve original filename
        assert_eq!(result_path.file_name().unwrap().to_str().unwrap(), "original_名前.txt");

        // Verify content
        let mut exported_content = Vec::new();
        File::open(&result_path)
            .expect("Should open exported file")
            .read_to_end(&mut exported_content)
            .expect("Should read exported file");
        assert_eq!(exported_content, original_content);
    }

    #[test]
    fn test_export_file_locked_session_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "locked_test.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/file.txt", 1)
            .expect("Import should succeed");

        session.lock();

        let export_dest = temp_dir.path().join("should_not_exist.txt");
        let result = export_file(&session, file_uuid, &export_dest);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_export_to_bytes_locked_session_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "locked_test.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/file.txt", 1)
            .expect("Import should succeed");

        session.lock();

        let result = export_to_bytes(&session, file_uuid);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_export_file_not_found() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let nonexistent_uuid = Uuid::new_v4();
        let result = export_to_bytes(&session, nonexistent_uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_export_empty_file() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "empty.txt", b"");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/empty.txt", 1)
            .expect("Import should succeed");

        let (content, metadata) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");

        assert!(content.is_empty());
        assert_eq!(metadata.plaintext.size, 0);
    }

    #[test]
    fn test_export_large_file() {
        let (temp_dir, vault_path) = create_test_vault();

        // Create a 1MB file
        let large_content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let source_path = create_temp_file(&temp_dir, "large.bin", &large_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/large.bin", 2)
            .expect("Import should succeed");

        let (content, _metadata) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");

        assert_eq!(content.len(), large_content.len());
        assert_eq!(content, large_content);
    }

    #[test]
    fn test_export_binary_content() {
        let (temp_dir, vault_path) = create_test_vault();

        // Binary content with all byte values
        let binary_content: Vec<u8> = (0u8..=255).collect();
        let source_path = create_temp_file(&temp_dir, "binary.bin", &binary_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/binary.bin", 1)
            .expect("Import should succeed");

        let export_dest = temp_dir.path().join("exported_binary.bin");
        export_file(&session, file_uuid, &export_dest)
            .expect("Export should succeed");

        let mut exported = Vec::new();
        File::open(&export_dest)
            .unwrap()
            .read_to_end(&mut exported)
            .unwrap();

        assert_eq!(exported, binary_content);
    }

    #[test]
    fn test_export_from_different_levels() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import files at each level
        let path1 = create_temp_file(&temp_dir, "level1.txt", b"Level 1 content");
        let path2 = create_temp_file(&temp_dir, "level2.txt", b"Level 2 content");
        let path3 = create_temp_file(&temp_dir, "level3.txt", b"Level 3 content");

        let uuid1 = import_file(&mut session, &path1, "/l1/file.txt", 1).expect("L1 import");
        let uuid2 = import_file(&mut session, &path2, "/l2/file.txt", 2).expect("L2 import");
        let uuid3 = import_file(&mut session, &path3, "/l3/file.txt", 3).expect("L3 import");

        // Export each file
        let (content1, meta1) = export_to_bytes(&session, uuid1).expect("L1 export");
        let (content2, meta2) = export_to_bytes(&session, uuid2).expect("L2 export");
        let (content3, meta3) = export_to_bytes(&session, uuid3).expect("L3 export");

        assert_eq!(content1, b"Level 1 content");
        assert_eq!(content2, b"Level 2 content");
        assert_eq!(content3, b"Level 3 content");

        assert_eq!(meta1.plaintext.access_level, 1);
        assert_eq!(meta2.plaintext.access_level, 2);
        assert_eq!(meta3.plaintext.access_level, 3);
    }

    #[test]
    fn test_export_persists_across_session() {
        let (temp_dir, vault_path) = create_test_vault();
        let original_content = b"Persistent content for export";
        let source_path = create_temp_file(&temp_dir, "persistent.txt", original_content);

        let file_uuid = {
            let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            import_file(&mut session, &source_path, "/data/persistent.txt", 1)
                .expect("Import should succeed")
        };

        // Reopen vault and export
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        let (content, metadata) = export_to_bytes(&session2, file_uuid)
            .expect("Export after reopen should succeed");

        assert_eq!(content, original_content);
        assert_eq!(metadata.plaintext.name, "persistent.txt");
    }

    #[test]
    fn test_export_roundtrip() {
        let (temp_dir, vault_path) = create_test_vault();
        let original_content = b"Roundtrip test: import -> export -> verify";
        let source_path = create_temp_file(&temp_dir, "roundtrip.txt", original_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import
        let file_uuid = import_file(&mut session, &source_path, "/roundtrip.txt", 2)
            .expect("Import should succeed");

        // Export to file
        let export_path = temp_dir.path().join("roundtrip_export.txt");
        export_file(&session, file_uuid, &export_path)
            .expect("Export should succeed");

        // Read exported file and compare
        let mut exported = Vec::new();
        File::open(&export_path)
            .unwrap()
            .read_to_end(&mut exported)
            .unwrap();

        assert_eq!(exported, original_content);
    }

    #[test]
    fn test_export_unicode_content() {
        let (temp_dir, vault_path) = create_test_vault();
        let unicode_content = "日本語テスト 中文测试 한국어 테스트 🔐🔑💾".as_bytes();
        let source_path = create_temp_file(&temp_dir, "unicode.txt", unicode_content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/unicode.txt", 1)
            .expect("Import should succeed");

        let (content, _) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");

        assert_eq!(content, unicode_content);
    }

    #[test]
    fn test_export_multiple_files_same_session() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import multiple files
        let mut file_uuids = Vec::new();
        for i in 0..5 {
            let content = format!("File {} content", i);
            let path = create_temp_file(&temp_dir, &format!("file{}.txt", i), content.as_bytes());
            let uuid = import_file(&mut session, &path, &format!("/files/{}.txt", i), 1)
                .expect("Import should succeed");
            file_uuids.push((uuid, content));
        }

        // Export all files and verify
        for (uuid, expected_content) in file_uuids {
            let (content, _) = export_to_bytes(&session, uuid)
                .expect("Export should succeed");
            assert_eq!(String::from_utf8_lossy(&content), expected_content);
        }
    }

    // ============================================================================
    // US-027: File Deletion Tests
    // ============================================================================

    #[test]
    fn test_delete_file_success() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "to_delete.txt", b"Delete me");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/to_delete.txt", 1)
            .expect("Import should succeed");

        // Verify file exists
        assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(blob_exists(&vault_path, file_uuid));
        assert!(metadata_exists(&vault_path, file_uuid));

        // Delete the file
        delete_file(&mut session, file_uuid).expect("Delete should succeed");

        // Verify file is gone from all storage locations
        assert!(!session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(!blob_exists(&vault_path, file_uuid));
        assert!(!metadata_exists(&vault_path, file_uuid));
    }

    #[test]
    fn test_delete_file_different_levels() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import files at different levels
        let path1 = create_temp_file(&temp_dir, "level1.txt", b"Level 1");
        let path2 = create_temp_file(&temp_dir, "level2.txt", b"Level 2");
        let path3 = create_temp_file(&temp_dir, "level3.txt", b"Level 3");

        let uuid1 = import_file(&mut session, &path1, "/l1.txt", 1).expect("L1 import");
        let uuid2 = import_file(&mut session, &path2, "/l2.txt", 2).expect("L2 import");
        let uuid3 = import_file(&mut session, &path3, "/l3.txt", 3).expect("L3 import");

        // Delete file from level 2
        delete_file(&mut session, uuid2).expect("Delete should succeed");

        // Verify level 2 file is gone
        assert!(!session.get_unlocked_keystore(2).unwrap().keystore().has_dek_entry(&uuid2));
        assert!(!blob_exists(&vault_path, uuid2));
        assert!(!metadata_exists(&vault_path, uuid2));

        // Verify level 1 and 3 files still exist
        assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&uuid1));
        assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&uuid3));
        assert!(blob_exists(&vault_path, uuid1));
        assert!(blob_exists(&vault_path, uuid3));
    }

    #[test]
    fn test_delete_file_locked_session_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "file.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/file.txt", 1)
            .expect("Import should succeed");

        session.lock();

        let result = delete_file(&mut session, file_uuid);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_delete_file_not_found() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let nonexistent_uuid = Uuid::new_v4();
        let result = delete_file(&mut session, nonexistent_uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_delete_file_persists_across_session() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "persistent.txt", b"Persistent data");

        let file_uuid = {
            let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            let uuid = import_file(&mut session, &source_path, "/persistent.txt", 1)
                .expect("Import should succeed");

            delete_file(&mut session, uuid).expect("Delete should succeed");
            uuid
        };

        // Reopen vault and verify file is still gone
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        assert!(!session2.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(!blob_exists(&vault_path, file_uuid));
        assert!(!metadata_exists(&vault_path, file_uuid));
    }

    #[test]
    fn test_delete_multiple_files() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import 5 files
        let mut uuids = Vec::new();
        for i in 0..5 {
            let path = create_temp_file(&temp_dir, &format!("file{}.txt", i), format!("Content {}", i).as_bytes());
            let uuid = import_file(&mut session, &path, &format!("/file{}.txt", i), 1)
                .expect("Import should succeed");
            uuids.push(uuid);
        }

        // Delete first 3 files
        for uuid in &uuids[..3] {
            delete_file(&mut session, *uuid).expect("Delete should succeed");
        }

        // Verify first 3 are gone
        for uuid in &uuids[..3] {
            assert!(!session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(uuid));
            assert!(!blob_exists(&vault_path, *uuid));
        }

        // Verify last 2 still exist
        for uuid in &uuids[3..] {
            assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(uuid));
            assert!(blob_exists(&vault_path, *uuid));
        }
    }

    #[test]
    fn test_delete_file_cannot_export_after() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "export_test.txt", b"Export test");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/export_test.txt", 1)
            .expect("Import should succeed");

        // Delete the file
        delete_file(&mut session, file_uuid).expect("Delete should succeed");

        // Attempting to export should fail
        let result = export_to_bytes(&session, file_uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_delete_file_double_delete_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "double_delete.txt", b"Delete twice");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/double_delete.txt", 1)
            .expect("Import should succeed");

        // First delete succeeds
        delete_file(&mut session, file_uuid).expect("First delete should succeed");

        // Second delete fails (file not found)
        let result = delete_file(&mut session, file_uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_delete_file_import_same_content_after() {
        let (temp_dir, vault_path) = create_test_vault();
        let content = b"Reusable content";
        let source_path = create_temp_file(&temp_dir, "reuse.txt", content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import, delete, import again
        let uuid1 = import_file(&mut session, &source_path, "/reuse.txt", 1)
            .expect("First import should succeed");
        delete_file(&mut session, uuid1).expect("Delete should succeed");
        let uuid2 = import_file(&mut session, &source_path, "/reuse.txt", 1)
            .expect("Second import should succeed");

        // UUIDs should be different
        assert_ne!(uuid1, uuid2);

        // New file should be exportable
        let (exported, _) = export_to_bytes(&session, uuid2).expect("Export should succeed");
        assert_eq!(exported, content);
    }

    #[test]
    fn test_delete_file_keystore_count_decreases() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import 3 files
        let mut uuids = Vec::new();
        for i in 0..3 {
            let path = create_temp_file(&temp_dir, &format!("count{}.txt", i), b"content");
            let uuid = import_file(&mut session, &path, &format!("/count{}.txt", i), 1)
                .expect("Import should succeed");
            uuids.push(uuid);
        }

        let initial_count = session.get_unlocked_keystore(1).unwrap().keystore().dek_count();
        assert_eq!(initial_count, 3);

        // Delete one file
        delete_file(&mut session, uuids[1]).expect("Delete should succeed");

        let final_count = session.get_unlocked_keystore(1).unwrap().keystore().dek_count();
        assert_eq!(final_count, 2);
    }

    // ============================================================================
    // US-028: File Rename and Move Tests
    // ============================================================================

    #[test]
    fn test_rename_file_success() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "original.txt", b"Rename test content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/docs/original.txt", 1)
            .expect("Import should succeed");

        // Rename the file
        let updated = rename_file(&mut session, file_uuid, "renamed.txt")
            .expect("Rename should succeed");

        assert_eq!(updated.name(), "renamed.txt");
        assert_eq!(updated.path(), "/docs/renamed.txt");

        // Verify content is unchanged
        let (content, metadata) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");
        assert_eq!(content, b"Rename test content");
        assert_eq!(metadata.plaintext.name, "renamed.txt");
    }

    #[test]
    fn test_rename_file_root_level() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "root.txt", b"Root file");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/root.txt", 1)
            .expect("Import should succeed");

        let updated = rename_file(&mut session, file_uuid, "new_root.txt")
            .expect("Rename should succeed");

        assert_eq!(updated.name(), "new_root.txt");
        assert_eq!(updated.path(), "/new_root.txt");
    }

    #[test]
    fn test_rename_file_different_levels() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Import files at each level
        let path1 = create_temp_file(&temp_dir, "level1.txt", b"Level 1");
        let path2 = create_temp_file(&temp_dir, "level2.txt", b"Level 2");
        let path3 = create_temp_file(&temp_dir, "level3.txt", b"Level 3");

        let uuid1 = import_file(&mut session, &path1, "/l1/file.txt", 1).expect("L1 import");
        let uuid2 = import_file(&mut session, &path2, "/l2/file.txt", 2).expect("L2 import");
        let uuid3 = import_file(&mut session, &path3, "/l3/file.txt", 3).expect("L3 import");

        // Rename each
        let renamed1 = rename_file(&mut session, uuid1, "new1.txt").expect("L1 rename");
        let renamed2 = rename_file(&mut session, uuid2, "new2.txt").expect("L2 rename");
        let renamed3 = rename_file(&mut session, uuid3, "new3.txt").expect("L3 rename");

        assert_eq!(renamed1.path(), "/l1/new1.txt");
        assert_eq!(renamed2.path(), "/l2/new2.txt");
        assert_eq!(renamed3.path(), "/l3/new3.txt");
    }

    #[test]
    fn test_rename_file_locked_session_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "file.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/file.txt", 1)
            .expect("Import should succeed");

        session.lock();

        let result = rename_file(&mut session, file_uuid, "new.txt");
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_rename_file_not_found() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let nonexistent_uuid = Uuid::new_v4();
        let result = rename_file(&mut session, nonexistent_uuid, "new.txt");
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_rename_file_unicode() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "文件.txt", b"Unicode content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/文档/文件.txt", 1)
            .expect("Import should succeed");

        let updated = rename_file(&mut session, file_uuid, "新名称.txt")
            .expect("Rename should succeed");

        assert_eq!(updated.name(), "新名称.txt");
        assert_eq!(updated.path(), "/文档/新名称.txt");
    }

    #[test]
    fn test_rename_file_preserves_content() {
        let (temp_dir, vault_path) = create_test_vault();
        let content = b"Important content that must be preserved";
        let source_path = create_temp_file(&temp_dir, "preserve.txt", content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/preserve.txt", 2)
            .expect("Import should succeed");

        rename_file(&mut session, file_uuid, "still_preserved.txt")
            .expect("Rename should succeed");

        // Content must be identical
        let (exported, _) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");
        assert_eq!(exported, content);
    }

    #[test]
    fn test_rename_file_persists_across_session() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "persistent.txt", b"Persistent");

        let file_uuid = {
            let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            let uuid = import_file(&mut session, &source_path, "/persistent.txt", 1)
                .expect("Import should succeed");

            rename_file(&mut session, uuid, "renamed_persistent.txt")
                .expect("Rename should succeed");

            uuid
        };

        // Reopen and verify
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        let (_, metadata) = export_to_bytes(&session2, file_uuid)
            .expect("Export should succeed");

        assert_eq!(metadata.plaintext.name, "renamed_persistent.txt");
    }

    #[test]
    fn test_move_file_success() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "moveme.txt", b"Move test content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/old/path/moveme.txt", 1)
            .expect("Import should succeed");

        let updated = move_file(&mut session, file_uuid, "/new/location/moved.txt")
            .expect("Move should succeed");

        assert_eq!(updated.name(), "moved.txt");
        assert_eq!(updated.path(), "/new/location/moved.txt");

        // Verify content is unchanged
        let (content, _) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");
        assert_eq!(content, b"Move test content");
    }

    #[test]
    fn test_move_file_to_root() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "deep.txt", b"Deep file");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/a/b/c/deep.txt", 1)
            .expect("Import should succeed");

        let updated = move_file(&mut session, file_uuid, "/root.txt")
            .expect("Move should succeed");

        assert_eq!(updated.name(), "root.txt");
        assert_eq!(updated.path(), "/root.txt");
    }

    #[test]
    fn test_move_file_different_levels() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let path1 = create_temp_file(&temp_dir, "level1.txt", b"Level 1");
        let path2 = create_temp_file(&temp_dir, "level2.txt", b"Level 2");
        let path3 = create_temp_file(&temp_dir, "level3.txt", b"Level 3");

        let uuid1 = import_file(&mut session, &path1, "/old/l1.txt", 1).expect("L1 import");
        let uuid2 = import_file(&mut session, &path2, "/old/l2.txt", 2).expect("L2 import");
        let uuid3 = import_file(&mut session, &path3, "/old/l3.txt", 3).expect("L3 import");

        let moved1 = move_file(&mut session, uuid1, "/new/location/l1.txt").expect("L1 move");
        let moved2 = move_file(&mut session, uuid2, "/archive/l2.txt").expect("L2 move");
        let moved3 = move_file(&mut session, uuid3, "/secret/l3.txt").expect("L3 move");

        assert_eq!(moved1.path(), "/new/location/l1.txt");
        assert_eq!(moved2.path(), "/archive/l2.txt");
        assert_eq!(moved3.path(), "/secret/l3.txt");
    }

    #[test]
    fn test_move_file_locked_session_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "file.txt", b"content");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/file.txt", 1)
            .expect("Import should succeed");

        session.lock();

        let result = move_file(&mut session, file_uuid, "/new/path.txt");
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_move_file_not_found() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let nonexistent_uuid = Uuid::new_v4();
        let result = move_file(&mut session, nonexistent_uuid, "/new/path.txt");
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_move_file_unicode_path() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "unicode.txt", b"Unicode move");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/english/path.txt", 1)
            .expect("Import should succeed");

        let updated = move_file(&mut session, file_uuid, "/日本語/フォルダ/ファイル.txt")
            .expect("Move should succeed");

        assert_eq!(updated.name(), "ファイル.txt");
        assert_eq!(updated.path(), "/日本語/フォルダ/ファイル.txt");
    }

    #[test]
    fn test_move_file_preserves_content() {
        let (temp_dir, vault_path) = create_test_vault();
        let content = b"Content must survive the move";
        let source_path = create_temp_file(&temp_dir, "moving.bin", content);

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/before/moving.bin", 2)
            .expect("Import should succeed");

        move_file(&mut session, file_uuid, "/after/moved.bin")
            .expect("Move should succeed");

        let (exported, _) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");
        assert_eq!(exported, content);
    }

    #[test]
    fn test_move_file_persists_across_session() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "persistent.txt", b"Persistent");

        let file_uuid = {
            let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            let uuid = import_file(&mut session, &source_path, "/old/path.txt", 1)
                .expect("Import should succeed");

            move_file(&mut session, uuid, "/new/persistent.txt")
                .expect("Move should succeed");

            uuid
        };

        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        let (_, metadata) = export_to_bytes(&session2, file_uuid)
            .expect("Export should succeed");

        assert_eq!(metadata.plaintext.path, "/new/persistent.txt");
    }

    #[test]
    fn test_move_file_preserves_access_level() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "level_test.txt", b"Level test");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/original.txt", 3)
            .expect("Import should succeed");

        let updated = move_file(&mut session, file_uuid, "/moved.txt")
            .expect("Move should succeed");

        // Access level should be unchanged
        assert_eq!(updated.access_level(), 3);
    }

    #[test]
    fn test_rename_then_move() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "both.txt", b"Both operations");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/start/both.txt", 1)
            .expect("Import should succeed");

        // First rename
        let renamed = rename_file(&mut session, file_uuid, "renamed.txt")
            .expect("Rename should succeed");
        assert_eq!(renamed.path(), "/start/renamed.txt");

        // Then move
        let moved = move_file(&mut session, file_uuid, "/end/final.txt")
            .expect("Move should succeed");
        assert_eq!(moved.path(), "/end/final.txt");
        assert_eq!(moved.name(), "final.txt");

        // Content unchanged
        let (content, _) = export_to_bytes(&session, file_uuid)
            .expect("Export should succeed");
        assert_eq!(content, b"Both operations");
    }

    #[test]
    fn test_move_then_rename() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "combo.txt", b"Combo test");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/a/combo.txt", 1)
            .expect("Import should succeed");

        // First move
        move_file(&mut session, file_uuid, "/b/moved.txt")
            .expect("Move should succeed");

        // Then rename
        let final_state = rename_file(&mut session, file_uuid, "final.txt")
            .expect("Rename should succeed");

        assert_eq!(final_state.path(), "/b/final.txt");
        assert_eq!(final_state.name(), "final.txt");
    }

    #[test]
    fn test_rename_after_delete_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "delete_me.txt", b"Delete then rename");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/delete_me.txt", 1)
            .expect("Import should succeed");

        delete_file(&mut session, file_uuid)
            .expect("Delete should succeed");

        let result = rename_file(&mut session, file_uuid, "new.txt");
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_move_after_delete_fails() {
        let (temp_dir, vault_path) = create_test_vault();
        let source_path = create_temp_file(&temp_dir, "delete_me.txt", b"Delete then move");

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = import_file(&mut session, &source_path, "/delete_me.txt", 1)
            .expect("Import should succeed");

        delete_file(&mut session, file_uuid)
            .expect("Delete should succeed");

        let result = move_file(&mut session, file_uuid, "/new/path.txt");
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    // ============================================================================
    // US-029: Directory Listing Tests
    // ============================================================================

    #[test]
    fn test_list_files_empty_vault() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let entries = list_files(&session, "/")
            .expect("List should succeed");

        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_files_root_directory() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Add files at root level
        let path1 = create_temp_file(&temp_dir, "file1.txt", b"Content 1");
        let path2 = create_temp_file(&temp_dir, "file2.txt", b"Content 2");

        import_file(&mut session, &path1, "/file1.txt", 1)
            .expect("Import should succeed");
        import_file(&mut session, &path2, "/file2.txt", 1)
            .expect("Import should succeed");

        let entries = list_files(&session, "/")
            .expect("List should succeed");

        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.is_file()));
        assert!(entries.iter().any(|e| e.name == "file1.txt"));
        assert!(entries.iter().any(|e| e.name == "file2.txt"));
    }

    #[test]
    fn test_list_files_with_subdirectories() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Add files at various paths
        let path1 = create_temp_file(&temp_dir, "file1.txt", b"Content 1");
        let path2 = create_temp_file(&temp_dir, "file2.txt", b"Content 2");
        let path3 = create_temp_file(&temp_dir, "report.pdf", b"Report");

        import_file(&mut session, &path1, "/docs/file1.txt", 1)
            .expect("Import should succeed");
        import_file(&mut session, &path2, "/docs/reports/file2.txt", 1)
            .expect("Import should succeed");
        import_file(&mut session, &path3, "/media/report.pdf", 1)
            .expect("Import should succeed");

        // List root - should show "docs" and "media" directories
        let root_entries = list_files(&session, "/")
            .expect("List should succeed");

        assert_eq!(root_entries.len(), 2);
        assert!(root_entries.iter().all(|e| e.is_directory()));
        assert!(root_entries.iter().any(|e| e.name == "docs"));
        assert!(root_entries.iter().any(|e| e.name == "media"));

        // List /docs - should show "file1.txt" file and "reports" directory
        let docs_entries = list_files(&session, "/docs")
            .expect("List should succeed");

        assert_eq!(docs_entries.len(), 2);
        assert!(docs_entries.iter().any(|e| e.name == "reports" && e.is_directory()));
        assert!(docs_entries.iter().any(|e| e.name == "file1.txt" && e.is_file()));

        // List /docs/reports - should show "file2.txt"
        let reports_entries = list_files(&session, "/docs/reports")
            .expect("List should succeed");

        assert_eq!(reports_entries.len(), 1);
        assert!(reports_entries[0].is_file());
        assert_eq!(reports_entries[0].name, "file2.txt");
    }

    #[test]
    fn test_list_files_preserves_metadata() {
        let (temp_dir, vault_path) = create_test_vault();
        let content = b"Test content for metadata";

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let source = create_temp_file(&temp_dir, "test.txt", content);
        let file_uuid = import_file(&mut session, &source, "/test.txt", 2)
            .expect("Import should succeed");

        let entries = list_files(&session, "/")
            .expect("List should succeed");

        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.name, "test.txt");
        assert_eq!(entry.size, content.len() as u64);
        assert_eq!(entry.access_level, 2);
        assert_eq!(entry.uuid, Some(file_uuid));
        assert!(entry.modified_time > 0);
    }

    #[test]
    fn test_list_files_sorting() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Add files in non-alphabetical order
        let path_z = create_temp_file(&temp_dir, "zebra.txt", b"Z");
        let path_a = create_temp_file(&temp_dir, "apple.txt", b"A");
        let path_m = create_temp_file(&temp_dir, "mango.txt", b"M");

        import_file(&mut session, &path_z, "/zebra.txt", 1).unwrap();
        import_file(&mut session, &path_a, "/apple.txt", 1).unwrap();
        import_file(&mut session, &path_m, "/mango.txt", 1).unwrap();

        let entries = list_files(&session, "/")
            .expect("List should succeed");

        // Should be sorted alphabetically
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "apple.txt");
        assert_eq!(entries[1].name, "mango.txt");
        assert_eq!(entries[2].name, "zebra.txt");
    }

    #[test]
    fn test_list_files_directories_before_files() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Add a mix of files and subdirectories
        let path1 = create_temp_file(&temp_dir, "zfile.txt", b"Z");
        let path2 = create_temp_file(&temp_dir, "afile.txt", b"A");
        let path3 = create_temp_file(&temp_dir, "nested.txt", b"N");

        import_file(&mut session, &path1, "/zfile.txt", 1).unwrap();
        import_file(&mut session, &path2, "/afile.txt", 1).unwrap();
        import_file(&mut session, &path3, "/docs/nested.txt", 1).unwrap();

        let entries = list_files(&session, "/")
            .expect("List should succeed");

        // Directories should come first
        assert_eq!(entries.len(), 3);
        assert!(entries[0].is_directory());
        assert_eq!(entries[0].name, "docs");
        assert!(entries[1].is_file());
        assert!(entries[2].is_file());
    }

    #[test]
    fn test_list_files_locked_session() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let source = create_temp_file(&temp_dir, "test.txt", b"content");
        import_file(&mut session, &source, "/test.txt", 1).unwrap();

        session.lock();

        let result = list_files(&session, "/");
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_list_all_files() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let path1 = create_temp_file(&temp_dir, "a.txt", b"A");
        let path2 = create_temp_file(&temp_dir, "b.txt", b"B");
        let path3 = create_temp_file(&temp_dir, "c.txt", b"C");

        import_file(&mut session, &path1, "/dir1/a.txt", 1).unwrap();
        import_file(&mut session, &path2, "/dir2/b.txt", 2).unwrap();
        import_file(&mut session, &path3, "/dir1/dir2/c.txt", 3).unwrap();

        let all_files = list_all_files(&session)
            .expect("List all should succeed");

        // Should return all 3 files (no directories)
        assert_eq!(all_files.len(), 3);
        assert!(all_files.iter().all(|e| e.is_file()));
        assert!(all_files.iter().any(|e| e.name == "a.txt"));
        assert!(all_files.iter().any(|e| e.name == "b.txt"));
        assert!(all_files.iter().any(|e| e.name == "c.txt"));
    }

    #[test]
    fn test_file_count() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Start with 0 files
        assert_eq!(file_count(&session).unwrap(), 0);

        // Add files at different levels
        let path1 = create_temp_file(&temp_dir, "a.txt", b"A");
        let path2 = create_temp_file(&temp_dir, "b.txt", b"B");
        let path3 = create_temp_file(&temp_dir, "c.txt", b"C");

        import_file(&mut session, &path1, "/a.txt", 1).unwrap();
        assert_eq!(file_count(&session).unwrap(), 1);

        import_file(&mut session, &path2, "/b.txt", 2).unwrap();
        assert_eq!(file_count(&session).unwrap(), 2);

        import_file(&mut session, &path3, "/c.txt", 3).unwrap();
        assert_eq!(file_count(&session).unwrap(), 3);
    }

    #[test]
    fn test_list_files_empty_subdirectory() {
        let (temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Add a file at root only
        let path = create_temp_file(&temp_dir, "root.txt", b"Root");
        import_file(&mut session, &path, "/root.txt", 1).unwrap();

        // Try to list a non-existent directory - should return empty
        let entries = list_files(&session, "/nonexistent")
            .expect("List should succeed");

        assert!(entries.is_empty());
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("docs"), "/docs");
        assert_eq!(normalize_path("/docs/"), "/docs");
        assert_eq!(normalize_path("/docs//"), "/docs");
        assert_eq!(normalize_path("  /docs/reports  "), "/docs/reports");
    }

    #[test]
    fn test_get_relative_path() {
        // Root directory cases
        assert_eq!(get_relative_path("/file.txt", "/"), Some("file.txt".to_string()));
        assert_eq!(get_relative_path("/docs/file.txt", "/"), Some("docs/file.txt".to_string()));

        // Subdirectory cases
        assert_eq!(get_relative_path("/docs/file.txt", "/docs"), Some("file.txt".to_string()));
        assert_eq!(get_relative_path("/docs/reports/file.txt", "/docs"), Some("reports/file.txt".to_string()));
        assert_eq!(get_relative_path("/docs/reports/file.txt", "/docs/reports"), Some("file.txt".to_string()));

        // Non-matching paths
        assert_eq!(get_relative_path("/media/file.txt", "/docs"), None);
        assert_eq!(get_relative_path("/documents/file.txt", "/docs"), None);
    }

    #[test]
    fn test_split_first_component() {
        assert_eq!(split_first_component(""), None);
        assert_eq!(split_first_component("file.txt"), Some(("file.txt", false)));
        assert_eq!(split_first_component("docs/file.txt"), Some(("docs", true)));
        assert_eq!(split_first_component("docs/reports/file.txt"), Some(("docs", true)));
    }
}
