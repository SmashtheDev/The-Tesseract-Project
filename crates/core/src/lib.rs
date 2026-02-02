//! TESSERACT Core Vault Management
//!
//! This crate provides the core vault operations:
//! - Vault creation, opening, and locking
//! - File import, export, and deletion
//! - Access level management
//! - Key hierarchy management

#![warn(missing_docs)]
#![warn(clippy::all)]

/// Vault header structure and operations.
pub mod header;

/// Vault directory structure creation and management.
pub mod vault;

/// Access level management.
pub mod access;

/// File operations (import, export, delete, rename).
pub mod files;

/// Keystore management.
pub mod keystore;

/// Blob storage for encrypted file content.
pub mod blob;

/// Encrypted metadata storage.
pub mod metadata;

/// Vault session management.
pub mod session;

/// Core error types.
pub mod error;

/// Secure temporary file management for file preview.
pub mod tempfile;

pub use error::VaultError;

// Re-export header types
pub use header::{
    VaultHeader, VaultVersion, CURRENT_VERSION, HEADER_SIZE, MAGIC_BYTES,
    ENCRYPTED_MASTER_KEY_SIZE, HMAC_TAG_SIZE, NONCE_SIZE, SALT_SIZE,
    // US-010: Header encryption and integrity functions
    create_encrypted_header, unlock_header,
    // US-021: Exponential backoff constants
    BACKOFF_BASE_SECONDS, BACKOFF_MAX_SECONDS,
    // US-022: Lockout after failures constants
    DEFAULT_LOCKOUT_THRESHOLD, DEFAULT_LOCKOUT_DURATION_SECONDS,
};

// Re-export keystore types
pub use keystore::{
    // US-011: Access-Level Keystore Format
    Keystore, KeystoreVersion, DekEntry,
    CURRENT_KEYSTORE_VERSION, DEK_ENTRY_SIZE, ENCRYPTED_KEY_SIZE,
    HEADER_SIZE as KEYSTORE_HEADER_SIZE, UUID_SIZE,
    // Keystore operations
    create_keystore, add_file_dek, wrap_kek, wrap_dek,
};

// Re-export blob types
pub use blob::{
    // US-012: Blob Storage Format
    BlobInfo, BLOBS_DIR, BLOB_EXTENSION, MIN_BLOB_SIZE,
    BLOB_NONCE_SIZE, BLOB_TAG_SIZE,
    // Path utilities
    blobs_dir, blob_path, ensure_blobs_dir, blob_exists,
    // Blob operations
    write_blob, write_blob_with_nonce, read_blob, read_blob_info,
    delete_blob, list_blobs, verify_blob,
};

// Re-export metadata types
pub use metadata::{
    // US-013: Encrypted Metadata Storage
    FileMetadata, MetadataPlaintext, MetadataInfo,
    METADATA_DIR, METADATA_EXTENSION, MIN_METADATA_SIZE,
    METADATA_NONCE_SIZE, METADATA_TAG_SIZE,
    // Path utilities
    metadata_dir, metadata_path, ensure_metadata_dir, metadata_exists,
    // Metadata operations
    write_metadata, write_metadata_with_nonce, read_metadata, read_metadata_info,
    delete_metadata, list_metadata, update_metadata,
    // File operations
    rename_file, move_file, change_access_level,
    // Verification utilities
    verify_metadata, contains_plaintext_patterns, read_raw_metadata,
};

// Re-export vault types
pub use vault::{
    // US-014: Vault Directory Structure Creation
    VaultConfig, VaultCreationResult,
    // Constants
    HEADER_FILENAME, KEYSTORES_DIR,
    BLOBS_DIR as VAULT_BLOBS_DIR, METADATA_DIR as VAULT_METADATA_DIR,
    DEFAULT_LEVEL_COUNT, MAX_LEVEL_COUNT, MIN_LEVEL_COUNT,
    // Path utilities
    header_path, keystores_dir, vault_blobs_dir, vault_metadata_dir, keystore_path,
    // Vault operations
    create_vault, delete_vault, vault_exists, is_vault_complete,
    list_keystores, validate_vault_structure,
    // US-023: Recovery Key Generation
    recover_master_key,
    // US-024: Recovery Key Authentication
    read_recovery_blob, has_recovery_blob, recovery_path, RECOVERY_FILENAME,
};

// Re-export recovery key types from crypto crate
pub use tesseract_crypto::recovery::{
    generate_recovery_key, RecoveryKey, ENCRYPTED_MASTER_KEY_SIZE as RECOVERY_BLOB_SIZE,
    RECOVERY_KEY_SIZE,
};

// Re-export session types
pub use session::{
    // US-015: Vault Open and Authentication
    VaultSession, UnlockedKeystore,
    // US-016: Vault Lock and Key Wiping
    SessionState, lock_vault,
    // US-018: Hierarchical Access Mode
    AccessMode, open_vault_hierarchical,
    // US-020: Per-Level Password Management
    change_level_password, PasswordChangeResult,
    // US-024: Recovery Key Authentication
    RecoverySession, authenticate_recovery, reset_level_password_with_recovery,
    // Session operations
    open_vault,
};

// Re-export file operations
pub use files::{
    // US-025: File Import
    import_file, import_bytes,
    // US-026: File Export
    export_file, export_to_bytes, export_file_with_original_name,
    // US-027: File Deletion
    delete_file,
    // US-029: Directory Listing
    FileEntry, EntryType, list_files, list_all_files, file_count,
};

// Re-export temp file operations
pub use tempfile::{
    // US-041: Secure Temporary File Viewing
    TempFileManager, TempFileInfo, TempFileStatus, TempFileError,
    // Secure deletion
    secure_delete_file, open_with_system,
    // Constants
    OVERWRITE_PASSES, OVERWRITE_BLOCK_SIZE, TEMP_SUBDIR,
};

// Re-export access level types
pub use access::{
    // US-017: Access Level Definition and Configuration
    AccessLevel, LevelConfig, LevelConfigVersion, LevelInfo,
    // Constants
    LEVELS_DIR, LEVELS_CONFIG_FILE, DEFAULT_LEVEL_NAMES, MIN_LEVELS_CONFIG_SIZE,
    // US-024: Recovery Key Authentication
    ENCRYPTED_KEK_SIZE, initialize_level_config,
    // Path utilities
    levels_dir, levels_config_path, ensure_levels_dir, levels_config_exists,
    // Level configuration I/O
    write_levels_config, read_levels_config,
    // High-level CRUD operations
    create_level, delete_level, list_levels_info,
};
