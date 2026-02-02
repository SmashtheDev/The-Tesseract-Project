//! Core error types for vault operations.

use thiserror::Error;

/// Errors that can occur during vault operations.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Authentication failed.
    #[error("Authentication failed: invalid password or vault corrupted")]
    AuthenticationFailed,

    /// Vault is locked and operation requires unlock.
    #[error("Vault is locked: unlock required")]
    VaultLocked,

    /// Access level insufficient for operation.
    #[error("Access denied: insufficient access level")]
    AccessDenied,

    /// File not found in vault.
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Vault already exists at path.
    #[error("Vault already exists at path: {0}")]
    VaultAlreadyExists(String),

    /// Vault not found at path.
    #[error("Vault not found at path: {0}")]
    VaultNotFound(String),

    /// Vault is temporarily locked out.
    #[error("Vault locked out: too many failed attempts. Retry after {0} seconds")]
    LockedOut(u64),

    /// IO error during vault operation.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] tesseract_crypto::CryptoError),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Header integrity verification failed.
    #[error("Header integrity check failed: vault may be corrupted")]
    HeaderIntegrityFailed,

    /// Invalid vault format.
    #[error("Invalid vault format: {0}")]
    InvalidFormat(String),

    /// Recovery not available for this vault.
    #[error("Recovery not available: vault has no recovery key configured")]
    RecoveryNotAvailable,

    /// Invalid data encountered.
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// IO error (alternative name for IoError).
    #[error("IO error: {0}")]
    Io(std::io::Error),
}
