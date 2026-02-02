//! Cryptographic error types.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Authentication failed during decryption.
    #[error("Authentication failed: ciphertext may have been tampered with")]
    AuthenticationFailed,

    /// Invalid key length provided.
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// Invalid nonce length provided.
    #[error("Invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length in bytes.
        expected: usize,
        /// Actual nonce length provided.
        actual: usize,
    },

    /// Nonce collision detected.
    #[error("Nonce collision detected: nonce has already been used")]
    NonceCollision,

    /// Random number generation failed.
    #[error("Failed to generate random bytes: {0}")]
    RandomGenerationFailed(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// HMAC verification failed.
    #[error("HMAC integrity verification failed")]
    IntegrityError,

    /// Invalid BIP39 mnemonic phrase.
    #[error("Invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    /// Invalid recovery key format.
    #[error("Invalid recovery key: {0}")]
    InvalidRecoveryKey(String),
}
