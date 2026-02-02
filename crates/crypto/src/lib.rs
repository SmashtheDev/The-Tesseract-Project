//! TESSERACT Cryptographic Primitives
//!
//! This crate provides cryptographic operations for TESSERACT:
//! - AES-256-GCM authenticated encryption
//! - Streaming encryption for large files
//! - Argon2id key derivation
//! - HMAC-SHA256 integrity verification
//! - Secure random number generation
//! - Secure memory handling
//! - Hardware acceleration detection

#![warn(missing_docs)]
#![warn(clippy::all)]

/// AES-256-GCM encryption/decryption module.
pub mod aes;

/// Argon2id key derivation function.
pub mod kdf;

/// HMAC-SHA256 integrity verification.
pub mod hmac;

/// HKDF (HMAC-based Key Derivation Function) for key expansion.
pub mod hkdf;

/// Cryptographically secure random number generation.
pub mod random;

/// Secure memory handling with automatic zeroization.
pub mod secure_memory;

/// Hardware acceleration detection.
pub mod acceleration;

/// Nonce uniqueness enforcement.
pub mod nonce;

/// Recovery key generation and management.
pub mod recovery;

/// Streaming encryption/decryption for large files.
pub mod streaming;

/// AES-256-XTS sector encryption for hardware containers.
pub mod xts;

/// Cryptographic error types.
pub mod error;

/// Comprehensive cryptographic test vector suite.
///
/// This module provides official test vectors from:
/// - NIST SP 800-38D (AES-256-GCM)
/// - RFC 9106 (Argon2id)
/// - RFC 4231 (HMAC-SHA256)
pub mod test_vectors;

/// Nonce uniqueness stress tests (US-064).
///
/// This module provides stress testing for nonce generation to verify
/// zero collisions under high-volume usage (1 million nonces).
pub mod stress_tests;

/// Metadata encryption verification (US-065).
///
/// This module provides comprehensive verification that no plaintext leakage
/// occurs in encrypted vault storage. It scans vault directories for any
/// plaintext patterns that should be encrypted.
pub mod encryption_verification;

/// Performance benchmark suite (US-067).
///
/// This module provides comprehensive performance benchmarking:
/// - Sequential read/write throughput (target: >= 85% native)
/// - Vault unlock time (target: < 3 seconds)
/// - Regression detection with 10% threshold
pub mod benchmarks;

pub use error::CryptoError;

// Re-export key acceleration API
pub use acceleration::{has_aes_ni, log_acceleration_status, AccelerationInfo};

// Re-export key derivation API
pub use kdf::{derive_key, Argon2Params, Argon2Version};

// Re-export random generation API
pub use random::{
    fill_random, generate_bytes, generate_key, generate_nonce, generate_salt, generate_uuid,
    KEY_SIZE, NONCE_SIZE, SALT_SIZE, UUID_SIZE,
};

// Re-export Uuid type for convenience
pub use uuid::Uuid;

// Re-export nonce registry API
pub use nonce::{generate_and_register_nonce, NonceRegistry, NONCE_SIZE as REGISTRY_NONCE_SIZE};

// Re-export secure memory API
pub use secure_memory::{
    constant_time_eq, secure_clear, SecureBytes, SecureKey, SecureMemoryError, SecureNonce,
    SecureSalt,
};

// Re-export HMAC API
pub use hmac::{hmac_sign, hmac_verify, hmac_verify_slice, is_key_length_adequate, HMAC_SIZE, MIN_KEY_SIZE};

// Re-export HKDF API
pub use hkdf::{
    hkdf, hkdf_expand, hkdf_expand_32, hkdf_expand_64, hkdf_extract, HASH_LEN, MAX_OKM_LEN,
};

// Re-export recovery key API
pub use recovery::{
    generate_recovery_key, RecoveryKey, ENCRYPTED_MASTER_KEY_SIZE, RECOVERY_KEY_SIZE,
};

// Re-export streaming encryption API
pub use streaming::{
    calculate_encrypted_size, calculate_max_plaintext_size, StreamConfig, StreamError,
    StreamingDecryptor, StreamingEncryptor, StreamResult, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
};

// Re-export test vector validation API
pub use test_vectors::{
    aes_gcm_vector_count, argon2id_vector_count, hmac_sha256_vector_count, validate_all_vectors,
    TestVectorSummary,
};

// Re-export stress test API
pub use stress_tests::{
    format_stress_test_report, run_nonce_stress_test, run_one_million_nonce_test,
    StressTestConfig, StressTestResult,
};

// Re-export benchmark API
pub use benchmarks::{
    benchmark_native_read, benchmark_native_write, benchmark_sequential_read,
    benchmark_sequential_write, benchmark_vault_unlock, check_regression,
    format_benchmark_report, format_regression_report, run_benchmark_suite,
    thresholds, BenchmarkConfig, BenchmarkResult, BenchmarkSuiteResult, RegressionCheckResult,
};

// Re-export XTS API for hardware encryption
pub use xts::{
    Xts256, XtsConfig, XtsError, XtsResult,
    XTS_KEY_SIZE, DEFAULT_SECTOR_SIZE, MIN_SECTOR_SIZE, MAX_SECTOR_SIZE,
};
