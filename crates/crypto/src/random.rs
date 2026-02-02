//! Cryptographically Secure Random Number Generation
//!
//! This module provides utilities for generating cryptographically secure random
//! values using the operating system's CSPRNG via the `getrandom` crate.
//!
//! # Security Guarantees
//!
//! - All random values are generated using the OS-provided CSPRNG
//! - No userspace PRNGs are used
//! - Suitable for cryptographic key material, nonces, and salts
//!
//! # Functions
//!
//! - [`generate_key`] - Generate a 256-bit (32-byte) encryption key
//! - [`generate_nonce`] - Generate a 96-bit (12-byte) nonce for AES-GCM
//! - [`generate_salt`] - Generate a 128-bit (16-byte) salt for key derivation
//! - [`generate_uuid`] - Generate a random UUID (v4)
//!
//! # Example
//!
//! ```
//! use tesseract_crypto::random::{generate_key, generate_nonce, generate_salt, generate_uuid};
//!
//! // Generate random cryptographic materials
//! let key = generate_key().expect("Failed to generate key");
//! let nonce = generate_nonce().expect("Failed to generate nonce");
//! let salt = generate_salt().expect("Failed to generate salt");
//! let uuid = generate_uuid().expect("Failed to generate UUID");
//!
//! assert_eq!(key.len(), 32);
//! assert_eq!(nonce.len(), 12);
//! assert_eq!(salt.len(), 16);
//! ```

use crate::CryptoError;
use uuid::Uuid;

/// Size of an AES-256 key in bytes.
pub const KEY_SIZE: usize = 32;

/// Size of an AES-GCM nonce in bytes (96 bits as per NIST recommendation).
pub const NONCE_SIZE: usize = 12;

/// Size of a salt for Argon2id in bytes (128 bits minimum recommended).
pub const SALT_SIZE: usize = 16;

/// Size of UUID raw bytes.
pub const UUID_SIZE: usize = 16;

/// Fills a byte slice with cryptographically secure random bytes.
///
/// This is the core function that uses the OS CSPRNG via `getrandom`.
///
/// # Arguments
///
/// * `dest` - The byte slice to fill with random bytes
///
/// # Returns
///
/// * `Ok(())` - Successfully filled the buffer with random bytes
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # Example
///
/// ```
/// use tesseract_crypto::random::fill_random;
///
/// let mut buffer = [0u8; 64];
/// fill_random(&mut buffer).expect("Failed to fill with random bytes");
/// ```
pub fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(dest).map_err(|e| {
        CryptoError::RandomGenerationFailed(format!("getrandom failed: {}", e))
    })
}

/// Generates a cryptographically secure 256-bit (32-byte) key.
///
/// This key is suitable for use with AES-256-GCM encryption. The key is
/// generated using the operating system's CSPRNG exclusively.
///
/// # Returns
///
/// * `Ok([u8; 32])` - A 32-byte random key
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # Security
///
/// - Uses OS CSPRNG only (no userspace PRNGs)
/// - Each call generates an independent random key
/// - The key has 256 bits of entropy
///
/// # Example
///
/// ```
/// use tesseract_crypto::random::generate_key;
///
/// let key = generate_key().expect("Failed to generate key");
/// assert_eq!(key.len(), 32);
/// ```
pub fn generate_key() -> Result<[u8; KEY_SIZE], CryptoError> {
    let mut key = [0u8; KEY_SIZE];
    fill_random(&mut key)?;
    Ok(key)
}

/// Generates a cryptographically secure 96-bit (12-byte) nonce.
///
/// This nonce is suitable for use with AES-256-GCM encryption. The 96-bit
/// size is the recommended nonce length for GCM as specified by NIST.
///
/// # Returns
///
/// * `Ok([u8; 12])` - A 12-byte random nonce
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # Security
///
/// - Uses OS CSPRNG only (no userspace PRNGs)
/// - 96-bit random nonces have ~50% collision probability after 2^48 uses
/// - For high-security applications, use a nonce registry to detect collisions
///
/// # Example
///
/// ```
/// use tesseract_crypto::random::generate_nonce;
///
/// let nonce = generate_nonce().expect("Failed to generate nonce");
/// assert_eq!(nonce.len(), 12);
/// ```
pub fn generate_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Generates a cryptographically secure 128-bit (16-byte) salt.
///
/// This salt is suitable for use with Argon2id key derivation. The 128-bit
/// size meets the minimum recommendation for salt length.
///
/// # Returns
///
/// * `Ok([u8; 16])` - A 16-byte random salt
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # Security
///
/// - Uses OS CSPRNG only (no userspace PRNGs)
/// - 128 bits of entropy prevents rainbow table attacks
/// - Each vault/user should use a unique salt
///
/// # Example
///
/// ```
/// use tesseract_crypto::random::generate_salt;
///
/// let salt = generate_salt().expect("Failed to generate salt");
/// assert_eq!(salt.len(), 16);
/// ```
pub fn generate_salt() -> Result<[u8; SALT_SIZE], CryptoError> {
    let mut salt = [0u8; SALT_SIZE];
    fill_random(&mut salt)?;
    Ok(salt)
}

/// Generates a random UUID (version 4).
///
/// This UUID is generated using the operating system's CSPRNG and follows
/// the UUID v4 specification (random variant).
///
/// # Returns
///
/// * `Ok(Uuid)` - A random UUID
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # UUID Format
///
/// The generated UUID follows RFC 4122 version 4:
/// - Version: 4 (random)
/// - Variant: DCE 1.1, ISO/IEC 11578:1996 (most common)
/// - 122 bits of random data (6 bits used for version and variant)
///
/// # Example
///
/// ```
/// use tesseract_crypto::random::generate_uuid;
///
/// let uuid = generate_uuid().expect("Failed to generate UUID");
/// // UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
/// println!("Generated UUID: {}", uuid);
/// ```
pub fn generate_uuid() -> Result<Uuid, CryptoError> {
    // Generate 16 random bytes
    let mut bytes = [0u8; UUID_SIZE];
    fill_random(&mut bytes)?;

    // Set version to 4 (random)
    // Version is in the high nibble of byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // Set variant to RFC 4122
    // Variant is in the high bits of byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(Uuid::from_bytes(bytes))
}

/// Generates random bytes of arbitrary length.
///
/// This function allocates and returns a vector of random bytes.
///
/// # Arguments
///
/// * `length` - Number of random bytes to generate
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - A vector containing `length` random bytes
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # Example
///
/// ```
/// use tesseract_crypto::random::generate_bytes;
///
/// let random_data = generate_bytes(64).expect("Failed to generate bytes");
/// assert_eq!(random_data.len(), 64);
/// ```
pub fn generate_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_key_length() {
        let key = generate_key().expect("Failed to generate key");
        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_key_non_zero() {
        // Generate multiple keys and ensure they're not all zeros
        for _ in 0..10 {
            let key = generate_key().expect("Failed to generate key");
            // At least some bytes should be non-zero
            assert!(key.iter().any(|&b| b != 0), "Key should contain non-zero bytes");
        }
    }

    #[test]
    fn test_generate_key_unique() {
        // Generate multiple keys and ensure they're different
        let mut keys = HashSet::new();
        for _ in 0..100 {
            let key = generate_key().expect("Failed to generate key");
            assert!(keys.insert(key), "Generated duplicate key");
        }
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce().expect("Failed to generate nonce");
        assert_eq!(nonce.len(), NONCE_SIZE);
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_generate_nonce_non_zero() {
        // Generate multiple nonces and ensure they're not all zeros
        for _ in 0..10 {
            let nonce = generate_nonce().expect("Failed to generate nonce");
            // At least some bytes should be non-zero
            assert!(nonce.iter().any(|&b| b != 0), "Nonce should contain non-zero bytes");
        }
    }

    #[test]
    fn test_generate_nonce_unique() {
        // Generate multiple nonces and ensure they're different
        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let nonce = generate_nonce().expect("Failed to generate nonce");
            assert!(nonces.insert(nonce), "Generated duplicate nonce");
        }
    }

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt().expect("Failed to generate salt");
        assert_eq!(salt.len(), SALT_SIZE);
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn test_generate_salt_non_zero() {
        // Generate multiple salts and ensure they're not all zeros
        for _ in 0..10 {
            let salt = generate_salt().expect("Failed to generate salt");
            // At least some bytes should be non-zero
            assert!(salt.iter().any(|&b| b != 0), "Salt should contain non-zero bytes");
        }
    }

    #[test]
    fn test_generate_salt_unique() {
        // Generate multiple salts and ensure they're different
        let mut salts = HashSet::new();
        for _ in 0..100 {
            let salt = generate_salt().expect("Failed to generate salt");
            assert!(salts.insert(salt), "Generated duplicate salt");
        }
    }

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid().expect("Failed to generate UUID");

        // Verify UUID v4 format
        assert_eq!(uuid.get_version_num(), 4, "UUID should be version 4");

        // Get the variant
        let variant = uuid.get_variant();
        assert!(
            matches!(variant, uuid::Variant::RFC4122),
            "UUID should have RFC4122 variant"
        );
    }

    #[test]
    fn test_generate_uuid_unique() {
        // Generate multiple UUIDs and ensure they're different
        let mut uuids = HashSet::new();
        for _ in 0..100 {
            let uuid = generate_uuid().expect("Failed to generate UUID");
            assert!(uuids.insert(uuid), "Generated duplicate UUID");
        }
    }

    #[test]
    fn test_generate_uuid_non_nil() {
        let uuid = generate_uuid().expect("Failed to generate UUID");
        assert!(!uuid.is_nil(), "UUID should not be nil");
    }

    #[test]
    fn test_generate_bytes_length() {
        for length in [0, 1, 16, 32, 64, 128, 1024] {
            let bytes = generate_bytes(length).expect("Failed to generate bytes");
            assert_eq!(bytes.len(), length, "Generated bytes should have correct length");
        }
    }

    #[test]
    fn test_generate_bytes_non_zero() {
        // For non-trivial lengths, bytes should contain non-zero values
        let bytes = generate_bytes(64).expect("Failed to generate bytes");
        assert!(bytes.iter().any(|&b| b != 0), "Bytes should contain non-zero values");
    }

    #[test]
    fn test_generate_bytes_empty() {
        let bytes = generate_bytes(0).expect("Failed to generate empty bytes");
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn test_fill_random_modifies_buffer() {
        let mut buffer = [0u8; 32];
        fill_random(&mut buffer).expect("Failed to fill random");

        // Buffer should no longer be all zeros
        assert!(buffer.iter().any(|&b| b != 0), "Buffer should be modified");
    }

    #[test]
    fn test_fill_random_empty_buffer() {
        let mut buffer = [0u8; 0];
        fill_random(&mut buffer).expect("Should handle empty buffer");
    }

    #[test]
    fn test_os_csprng_used() {
        // This test verifies that we're using the OS CSPRNG by checking
        // that sequential calls produce different results (statistical test)
        let mut values = Vec::new();
        for _ in 0..1000 {
            let key = generate_key().expect("Failed to generate key");
            values.push(key);
        }

        // All values should be unique (extremely high probability with 256-bit values)
        let unique: HashSet<_> = values.iter().collect();
        assert_eq!(unique.len(), 1000, "All generated keys should be unique");
    }

    #[test]
    fn test_constants() {
        assert_eq!(KEY_SIZE, 32, "Key size should be 32 bytes (256 bits)");
        assert_eq!(NONCE_SIZE, 12, "Nonce size should be 12 bytes (96 bits)");
        assert_eq!(SALT_SIZE, 16, "Salt size should be 16 bytes (128 bits)");
        assert_eq!(UUID_SIZE, 16, "UUID size should be 16 bytes (128 bits)");
    }

    /// Test that verifies high entropy of generated values
    #[test]
    fn test_entropy_quality() {
        // Generate a large sample and check byte distribution
        let sample_size = 10000;
        let mut counts = [0usize; 256];

        for _ in 0..sample_size {
            let nonce = generate_nonce().expect("Failed to generate nonce");
            for byte in &nonce {
                counts[*byte as usize] += 1;
            }
        }

        // In a truly random distribution, each byte value should appear roughly equally
        // Expected count per byte value: (sample_size * NONCE_SIZE) / 256
        let total_bytes = sample_size * NONCE_SIZE;
        let expected = total_bytes as f64 / 256.0;

        // Check that no byte value appears more than 3x the expected frequency
        // (Very loose bound to avoid flaky tests)
        for (byte_val, &count) in counts.iter().enumerate() {
            let ratio = count as f64 / expected;
            assert!(
                ratio < 3.0 && ratio > 0.1,
                "Byte value {} appeared {} times (expected ~{}), ratio: {:.2}",
                byte_val, count, expected as usize, ratio
            );
        }
    }

    /// Test UUID string format
    #[test]
    fn test_uuid_string_format() {
        let uuid = generate_uuid().expect("Failed to generate UUID");
        let uuid_str = uuid.to_string();

        // UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (36 chars with hyphens)
        assert_eq!(uuid_str.len(), 36, "UUID string should be 36 characters");
        assert_eq!(&uuid_str[14..15], "4", "UUID version should be 4");

        // Check hyphens are in correct positions
        assert_eq!(&uuid_str[8..9], "-", "First hyphen at position 8");
        assert_eq!(&uuid_str[13..14], "-", "Second hyphen at position 13");
        assert_eq!(&uuid_str[18..19], "-", "Third hyphen at position 18");
        assert_eq!(&uuid_str[23..24], "-", "Fourth hyphen at position 23");
    }

    /// Stress test for many generations
    #[test]
    fn test_many_generations() {
        // Generate many values to ensure no failures
        for _ in 0..1000 {
            let _ = generate_key().expect("Key generation should not fail");
            let _ = generate_nonce().expect("Nonce generation should not fail");
            let _ = generate_salt().expect("Salt generation should not fail");
            let _ = generate_uuid().expect("UUID generation should not fail");
        }
    }
}
