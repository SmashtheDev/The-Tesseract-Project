//! HKDF (HMAC-based Key Derivation Function)
//!
//! Implements RFC 5869 HKDF using HMAC-SHA256 for expanding keying material.
//! HKDF is used to derive multiple independent keys from a single input key material.
//!
//! # Key Derivation Process
//!
//! ```text
//! Input Key Material (IKM)
//!         |
//!         v
//!   HKDF-Extract (optional)
//!         |
//!         v
//!   Pseudorandom Key (PRK)
//!         |
//!         v
//!   HKDF-Expand with info/context
//!         |
//!         v
//!   Output Key Material (OKM)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use tesseract_crypto::hkdf::{hkdf_expand, hkdf_extract};
//!
//! // Extract phase (optional if IKM is already uniform)
//! let ikm = [0x42u8; 32];
//! let salt = [0u8; 32];
//! let prk = hkdf_extract(&salt, &ikm);
//!
//! // Expand phase - derive keys with different contexts
//! let key1 = hkdf_expand(&prk, b"context-1", 32)?;
//! let key2 = hkdf_expand(&prk, b"context-2", 32)?;
//! assert_ne!(key1, key2);
//! ```

use crate::CryptoError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Size of HMAC-SHA256 output (and PRK).
pub const HASH_LEN: usize = 32;

/// Maximum output key material length (255 * HASH_LEN).
pub const MAX_OKM_LEN: usize = 255 * HASH_LEN;

type HmacSha256 = Hmac<Sha256>;

/// HKDF-Extract: Extract a pseudorandom key from input key material.
///
/// This step is optional if the input key material is already a uniformly
/// random bitstring (e.g., output of Argon2).
///
/// # Arguments
///
/// * `salt` - Optional salt value (can be zero-length, uses zeros if empty)
/// * `ikm` - Input key material
///
/// # Returns
///
/// A 32-byte pseudorandom key (PRK).
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    // If salt is not provided, use a string of HashLen zeros
    let salt = if salt.is_empty() {
        &[0u8; HASH_LEN][..]
    } else {
        salt
    };

    // PRK = HMAC-Hash(salt, IKM)
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC can take key of any size");
    mac.update(ikm);
    let result = mac.finalize();

    let mut prk = [0u8; HASH_LEN];
    prk.copy_from_slice(&result.into_bytes());
    prk
}

/// HKDF-Expand: Expand a pseudorandom key to the desired length.
///
/// # Arguments
///
/// * `prk` - Pseudorandom key (at least HashLen bytes)
/// * `info` - Optional context and application-specific information
/// * `length` - Length of output key material in bytes (max 255 * HashLen)
///
/// # Returns
///
/// Output key material of the specified length.
///
/// # Errors
///
/// Returns an error if:
/// - `length` exceeds maximum (255 * 32 = 8160 bytes)
/// - `prk` is shorter than `HASH_LEN` bytes
pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if length > MAX_OKM_LEN {
        return Err(CryptoError::KeyDerivationFailed(format!(
            "HKDF output length {} exceeds maximum {}",
            length, MAX_OKM_LEN
        )));
    }

    if prk.len() < HASH_LEN {
        return Err(CryptoError::KeyDerivationFailed(format!(
            "PRK must be at least {} bytes, got {}",
            HASH_LEN,
            prk.len()
        )));
    }

    if length == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }

    // N = ceil(L/HashLen)
    let n = (length + HASH_LEN - 1) / HASH_LEN;

    let mut okm = Zeroizing::new(Vec::with_capacity(length));
    let mut t = Zeroizing::new(Vec::with_capacity(HASH_LEN));

    for i in 1..=n {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC can take key of any size");
        mac.update(&t);
        mac.update(info);
        mac.update(&[i as u8]);

        let result = mac.finalize();
        t.clear();
        t.extend_from_slice(&result.into_bytes());

        // Append T(i) to output (up to length bytes)
        let remaining = length - okm.len();
        let to_copy = remaining.min(HASH_LEN);
        okm.extend_from_slice(&t[..to_copy]);
    }

    Ok(okm)
}

/// HKDF-Expand with fixed 32-byte output.
///
/// Convenience function for the common case of deriving a 256-bit key.
///
/// # Arguments
///
/// * `prk` - Pseudorandom key (at least 32 bytes)
/// * `info` - Context and application-specific information
///
/// # Returns
///
/// A 32-byte output key.
pub fn hkdf_expand_32(prk: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let okm = hkdf_expand(prk, info, 32)?;
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&okm);
    Ok(result)
}

/// HKDF-Expand with fixed 64-byte output.
///
/// Convenience function for deriving a 512-bit key (e.g., for XTS).
///
/// # Arguments
///
/// * `prk` - Pseudorandom key (at least 32 bytes)
/// * `info` - Context and application-specific information
///
/// # Returns
///
/// A 64-byte output key.
pub fn hkdf_expand_64(prk: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 64]>, CryptoError> {
    let okm = hkdf_expand(prk, info, 64)?;
    let mut result = Zeroizing::new([0u8; 64]);
    result.copy_from_slice(&okm);
    Ok(result)
}

/// Combined HKDF extract-then-expand for deriving a key directly.
///
/// # Arguments
///
/// * `salt` - Salt value (can be empty)
/// * `ikm` - Input key material
/// * `info` - Context and application-specific information
/// * `length` - Desired output length
///
/// # Returns
///
/// Output key material of the specified length.
pub fn hkdf(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to convert hex string to bytes.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.replace([' ', '\n'], "");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 5869 Test Case 1 - Basic test case with SHA-256
    #[test]
    fn test_rfc5869_case1() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let expected_prk =
            hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = hex_to_bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.to_vec(), expected_prk);

        let okm = hkdf_expand(&prk, &info, 42).unwrap();
        assert_eq!(*okm, expected_okm);
    }

    // RFC 5869 Test Case 2 - Longer inputs/outputs
    #[test]
    fn test_rfc5869_case2() {
        let ikm = hex_to_bytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = hex_to_bytes(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = hex_to_bytes(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let expected_prk =
            hex_to_bytes("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        let expected_okm = hex_to_bytes(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.to_vec(), expected_prk);

        let okm = hkdf_expand(&prk, &info, 82).unwrap();
        assert_eq!(*okm, expected_okm);
    }

    // RFC 5869 Test Case 3 - Zero-length salt/info
    #[test]
    fn test_rfc5869_case3() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = vec![];
        let info = vec![];
        let expected_prk =
            hex_to_bytes("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        let expected_okm = hex_to_bytes(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        );

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk.to_vec(), expected_prk);

        let okm = hkdf_expand(&prk, &info, 42).unwrap();
        assert_eq!(*okm, expected_okm);
    }

    #[test]
    fn test_different_info_produces_different_keys() {
        let prk = [0x42u8; 32];

        let key1 = hkdf_expand_32(&prk, b"context-1").unwrap();
        let key2 = hkdf_expand_32(&prk, b"context-2").unwrap();

        assert_ne!(*key1, *key2, "Different info should produce different keys");
    }

    #[test]
    fn test_hkdf_expand_64() {
        let prk = [0x42u8; 32];
        let key = hkdf_expand_64(&prk, b"test-context").unwrap();
        assert_eq!(key.len(), 64);

        // Verify it's deterministic
        let key2 = hkdf_expand_64(&prk, b"test-context").unwrap();
        assert_eq!(*key, *key2);
    }

    #[test]
    fn test_hkdf_combined() {
        let salt = [0u8; 32];
        let ikm = [0x42u8; 32];
        let info = b"test-context";

        let key = hkdf(&salt, &ikm, info, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Verify it matches extract + expand
        let prk = hkdf_extract(&salt, &ikm);
        let key2 = hkdf_expand(&prk, info, 32).unwrap();
        assert_eq!(*key, *key2);
    }

    #[test]
    fn test_hkdf_expand_max_length() {
        let prk = [0x42u8; 32];
        let key = hkdf_expand(&prk, b"test", MAX_OKM_LEN).unwrap();
        assert_eq!(key.len(), MAX_OKM_LEN);
    }

    #[test]
    fn test_hkdf_expand_exceeds_max_length() {
        let prk = [0x42u8; 32];
        let result = hkdf_expand(&prk, b"test", MAX_OKM_LEN + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand_zero_length() {
        let prk = [0x42u8; 32];
        let key = hkdf_expand(&prk, b"test", 0).unwrap();
        assert!(key.is_empty());
    }

    #[test]
    fn test_hkdf_expand_short_prk_rejected() {
        let prk = [0x42u8; 16]; // Less than HASH_LEN
        let result = hkdf_expand(&prk, b"test", 32);
        assert!(result.is_err());
    }
}
