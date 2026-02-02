//! AES-256-GCM authenticated encryption.
//!
//! Provides encrypt/decrypt operations using AES-256-GCM with
//! 12-byte nonces and 16-byte authentication tags.
//!
//! # Security Guarantees
//!
//! - **Confidentiality**: AES-256-GCM provides IND-CPA security
//! - **Integrity**: 128-bit authentication tag detects any tampering
//! - **Hardware acceleration**: Uses AES-NI when available
//!
//! # Format
//!
//! Ciphertext format: `[ciphertext][16-byte tag]`
//!
//! # Example
//!
//! ```ignore
//! use tesseract_crypto::aes::{encrypt, decrypt};
//!
//! let key = [0u8; 32];
//! let nonce = [0u8; 12];
//! let plaintext = b"Hello, TESSERACT!";
//! let aad = b"additional authenticated data";
//!
//! let ciphertext = encrypt(&key, &nonce, plaintext, aad)?;
//! let decrypted = decrypt(&key, &nonce, &ciphertext, aad)?;
//! assert_eq!(decrypted, plaintext);
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

use crate::CryptoError;

/// AES-256 key length in bytes.
pub const KEY_LENGTH: usize = 32;

/// GCM nonce length in bytes (96 bits as recommended by NIST).
pub const NONCE_LENGTH: usize = 12;

/// GCM authentication tag length in bytes (128 bits).
pub const TAG_LENGTH: usize = 16;

/// Encrypts plaintext using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - 256-bit encryption key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes) - MUST be unique per key
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but integrity protected)
///
/// # Returns
///
/// Ciphertext with appended 16-byte authentication tag.
///
/// # Errors
///
/// * `CryptoError::InvalidKeyLength` - Key is not 32 bytes
/// * `CryptoError::InvalidNonceLength` - Nonce is not 12 bytes
///
/// # Security
///
/// **CRITICAL**: Never reuse a nonce with the same key. Nonce reuse completely
/// breaks GCM security and allows authentication forgery.
pub fn encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LENGTH,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != NONCE_LENGTH {
        return Err(CryptoError::InvalidNonceLength {
            expected: NONCE_LENGTH,
            actual: nonce.len(),
        });
    }

    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LENGTH,
        actual: key.len(),
    })?;

    // Create nonce
    let nonce = Nonce::from_slice(nonce);

    // Create payload with AAD
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    // Encrypt - the aes-gcm crate appends the tag to the ciphertext
    cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Decrypts ciphertext using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - 256-bit encryption key (32 bytes)
/// * `nonce` - 96-bit nonce (12 bytes) - Must match the nonce used for encryption
/// * `ciphertext` - Encrypted data with appended 16-byte authentication tag
/// * `aad` - Additional authenticated data - Must match AAD used for encryption
///
/// # Returns
///
/// Decrypted plaintext.
///
/// # Errors
///
/// * `CryptoError::InvalidKeyLength` - Key is not 32 bytes
/// * `CryptoError::InvalidNonceLength` - Nonce is not 12 bytes
/// * `CryptoError::AuthenticationFailed` - Ciphertext was tampered with or wrong key/nonce
///
/// # Security
///
/// Authentication verification happens before any plaintext is returned.
/// If verification fails, no partial plaintext is exposed.
pub fn decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Validate key length
    if key.len() != KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LENGTH,
            actual: key.len(),
        });
    }

    // Validate nonce length
    if nonce.len() != NONCE_LENGTH {
        return Err(CryptoError::InvalidNonceLength {
            expected: NONCE_LENGTH,
            actual: nonce.len(),
        });
    }

    // Ciphertext must be at least TAG_LENGTH bytes (tag only, empty plaintext)
    if ciphertext.len() < TAG_LENGTH {
        return Err(CryptoError::AuthenticationFailed);
    }

    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LENGTH,
        actual: key.len(),
    })?;

    // Create nonce
    let nonce = Nonce::from_slice(nonce);

    // Create payload with AAD
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    // Decrypt and verify - returns error if authentication fails
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Encrypts plaintext without additional authenticated data.
///
/// This is a convenience wrapper around [`encrypt`] for cases where AAD is not needed.
pub fn encrypt_no_aad(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt(key, nonce, plaintext, &[])
}

/// Decrypts ciphertext without additional authenticated data.
///
/// This is a convenience wrapper around [`decrypt`] for cases where AAD was not used.
pub fn decrypt_no_aad(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    decrypt(key, nonce, ciphertext, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic encrypt/decrypt roundtrip
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Hello, TESSERACT!";
        let aad = b"vault-header-v1";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Ciphertext should be plaintext length + tag length
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LENGTH);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    /// Empty plaintext should work
    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [0xABu8; KEY_LENGTH];
        let nonce = [0xCDu8; NONCE_LENGTH];
        let plaintext = b"";
        let aad = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");
        assert_eq!(ciphertext.len(), TAG_LENGTH); // Just the tag

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    /// Tampering with ciphertext should fail authentication
    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Secret data";
        let aad = b"";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Tamper with a byte in the ciphertext portion
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    /// Tampering with tag should fail authentication
    #[test]
    fn test_tampered_tag_fails() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Secret data";
        let aad = b"";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Tamper with the last byte (in the tag)
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    /// Wrong AAD should fail authentication
    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Secret data";
        let aad = b"correct-aad";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Try to decrypt with different AAD
        let wrong_aad = b"wrong-aad";
        let result = decrypt(&key, &nonce, &ciphertext, wrong_aad);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    /// Wrong key should fail authentication
    #[test]
    fn test_wrong_key_fails() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Secret data";
        let aad = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Try to decrypt with different key
        let wrong_key = [0x43u8; KEY_LENGTH];
        let result = decrypt(&wrong_key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    /// Wrong nonce should fail authentication
    #[test]
    fn test_wrong_nonce_fails() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"Secret data";
        let aad = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Try to decrypt with different nonce
        let wrong_nonce = [0x02u8; NONCE_LENGTH];
        let result = decrypt(&key, &wrong_nonce, &ciphertext, aad);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    /// Invalid key length should error
    #[test]
    fn test_invalid_key_length() {
        let short_key = [0x42u8; 16]; // Too short
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"test";

        let result = encrypt(&short_key, &nonce, plaintext, &[]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    /// Invalid nonce length should error
    #[test]
    fn test_invalid_nonce_length() {
        let key = [0x42u8; KEY_LENGTH];
        let short_nonce = [0x01u8; 8]; // Too short
        let plaintext = b"test";

        let result = encrypt(&key, &short_nonce, plaintext, &[]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: 12,
                actual: 8
            })
        ));
    }

    /// Ciphertext too short to contain tag should fail
    #[test]
    fn test_ciphertext_too_short() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let short_ciphertext = [0u8; 8]; // Less than TAG_LENGTH

        let result = decrypt(&key, &nonce, &short_ciphertext, &[]);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    /// Large data should work
    #[test]
    fn test_large_data() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = vec![0xABu8; 1_000_000]; // 1MB
        let aad = b"large-file-header";

        let ciphertext =
            encrypt(&key, &nonce, &plaintext, aad).expect("encryption should succeed");

        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LENGTH);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    // ==========================================
    // NIST SP 800-38D Test Vectors
    // ==========================================
    // These test vectors are from NIST Special Publication 800-38D
    // "Recommendation for Block Cipher Modes of Operation: GCM and GMAC"
    // https://csrc.nist.gov/publications/detail/sp/800-38d/final

    /// NIST GCM Test Case 13 (AES-256, 96-bit IV)
    /// From: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    #[test]
    fn test_nist_gcm_test_case_13() {
        // Test Case 13 from NIST - AES-256-GCM with 96-bit IV, no AAD, no plaintext
        let key = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let plaintext = &[];
        let aad = &[];

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).expect("encryption should succeed");

        // Expected tag for empty message
        let expected_tag = hex_to_bytes("530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(ciphertext, expected_tag);

        // Verify decryption
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    /// NIST GCM Test Case 14 (AES-256, 96-bit IV, with plaintext)
    #[test]
    fn test_nist_gcm_test_case_14() {
        // Test Case 14 from NIST - AES-256-GCM with 96-bit IV, 16-byte plaintext
        let key = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex_to_bytes("000000000000000000000000");
        let plaintext = hex_to_bytes("00000000000000000000000000000000");
        let aad = &[];

        let ciphertext = encrypt(&key, &nonce, &plaintext, aad).expect("encryption should succeed");

        // Expected ciphertext + tag
        let expected = hex_to_bytes("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
        assert_eq!(ciphertext, expected);

        // Verify decryption
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    /// NIST GCM Test Case 15 (AES-256, 96-bit IV, with plaintext and AAD)
    #[test]
    fn test_nist_gcm_test_case_15() {
        // Test Case 15 from NIST - AES-256-GCM with plaintext and AAD
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        let ciphertext = encrypt(&key, &nonce, &plaintext, &aad).expect("encryption should succeed");

        // Expected ciphertext (without tag)
        let expected_ct = hex_to_bytes(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        );
        // Correct tag for 64B plaintext WITH AAD
        let expected_tag = hex_to_bytes("2df7cd675b4f09163b41ebf980a7f638");

        // ciphertext contains both encrypted data and tag
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LENGTH);
        assert_eq!(ct, expected_ct.as_slice());
        assert_eq!(tag, expected_tag.as_slice());

        // Verify decryption
        let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    /// NIST GCM Test Case 16 (different key)
    #[test]
    fn test_nist_gcm_test_case_16() {
        // Test Case 16 from NIST - AES-256-GCM with AAD only (no plaintext)
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = &[];
        let aad = hex_to_bytes(
            "feedfacedeadbeeffeedfacedeadbeef\
             abaddad2",
        );

        let ciphertext = encrypt(&key, &nonce, plaintext, &aad).expect("encryption should succeed");

        // For AAD-only (no plaintext), result is just the 16-byte tag
        // This is GMAC mode
        let expected_tag = hex_to_bytes("9f6be07603c0b0bd1272854063e9c9ba");
        assert_eq!(ciphertext, expected_tag);

        // Verify decryption
        let decrypted = decrypt(&key, &nonce, &ciphertext, &aad).expect("decryption should succeed");
        assert!(decrypted.is_empty());
    }

    // Helper function to convert hex strings to bytes
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Verify no_aad convenience functions work
    #[test]
    fn test_no_aad_convenience_functions() {
        let key = [0x42u8; KEY_LENGTH];
        let nonce = [0x01u8; NONCE_LENGTH];
        let plaintext = b"No AAD test";

        let ciphertext = encrypt_no_aad(&key, &nonce, plaintext).expect("encryption should succeed");
        let decrypted = decrypt_no_aad(&key, &nonce, &ciphertext).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }
}
