//! HMAC-SHA256 integrity verification.
//!
//! Provides message authentication codes for integrity verification
//! of metadata and vault headers.
//!
//! # Security Properties
//!
//! - Uses HMAC-SHA256 as specified in RFC 2104 and FIPS 198-1
//! - Constant-time tag comparison to prevent timing attacks
//! - Minimum key length enforcement (128 bits recommended)
//!
//! # Example
//!
//! ```
//! use tesseract_crypto::hmac::{hmac_sign, hmac_verify};
//!
//! let key = [0u8; 32]; // 256-bit key
//! let data = b"message to authenticate";
//!
//! // Sign the data
//! let tag = hmac_sign(&key, data);
//!
//! // Verify the tag
//! assert!(hmac_verify(&key, data, &tag).is_ok());
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::CryptoError;

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Size of the HMAC-SHA256 output in bytes (256 bits).
pub const HMAC_SIZE: usize = 32;

/// Minimum recommended key size in bytes (128 bits).
pub const MIN_KEY_SIZE: usize = 16;

/// Compute HMAC-SHA256 over the given data.
///
/// # Arguments
///
/// * `key` - The secret key for HMAC computation. Any key length is accepted,
///           but at least 128 bits (16 bytes) is recommended for security.
/// * `data` - The data to authenticate.
///
/// # Returns
///
/// A 32-byte (256-bit) authentication tag.
///
/// # Example
///
/// ```
/// use tesseract_crypto::hmac::hmac_sign;
///
/// let key = [0xab; 32];
/// let data = b"important data";
/// let tag = hmac_sign(&key, data);
/// assert_eq!(tag.len(), 32);
/// ```
pub fn hmac_sign(key: &[u8], data: &[u8]) -> [u8; HMAC_SIZE] {
    // Create HMAC instance with the key
    // HMAC accepts any key length - short keys are padded, long keys are hashed
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");

    // Process the data
    mac.update(data);

    // Finalize and get the result
    let result = mac.finalize();
    let tag_bytes = result.into_bytes();

    // Convert to fixed-size array
    let mut tag = [0u8; HMAC_SIZE];
    tag.copy_from_slice(&tag_bytes);
    tag
}

/// Verify an HMAC-SHA256 tag over the given data.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `key` - The secret key used for the original HMAC computation.
/// * `data` - The data that was authenticated.
/// * `tag` - The authentication tag to verify (must be exactly 32 bytes).
///
/// # Returns
///
/// * `Ok(())` if the tag is valid.
/// * `Err(CryptoError::IntegrityError)` if the tag is invalid.
///
/// # Example
///
/// ```
/// use tesseract_crypto::hmac::{hmac_sign, hmac_verify};
///
/// let key = [0xab; 32];
/// let data = b"important data";
/// let tag = hmac_sign(&key, data);
///
/// // Valid tag
/// assert!(hmac_verify(&key, data, &tag).is_ok());
///
/// // Tampered data fails verification
/// let tampered_data = b"modified data";
/// assert!(hmac_verify(&key, tampered_data, &tag).is_err());
/// ```
pub fn hmac_verify(key: &[u8], data: &[u8], tag: &[u8; HMAC_SIZE]) -> Result<(), CryptoError> {
    // Compute the expected tag
    let expected_tag = hmac_sign(key, data);

    // Constant-time comparison to prevent timing attacks
    if constant_time_compare(&expected_tag, tag) {
        Ok(())
    } else {
        Err(CryptoError::IntegrityError)
    }
}

/// Verify an HMAC-SHA256 tag with a variable-length tag slice.
///
/// This is a convenience function that first checks the tag length,
/// then performs constant-time verification.
///
/// # Arguments
///
/// * `key` - The secret key used for the original HMAC computation.
/// * `data` - The data that was authenticated.
/// * `tag` - The authentication tag to verify.
///
/// # Returns
///
/// * `Ok(())` if the tag is valid and has correct length.
/// * `Err(CryptoError::IntegrityError)` if the tag is invalid or wrong length.
pub fn hmac_verify_slice(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), CryptoError> {
    // Check tag length first (not timing-sensitive, length is public)
    if tag.len() != HMAC_SIZE {
        return Err(CryptoError::IntegrityError);
    }

    // Convert to fixed-size array and verify
    let mut tag_array = [0u8; HMAC_SIZE];
    tag_array.copy_from_slice(tag);
    hmac_verify(key, data, &tag_array)
}

/// Constant-time comparison of two byte arrays.
///
/// This function compares two equal-length byte arrays in constant time
/// to prevent timing side-channel attacks. The comparison time depends
/// only on the length of the arrays, not their contents.
///
/// # Arguments
///
/// * `a` - First byte array.
/// * `b` - Second byte array.
///
/// # Returns
///
/// `true` if the arrays are equal, `false` otherwise.
///
/// # Security
///
/// This function uses XOR accumulation to ensure constant-time behavior.
/// It always processes all bytes regardless of differences found.
fn constant_time_compare(a: &[u8; HMAC_SIZE], b: &[u8; HMAC_SIZE]) -> bool {
    // XOR accumulator - will be 0 if all bytes match
    let mut diff: u8 = 0;

    // Compare all bytes, accumulating differences
    for i in 0..HMAC_SIZE {
        diff |= a[i] ^ b[i];
    }

    // Result is true only if diff is 0 (all bytes matched)
    diff == 0
}

/// Check if a key meets the minimum recommended length.
///
/// While HMAC accepts any key length, using keys shorter than 128 bits
/// is not recommended for security reasons.
///
/// # Arguments
///
/// * `key` - The key to check.
///
/// # Returns
///
/// `true` if the key is at least `MIN_KEY_SIZE` bytes (16 bytes / 128 bits).
pub fn is_key_length_adequate(key: &[u8]) -> bool {
    key.len() >= MIN_KEY_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Basic functionality tests
    // ========================================

    #[test]
    fn test_hmac_sign_produces_32_byte_output() {
        let key = [0u8; 32];
        let data = b"test data";
        let tag = hmac_sign(&key, data);
        assert_eq!(tag.len(), HMAC_SIZE);
    }

    #[test]
    fn test_hmac_sign_deterministic() {
        let key = [0xab; 32];
        let data = b"test data";
        let tag1 = hmac_sign(&key, data);
        let tag2 = hmac_sign(&key, data);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_verify_roundtrip() {
        let key = [0xcd; 32];
        let data = b"important message";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_hmac_verify_fails_on_tampered_data() {
        let key = [0xef; 32];
        let data = b"original data";
        let tag = hmac_sign(&key, data);

        let tampered = b"modified data";
        assert!(hmac_verify(&key, tampered, &tag).is_err());
    }

    #[test]
    fn test_hmac_verify_fails_on_tampered_tag() {
        let key = [0x12; 32];
        let data = b"some data";
        let mut tag = hmac_sign(&key, data);

        // Flip one bit in the tag
        tag[0] ^= 0x01;
        assert!(hmac_verify(&key, data, &tag).is_err());
    }

    #[test]
    fn test_hmac_verify_fails_with_wrong_key() {
        let key1 = [0x11; 32];
        let key2 = [0x22; 32];
        let data = b"secret message";
        let tag = hmac_sign(&key1, data);

        assert!(hmac_verify(&key2, data, &tag).is_err());
    }

    #[test]
    fn test_different_keys_produce_different_tags() {
        let key1 = [0x00; 32];
        let key2 = [0xff; 32];
        let data = b"same data";

        let tag1 = hmac_sign(&key1, data);
        let tag2 = hmac_sign(&key2, data);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_different_data_produces_different_tags() {
        let key = [0xaa; 32];
        let data1 = b"data one";
        let data2 = b"data two";

        let tag1 = hmac_sign(&key, data1);
        let tag2 = hmac_sign(&key, data2);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_empty_data() {
        let key = [0xbb; 32];
        let data = b"";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_large_data() {
        let key = [0xcc; 32];
        let data = vec![0xdd; 1_000_000]; // 1 MB
        let tag = hmac_sign(&key, &data);
        assert!(hmac_verify(&key, &data, &tag).is_ok());
    }

    // ========================================
    // Key length tests
    // ========================================

    #[test]
    fn test_short_key() {
        // HMAC accepts short keys (pads internally)
        let key = [0x01; 4]; // Only 4 bytes
        let data = b"test";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_long_key() {
        // HMAC accepts long keys (hashes internally)
        let key = [0x02; 128]; // 128 bytes
        let data = b"test";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_empty_key() {
        // HMAC accepts even empty keys (not recommended)
        let key: [u8; 0] = [];
        let data = b"test";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_is_key_length_adequate() {
        assert!(!is_key_length_adequate(&[0u8; 0]));
        assert!(!is_key_length_adequate(&[0u8; 15]));
        assert!(is_key_length_adequate(&[0u8; 16]));
        assert!(is_key_length_adequate(&[0u8; 32]));
        assert!(is_key_length_adequate(&[0u8; 64]));
    }

    // ========================================
    // Variable-length tag verification
    // ========================================

    #[test]
    fn test_hmac_verify_slice() {
        let key = [0xdd; 32];
        let data = b"test slice verification";
        let tag = hmac_sign(&key, data);

        assert!(hmac_verify_slice(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_hmac_verify_slice_wrong_length() {
        let key = [0xee; 32];
        let data = b"test";

        // Too short
        let short_tag = [0u8; 16];
        assert!(hmac_verify_slice(&key, data, &short_tag).is_err());

        // Too long
        let long_tag = [0u8; 64];
        assert!(hmac_verify_slice(&key, data, &long_tag).is_err());
    }

    // ========================================
    // Constant-time comparison tests
    // ========================================

    #[test]
    fn test_constant_time_compare_equal() {
        let a = [0xab; HMAC_SIZE];
        let b = [0xab; HMAC_SIZE];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different() {
        let a = [0x00; HMAC_SIZE];
        let mut b = [0x00; HMAC_SIZE];
        b[31] = 0x01;
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_first_byte_differs() {
        let a = [0x00; HMAC_SIZE];
        let mut b = [0x00; HMAC_SIZE];
        b[0] = 0x01;
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_all_different() {
        let a = [0x00; HMAC_SIZE];
        let b = [0xff; HMAC_SIZE];
        assert!(!constant_time_compare(&a, &b));
    }

    // ========================================
    // RFC 4231 Test Vectors
    // ========================================

    /// Helper to convert hex string to bytes.
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let hex = hex.replace(" ", "");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 4231 Test Case 1
    /// Key = 0x0b repeated 20 times
    /// Data = "Hi There"
    #[test]
    fn test_rfc4231_case1() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let expected = hex_to_bytes(
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7"
        );

        let tag = hmac_sign(&key, data);
        assert_eq!(&tag[..], &expected[..]);
    }

    /// RFC 4231 Test Case 2
    /// Key = "Jefe"
    /// Data = "what do ya want for nothing?"
    #[test]
    fn test_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex_to_bytes(
            "5bdcc146bf60754e6a042426089575c7\
             5a003f089d2739839dec58b964ec3843"
        );

        let tag = hmac_sign(key, data);
        assert_eq!(&tag[..], &expected[..]);
    }

    /// RFC 4231 Test Case 3
    /// Key = 0xaa repeated 20 times
    /// Data = 0xdd repeated 50 times
    #[test]
    fn test_rfc4231_case3() {
        let key = vec![0xaa; 20];
        let data = vec![0xdd; 50];
        let expected = hex_to_bytes(
            "773ea91e36800e46854db8ebd09181a7\
             2959098b3ef8c122d9635514ced565fe"
        );

        let tag = hmac_sign(&key, &data);
        assert_eq!(&tag[..], &expected[..]);
    }

    /// RFC 4231 Test Case 4
    /// Key = 0x0102...1819 (25 bytes)
    /// Data = 0xcd repeated 50 times
    #[test]
    fn test_rfc4231_case4() {
        let key: Vec<u8> = (1..=25).collect();
        let data = vec![0xcd; 50];
        let expected = hex_to_bytes(
            "82558a389a443c0ea4cc819899f2083a\
             85f0faa3e578f8077a2e3ff46729665b"
        );

        let tag = hmac_sign(&key, &data);
        assert_eq!(&tag[..], &expected[..]);
    }

    /// RFC 4231 Test Case 5
    /// Test with truncation - we don't truncate but verify full output
    /// Key = 0x0c repeated 20 times
    /// Data = "Test With Truncation"
    #[test]
    fn test_rfc4231_case5() {
        let key = vec![0x0c; 20];
        let data = b"Test With Truncation";
        // Note: RFC 4231 shows truncated value for Case 5
        // We compute the full HMAC and verify the first 16 bytes match
        let expected_truncated = hex_to_bytes("a3b6167473100ee06e0c796c2955552b");

        let tag = hmac_sign(&key, data);
        assert_eq!(&tag[..16], &expected_truncated[..]);
    }

    /// RFC 4231 Test Case 6
    /// Key = 0xaa repeated 131 times (key longer than block size)
    /// Data = "Test Using Larger Than Block-Size Key - Hash Key First"
    #[test]
    fn test_rfc4231_case6() {
        let key = vec![0xaa; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = hex_to_bytes(
            "60e431591ee0b67f0d8a26aacbf5b77f\
             8e0bc6213728c5140546040f0ee37f54"
        );

        let tag = hmac_sign(&key, data);
        assert_eq!(&tag[..], &expected[..]);
    }

    /// RFC 4231 Test Case 7
    /// Key = 0xaa repeated 131 times (key longer than block size)
    /// Data = "This is a test using a larger than block-size key and a larger
    ///         than block-size data. The key needs to be hashed before being
    ///         used by the HMAC algorithm."
    #[test]
    fn test_rfc4231_case7() {
        let key = vec![0xaa; 131];
        let data = b"This is a test using a larger than block-size key and a \
                     larger than block-size data. The key needs to be hashed \
                     before being used by the HMAC algorithm.";
        let expected = hex_to_bytes(
            "9b09ffa71b942fcb27635fbcd5b0e944\
             bfdc63644f0713938a7f51535c3a35e2"
        );

        let tag = hmac_sign(&key, data);
        assert_eq!(&tag[..], &expected[..]);
    }

    // ========================================
    // Tamper detection tests
    // ========================================

    #[test]
    fn test_single_bit_flip_detected() {
        let key = [0x42; 32];
        let data = b"sensitive data";
        let tag = hmac_sign(&key, data);

        // Test each bit position
        for byte_idx in 0..HMAC_SIZE {
            for bit_idx in 0..8 {
                let mut tampered_tag = tag;
                tampered_tag[byte_idx] ^= 1 << bit_idx;
                assert!(
                    hmac_verify(&key, data, &tampered_tag).is_err(),
                    "Bit flip at byte {} bit {} not detected",
                    byte_idx, bit_idx
                );
            }
        }
    }

    #[test]
    fn test_data_single_bit_flip_detected() {
        let key = [0x55; 32];
        let data = b"test data for tampering";
        let tag = hmac_sign(&key, data);

        // Flip each bit in the data
        for byte_idx in 0..data.len() {
            for bit_idx in 0..8 {
                let mut tampered_data = data.to_vec();
                tampered_data[byte_idx] ^= 1 << bit_idx;
                assert!(
                    hmac_verify(&key, &tampered_data, &tag).is_err(),
                    "Data bit flip at byte {} bit {} not detected",
                    byte_idx, bit_idx
                );
            }
        }
    }

    #[test]
    fn test_length_extension_not_possible() {
        // HMAC is designed to prevent length extension attacks
        let key = [0x99; 32];
        let data1 = b"short";
        let data2 = b"shortextra";

        let tag1 = hmac_sign(&key, data1);

        // Tag for extended data should be completely different
        // An attacker cannot compute HMAC(key, data1 || extra) from HMAC(key, data1)
        assert!(hmac_verify(&key, data2, &tag1).is_err());
    }

    // ========================================
    // Edge case tests
    // ========================================

    #[test]
    fn test_null_bytes_in_data() {
        let key = [0x77; 32];
        let data = b"data\x00with\x00nulls";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_unicode_data() {
        let key = [0x88; 32];
        let data = "안녕하세요 🔐 TESSERACT".as_bytes();
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    #[test]
    fn test_binary_key() {
        let key = (0..32).collect::<Vec<u8>>();
        let data = b"test with sequential key";
        let tag = hmac_sign(&key, data);
        assert!(hmac_verify(&key, data, &tag).is_ok());
    }

    // ========================================
    // Stress tests
    // ========================================

    #[test]
    fn test_many_operations() {
        let key = [0xfe; 32];

        for i in 0..1000 {
            let data = format!("iteration {}", i);
            let tag = hmac_sign(&key, data.as_bytes());
            assert!(
                hmac_verify(&key, data.as_bytes(), &tag).is_ok(),
                "Failed at iteration {}", i
            );
        }
    }

    #[test]
    fn test_various_data_sizes() {
        let key = [0xdc; 32];

        // Test powers of 2 from 1 to 64KB
        for power in 0..17 {
            let size = 1 << power;
            let data = vec![0xab; size];
            let tag = hmac_sign(&key, &data);
            assert!(
                hmac_verify(&key, &data, &tag).is_ok(),
                "Failed for size {}", size
            );
        }
    }
}
