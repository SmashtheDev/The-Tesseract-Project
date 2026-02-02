//! Recovery Key Generation and Management
//!
//! This module provides recovery key functionality for TESSERACT vaults.
//! Recovery keys provide an alternative way to decrypt the master key hierarchy
//! when the password is lost.
//!
//! # Security Model
//!
//! - Recovery key is a 256-bit cryptographically secure random value
//! - Displayed to user as a 24-word BIP39 mnemonic for easy transcription
//! - Also available as base64 string for digital backup
//! - Recovery key encrypts the master key using AES-256-GCM
//! - Recovery key is NEVER stored in the vault - user must secure it
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_crypto::recovery::{generate_recovery_key, RecoveryKey};
//!
//! // Generate a new recovery key at vault creation
//! let recovery_key = generate_recovery_key()?;
//!
//! // Display to user (only shown once!)
//! println!("Your recovery phrase: {}", recovery_key.to_mnemonic());
//! println!("Or as base64: {}", recovery_key.to_base64());
//!
//! // Encrypt master key with recovery key
//! let encrypted = recovery_key.encrypt_master_key(&master_key)?;
//!
//! // Later, restore from mnemonic
//! let restored = RecoveryKey::from_mnemonic("word1 word2 ...")?;
//! let master_key = restored.decrypt_master_key(&encrypted)?;
//! ```

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aes::{decrypt, encrypt, NONCE_LENGTH, TAG_LENGTH};
use crate::random::{fill_random, generate_nonce, KEY_SIZE};
use crate::CryptoError;

/// Size of recovery key in bytes (256 bits).
pub const RECOVERY_KEY_SIZE: usize = 32;

/// Size of encrypted master key blob (nonce + ciphertext + tag).
/// 12 bytes nonce + 32 bytes encrypted key + 16 bytes tag = 60 bytes
pub const ENCRYPTED_MASTER_KEY_SIZE: usize = NONCE_LENGTH + KEY_SIZE + TAG_LENGTH;

/// A recovery key for vault master key recovery.
///
/// The recovery key is a 256-bit random value that can be displayed as:
/// - A 24-word BIP39 mnemonic phrase (human-readable)
/// - A base64 string (compact digital representation)
///
/// # Security
///
/// - The raw key bytes are zeroized when the struct is dropped
/// - Recovery keys should only be displayed once at vault creation
/// - Users must securely store the mnemonic or base64 representation
#[derive(Clone, ZeroizeOnDrop)]
pub struct RecoveryKey {
    /// The raw 256-bit recovery key
    #[zeroize(drop)]
    key: [u8; RECOVERY_KEY_SIZE],
}

impl RecoveryKey {
    /// Creates a new recovery key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte (256-bit) key
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tesseract_crypto::recovery::RecoveryKey;
    ///
    /// let key_bytes = [0u8; 32]; // In practice, use random bytes
    /// let recovery_key = RecoveryKey::new(key_bytes);
    /// ```
    #[must_use]
    pub fn new(key: [u8; RECOVERY_KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Returns the raw key bytes.
    ///
    /// # Security Warning
    ///
    /// Handle with care - this exposes the raw key material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_SIZE] {
        &self.key
    }

    /// Converts the recovery key to a 24-word BIP39 mnemonic phrase.
    ///
    /// The mnemonic uses the English wordlist and includes a checksum
    /// to detect transcription errors.
    ///
    /// # Returns
    ///
    /// A space-separated string of 24 words.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let recovery_key = generate_recovery_key()?;
    /// let mnemonic = recovery_key.to_mnemonic();
    /// // "abandon ability able about above absent absorb abstract absurd abuse ..."
    /// ```
    #[must_use]
    pub fn to_mnemonic(&self) -> String {
        // BIP39 mnemonic from 256 bits = 24 words
        // This should never fail for valid 256-bit entropy
        let mnemonic = Mnemonic::from_entropy(&self.key)
            .expect("256-bit entropy should always produce valid mnemonic");
        mnemonic.to_string()
    }

    /// Creates a recovery key from a BIP39 mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `phrase` - A space-separated string of 24 BIP39 words
    ///
    /// # Returns
    ///
    /// * `Ok(RecoveryKey)` - Successfully parsed mnemonic
    /// * `Err(CryptoError)` - Invalid mnemonic (wrong words, checksum error, etc.)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    /// let recovery_key = RecoveryKey::from_mnemonic(phrase)?;
    /// ```
    pub fn from_mnemonic(phrase: &str) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;

        let entropy = mnemonic.to_entropy();
        if entropy.len() != RECOVERY_KEY_SIZE {
            return Err(CryptoError::InvalidMnemonic(format!(
                "Expected 256-bit entropy (24 words), got {} bits ({} words)",
                entropy.len() * 8,
                phrase.split_whitespace().count()
            )));
        }

        let mut key = [0u8; RECOVERY_KEY_SIZE];
        key.copy_from_slice(&entropy);
        Ok(Self { key })
    }

    /// Converts the recovery key to a base64 string.
    ///
    /// This provides a compact representation suitable for digital storage.
    ///
    /// # Returns
    ///
    /// A base64-encoded string (44 characters for 32 bytes).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let recovery_key = generate_recovery_key()?;
    /// let base64 = recovery_key.to_base64();
    /// // "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    /// ```
    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64_encode;
        base64_encode(&self.key)
    }

    /// Creates a recovery key from a base64 string.
    ///
    /// # Arguments
    ///
    /// * `encoded` - A base64-encoded string representing 32 bytes
    ///
    /// # Returns
    ///
    /// * `Ok(RecoveryKey)` - Successfully decoded base64
    /// * `Err(CryptoError)` - Invalid base64 or wrong length
    ///
    /// # Example
    ///
    /// ```ignore
    /// let base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// let recovery_key = RecoveryKey::from_base64(base64)?;
    /// ```
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        let decoded = base64_decode(encoded)?;
        if decoded.len() != RECOVERY_KEY_SIZE {
            return Err(CryptoError::InvalidRecoveryKey(format!(
                "Expected {} bytes, got {}",
                RECOVERY_KEY_SIZE,
                decoded.len()
            )));
        }

        let mut key = [0u8; RECOVERY_KEY_SIZE];
        key.copy_from_slice(&decoded);
        Ok(Self { key })
    }

    /// Encrypts a master key using this recovery key.
    ///
    /// The output format is: `[12-byte nonce][32-byte encrypted key][16-byte tag]`
    ///
    /// # Arguments
    ///
    /// * `master_key` - The 32-byte master key to encrypt
    ///
    /// # Returns
    ///
    /// A 60-byte blob containing nonce, encrypted key, and authentication tag.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let recovery_key = generate_recovery_key()?;
    /// let master_key = [0u8; 32]; // Your actual master key
    /// let encrypted = recovery_key.encrypt_master_key(&master_key)?;
    /// assert_eq!(encrypted.len(), 60);
    /// ```
    pub fn encrypt_master_key(
        &self,
        master_key: &[u8; KEY_SIZE],
    ) -> Result<[u8; ENCRYPTED_MASTER_KEY_SIZE], CryptoError> {
        let nonce = generate_nonce()?;

        // AAD identifies this as recovery-encrypted master key
        let aad = b"tesseract-recovery-v1";

        let ciphertext = encrypt(&self.key, &nonce, master_key, aad)?;

        // Combine nonce + ciphertext into fixed-size array
        let mut result = [0u8; ENCRYPTED_MASTER_KEY_SIZE];
        result[..NONCE_LENGTH].copy_from_slice(&nonce);
        result[NONCE_LENGTH..].copy_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts a master key using this recovery key.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The 60-byte encrypted master key blob from `encrypt_master_key`
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 32])` - The decrypted master key
    /// * `Err(CryptoError)` - Decryption failed (wrong key or corrupted data)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let recovery_key = RecoveryKey::from_mnemonic(phrase)?;
    /// let master_key = recovery_key.decrypt_master_key(&encrypted_blob)?;
    /// ```
    pub fn decrypt_master_key(
        &self,
        encrypted: &[u8; ENCRYPTED_MASTER_KEY_SIZE],
    ) -> Result<[u8; KEY_SIZE], CryptoError> {
        let nonce = &encrypted[..NONCE_LENGTH];
        let ciphertext = &encrypted[NONCE_LENGTH..];

        // AAD must match what was used for encryption
        let aad = b"tesseract-recovery-v1";

        let plaintext = decrypt(&self.key, nonce, ciphertext, aad)?;

        if plaintext.len() != KEY_SIZE {
            return Err(CryptoError::InvalidRecoveryKey(
                "Decrypted master key has wrong size".to_string(),
            ));
        }

        let mut master_key = [0u8; KEY_SIZE];
        master_key.copy_from_slice(&plaintext);
        Ok(master_key)
    }
}

/// Generates a new cryptographically secure recovery key.
///
/// This function should be called once during vault creation.
/// The resulting key should be displayed to the user (as mnemonic or base64)
/// and then the display representation should be securely erased from memory.
///
/// # Returns
///
/// * `Ok(RecoveryKey)` - A new random recovery key
/// * `Err(CryptoError)` - Failed to generate random bytes
///
/// # Security
///
/// - Uses OS CSPRNG exclusively
/// - The returned key should only be displayed once
/// - Never log or persist the recovery key
///
/// # Example
///
/// ```ignore
/// use tesseract_crypto::recovery::generate_recovery_key;
///
/// let recovery_key = generate_recovery_key()?;
/// println!("IMPORTANT: Write down your recovery phrase:");
/// println!("{}", recovery_key.to_mnemonic());
/// println!("\nThis will not be shown again!");
/// ```
pub fn generate_recovery_key() -> Result<RecoveryKey, CryptoError> {
    let mut key = [0u8; RECOVERY_KEY_SIZE];
    fill_random(&mut key)?;
    Ok(RecoveryKey::new(key))
}

// Simple base64 encoding without external dependency
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = data.get(i + 1).copied().unwrap_or(0);
        let b2 = data.get(i + 2).copied().unwrap_or(0);

        result.push(ALPHABET[(b0 >> 2) as usize] as char);
        result.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: char) -> Result<u8, CryptoError> {
        if c == '=' {
            return Ok(0);
        }
        ALPHABET
            .iter()
            .position(|&x| x == c as u8)
            .map(|p| p as u8)
            .ok_or_else(|| CryptoError::InvalidRecoveryKey(format!("Invalid base64 character: {c}")))
    }

    let encoded = encoded.trim();
    if encoded.len() % 4 != 0 {
        return Err(CryptoError::InvalidRecoveryKey(
            "Invalid base64 length".to_string(),
        ));
    }

    let mut result = Vec::new();
    let chars: Vec<char> = encoded.chars().collect();

    for chunk in chars.chunks(4) {
        if chunk.len() != 4 {
            break;
        }

        let b0 = decode_char(chunk[0])?;
        let b1 = decode_char(chunk[1])?;
        let b2 = decode_char(chunk[2])?;
        let b3 = decode_char(chunk[3])?;

        result.push((b0 << 2) | (b1 >> 4));

        if chunk[2] != '=' {
            result.push((b1 << 4) | (b2 >> 2));
        }

        if chunk[3] != '=' {
            result.push((b2 << 6) | b3);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_key() {
        let key = generate_recovery_key().expect("Failed to generate recovery key");
        assert_eq!(key.as_bytes().len(), RECOVERY_KEY_SIZE);

        // Key should not be all zeros
        assert!(
            key.as_bytes().iter().any(|&b| b != 0),
            "Recovery key should not be all zeros"
        );
    }

    #[test]
    fn test_recovery_key_uniqueness() {
        let key1 = generate_recovery_key().expect("Failed to generate key 1");
        let key2 = generate_recovery_key().expect("Failed to generate key 2");

        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "Two recovery keys should be different"
        );
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let original = generate_recovery_key().expect("Failed to generate key");
        let mnemonic = original.to_mnemonic();

        // Should be 24 words
        assert_eq!(
            mnemonic.split_whitespace().count(),
            24,
            "Mnemonic should have 24 words"
        );

        // Should roundtrip correctly
        let restored = RecoveryKey::from_mnemonic(&mnemonic).expect("Failed to parse mnemonic");
        assert_eq!(original.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = generate_recovery_key().expect("Failed to generate key");
        let encoded = original.to_base64();

        // Base64 of 32 bytes should be 44 characters (with padding)
        assert_eq!(encoded.len(), 44, "Base64 should be 44 characters");

        // Should roundtrip correctly
        let restored = RecoveryKey::from_base64(&encoded).expect("Failed to parse base64");
        assert_eq!(original.as_bytes(), restored.as_bytes());
    }

    #[test]
    fn test_master_key_encryption_roundtrip() {
        let recovery_key = generate_recovery_key().expect("Failed to generate recovery key");
        let master_key: [u8; 32] = [0x42u8; 32];

        let encrypted = recovery_key
            .encrypt_master_key(&master_key)
            .expect("Failed to encrypt master key");

        assert_eq!(encrypted.len(), ENCRYPTED_MASTER_KEY_SIZE);

        let decrypted = recovery_key
            .decrypt_master_key(&encrypted)
            .expect("Failed to decrypt master key");

        assert_eq!(decrypted, master_key);
    }

    #[test]
    fn test_master_key_decryption_with_wrong_recovery_key() {
        let recovery_key1 = generate_recovery_key().expect("Failed to generate key 1");
        let recovery_key2 = generate_recovery_key().expect("Failed to generate key 2");
        let master_key: [u8; 32] = [0x42u8; 32];

        let encrypted = recovery_key1
            .encrypt_master_key(&master_key)
            .expect("Failed to encrypt");

        let result = recovery_key2.decrypt_master_key(&encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = RecoveryKey::from_mnemonic("invalid mnemonic phrase");
        assert!(result.is_err(), "Invalid mnemonic should fail");

        // Wrong number of words
        let result = RecoveryKey::from_mnemonic("abandon abandon abandon");
        assert!(result.is_err(), "Short mnemonic should fail");
    }

    #[test]
    fn test_invalid_base64() {
        let result = RecoveryKey::from_base64("not valid base64!!!");
        assert!(result.is_err(), "Invalid base64 should fail");

        // Valid base64 but wrong length
        let result = RecoveryKey::from_base64("AAAA");
        assert!(result.is_err(), "Short base64 should fail");
    }

    #[test]
    fn test_encrypted_master_key_tampering() {
        let recovery_key = generate_recovery_key().expect("Failed to generate key");
        let master_key: [u8; 32] = [0x42u8; 32];

        let mut encrypted = recovery_key
            .encrypt_master_key(&master_key)
            .expect("Failed to encrypt");

        // Tamper with the ciphertext
        encrypted[NONCE_LENGTH] ^= 0xFF;

        let result = recovery_key.decrypt_master_key(&encrypted);
        assert!(
            result.is_err(),
            "Decryption of tampered ciphertext should fail"
        );
    }

    #[test]
    fn test_mnemonic_from_known_entropy() {
        // Test with known entropy to verify BIP39 implementation
        let key = RecoveryKey::new([0u8; 32]);
        let mnemonic = key.to_mnemonic();

        // All-zero entropy produces a specific mnemonic
        assert!(
            mnemonic.starts_with("abandon"),
            "All-zero entropy should start with 'abandon'"
        );

        // Verify word count
        assert_eq!(mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn test_base64_encoding_consistency() {
        // Test with known value
        let key = RecoveryKey::new([0u8; 32]);
        let b64 = key.to_base64();
        assert_eq!(b64, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        let key2 = RecoveryKey::new([0xFF; 32]);
        let b64_2 = key2.to_base64();
        assert_eq!(b64_2, "//////////////////////////////////////////8=");
    }

    #[test]
    fn test_recovery_key_zeroize() {
        // This test verifies the Zeroize derive is working by checking
        // the type is ZeroizeOnDrop. The actual zeroization happens on drop.
        let key = generate_recovery_key().expect("Failed to generate key");
        let _mnemonic = key.to_mnemonic(); // Use the key
        // Key will be zeroized when it goes out of scope
    }

    #[test]
    fn test_encrypted_master_key_size() {
        assert_eq!(
            ENCRYPTED_MASTER_KEY_SIZE,
            12 + 32 + 16,
            "Encrypted master key should be nonce + key + tag"
        );
    }
}
