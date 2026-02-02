//! THC (TESSERACT Hardware Container) format.
//!
//! This module defines the container header format and operations
//! for encrypted drive containers.

use crate::crypto::{derive_dual_keys, DualKeys};
use crate::error::{HardwareError, Result};
use tesseract_crypto::{aes, generate_bytes, generate_nonce, hmac_sign, hmac_verify_slice};
use tracing::{debug, info, warn, instrument};
use zeroize::Zeroizing;

/// THC magic bytes: "TESS-HWC" followed by null.
pub const THC_MAGIC: &[u8; 8] = b"TESS-HWC";

/// Current THC format version.
pub const THC_VERSION: u8 = 1;

/// Total header size in bytes (4096 for sector alignment).
pub const THC_HEADER_SIZE: usize = 4096;

/// Salt size for key derivation.
pub const SALT_SIZE: usize = 32;

/// Master key size (256 bits).
pub const MASTER_KEY_SIZE: usize = 32;

/// AES-GCM nonce size (96 bits).
pub const NONCE_SIZE: usize = 12;

/// AES-GCM tag size (128 bits).
pub const TAG_SIZE: usize = 16;

/// Encrypted master key size (32 bytes key + 12 bytes nonce + 16 bytes tag).
pub const ENCRYPTED_KEY_SIZE: usize = MASTER_KEY_SIZE + NONCE_SIZE + TAG_SIZE;

/// HMAC tag size for header integrity.
pub const HMAC_TAG_SIZE: usize = 32;

/// Reserved space for future use.
pub const RESERVED_SIZE: usize = THC_HEADER_SIZE
    - 8  // magic
    - 1  // version
    - 1  // cipher suite
    - 4  // argon2 memory
    - 1  // argon2 iterations
    - 1  // argon2 parallelism
    - SALT_SIZE  // hw_salt
    - SALT_SIZE  // vault_salt
    - ENCRYPTED_KEY_SIZE  // encrypted master key
    - HMAC_TAG_SIZE;  // header MAC

/// Cipher suite identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-256-XTS for disk encryption (standard).
    Aes256Xts = 0,
    /// Reserved for future cipher suites.
    Reserved = 255,
}

impl CipherSuite {
    /// Get cipher suite from byte value.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Aes256Xts),
            _ => None,
        }
    }

    /// Get human-readable name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes256Xts => "AES-256-XTS",
            Self::Reserved => "Reserved",
        }
    }
}

/// THC header structure.
///
/// Total size: 4096 bytes for sector alignment.
///
/// Layout:
/// - `[0..8]`: Magic bytes ("TESS-HWC")
/// - `[8]`: Version (1)
/// - `[9]`: Cipher suite
/// - `[10..14]`: Argon2 memory (MB, little-endian u32)
/// - `[14]`: Argon2 iterations
/// - `[15]`: Argon2 parallelism
/// - `[16..48]`: Hardware salt (32 bytes)
/// - `[48..80]`: Vault salt (32 bytes)
/// - `[80..140]`: Encrypted master key (60 bytes)
/// - `[140..172]`: Header HMAC (32 bytes)
/// - `[172..4096]`: Reserved (zeros)
#[derive(Debug, Clone)]
pub struct ThcHeader {
    /// Format version.
    pub version: u8,
    /// Cipher suite used.
    pub cipher: CipherSuite,
    /// Argon2 memory cost in MB.
    pub argon2_memory_mb: u32,
    /// Argon2 iteration count.
    pub argon2_iterations: u8,
    /// Argon2 parallelism factor.
    pub argon2_parallelism: u8,
    /// Salt for hardware key derivation.
    pub hw_salt: [u8; SALT_SIZE],
    /// Salt for vault key derivation.
    pub vault_salt: [u8; SALT_SIZE],
    /// Encrypted master key (key + nonce + tag).
    pub encrypted_master_key: [u8; ENCRYPTED_KEY_SIZE],
    /// HMAC of header (computed over all preceding fields).
    pub hmac_tag: [u8; HMAC_TAG_SIZE],
}

impl ThcHeader {
    /// Create a new header with generated salts.
    ///
    /// Note: This creates an uninitialized header. Use `initialize()` to
    /// set up encryption with a password.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: THC_VERSION,
            cipher: CipherSuite::Aes256Xts,
            argon2_memory_mb: 64,  // 64 MB default
            argon2_iterations: 3,
            argon2_parallelism: 4,
            hw_salt: [0u8; SALT_SIZE],
            vault_salt: [0u8; SALT_SIZE],
            encrypted_master_key: [0u8; ENCRYPTED_KEY_SIZE],
            hmac_tag: [0u8; HMAC_TAG_SIZE],
        }
    }

    /// Serialize header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; THC_HEADER_SIZE] {
        let mut bytes = [0u8; THC_HEADER_SIZE];

        // Magic bytes
        bytes[0..8].copy_from_slice(THC_MAGIC);

        // Version and cipher
        bytes[8] = self.version;
        bytes[9] = self.cipher as u8;

        // Argon2 parameters
        bytes[10..14].copy_from_slice(&self.argon2_memory_mb.to_le_bytes());
        bytes[14] = self.argon2_iterations;
        bytes[15] = self.argon2_parallelism;

        // Salts
        bytes[16..48].copy_from_slice(&self.hw_salt);
        bytes[48..80].copy_from_slice(&self.vault_salt);

        // Encrypted master key
        bytes[80..140].copy_from_slice(&self.encrypted_master_key);

        // HMAC tag
        bytes[140..172].copy_from_slice(&self.hmac_tag);

        // Reserved space is already zeros

        bytes
    }

    /// Deserialize header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the magic bytes or version are invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < THC_HEADER_SIZE {
            return Err(HardwareError::InvalidHeader {
                reason: format!(
                    "Header too small: {} bytes, expected {}",
                    bytes.len(),
                    THC_HEADER_SIZE
                ),
            });
        }

        // Verify magic
        if &bytes[0..8] != THC_MAGIC {
            return Err(HardwareError::InvalidHeader {
                reason: "Invalid magic bytes".to_string(),
            });
        }

        // Parse version
        let version = bytes[8];
        if version != THC_VERSION {
            return Err(HardwareError::UnsupportedVersion { version });
        }

        // Parse cipher
        let cipher = CipherSuite::from_byte(bytes[9]).ok_or(HardwareError::InvalidHeader {
            reason: format!("Unknown cipher suite: {}", bytes[9]),
        })?;

        // Parse Argon2 parameters
        let argon2_memory_mb = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let argon2_iterations = bytes[14];
        let argon2_parallelism = bytes[15];

        // Parse salts
        let mut hw_salt = [0u8; SALT_SIZE];
        hw_salt.copy_from_slice(&bytes[16..48]);

        let mut vault_salt = [0u8; SALT_SIZE];
        vault_salt.copy_from_slice(&bytes[48..80]);

        // Parse encrypted master key
        let mut encrypted_master_key = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_master_key.copy_from_slice(&bytes[80..140]);

        // Parse HMAC tag
        let mut hmac_tag = [0u8; HMAC_TAG_SIZE];
        hmac_tag.copy_from_slice(&bytes[140..172]);

        Ok(Self {
            version,
            cipher,
            argon2_memory_mb,
            argon2_iterations,
            argon2_parallelism,
            hw_salt,
            vault_salt,
            encrypted_master_key,
            hmac_tag,
        })
    }

    /// Check if the version is compatible with current implementation.
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.version == THC_VERSION
    }

    /// Get the Argon2 memory cost in bytes.
    #[must_use]
    pub fn argon2_memory_bytes(&self) -> u32 {
        self.argon2_memory_mb * 1024 * 1024
    }

    /// Initialize a new header with the given password.
    ///
    /// This generates random salts, derives keys from the password,
    /// generates and encrypts a random master key, and computes the header HMAC.
    ///
    /// # Arguments
    ///
    /// * `password` - Master password for key derivation
    /// * `memory_mb` - Argon2 memory cost in megabytes (default: 64)
    /// * `iterations` - Argon2 iteration count (default: 3)
    /// * `parallelism` - Argon2 parallelism factor (default: 4)
    ///
    /// # Returns
    ///
    /// An initialized `ThcHeader` ready to be written to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if random generation or encryption fails.
    #[instrument(level = "info", skip(password), fields(memory_mb, iterations, parallelism))]
    pub fn initialize(
        password: &[u8],
        memory_mb: u32,
        iterations: u8,
        parallelism: u8,
    ) -> Result<Self> {
        info!(memory_mb, iterations, parallelism, "Initializing new THC header");
        debug!("Generating random salts");
        // Generate random salts (32 bytes each)
        let hw_salt_vec = generate_bytes(SALT_SIZE)?;
        let vault_salt_vec = generate_bytes(SALT_SIZE)?;

        let mut hw_salt = [0u8; SALT_SIZE];
        let mut vault_salt = [0u8; SALT_SIZE];
        hw_salt.copy_from_slice(&hw_salt_vec);
        vault_salt.copy_from_slice(&vault_salt_vec);

        // Derive keys from password
        let keys = derive_dual_keys(
            password,
            &hw_salt,
            &vault_salt,
            memory_mb,
            iterations,
            parallelism,
        )?;

        // Generate random master key (32 bytes - this is what gets encrypted in the header)
        let master_key_vec = generate_bytes(MASTER_KEY_SIZE)?;
        let mut master_key = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        master_key.copy_from_slice(&master_key_vec);

        // Generate nonce for master key encryption
        let nonce = generate_nonce()?;

        // Encrypt master key with vault key using AES-256-GCM
        let encrypted = aes::encrypt_no_aad(keys.vault_key(), &nonce, &*master_key)?;

        // Pack encrypted master key: nonce (12) + ciphertext (32) + tag (16) = 60 bytes
        // Note: aes::encrypt returns ciphertext + tag appended
        let mut encrypted_master_key = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_master_key[..NONCE_SIZE].copy_from_slice(&nonce);
        encrypted_master_key[NONCE_SIZE..].copy_from_slice(&encrypted);

        // Create header with all fields except HMAC
        let mut header = Self {
            version: THC_VERSION,
            cipher: CipherSuite::Aes256Xts,
            argon2_memory_mb: memory_mb,
            argon2_iterations: iterations,
            argon2_parallelism: parallelism,
            hw_salt,
            vault_salt,
            encrypted_master_key,
            hmac_tag: [0u8; HMAC_TAG_SIZE],
        };

        // Compute HMAC over header data (excluding HMAC field itself)
        header.hmac_tag = header.compute_hmac(keys.vault_key());

        info!("THC header initialized successfully");
        Ok(header)
    }

    /// Initialize a header with default Argon2 parameters.
    ///
    /// Uses memory=64MB, iterations=3, parallelism=4.
    pub fn initialize_default(password: &[u8]) -> Result<Self> {
        Self::initialize(password, 64, 3, 4)
    }

    /// Unlock the container with the given password.
    ///
    /// This derives keys from the password, verifies the header HMAC,
    /// and decrypts the master key.
    ///
    /// # Arguments
    ///
    /// * `password` - Master password for key derivation
    ///
    /// # Returns
    ///
    /// `DualKeys` containing the hardware key and vault key.
    ///
    /// # Errors
    ///
    /// * `HardwareError::IntegrityError` - Header HMAC verification failed
    /// * `HardwareError::InvalidPassword` - Password is incorrect (decryption failed)
    #[instrument(level = "info", skip(self, password))]
    pub fn unlock(&self, password: &[u8]) -> Result<DualKeys> {
        info!("Attempting to unlock THC container");
        debug!(
            memory_mb = self.argon2_memory_mb,
            iterations = self.argon2_iterations,
            parallelism = self.argon2_parallelism,
            "Deriving keys with Argon2id"
        );

        // Derive keys from password using stored parameters
        let keys = derive_dual_keys(
            password,
            &self.hw_salt,
            &self.vault_salt,
            self.argon2_memory_mb,
            self.argon2_iterations,
            self.argon2_parallelism,
        )?;

        // Verify HMAC first (tampering detection)
        debug!("Verifying header HMAC");
        let expected_hmac = self.compute_hmac(keys.vault_key());
        if hmac_verify_slice(keys.vault_key(), &self.hmac_data(), &self.hmac_tag).is_err() {
            // Could be wrong password or tampering
            // Try to distinguish by checking if computed HMAC matches expected
            if self.hmac_tag != expected_hmac {
                // HMAC doesn't match - either wrong password or tampered header
                warn!("HMAC verification failed - invalid password or tampering detected");
                return Err(HardwareError::InvalidPassword);
            }
        }

        // Extract nonce and encrypted data from encrypted_master_key
        debug!("Decrypting master key");
        let nonce = &self.encrypted_master_key[..NONCE_SIZE];
        let ciphertext = &self.encrypted_master_key[NONCE_SIZE..];

        // Decrypt master key
        let _decrypted = aes::decrypt_no_aad(keys.vault_key(), nonce, ciphertext)
            .map_err(|_| {
                warn!("Master key decryption failed - invalid password");
                HardwareError::InvalidPassword
            })?;

        // Master key decryption successful, return the derived keys
        info!("THC container unlocked successfully");
        Ok(keys)
    }

    /// Change the master password for this container.
    ///
    /// This verifies the current password, decrypts the master key,
    /// and re-encrypts it with the new password-derived key.
    ///
    /// # Arguments
    ///
    /// * `current_password` - Current master password (for verification)
    /// * `new_password` - New master password to set
    ///
    /// # Returns
    ///
    /// A new `ThcHeader` with the master key re-encrypted under the new password.
    /// The caller is responsible for writing this header back to disk.
    ///
    /// # Errors
    ///
    /// * `HardwareError::InvalidPassword` - Current password is incorrect
    /// * `HardwareError::CryptoError` - Encryption/decryption failed
    #[instrument(level = "info", skip(self, current_password, new_password))]
    pub fn change_password(
        &self,
        current_password: &[u8],
        new_password: &[u8],
    ) -> Result<Self> {
        info!("Changing THC container password");
        // Step 1: Verify current password and get decrypted master key
        let current_keys = derive_dual_keys(
            current_password,
            &self.hw_salt,
            &self.vault_salt,
            self.argon2_memory_mb,
            self.argon2_iterations,
            self.argon2_parallelism,
        )?;

        // Verify HMAC first (tampering detection)
        debug!("Verifying current password via HMAC");
        let expected_hmac = self.compute_hmac(current_keys.vault_key());
        if self.hmac_tag != expected_hmac {
            warn!("Current password verification failed");
            return Err(HardwareError::InvalidPassword);
        }

        // Extract nonce and encrypted data from encrypted_master_key
        debug!("Decrypting master key with current password");
        let nonce = &self.encrypted_master_key[..NONCE_SIZE];
        let ciphertext = &self.encrypted_master_key[NONCE_SIZE..];

        // Decrypt master key
        let master_key = aes::decrypt_no_aad(current_keys.vault_key(), nonce, ciphertext)
            .map_err(|_| {
                warn!("Failed to decrypt master key with current password");
                HardwareError::InvalidPassword
            })?;

        // Step 2: Generate new salts for the new password
        debug!("Generating new salts for forward secrecy");
        let new_hw_salt_vec = generate_bytes(SALT_SIZE)?;
        let new_vault_salt_vec = generate_bytes(SALT_SIZE)?;

        let mut new_hw_salt = [0u8; SALT_SIZE];
        let mut new_vault_salt = [0u8; SALT_SIZE];
        new_hw_salt.copy_from_slice(&new_hw_salt_vec);
        new_vault_salt.copy_from_slice(&new_vault_salt_vec);

        // Step 3: Derive new keys from new password
        let new_keys = derive_dual_keys(
            new_password,
            &new_hw_salt,
            &new_vault_salt,
            self.argon2_memory_mb,
            self.argon2_iterations,
            self.argon2_parallelism,
        )?;

        // Step 4: Re-encrypt master key with new vault key
        let new_nonce = generate_nonce()?;
        let encrypted = aes::encrypt_no_aad(new_keys.vault_key(), &new_nonce, &master_key)?;

        // Pack encrypted master key: nonce (12) + ciphertext (32) + tag (16) = 60 bytes
        let mut new_encrypted_master_key = [0u8; ENCRYPTED_KEY_SIZE];
        new_encrypted_master_key[..NONCE_SIZE].copy_from_slice(&new_nonce);
        new_encrypted_master_key[NONCE_SIZE..].copy_from_slice(&encrypted);

        // Step 5: Create new header with updated values
        let mut new_header = Self {
            version: self.version,
            cipher: self.cipher,
            argon2_memory_mb: self.argon2_memory_mb,
            argon2_iterations: self.argon2_iterations,
            argon2_parallelism: self.argon2_parallelism,
            hw_salt: new_hw_salt,
            vault_salt: new_vault_salt,
            encrypted_master_key: new_encrypted_master_key,
            hmac_tag: [0u8; HMAC_TAG_SIZE],
        };

        // Step 6: Compute new HMAC
        new_header.hmac_tag = new_header.compute_hmac(new_keys.vault_key());

        info!("THC container password changed successfully");
        Ok(new_header)
    }

    /// Compute HMAC over header data (excluding HMAC field).
    ///
    /// The HMAC covers: version, cipher, argon2 params, salts, encrypted master key.
    fn compute_hmac(&self, key: &[u8]) -> [u8; HMAC_TAG_SIZE] {
        let data = self.hmac_data();
        hmac_sign(key, &data)
    }

    /// Get the header data that is covered by the HMAC.
    ///
    /// This includes everything except the HMAC tag itself.
    fn hmac_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(140);

        // Version and cipher
        data.push(self.version);
        data.push(self.cipher as u8);

        // Argon2 parameters
        data.extend_from_slice(&self.argon2_memory_mb.to_le_bytes());
        data.push(self.argon2_iterations);
        data.push(self.argon2_parallelism);

        // Salts
        data.extend_from_slice(&self.hw_salt);
        data.extend_from_slice(&self.vault_salt);

        // Encrypted master key
        data.extend_from_slice(&self.encrypted_master_key);

        data
    }
}

impl Default for ThcHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thc_magic() {
        assert_eq!(THC_MAGIC.len(), 8);
        assert_eq!(THC_MAGIC, b"TESS-HWC");
    }

    #[test]
    fn test_header_size() {
        assert_eq!(THC_HEADER_SIZE, 4096);
    }

    #[test]
    fn test_cipher_suite_from_byte() {
        assert_eq!(CipherSuite::from_byte(0), Some(CipherSuite::Aes256Xts));
        assert_eq!(CipherSuite::from_byte(1), None);
        assert_eq!(CipherSuite::from_byte(255), None);
    }

    #[test]
    fn test_cipher_suite_name() {
        assert_eq!(CipherSuite::Aes256Xts.name(), "AES-256-XTS");
    }

    #[test]
    fn test_header_new() {
        let header = ThcHeader::new();
        assert_eq!(header.version, THC_VERSION);
        assert_eq!(header.cipher, CipherSuite::Aes256Xts);
        assert_eq!(header.argon2_memory_mb, 64);
        assert_eq!(header.argon2_iterations, 3);
        assert_eq!(header.argon2_parallelism, 4);
    }

    #[test]
    fn test_header_to_bytes() {
        let header = ThcHeader::new();
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), THC_HEADER_SIZE);
        assert_eq!(&bytes[0..8], THC_MAGIC);
        assert_eq!(bytes[8], THC_VERSION);
        assert_eq!(bytes[9], CipherSuite::Aes256Xts as u8);
    }

    #[test]
    fn test_header_roundtrip() {
        let mut original = ThcHeader::new();
        original.argon2_memory_mb = 128;
        original.argon2_iterations = 5;
        original.hw_salt[0] = 42;
        original.vault_salt[31] = 99;

        let bytes = original.to_bytes();
        let parsed = ThcHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.cipher, original.cipher);
        assert_eq!(parsed.argon2_memory_mb, 128);
        assert_eq!(parsed.argon2_iterations, 5);
        assert_eq!(parsed.hw_salt[0], 42);
        assert_eq!(parsed.vault_salt[31], 99);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut bytes = [0u8; THC_HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"INVALID!");

        let result = ThcHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(HardwareError::InvalidHeader { .. })));
    }

    #[test]
    fn test_header_unsupported_version() {
        let mut bytes = ThcHeader::new().to_bytes();
        bytes[8] = 99; // Invalid version

        let result = ThcHeader::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(HardwareError::UnsupportedVersion { version: 99 })
        ));
    }

    #[test]
    fn test_header_too_small() {
        let bytes = [0u8; 100];
        let result = ThcHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(HardwareError::InvalidHeader { .. })));
    }

    #[test]
    fn test_argon2_memory_bytes() {
        let header = ThcHeader::new();
        assert_eq!(header.argon2_memory_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn test_is_compatible() {
        let header = ThcHeader::new();
        assert!(header.is_compatible());
    }

    #[test]
    fn test_initialize_header() {
        // Use minimal parameters for fast testing
        let header = ThcHeader::initialize(b"test-password", 1, 1, 1).unwrap();

        assert_eq!(header.version, THC_VERSION);
        assert_eq!(header.cipher, CipherSuite::Aes256Xts);
        assert_eq!(header.argon2_memory_mb, 1);
        assert_eq!(header.argon2_iterations, 1);
        assert_eq!(header.argon2_parallelism, 1);

        // Salts should not be all zeros
        assert!(header.hw_salt.iter().any(|&b| b != 0));
        assert!(header.vault_salt.iter().any(|&b| b != 0));

        // Encrypted master key should not be all zeros
        assert!(header.encrypted_master_key.iter().any(|&b| b != 0));

        // HMAC should not be all zeros
        assert!(header.hmac_tag.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_initialize_default() {
        let header = ThcHeader::initialize_default(b"test-password").unwrap();

        assert_eq!(header.argon2_memory_mb, 64);
        assert_eq!(header.argon2_iterations, 3);
        assert_eq!(header.argon2_parallelism, 4);
    }

    #[test]
    fn test_unlock_correct_password() {
        let password = b"correct-password";
        let header = ThcHeader::initialize(password, 1, 1, 1).unwrap();

        let keys = header.unlock(password).unwrap();

        // Should return valid keys
        assert_eq!(keys.hardware_key().len(), 64);
        assert_eq!(keys.vault_key().len(), 32);
    }

    #[test]
    fn test_unlock_wrong_password() {
        let header = ThcHeader::initialize(b"correct-password", 1, 1, 1).unwrap();

        let result = header.unlock(b"wrong-password");

        assert!(matches!(result, Err(HardwareError::InvalidPassword)));
    }

    #[test]
    fn test_initialize_unlock_roundtrip() {
        let password = b"my-secret-password";
        let header = ThcHeader::initialize(password, 1, 1, 1).unwrap();

        // Serialize and deserialize
        let bytes = header.to_bytes();
        let parsed = ThcHeader::from_bytes(&bytes).unwrap();

        // Unlock should work with same password
        let keys = parsed.unlock(password).unwrap();
        assert_eq!(keys.hardware_key().len(), 64);
        assert_eq!(keys.vault_key().len(), 32);
    }

    #[test]
    fn test_hmac_prevents_tampering() {
        let password = b"test-password";
        let header = ThcHeader::initialize(password, 1, 1, 1).unwrap();

        // Serialize
        let mut bytes = header.to_bytes();

        // Tamper with the encrypted master key
        bytes[100] ^= 0xFF;

        // Parse tampered header
        let tampered = ThcHeader::from_bytes(&bytes).unwrap();

        // Unlock should fail
        let result = tampered.unlock(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_passwords_different_hmac() {
        let header1 = ThcHeader::initialize(b"password1", 1, 1, 1).unwrap();
        let header2 = ThcHeader::initialize(b"password2", 1, 1, 1).unwrap();

        // HMACs should be different (even ignoring randomness of salts,
        // different passwords lead to different keys and thus different HMACs)
        assert_ne!(header1.hmac_tag, header2.hmac_tag);
    }

    #[test]
    fn test_same_password_different_salts() {
        let password = b"same-password";
        let header1 = ThcHeader::initialize(password, 1, 1, 1).unwrap();
        let header2 = ThcHeader::initialize(password, 1, 1, 1).unwrap();

        // Salts should be different (randomly generated)
        assert_ne!(header1.hw_salt, header2.hw_salt);
        assert_ne!(header1.vault_salt, header2.vault_salt);

        // But both should still unlock with the same password
        assert!(header1.unlock(password).is_ok());
        assert!(header2.unlock(password).is_ok());
    }

    #[test]
    fn test_change_password_success() {
        let old_password = b"old-password";
        let new_password = b"new-password";

        // Create header with old password
        let header = ThcHeader::initialize(old_password, 1, 1, 1).unwrap();

        // Change password
        let new_header = header.change_password(old_password, new_password).unwrap();

        // Old password should no longer work
        assert!(matches!(
            new_header.unlock(old_password),
            Err(HardwareError::InvalidPassword)
        ));

        // New password should work
        let keys = new_header.unlock(new_password).unwrap();
        assert_eq!(keys.hardware_key().len(), 64);
        assert_eq!(keys.vault_key().len(), 32);
    }

    #[test]
    fn test_change_password_wrong_current() {
        let password = b"correct-password";
        let header = ThcHeader::initialize(password, 1, 1, 1).unwrap();

        // Try to change with wrong current password
        let result = header.change_password(b"wrong-password", b"new-password");

        assert!(matches!(result, Err(HardwareError::InvalidPassword)));
    }

    #[test]
    fn test_change_password_preserves_version() {
        let old_password = b"old-password";
        let new_password = b"new-password";

        let header = ThcHeader::initialize(old_password, 1, 1, 1).unwrap();
        let new_header = header.change_password(old_password, new_password).unwrap();

        // Version and cipher should be preserved
        assert_eq!(new_header.version, header.version);
        assert_eq!(new_header.cipher, header.cipher);
        assert_eq!(new_header.argon2_memory_mb, header.argon2_memory_mb);
        assert_eq!(new_header.argon2_iterations, header.argon2_iterations);
        assert_eq!(new_header.argon2_parallelism, header.argon2_parallelism);
    }

    #[test]
    fn test_change_password_new_salts() {
        let old_password = b"old-password";
        let new_password = b"new-password";

        let header = ThcHeader::initialize(old_password, 1, 1, 1).unwrap();
        let new_header = header.change_password(old_password, new_password).unwrap();

        // Salts should be different (new ones generated)
        assert_ne!(new_header.hw_salt, header.hw_salt);
        assert_ne!(new_header.vault_salt, header.vault_salt);
    }

    #[test]
    fn test_change_password_roundtrip() {
        let old_password = b"old-password";
        let new_password = b"new-password";

        let header = ThcHeader::initialize(old_password, 1, 1, 1).unwrap();
        let new_header = header.change_password(old_password, new_password).unwrap();

        // Serialize and deserialize
        let bytes = new_header.to_bytes();
        let parsed = ThcHeader::from_bytes(&bytes).unwrap();

        // Should unlock with new password
        let keys = parsed.unlock(new_password).unwrap();
        assert_eq!(keys.hardware_key().len(), 64);
        assert_eq!(keys.vault_key().len(), 32);
    }
}
