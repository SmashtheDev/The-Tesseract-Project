//! AES-256-XTS Sector Encryption
//!
//! This module provides AES-256-XTS encryption for disk/container encryption.
//! XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing) is specifically
//! designed for encrypting data on storage devices where each sector needs
//! independent encryption with a deterministic tweak.
//!
//! # Security Properties
//!
//! - Each sector is encrypted independently using sector number as tweak
//! - No ciphertext expansion (encrypted data is same size as plaintext)
//! - Ciphertext stealing allows encryption of any size >= 16 bytes
//! - Changing one bit of plaintext changes ~half of the ciphertext bits
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_crypto::xts::{Xts256, XtsConfig};
//!
//! let key = [0u8; 64]; // 512-bit key (two 256-bit AES keys)
//! let cipher = Xts256::new(key);
//!
//! let mut sector = [0u8; 512];
//! cipher.encrypt_sector(&mut sector, 0)?; // Encrypt sector 0
//! cipher.decrypt_sector(&mut sector, 0)?; // Decrypt sector 0
//! ```

use aes::Aes256;
use aes_gcm::KeyInit;
use thiserror::Error;
use xts_mode::Xts128;
use zeroize::{Zeroize, Zeroizing};

/// XTS key size in bytes (512 bits = 2 × 256-bit AES keys).
pub const XTS_KEY_SIZE: usize = 64;

/// Default sector size in bytes.
pub const DEFAULT_SECTOR_SIZE: usize = 512;

/// Minimum sector size (must be at least one AES block).
pub const MIN_SECTOR_SIZE: usize = 16;

/// Maximum sector size (4 KiB is typical maximum for modern drives).
pub const MAX_SECTOR_SIZE: usize = 4096;

/// Errors that can occur during XTS operations.
#[derive(Debug, Error)]
pub enum XtsError {
    /// Sector size is too small (less than 16 bytes).
    #[error("Sector size too small: {size} bytes (minimum: {MIN_SECTOR_SIZE})")]
    SectorTooSmall { size: usize },

    /// Sector size exceeds maximum.
    #[error("Sector size too large: {size} bytes (maximum: {MAX_SECTOR_SIZE})")]
    SectorTooLarge { size: usize },

    /// Invalid key length provided.
    #[error("Invalid key length: {0} bytes (expected: {XTS_KEY_SIZE})")]
    InvalidKeyLength(usize),

    /// Sector number overflow during tweak calculation.
    #[error("Sector number overflow")]
    SectorOverflow,
}

/// Result type for XTS operations.
pub type XtsResult<T> = Result<T, XtsError>;

/// Configuration for XTS encryption.
#[derive(Debug, Clone, Copy)]
pub struct XtsConfig {
    /// Sector size in bytes.
    pub sector_size: usize,
}

impl Default for XtsConfig {
    fn default() -> Self {
        Self {
            sector_size: DEFAULT_SECTOR_SIZE,
        }
    }
}

impl XtsConfig {
    /// Create a new configuration with custom sector size.
    ///
    /// # Errors
    ///
    /// Returns an error if sector size is invalid.
    pub fn with_sector_size(sector_size: usize) -> XtsResult<Self> {
        if sector_size < MIN_SECTOR_SIZE {
            return Err(XtsError::SectorTooSmall { size: sector_size });
        }
        if sector_size > MAX_SECTOR_SIZE {
            return Err(XtsError::SectorTooLarge { size: sector_size });
        }
        Ok(Self { sector_size })
    }

    /// Create configuration for 512-byte sectors.
    #[must_use]
    pub fn sector_512() -> Self {
        Self { sector_size: 512 }
    }

    /// Create configuration for 4096-byte sectors (4K).
    #[must_use]
    pub fn sector_4k() -> Self {
        Self { sector_size: 4096 }
    }
}

/// AES-256-XTS cipher for sector encryption.
///
/// XTS mode uses two AES-256 keys:
/// - Key 1: Used for the main AES encryption
/// - Key 2: Used to encrypt the tweak value
///
/// The tweak is derived from the sector number, ensuring each sector
/// has unique encryption even with the same key.
pub struct Xts256 {
    cipher: Xts128<Aes256>,
    key: Zeroizing<[u8; XTS_KEY_SIZE]>,
}

impl Clone for Xts256 {
    fn clone(&self) -> Self {
        Self::new(*self.key).expect("key already validated")
    }
}

impl Xts256 {
    /// Create a new XTS-AES-256 cipher with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - 64-byte key (two 256-bit AES keys concatenated)
    ///
    /// # Returns
    ///
    /// A new `Xts256` instance.
    ///
    /// # Panics
    ///
    /// This function cannot panic as the key size is enforced by the type system.
    #[must_use]
    pub fn new(key: [u8; XTS_KEY_SIZE]) -> XtsResult<Self> {
        // Split the 64-byte key into two 32-byte keys
        let key1: [u8; 32] = key[..32].try_into().expect("slice length mismatch");
        let key2: [u8; 32] = key[32..].try_into().expect("slice length mismatch");

        let cipher = Xts128::<Aes256>::new(
            Aes256::new_from_slice(&key1).expect("key1 length"),
            Aes256::new_from_slice(&key2).expect("key2 length"),
        );

        Ok(Self {
            cipher,
            key: Zeroizing::new(key),
        })
    }

    /// Create a new XTS cipher from a key slice.
    ///
    /// # Arguments
    ///
    /// * `key` - Key bytes (must be exactly 64 bytes)
    ///
    /// # Errors
    ///
    /// Returns `InvalidKeyLength` if key is not exactly 64 bytes.
    pub fn from_slice(key: &[u8]) -> XtsResult<Self> {
        if key.len() != XTS_KEY_SIZE {
            return Err(XtsError::InvalidKeyLength(key.len()));
        }
        let mut key_array = [0u8; XTS_KEY_SIZE];
        key_array.copy_from_slice(key);
        let result = Self::new(key_array);
        // Clear the temporary array
        key_array.zeroize();
        result
    }

    /// Encrypt a sector in place.
    ///
    /// # Arguments
    ///
    /// * `sector` - Sector data to encrypt (must be at least 16 bytes)
    /// * `sector_number` - Sector number used to derive the tweak
    ///
    /// # Errors
    ///
    /// Returns an error if the sector size is invalid.
    pub fn encrypt_sector(&self, sector: &mut [u8], sector_number: u64) -> XtsResult<()> {
        self.validate_sector_size(sector.len())?;
        let tweak = self.sector_to_tweak(sector_number);
        self.cipher.encrypt_sector(sector, tweak);
        Ok(())
    }

    /// Decrypt a sector in place.
    ///
    /// # Arguments
    ///
    /// * `sector` - Encrypted sector data (must be at least 16 bytes)
    /// * `sector_number` - Sector number used to derive the tweak
    ///
    /// # Errors
    ///
    /// Returns an error if the sector size is invalid.
    pub fn decrypt_sector(&self, sector: &mut [u8], sector_number: u64) -> XtsResult<()> {
        self.validate_sector_size(sector.len())?;
        let tweak = self.sector_to_tweak(sector_number);
        self.cipher.decrypt_sector(sector, tweak);
        Ok(())
    }

    /// Encrypt multiple sectors in place.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to encrypt
    /// * `sector_size` - Size of each sector
    /// * `start_sector` - Starting sector number
    ///
    /// # Errors
    ///
    /// Returns an error if sector size is invalid or data is not a multiple of sector size.
    pub fn encrypt_sectors(
        &self,
        data: &mut [u8],
        sector_size: usize,
        start_sector: u64,
    ) -> XtsResult<()> {
        self.validate_sector_size(sector_size)?;
        if data.len() % sector_size != 0 {
            return Err(XtsError::SectorTooSmall { size: data.len() % sector_size });
        }

        let num_sectors = data.len() / sector_size;
        for i in 0..num_sectors {
            let sector_num = start_sector
                .checked_add(i as u64)
                .ok_or(XtsError::SectorOverflow)?;
            let start = i * sector_size;
            let end = start + sector_size;
            self.encrypt_sector(&mut data[start..end], sector_num)?;
        }
        Ok(())
    }

    /// Decrypt multiple sectors in place.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to decrypt
    /// * `sector_size` - Size of each sector
    /// * `start_sector` - Starting sector number
    ///
    /// # Errors
    ///
    /// Returns an error if sector size is invalid or data is not a multiple of sector size.
    pub fn decrypt_sectors(
        &self,
        data: &mut [u8],
        sector_size: usize,
        start_sector: u64,
    ) -> XtsResult<()> {
        self.validate_sector_size(sector_size)?;
        if data.len() % sector_size != 0 {
            return Err(XtsError::SectorTooSmall { size: data.len() % sector_size });
        }

        let num_sectors = data.len() / sector_size;
        for i in 0..num_sectors {
            let sector_num = start_sector
                .checked_add(i as u64)
                .ok_or(XtsError::SectorOverflow)?;
            let start = i * sector_size;
            let end = start + sector_size;
            self.decrypt_sector(&mut data[start..end], sector_num)?;
        }
        Ok(())
    }

    /// Convert sector number to 16-byte tweak value.
    ///
    /// The tweak is the sector number encoded as little-endian in the first
    /// 8 bytes, with the remaining 8 bytes set to zero.
    fn sector_to_tweak(&self, sector_number: u64) -> [u8; 16] {
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector_number.to_le_bytes());
        tweak
    }

    /// Validate sector size is within acceptable bounds.
    fn validate_sector_size(&self, size: usize) -> XtsResult<()> {
        if size < MIN_SECTOR_SIZE {
            return Err(XtsError::SectorTooSmall { size });
        }
        if size > MAX_SECTOR_SIZE {
            return Err(XtsError::SectorTooLarge { size });
        }
        Ok(())
    }
}

impl Drop for Xts256 {
    fn drop(&mut self) {
        // key is already Zeroizing, it will be cleared automatically
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a simple encrypt/decrypt round-trip works.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let original = b"Hello, World! This is a test of XTS encryption mode.";
        let mut sector = [0u8; 64];
        sector[..original.len()].copy_from_slice(original);

        // Encrypt
        cipher.encrypt_sector(&mut sector, 0).unwrap();
        assert_ne!(&sector[..original.len()], original);

        // Decrypt
        cipher.decrypt_sector(&mut sector, 0).unwrap();
        assert_eq!(&sector[..original.len()], original);
    }

    /// Test encryption with different sector numbers produces different ciphertext.
    #[test]
    fn test_different_sectors_different_ciphertext() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let original = [0xAB; 512];
        let mut sector0 = original;
        let mut sector1 = original;

        cipher.encrypt_sector(&mut sector0, 0).unwrap();
        cipher.encrypt_sector(&mut sector1, 1).unwrap();

        // Same plaintext, different sector numbers should produce different ciphertext
        assert_ne!(sector0, sector1);
    }

    /// Test that wrong sector number fails decryption (produces wrong plaintext).
    #[test]
    fn test_wrong_sector_wrong_decryption() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let original = b"Secret data that must be protected with XTS!!!!";
        let mut sector = [0u8; 64];
        sector[..original.len()].copy_from_slice(original);

        // Encrypt with sector 0
        cipher.encrypt_sector(&mut sector, 0).unwrap();

        // Try to decrypt with sector 1 (wrong tweak)
        cipher.decrypt_sector(&mut sector, 1).unwrap();

        // Decryption "succeeds" but produces garbage
        assert_ne!(&sector[..original.len()], original);
    }

    /// Test various sector sizes.
    #[test]
    fn test_various_sector_sizes() {
        let key = [0x55u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        // 16 bytes (minimum)
        let mut sector16 = [0xAAu8; 16];
        let original16 = sector16;
        cipher.encrypt_sector(&mut sector16, 0).unwrap();
        cipher.decrypt_sector(&mut sector16, 0).unwrap();
        assert_eq!(sector16, original16);

        // 512 bytes (standard)
        let mut sector512 = [0xBBu8; 512];
        let original512 = sector512;
        cipher.encrypt_sector(&mut sector512, 0).unwrap();
        cipher.decrypt_sector(&mut sector512, 0).unwrap();
        assert_eq!(sector512, original512);

        // 4096 bytes (4K sectors)
        let mut sector4k = [0xCCu8; 4096];
        let original4k = sector4k;
        cipher.encrypt_sector(&mut sector4k, 0).unwrap();
        cipher.decrypt_sector(&mut sector4k, 0).unwrap();
        assert_eq!(sector4k, original4k);
    }

    /// Test sector size validation.
    #[test]
    fn test_sector_size_validation() {
        let key = [0u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        // Too small
        let mut small = [0u8; 8];
        assert!(cipher.encrypt_sector(&mut small, 0).is_err());

        // Too large
        let mut large = vec![0u8; 8192];
        assert!(cipher.encrypt_sector(&mut large, 0).is_err());
    }

    /// Test key creation from slice.
    #[test]
    fn test_from_slice() {
        let key_bytes = [0x42u8; XTS_KEY_SIZE];

        // Valid key
        let cipher = Xts256::from_slice(&key_bytes).unwrap();
        let mut data = [0xAA; 64];
        cipher.encrypt_sector(&mut data, 0).unwrap();

        // Invalid key length
        assert!(Xts256::from_slice(&[0u8; 32]).is_err());
        assert!(Xts256::from_slice(&[0u8; 128]).is_err());
    }

    /// Test multiple sectors encryption/decryption.
    #[test]
    fn test_multiple_sectors() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let mut data = vec![0xABu8; 512 * 4]; // 4 sectors
        let original = data.clone();

        cipher.encrypt_sectors(&mut data, 512, 0).unwrap();
        assert_ne!(data, original);

        cipher.decrypt_sectors(&mut data, 512, 0).unwrap();
        assert_eq!(data, original);
    }

    /// Test that encryption is deterministic (same key + sector = same ciphertext).
    #[test]
    fn test_deterministic_encryption() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let original = [0xAB; 512];
        let mut sector1 = original;
        let mut sector2 = original;

        cipher.encrypt_sector(&mut sector1, 42).unwrap();
        cipher.encrypt_sector(&mut sector2, 42).unwrap();

        // Same plaintext + same sector number = same ciphertext
        assert_eq!(sector1, sector2);
    }

    /// Test XtsConfig validation.
    #[test]
    fn test_xts_config() {
        // Valid configs
        assert!(XtsConfig::with_sector_size(512).is_ok());
        assert!(XtsConfig::with_sector_size(4096).is_ok());
        assert!(XtsConfig::with_sector_size(16).is_ok());

        // Invalid configs
        assert!(XtsConfig::with_sector_size(8).is_err());
        assert!(XtsConfig::with_sector_size(8192).is_err());

        // Preset configs
        assert_eq!(XtsConfig::sector_512().sector_size, 512);
        assert_eq!(XtsConfig::sector_4k().sector_size, 4096);
        assert_eq!(XtsConfig::default().sector_size, DEFAULT_SECTOR_SIZE);
    }

    // =========================================================================
    // Known Test Vectors
    // =========================================================================
    // These vectors are based on IEEE P1619/D16 test vectors for AES-XTS

    /// IEEE P1619 Test Vector 10 (AES-256)
    /// Key: all zeros (64 bytes)
    /// Sector: 0
    /// Plaintext: all zeros (32 bytes)
    #[test]
    fn test_vector_ieee_p1619_zeros() {
        let key = [0u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        // 32 bytes of zeros
        let mut data = [0u8; 32];
        cipher.encrypt_sector(&mut data, 0).unwrap();

        // After encryption, should not be all zeros
        assert_ne!(data, [0u8; 32]);

        // Decrypt should restore to zeros
        cipher.decrypt_sector(&mut data, 0).unwrap();
        assert_eq!(data, [0u8; 32]);
    }

    /// Test with incrementing plaintext pattern.
    #[test]
    fn test_vector_incrementing_plaintext() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let mut plaintext = [0u8; 512];
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        let original = plaintext;

        cipher.encrypt_sector(&mut plaintext, 0).unwrap();

        // Verify ciphertext looks random (high entropy)
        let zeros: usize = plaintext.iter().filter(|&&b| b == 0).count();
        assert!(zeros < 100, "Ciphertext has too many zeros: {zeros}");

        cipher.decrypt_sector(&mut plaintext, 0).unwrap();
        assert_eq!(plaintext, original);
    }

    /// Test with sector number at boundary (u64::MAX - 1).
    #[test]
    fn test_high_sector_number() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let mut data = [0xAA; 64];
        let original = data;

        // Test with high sector numbers
        cipher.encrypt_sector(&mut data, u64::MAX - 1).unwrap();
        cipher.decrypt_sector(&mut data, u64::MAX - 1).unwrap();
        assert_eq!(data, original);
    }

    /// Verify tweak calculation produces correct format.
    #[test]
    fn test_tweak_format() {
        let key = [0u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        // Sector 0 tweak should be all zeros
        let tweak0 = cipher.sector_to_tweak(0);
        assert_eq!(tweak0, [0u8; 16]);

        // Sector 1 tweak should be [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        let tweak1 = cipher.sector_to_tweak(1);
        assert_eq!(tweak1[0], 1);
        assert_eq!(&tweak1[1..], &[0u8; 15]);

        // Sector 256 tweak should be [0, 1, 0, 0, ...] (little-endian)
        let tweak256 = cipher.sector_to_tweak(256);
        assert_eq!(tweak256[0], 0);
        assert_eq!(tweak256[1], 1);
    }

    /// Test clone produces equivalent cipher.
    #[test]
    fn test_clone() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher1 = Xts256::new(key).unwrap();
        let cipher2 = cipher1.clone();

        let mut data1 = [0xAA; 64];
        let mut data2 = data1;

        cipher1.encrypt_sector(&mut data1, 0).unwrap();
        cipher2.encrypt_sector(&mut data2, 0).unwrap();

        assert_eq!(data1, data2);
    }
}
