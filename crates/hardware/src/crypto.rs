//! Hardware encryption cryptographic operations.
//!
//! This module provides cryptographic operations specific to hardware
//! encryption including AES-256-XTS for sector encryption and dual-key
//! derivation from master passwords.
//!
//! # Key Hierarchy
//!
//! ```text
//! Master Password
//!       |
//!       v
//!   Argon2id KDF (with combined salt)
//!       |
//!       v
//!   Master Key Material (32 bytes)
//!       |
//!       +-----> HKDF-Expand (context: "TESSERACT-HARDWARE-KEY") --> Hardware Key (64 bytes for XTS)
//!       |
//!       +-----> HKDF-Expand (context: "TESSERACT-SOFTWARE-KEY") --> Vault Key (32 bytes for GCM)
//! ```
//!
//! # Security Properties
//!
//! - Keys are cryptographically independent: compromising one does not reveal the other
//! - Same password unlocks both layers seamlessly
//! - Argon2id provides memory-hard protection against brute-force attacks
//! - HKDF-SHA256 expands key material securely per RFC 5869

use crate::error::Result;
use tesseract_crypto::{derive_key, hkdf_expand_32, hkdf_expand_64, Argon2Params};
use zeroize::Zeroizing;

// Re-export XTS from tesseract-crypto crate
pub use tesseract_crypto::xts::{
    Xts256, XtsConfig, XtsError, XtsResult,
    XTS_KEY_SIZE, DEFAULT_SECTOR_SIZE, MIN_SECTOR_SIZE, MAX_SECTOR_SIZE,
};

/// Context string for hardware key derivation.
pub const HARDWARE_KEY_CONTEXT: &[u8] = b"TESSERACT-HARDWARE-KEY";

/// Context string for vault key derivation.
pub const VAULT_KEY_CONTEXT: &[u8] = b"TESSERACT-SOFTWARE-KEY";

/// Size of derived keys (256 bits).
pub const KEY_SIZE: usize = 32;

/// Combined salt size for Argon2 (concatenated hw_salt and vault_salt).
const COMBINED_SALT_SIZE: usize = 64;

/// Dual keys derived from master password.
///
/// One key is used for hardware/container encryption (XTS),
/// the other for vault file encryption (GCM).
#[derive(Clone)]
pub struct DualKeys {
    /// Key for hardware/container encryption (XTS).
    /// This is 64 bytes for XTS (two 256-bit keys).
    hardware_key: Zeroizing<[u8; XTS_KEY_SIZE]>,
    /// Key for vault file encryption (GCM).
    vault_key: Zeroizing<[u8; KEY_SIZE]>,
}

impl DualKeys {
    /// Get the hardware key for XTS encryption.
    ///
    /// Returns a 64-byte key (two 256-bit keys concatenated).
    #[must_use]
    pub fn hardware_key(&self) -> &[u8; XTS_KEY_SIZE] {
        &self.hardware_key
    }

    /// Get the vault key for GCM encryption.
    #[must_use]
    pub fn vault_key(&self) -> &[u8; KEY_SIZE] {
        &self.vault_key
    }

    /// Securely clear keys from memory.
    pub fn clear(&mut self) {
        use zeroize::Zeroize;
        self.hardware_key.zeroize();
        self.vault_key.zeroize();
    }
}

impl Drop for DualKeys {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Derive dual keys from a master password.
///
/// Uses Argon2id for initial key derivation, then HKDF-SHA256 to
/// derive independent hardware and vault keys.
///
/// # Arguments
///
/// * `password` - Master password
/// * `hw_salt` - Salt for hardware key derivation (32 bytes)
/// * `vault_salt` - Salt for vault key derivation (32 bytes)
/// * `memory_mb` - Argon2 memory cost in megabytes
/// * `iterations` - Argon2 iteration count
/// * `parallelism` - Argon2 parallelism factor
///
/// # Returns
///
/// `DualKeys` containing the hardware key (64 bytes for XTS) and vault key (32 bytes for GCM).
///
/// # Errors
///
/// Returns an error if key derivation fails (invalid parameters, memory allocation failure).
///
/// # Key Independence
///
/// The hardware and vault keys are cryptographically independent due to HKDF's properties:
/// - Different context strings ensure no relationship between outputs
/// - Compromising one key does not reveal any information about the other
pub fn derive_dual_keys(
    password: &[u8],
    hw_salt: &[u8; 32],
    vault_salt: &[u8; 32],
    memory_mb: u32,
    iterations: u8,
    parallelism: u8,
) -> Result<DualKeys> {
    // Step 1: Combine salts for Argon2 (ensures both salts contribute entropy)
    let mut combined_salt = Zeroizing::new([0u8; COMBINED_SALT_SIZE]);
    combined_salt[..32].copy_from_slice(hw_salt);
    combined_salt[32..].copy_from_slice(vault_salt);

    // Step 2: Derive master key material using Argon2id
    let argon2_params = Argon2Params::new(
        memory_mb * 1024, // Convert MB to KB
        iterations.into(),
        parallelism.into(),
        32, // 256-bit master key
    );

    let master_key = derive_key(password, &*combined_salt, &argon2_params)?;

    // Step 3: Use HKDF-Expand with master key as PRK to derive hardware key (64 bytes)
    let hardware_key = hkdf_expand_64(&master_key, HARDWARE_KEY_CONTEXT)?;

    // Step 4: Use HKDF-Expand with master key as PRK to derive vault key (32 bytes)
    let vault_key = hkdf_expand_32(&master_key, VAULT_KEY_CONTEXT)?;

    Ok(DualKeys {
        hardware_key,
        vault_key,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_constants() {
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(XTS_KEY_SIZE, 64);
        assert_eq!(DEFAULT_SECTOR_SIZE, 512);
    }

    #[test]
    fn test_context_strings() {
        assert!(HARDWARE_KEY_CONTEXT.starts_with(b"TESSERACT"));
        assert!(VAULT_KEY_CONTEXT.starts_with(b"TESSERACT"));
        assert_ne!(HARDWARE_KEY_CONTEXT, VAULT_KEY_CONTEXT);
    }

    #[test]
    fn test_dual_keys_access() {
        let keys = DualKeys {
            hardware_key: Zeroizing::new([1u8; XTS_KEY_SIZE]),
            vault_key: Zeroizing::new([2u8; KEY_SIZE]),
        };

        assert_eq!(keys.hardware_key().len(), XTS_KEY_SIZE);
        assert_eq!(keys.vault_key().len(), KEY_SIZE);
        assert_eq!(keys.hardware_key()[0], 1);
        assert_eq!(keys.vault_key()[0], 2);
    }

    #[test]
    fn test_dual_keys_clear() {
        let mut keys = DualKeys {
            hardware_key: Zeroizing::new([255u8; XTS_KEY_SIZE]),
            vault_key: Zeroizing::new([255u8; KEY_SIZE]),
        };

        keys.clear();

        assert_eq!(keys.hardware_key()[0], 0);
        assert_eq!(keys.vault_key()[0], 0);
    }

    #[test]
    fn test_derive_dual_keys() {
        // Use minimal parameters for fast testing
        let result = derive_dual_keys(
            b"password",
            &[0u8; 32],
            &[0u8; 32],
            1, // 1 MB (minimal)
            1, // 1 iteration
            1, // 1 thread
        );
        assert!(result.is_ok());

        let keys = result.unwrap();
        // Verify keys are not zeros (actually derived)
        assert!(keys.hardware_key().iter().any(|&b| b != 0), "Hardware key should not be all zeros");
        assert!(keys.vault_key().iter().any(|&b| b != 0), "Vault key should not be all zeros");
    }

    #[test]
    fn test_derive_dual_keys_deterministic() {
        let password = b"test-password";
        let hw_salt = [0x01u8; 32];
        let vault_salt = [0x02u8; 32];

        let keys1 = derive_dual_keys(password, &hw_salt, &vault_salt, 1, 1, 1).unwrap();
        let keys2 = derive_dual_keys(password, &hw_salt, &vault_salt, 1, 1, 1).unwrap();

        assert_eq!(keys1.hardware_key(), keys2.hardware_key(), "Same inputs should produce same hardware key");
        assert_eq!(keys1.vault_key(), keys2.vault_key(), "Same inputs should produce same vault key");
    }

    #[test]
    fn test_derive_dual_keys_independence() {
        let password = b"test-password";
        let hw_salt = [0x01u8; 32];
        let vault_salt = [0x02u8; 32];

        let keys = derive_dual_keys(password, &hw_salt, &vault_salt, 1, 1, 1).unwrap();

        // Hardware key (64 bytes) should not contain vault key (32 bytes) as substring
        let hw_key = keys.hardware_key();
        let vault_key = keys.vault_key();

        // Check that hardware key doesn't contain vault key at any offset
        for i in 0..=(XTS_KEY_SIZE - KEY_SIZE) {
            assert_ne!(&hw_key[i..i+KEY_SIZE], vault_key.as_slice(),
                "Keys should be independent (vault key found in hardware key at offset {i})");
        }
    }

    #[test]
    fn test_derive_dual_keys_different_passwords() {
        let hw_salt = [0x01u8; 32];
        let vault_salt = [0x02u8; 32];

        let keys1 = derive_dual_keys(b"password1", &hw_salt, &vault_salt, 1, 1, 1).unwrap();
        let keys2 = derive_dual_keys(b"password2", &hw_salt, &vault_salt, 1, 1, 1).unwrap();

        assert_ne!(keys1.hardware_key(), keys2.hardware_key(), "Different passwords should produce different hardware keys");
        assert_ne!(keys1.vault_key(), keys2.vault_key(), "Different passwords should produce different vault keys");
    }

    #[test]
    fn test_derive_dual_keys_different_salts() {
        let password = b"password";

        let keys1 = derive_dual_keys(password, &[0x01u8; 32], &[0x02u8; 32], 1, 1, 1).unwrap();
        let keys2 = derive_dual_keys(password, &[0x03u8; 32], &[0x04u8; 32], 1, 1, 1).unwrap();

        assert_ne!(keys1.hardware_key(), keys2.hardware_key(), "Different salts should produce different hardware keys");
        assert_ne!(keys1.vault_key(), keys2.vault_key(), "Different salts should produce different vault keys");
    }

    #[test]
    fn test_xts256_new() {
        let key = [0u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key);
        assert!(cipher.is_ok());
    }

    #[test]
    fn test_xts256_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; XTS_KEY_SIZE];
        let cipher = Xts256::new(key).unwrap();

        let original = b"Secret data to protect with XTS encryption mode!!";
        let mut sector = [0u8; 64];
        sector[..original.len()].copy_from_slice(original);

        // Encrypt
        cipher.encrypt_sector(&mut sector, 0).unwrap();
        assert_ne!(&sector[..original.len()], original);

        // Decrypt
        cipher.decrypt_sector(&mut sector, 0).unwrap();
        assert_eq!(&sector[..original.len()], original);
    }

    #[test]
    fn test_xts256_different_sectors() {
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

    #[test]
    fn test_xts256_with_dual_keys() {
        // Test that derived DualKeys can be used with Xts256
        let keys = derive_dual_keys(
            b"test-password",
            &[0x01u8; 32],
            &[0x02u8; 32],
            1, 1, 1
        ).unwrap();

        let cipher = Xts256::new(*keys.hardware_key()).unwrap();
        let mut sector = [0xAA; 512];
        let original = sector;

        cipher.encrypt_sector(&mut sector, 0).unwrap();
        assert_ne!(sector, original);

        cipher.decrypt_sector(&mut sector, 0).unwrap();
        assert_eq!(sector, original);
    }
}
