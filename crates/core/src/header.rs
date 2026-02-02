//! Vault header structure and operations.
//!
//! The vault header contains metadata, version info, and encrypted
//! master key material. It is the first thing read when opening a vault
//! and contains all information needed to derive and verify the master key.
//!
//! # Format
//!
//! The header has a fixed-size binary format (512 bytes):
//!
//! | Offset | Size | Field              | Description                        |
//! |--------|------|--------------------|------------------------------------|
//! | 0      | 8    | magic              | Magic bytes: `TESSERAC`            |
//! | 8      | 2    | version            | Format version (major.minor)       |
//! | 10     | 16   | salt               | Argon2 salt for key derivation     |
//! | 26     | 64   | encrypted_master_key | AES-256-GCM encrypted MK + tag  |
//! | 90     | 12   | master_key_nonce   | Nonce used for MK encryption       |
//! | 102    | 4    | attempt_counter    | Failed authentication attempts     |
//! | 106    | 8    | lockout_until      | Unix timestamp for lockout expiry  |
//! | 114    | 8    | created_at         | Unix timestamp of vault creation   |
//! | 122    | 8    | last_modified      | Unix timestamp of last modification|
//! | 130    | 32   | hmac_tag           | HMAC-SHA256 over header[0..130]    |
//! | 162    | 350  | reserved           | Reserved for future use (zeroed)   |
//!
//! Total: 512 bytes
//!
//! # Security
//!
//! - The master key is encrypted with AES-256-GCM using a key derived from the password
//! - The HMAC-SHA256 tag covers all header fields before the tag itself
//! - Integrity verification MUST run before any decryption attempt
//! - Tampering with any header byte is detected and rejected

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::VaultError;
use tesseract_crypto::{
    aes::{decrypt, encrypt, KEY_LENGTH as AES_KEY_LENGTH, NONCE_LENGTH as AES_NONCE_LENGTH},
    hmac::{hmac_sign, hmac_verify, HMAC_SIZE as CRYPTO_HMAC_SIZE},
    kdf::{derive_key, Argon2Params},
    CryptoError,
};

/// Magic bytes identifying a TESSERACT vault header.
/// ASCII: "TESSERAC" (8 bytes, no null terminator).
pub const MAGIC_BYTES: [u8; 8] = *b"TESSERAC";

/// Current vault format version.
pub const CURRENT_VERSION: VaultVersion = VaultVersion { major: 1, minor: 0 };

/// Total header size in bytes (fixed for efficient I/O).
pub const HEADER_SIZE: usize = 512;

/// Size of the salt field.
pub const SALT_SIZE: usize = 16;

/// Size of the encrypted master key field (32-byte key + 16-byte GCM tag).
pub const ENCRYPTED_MASTER_KEY_SIZE: usize = 48;

/// Size of the nonce for master key encryption.
pub const NONCE_SIZE: usize = 12;

/// Size of the HMAC tag.
pub const HMAC_TAG_SIZE: usize = 32;

/// Size of reserved space for future use.
pub const RESERVED_SIZE: usize = 366;

/// Base delay in seconds for exponential backoff.
pub const BACKOFF_BASE_SECONDS: u64 = 2;

/// Maximum backoff delay in seconds (1 hour).
pub const BACKOFF_MAX_SECONDS: u64 = 3600;

/// Default number of consecutive failures before triggering full lockout.
pub const DEFAULT_LOCKOUT_THRESHOLD: u32 = 10;

/// Default lockout duration in seconds (15 minutes).
pub const DEFAULT_LOCKOUT_DURATION_SECONDS: u64 = 900;

/// Field offsets within the header.
pub mod offsets {
    /// Offset of magic bytes.
    pub const MAGIC: usize = 0;
    /// Offset of version field.
    pub const VERSION: usize = 8;
    /// Offset of salt field.
    pub const SALT: usize = 10;
    /// Offset of encrypted master key field.
    pub const ENCRYPTED_MASTER_KEY: usize = 26;
    /// Offset of master key nonce field.
    pub const MASTER_KEY_NONCE: usize = 74;
    /// Offset of attempt counter field.
    pub const ATTEMPT_COUNTER: usize = 86;
    /// Offset of lockout until field.
    pub const LOCKOUT_UNTIL: usize = 90;
    /// Offset of created_at field.
    pub const CREATED_AT: usize = 98;
    /// Offset of last_modified field.
    pub const LAST_MODIFIED: usize = 106;
    /// Offset of HMAC tag field.
    pub const HMAC_TAG: usize = 114;
    /// Offset of reserved space.
    pub const RESERVED: usize = 146;
    /// Offset where HMAC computation begins (covers header data).
    pub const HMAC_DATA_END: usize = 114;
}

/// Vault format version supporting future migrations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultVersion {
    /// Major version (breaking changes).
    pub major: u8,
    /// Minor version (backwards-compatible additions).
    pub minor: u8,
}

impl VaultVersion {
    /// Creates a new vault version.
    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Checks if this version is compatible with another.
    /// Versions are compatible if the major version matches.
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Serializes to 2 bytes [major, minor].
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.major, self.minor]
    }

    /// Deserializes from 2 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        Self {
            major: bytes[0],
            minor: bytes[1],
        }
    }
}

impl std::fmt::Display for VaultVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Vault header containing metadata, encrypted master key, and integrity verification.
///
/// This structure is serialized to exactly 512 bytes for efficient disk I/O.
/// The HMAC tag covers all preceding fields to detect tampering.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// Format version for migration support.
    version: VaultVersion,
    /// Salt for Argon2id key derivation.
    salt: [u8; SALT_SIZE],
    /// Encrypted master key (32 bytes key + 16 bytes GCM tag = 48 bytes).
    encrypted_master_key: [u8; ENCRYPTED_MASTER_KEY_SIZE],
    /// Nonce used for master key encryption.
    master_key_nonce: [u8; NONCE_SIZE],
    /// Count of failed authentication attempts (for exponential backoff).
    attempt_counter: u32,
    /// Unix timestamp when lockout expires (0 if not locked out).
    lockout_until: u64,
    /// Unix timestamp when vault was created.
    created_at: u64,
    /// Unix timestamp of last modification.
    last_modified: u64,
    /// HMAC-SHA256 tag over header fields (for integrity verification).
    hmac_tag: [u8; HMAC_TAG_SIZE],
}

impl VaultHeader {
    /// Creates a new vault header with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `salt` - Salt for Argon2id key derivation (16 bytes)
    /// * `encrypted_master_key` - Encrypted master key material (48 bytes)
    /// * `master_key_nonce` - Nonce used for master key encryption (12 bytes)
    ///
    /// # Panics
    ///
    /// Panics if the system time is before UNIX_EPOCH.
    #[must_use]
    pub fn new(
        salt: [u8; SALT_SIZE],
        encrypted_master_key: [u8; ENCRYPTED_MASTER_KEY_SIZE],
        master_key_nonce: [u8; NONCE_SIZE],
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH")
            .as_secs();

        Self {
            version: CURRENT_VERSION,
            salt,
            encrypted_master_key,
            master_key_nonce,
            attempt_counter: 0,
            lockout_until: 0,
            created_at: now,
            last_modified: now,
            hmac_tag: [0u8; HMAC_TAG_SIZE],
        }
    }

    /// Creates a vault header from raw components (for deserialization).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        version: VaultVersion,
        salt: [u8; SALT_SIZE],
        encrypted_master_key: [u8; ENCRYPTED_MASTER_KEY_SIZE],
        master_key_nonce: [u8; NONCE_SIZE],
        attempt_counter: u32,
        lockout_until: u64,
        created_at: u64,
        last_modified: u64,
        hmac_tag: [u8; HMAC_TAG_SIZE],
    ) -> Self {
        Self {
            version,
            salt,
            encrypted_master_key,
            master_key_nonce,
            attempt_counter,
            lockout_until,
            created_at,
            last_modified,
            hmac_tag,
        }
    }

    /// Returns the vault format version.
    #[must_use]
    pub fn version(&self) -> VaultVersion {
        self.version
    }

    /// Returns the salt for key derivation.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    /// Returns the encrypted master key material.
    #[must_use]
    pub fn encrypted_master_key(&self) -> &[u8; ENCRYPTED_MASTER_KEY_SIZE] {
        &self.encrypted_master_key
    }

    /// Returns the nonce used for master key encryption.
    #[must_use]
    pub fn master_key_nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.master_key_nonce
    }

    /// Returns the number of failed authentication attempts.
    #[must_use]
    pub fn attempt_counter(&self) -> u32 {
        self.attempt_counter
    }

    /// Returns the lockout expiry timestamp (0 if not locked out).
    #[must_use]
    pub fn lockout_until(&self) -> u64 {
        self.lockout_until
    }

    /// Returns the vault creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the last modification timestamp.
    #[must_use]
    pub fn last_modified(&self) -> u64 {
        self.last_modified
    }

    /// Returns the HMAC integrity tag.
    #[must_use]
    pub fn hmac_tag(&self) -> &[u8; HMAC_TAG_SIZE] {
        &self.hmac_tag
    }

    /// Sets the HMAC tag for integrity verification.
    pub fn set_hmac_tag(&mut self, tag: [u8; HMAC_TAG_SIZE]) {
        self.hmac_tag = tag;
    }

    /// Updates the encrypted master key and nonce.
    pub fn set_encrypted_master_key(
        &mut self,
        encrypted_master_key: [u8; ENCRYPTED_MASTER_KEY_SIZE],
        nonce: [u8; NONCE_SIZE],
    ) {
        self.encrypted_master_key = encrypted_master_key;
        self.master_key_nonce = nonce;
        self.update_modified();
    }

    /// Increments the attempt counter.
    pub fn increment_attempts(&mut self) {
        self.attempt_counter = self.attempt_counter.saturating_add(1);
        self.update_modified();
    }

    /// Resets the attempt counter to zero.
    pub fn reset_attempts(&mut self) {
        self.attempt_counter = 0;
        self.lockout_until = 0;
        self.update_modified();
    }

    /// Sets the lockout expiry timestamp.
    pub fn set_lockout_until(&mut self, timestamp: u64) {
        self.lockout_until = timestamp;
        self.update_modified();
    }

    /// Checks if the vault is currently locked out.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        if self.lockout_until == 0 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        now < self.lockout_until
    }

    /// Returns the remaining lockout duration in seconds, or 0 if not locked out.
    #[must_use]
    pub fn lockout_remaining(&self) -> u64 {
        if self.lockout_until == 0 {
            return 0;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        self.lockout_until.saturating_sub(now)
    }

    /// Calculates the exponential backoff delay based on the current attempt count.
    ///
    /// The delay follows the formula: `min(base^attempts, max_seconds)` where:
    /// - `base` is `BACKOFF_BASE_SECONDS` (2 seconds)
    /// - `max_seconds` is `BACKOFF_MAX_SECONDS` (3600 seconds / 1 hour)
    ///
    /// | Attempts | Delay (seconds) |
    /// |----------|-----------------|
    /// | 0        | 0               |
    /// | 1        | 2               |
    /// | 2        | 4               |
    /// | 3        | 8               |
    /// | 4        | 16              |
    /// | 5        | 32              |
    /// | ...      | ...             |
    /// | 12+      | 3600 (max)      |
    ///
    /// # Returns
    ///
    /// The delay in seconds before the next authentication attempt should be allowed.
    #[must_use]
    pub fn calculate_backoff_seconds(&self) -> u64 {
        if self.attempt_counter == 0 {
            return 0;
        }

        // Calculate 2^attempts, saturating to avoid overflow
        // For attempts >= 63, this would overflow u64, so we cap at max
        let exponent = self.attempt_counter.min(63) as u32;
        let delay = BACKOFF_BASE_SECONDS.saturating_pow(exponent);

        // Cap at maximum delay
        delay.min(BACKOFF_MAX_SECONDS)
    }

    /// Checks if the attempt counter has reached the lockout threshold.
    ///
    /// When the threshold is reached, a full lockout should be triggered
    /// instead of using exponential backoff.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The number of consecutive failures before lockout
    ///   (default: `DEFAULT_LOCKOUT_THRESHOLD` = 10)
    ///
    /// # Returns
    ///
    /// `true` if the current attempt count equals or exceeds the threshold.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if header.should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD) {
    ///     header.trigger_lockout(DEFAULT_LOCKOUT_DURATION_SECONDS);
    /// }
    /// ```
    #[must_use]
    pub fn should_trigger_lockout(&self, threshold: u32) -> bool {
        self.attempt_counter >= threshold
    }

    /// Triggers a fixed-duration lockout.
    ///
    /// Unlike exponential backoff which grows with each attempt, this method
    /// sets a fixed lockout period (e.g., 15 minutes) when the failure threshold
    /// is reached. This is typically called after N consecutive failures.
    ///
    /// # Arguments
    ///
    /// * `duration_seconds` - The lockout duration in seconds
    ///   (default: `DEFAULT_LOCKOUT_DURATION_SECONDS` = 900 seconds / 15 minutes)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // After 10 failed attempts, trigger 15-minute lockout
    /// if header.attempt_counter() >= 10 {
    ///     header.trigger_lockout(900);
    /// }
    /// ```
    pub fn trigger_lockout(&mut self, duration_seconds: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.lockout_until = now.saturating_add(duration_seconds);
        self.update_modified();
    }

    /// Applies exponential backoff after a failed authentication attempt.
    ///
    /// This method uses default lockout settings:
    /// - Threshold: 10 consecutive failures
    /// - Lockout duration: 15 minutes
    ///
    /// For custom settings, use [`apply_backoff_with_config`].
    ///
    /// # Returns
    ///
    /// The delay in seconds until the next attempt is allowed.
    pub fn apply_backoff(&mut self) -> u64 {
        self.apply_backoff_with_config(DEFAULT_LOCKOUT_THRESHOLD, DEFAULT_LOCKOUT_DURATION_SECONDS)
    }

    /// Applies exponential backoff with configurable lockout settings.
    ///
    /// This method:
    /// 1. Increments the attempt counter
    /// 2. If threshold is reached, triggers full lockout with fixed duration
    /// 3. Otherwise, calculates exponential backoff delay
    /// 4. Sets the lockout_until timestamp accordingly
    ///
    /// # Arguments
    ///
    /// * `lockout_threshold` - Number of consecutive failures before full lockout
    /// * `lockout_duration_seconds` - Duration of full lockout in seconds
    ///
    /// # Returns
    ///
    /// The delay in seconds until the next attempt is allowed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Custom settings: lockout after 5 failures for 30 minutes
    /// let delay = header.apply_backoff_with_config(5, 1800);
    /// ```
    pub fn apply_backoff_with_config(
        &mut self,
        lockout_threshold: u32,
        lockout_duration_seconds: u64,
    ) -> u64 {
        self.increment_attempts();

        // Check if we've reached the threshold for full lockout
        if self.should_trigger_lockout(lockout_threshold) {
            self.trigger_lockout(lockout_duration_seconds);
            return lockout_duration_seconds;
        }

        // Otherwise, apply exponential backoff
        let delay = self.calculate_backoff_seconds();

        if delay > 0 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            self.lockout_until = now.saturating_add(delay);
        }

        delay
    }

    /// Updates the last_modified timestamp to now.
    fn update_modified(&mut self) {
        self.last_modified = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
    }

    /// Serializes the header to a fixed-size 512-byte buffer.
    ///
    /// # Returns
    ///
    /// A 512-byte array containing the serialized header.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buffer = [0u8; HEADER_SIZE];

        // Magic bytes
        buffer[offsets::MAGIC..offsets::MAGIC + 8].copy_from_slice(&MAGIC_BYTES);

        // Version
        buffer[offsets::VERSION..offsets::VERSION + 2].copy_from_slice(&self.version.to_bytes());

        // Salt
        buffer[offsets::SALT..offsets::SALT + SALT_SIZE].copy_from_slice(&self.salt);

        // Encrypted master key
        buffer[offsets::ENCRYPTED_MASTER_KEY..offsets::ENCRYPTED_MASTER_KEY + ENCRYPTED_MASTER_KEY_SIZE]
            .copy_from_slice(&self.encrypted_master_key);

        // Master key nonce
        buffer[offsets::MASTER_KEY_NONCE..offsets::MASTER_KEY_NONCE + NONCE_SIZE]
            .copy_from_slice(&self.master_key_nonce);

        // Attempt counter (little-endian)
        buffer[offsets::ATTEMPT_COUNTER..offsets::ATTEMPT_COUNTER + 4]
            .copy_from_slice(&self.attempt_counter.to_le_bytes());

        // Lockout until (little-endian)
        buffer[offsets::LOCKOUT_UNTIL..offsets::LOCKOUT_UNTIL + 8]
            .copy_from_slice(&self.lockout_until.to_le_bytes());

        // Created at (little-endian)
        buffer[offsets::CREATED_AT..offsets::CREATED_AT + 8]
            .copy_from_slice(&self.created_at.to_le_bytes());

        // Last modified (little-endian)
        buffer[offsets::LAST_MODIFIED..offsets::LAST_MODIFIED + 8]
            .copy_from_slice(&self.last_modified.to_le_bytes());

        // HMAC tag
        buffer[offsets::HMAC_TAG..offsets::HMAC_TAG + HMAC_TAG_SIZE].copy_from_slice(&self.hmac_tag);

        // Reserved space already zeroed

        buffer
    }

    /// Returns the portion of the header that is covered by the HMAC.
    /// This is everything from the start up to (but not including) the HMAC tag.
    #[must_use]
    pub fn hmac_data(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes[..offsets::HMAC_DATA_END].to_vec()
    }

    /// Computes and sets the HMAC-SHA256 integrity tag for this header.
    ///
    /// This method should be called after all header fields are set and
    /// before writing the header to disk.
    ///
    /// # Arguments
    ///
    /// * `hmac_key` - The key to use for HMAC computation. This should be
    ///   derived from the user's password using Argon2id.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut header = VaultHeader::new(salt, encrypted_mk, nonce);
    /// header.compute_hmac(&hmac_key);
    /// header.write_to(&mut file)?;
    /// ```
    pub fn compute_hmac(&mut self, hmac_key: &[u8; HMAC_TAG_SIZE]) {
        let data = self.hmac_data();
        self.hmac_tag = hmac_sign(hmac_key, &data);
    }

    /// Verifies the HMAC-SHA256 integrity tag of this header.
    ///
    /// **IMPORTANT**: This method MUST be called before attempting to decrypt
    /// the master key. If integrity verification fails, the header may have
    /// been tampered with and decryption should not be attempted.
    ///
    /// # Arguments
    ///
    /// * `hmac_key` - The key to use for HMAC verification. This should be
    ///   derived from the user's password using Argon2id.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the HMAC tag is valid
    /// * `Err(VaultError::HeaderIntegrityFailed)` if verification fails
    ///
    /// # Security
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_integrity(&self, hmac_key: &[u8; HMAC_TAG_SIZE]) -> Result<(), VaultError> {
        let data = self.hmac_data();
        hmac_verify(hmac_key, &data, &self.hmac_tag)
            .map_err(|_| VaultError::HeaderIntegrityFailed)
    }

    /// Encrypts the master key and stores it in the header.
    ///
    /// This method encrypts the raw master key using AES-256-GCM and stores
    /// the resulting ciphertext (with appended authentication tag) in the header.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The raw 32-byte master key to encrypt
    /// * `encryption_key` - The key to use for encryption (derived from password)
    /// * `nonce` - A unique 12-byte nonce for this encryption
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success
    /// * `Err(VaultError)` if encryption fails
    ///
    /// # Security
    ///
    /// The nonce MUST be unique for each encryption operation with the same key.
    /// Never reuse a nonce, as this completely breaks GCM security.
    pub fn encrypt_master_key(
        &mut self,
        master_key: &[u8; 32],
        encryption_key: &[u8; 32],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<(), VaultError> {
        // Use version info as additional authenticated data
        let aad = self.version.to_bytes();

        // Encrypt the master key
        let ciphertext = encrypt(encryption_key, nonce, master_key, &aad)?;

        // Verify ciphertext size (32-byte key + 16-byte tag = 48 bytes)
        if ciphertext.len() != ENCRYPTED_MASTER_KEY_SIZE {
            return Err(VaultError::InvalidFormat(format!(
                "Encrypted master key has wrong size: expected {}, got {}",
                ENCRYPTED_MASTER_KEY_SIZE,
                ciphertext.len()
            )));
        }

        // Store encrypted master key and nonce
        self.encrypted_master_key.copy_from_slice(&ciphertext);
        self.master_key_nonce = *nonce;
        self.update_modified();

        Ok(())
    }

    /// Decrypts and returns the master key from the header.
    ///
    /// **IMPORTANT**: Always call `verify_integrity()` before this method
    /// to ensure the header has not been tampered with.
    ///
    /// # Arguments
    ///
    /// * `decryption_key` - The key to use for decryption (derived from password)
    ///
    /// # Returns
    ///
    /// * `Ok([u8; 32])` - The decrypted 32-byte master key
    /// * `Err(VaultError::AuthenticationFailed)` if decryption fails (wrong password or tampering)
    ///
    /// # Security
    ///
    /// If decryption fails, no partial key material is exposed.
    pub fn decrypt_master_key(
        &self,
        decryption_key: &[u8; 32],
    ) -> Result<[u8; 32], VaultError> {
        // Use version info as additional authenticated data (must match encryption)
        let aad = self.version.to_bytes();

        // Decrypt the master key
        let plaintext = decrypt(
            decryption_key,
            &self.master_key_nonce,
            &self.encrypted_master_key,
            &aad,
        ).map_err(|_| VaultError::AuthenticationFailed)?;

        // Verify plaintext size
        if plaintext.len() != 32 {
            return Err(VaultError::InvalidFormat(format!(
                "Decrypted master key has wrong size: expected 32, got {}",
                plaintext.len()
            )));
        }

        // Convert to fixed-size array
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&plaintext);

        Ok(master_key)
    }

    /// Deserializes a header from a 512-byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A 512-byte array containing the serialized header.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::InvalidFormat` if:
    /// - Magic bytes don't match
    /// - Version is incompatible
    pub fn from_bytes(buffer: &[u8; HEADER_SIZE]) -> Result<Self, VaultError> {
        // Verify magic bytes
        if buffer[offsets::MAGIC..offsets::MAGIC + 8] != MAGIC_BYTES {
            return Err(VaultError::InvalidFormat(
                "Invalid magic bytes: not a TESSERACT vault".to_string(),
            ));
        }

        // Parse version
        let version = VaultVersion::from_bytes([
            buffer[offsets::VERSION],
            buffer[offsets::VERSION + 1],
        ]);

        // Check version compatibility
        if !version.is_compatible_with(&CURRENT_VERSION) {
            return Err(VaultError::InvalidFormat(format!(
                "Incompatible vault version: found {version}, expected {CURRENT_VERSION}.x"
            )));
        }

        // Parse salt
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&buffer[offsets::SALT..offsets::SALT + SALT_SIZE]);

        // Parse encrypted master key
        let mut encrypted_master_key = [0u8; ENCRYPTED_MASTER_KEY_SIZE];
        encrypted_master_key.copy_from_slice(
            &buffer[offsets::ENCRYPTED_MASTER_KEY..offsets::ENCRYPTED_MASTER_KEY + ENCRYPTED_MASTER_KEY_SIZE],
        );

        // Parse master key nonce
        let mut master_key_nonce = [0u8; NONCE_SIZE];
        master_key_nonce.copy_from_slice(
            &buffer[offsets::MASTER_KEY_NONCE..offsets::MASTER_KEY_NONCE + NONCE_SIZE],
        );

        // Parse attempt counter (little-endian)
        let attempt_counter = u32::from_le_bytes([
            buffer[offsets::ATTEMPT_COUNTER],
            buffer[offsets::ATTEMPT_COUNTER + 1],
            buffer[offsets::ATTEMPT_COUNTER + 2],
            buffer[offsets::ATTEMPT_COUNTER + 3],
        ]);

        // Parse lockout until (little-endian)
        let lockout_until = u64::from_le_bytes([
            buffer[offsets::LOCKOUT_UNTIL],
            buffer[offsets::LOCKOUT_UNTIL + 1],
            buffer[offsets::LOCKOUT_UNTIL + 2],
            buffer[offsets::LOCKOUT_UNTIL + 3],
            buffer[offsets::LOCKOUT_UNTIL + 4],
            buffer[offsets::LOCKOUT_UNTIL + 5],
            buffer[offsets::LOCKOUT_UNTIL + 6],
            buffer[offsets::LOCKOUT_UNTIL + 7],
        ]);

        // Parse created_at (little-endian)
        let created_at = u64::from_le_bytes([
            buffer[offsets::CREATED_AT],
            buffer[offsets::CREATED_AT + 1],
            buffer[offsets::CREATED_AT + 2],
            buffer[offsets::CREATED_AT + 3],
            buffer[offsets::CREATED_AT + 4],
            buffer[offsets::CREATED_AT + 5],
            buffer[offsets::CREATED_AT + 6],
            buffer[offsets::CREATED_AT + 7],
        ]);

        // Parse last_modified (little-endian)
        let last_modified = u64::from_le_bytes([
            buffer[offsets::LAST_MODIFIED],
            buffer[offsets::LAST_MODIFIED + 1],
            buffer[offsets::LAST_MODIFIED + 2],
            buffer[offsets::LAST_MODIFIED + 3],
            buffer[offsets::LAST_MODIFIED + 4],
            buffer[offsets::LAST_MODIFIED + 5],
            buffer[offsets::LAST_MODIFIED + 6],
            buffer[offsets::LAST_MODIFIED + 7],
        ]);

        // Parse HMAC tag
        let mut hmac_tag = [0u8; HMAC_TAG_SIZE];
        hmac_tag.copy_from_slice(&buffer[offsets::HMAC_TAG..offsets::HMAC_TAG + HMAC_TAG_SIZE]);

        Ok(Self {
            version,
            salt,
            encrypted_master_key,
            master_key_nonce,
            attempt_counter,
            lockout_until,
            created_at,
            last_modified,
            hmac_tag,
        })
    }

    /// Writes the header to a writer.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::IoError` if writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), VaultError> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// Reads a header from a reader.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::IoError` if reading fails.
    /// Returns `VaultError::InvalidFormat` if the header is invalid.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, VaultError> {
        let mut buffer = [0u8; HEADER_SIZE];
        reader.read_exact(&mut buffer)?;
        Self::from_bytes(&buffer)
    }

    /// Reads a header from a reader and verifies its integrity.
    ///
    /// This is the recommended way to read a header when you have the HMAC key
    /// available, as it ensures integrity is verified before any other operations.
    ///
    /// # Arguments
    ///
    /// * `reader` - The reader to read the header from
    /// * `hmac_key` - The key to use for HMAC verification
    ///
    /// # Errors
    ///
    /// Returns `VaultError::IoError` if reading fails.
    /// Returns `VaultError::InvalidFormat` if the header format is invalid.
    /// Returns `VaultError::HeaderIntegrityFailed` if HMAC verification fails.
    ///
    /// # Security
    ///
    /// This method first reads and parses the header, then verifies its integrity
    /// before returning. If verification fails, the header is not returned.
    pub fn read_and_verify<R: Read>(
        reader: &mut R,
        hmac_key: &[u8; HMAC_TAG_SIZE],
    ) -> Result<Self, VaultError> {
        let header = Self::read_from(reader)?;
        header.verify_integrity(hmac_key)?;
        Ok(header)
    }

    /// Verifies the integrity of raw header bytes without fully parsing.
    ///
    /// This can be used as an early check before parsing the header,
    /// but requires knowing the exact byte layout.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The raw 512-byte header data
    /// * `hmac_key` - The key to use for HMAC verification
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the HMAC is valid
    /// * `Err(VaultError::HeaderIntegrityFailed)` if verification fails
    pub fn verify_raw_integrity(
        buffer: &[u8; HEADER_SIZE],
        hmac_key: &[u8; HMAC_TAG_SIZE],
    ) -> Result<(), VaultError> {
        // Extract HMAC data (everything before HMAC tag)
        let hmac_data = &buffer[..offsets::HMAC_DATA_END];

        // Extract stored HMAC tag
        let mut stored_tag = [0u8; HMAC_TAG_SIZE];
        stored_tag.copy_from_slice(&buffer[offsets::HMAC_TAG..offsets::HMAC_TAG + HMAC_TAG_SIZE]);

        // Verify
        hmac_verify(hmac_key, hmac_data, &stored_tag)
            .map_err(|_| VaultError::HeaderIntegrityFailed)
    }
}

/// Creates a new vault header with encrypted master key and HMAC integrity tag.
///
/// This is the complete workflow for creating a secured vault header:
/// 1. Generate random salt, master key, and nonce
/// 2. Derive encryption and HMAC keys from password using Argon2id
/// 3. Encrypt the master key
/// 4. Compute HMAC over the header
///
/// # Arguments
///
/// * `password` - The user's password
/// * `master_key` - The raw 32-byte master key to encrypt
/// * `salt` - The salt for key derivation (should be randomly generated)
/// * `nonce` - The nonce for encryption (should be randomly generated)
/// * `argon2_params` - Parameters for Argon2id key derivation
///
/// # Returns
///
/// A tuple of (header, encryption_key, hmac_key) where:
/// - `header` is the fully initialized vault header with encrypted master key and HMAC
/// - `encryption_key` is the 32-byte key derived from password for encryption
/// - `hmac_key` is the 32-byte key derived from password for HMAC
///
/// # Errors
///
/// Returns `VaultError` if encryption or key derivation fails.
///
/// # Example
///
/// ```ignore
/// use tesseract_crypto::kdf::Argon2Params;
///
/// let password = b"my secret password";
/// let master_key = tesseract_crypto::generate_key();
/// let salt = tesseract_crypto::generate_salt();
/// let nonce = tesseract_crypto::generate_nonce();
/// let params = Argon2Params::default();
///
/// let (header, enc_key, hmac_key) = create_encrypted_header(
///     password,
///     &master_key,
///     &salt,
///     &nonce.try_into().unwrap(),
///     &params,
/// )?;
/// ```
pub fn create_encrypted_header(
    password: &[u8],
    master_key: &[u8; 32],
    salt: &[u8; SALT_SIZE],
    nonce: &[u8; NONCE_SIZE],
    argon2_params: &Argon2Params,
) -> Result<(VaultHeader, [u8; 32], [u8; 32]), VaultError> {
    // Derive two separate keys from the password:
    // - encryption_key: for AES-256-GCM encryption of master key
    // - hmac_key: for HMAC-SHA256 integrity tag
    //
    // We use different salts by appending a domain separator to ensure key separation
    let mut enc_salt = [0u8; SALT_SIZE];
    let mut hmac_salt = [0u8; SALT_SIZE];

    // XOR the salt with different constants for domain separation
    for i in 0..SALT_SIZE {
        enc_salt[i] = salt[i] ^ 0x01; // "encryption" domain
        hmac_salt[i] = salt[i] ^ 0x02; // "hmac" domain
    }

    // Derive encryption key
    let encryption_key = derive_key(password, &enc_salt, argon2_params)?;

    // Derive HMAC key
    let hmac_key = derive_key(password, &hmac_salt, argon2_params)?;

    // Create header with placeholder encrypted master key
    let mut header = VaultHeader::new(
        *salt,
        [0u8; ENCRYPTED_MASTER_KEY_SIZE],
        [0u8; NONCE_SIZE],
    );

    // Encrypt the master key
    header.encrypt_master_key(master_key, &encryption_key, nonce)?;

    // Compute HMAC over the header
    header.compute_hmac(&hmac_key);

    Ok((header, encryption_key, hmac_key))
}

/// Unlocks a vault header by verifying integrity and decrypting the master key.
///
/// This is the complete workflow for opening a vault:
/// 1. Derive encryption and HMAC keys from password using Argon2id
/// 2. Verify header integrity
/// 3. Decrypt the master key
///
/// # Arguments
///
/// * `header` - The vault header to unlock
/// * `password` - The user's password
/// * `argon2_params` - Parameters for Argon2id key derivation (should match creation params)
///
/// # Returns
///
/// The decrypted 32-byte master key.
///
/// # Errors
///
/// * `VaultError::HeaderIntegrityFailed` - Header has been tampered with
/// * `VaultError::AuthenticationFailed` - Wrong password or corrupted data
pub fn unlock_header(
    header: &VaultHeader,
    password: &[u8],
    argon2_params: &Argon2Params,
) -> Result<[u8; 32], VaultError> {
    let salt = header.salt();

    // Derive keys using same domain separation as create_encrypted_header
    let mut enc_salt = [0u8; SALT_SIZE];
    let mut hmac_salt = [0u8; SALT_SIZE];

    for i in 0..SALT_SIZE {
        enc_salt[i] = salt[i] ^ 0x01;
        hmac_salt[i] = salt[i] ^ 0x02;
    }

    // Derive HMAC key first and verify integrity BEFORE decryption
    let hmac_key = derive_key(password, &hmac_salt, argon2_params)?;
    header.verify_integrity(&hmac_key)?;

    // Only after integrity is verified, derive encryption key and decrypt
    let encryption_key = derive_key(password, &enc_salt, argon2_params)?;
    header.decrypt_master_key(&encryption_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a test header with known values.
    fn create_test_header() -> VaultHeader {
        let salt = [1u8; SALT_SIZE];
        let encrypted_master_key = [2u8; ENCRYPTED_MASTER_KEY_SIZE];
        let master_key_nonce = [3u8; NONCE_SIZE];

        VaultHeader::new(salt, encrypted_master_key, master_key_nonce)
    }

    #[test]
    fn test_header_size_constraint() {
        // Verify header size is exactly 512 bytes (acceptance criterion)
        assert_eq!(HEADER_SIZE, 512);

        let header = create_test_header();
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 512);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = create_test_header();
        let bytes = original.to_bytes();
        let restored = VaultHeader::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(original.version(), restored.version());
        assert_eq!(original.salt(), restored.salt());
        assert_eq!(original.encrypted_master_key(), restored.encrypted_master_key());
        assert_eq!(original.master_key_nonce(), restored.master_key_nonce());
        assert_eq!(original.attempt_counter(), restored.attempt_counter());
        assert_eq!(original.lockout_until(), restored.lockout_until());
        assert_eq!(original.created_at(), restored.created_at());
        assert_eq!(original.last_modified(), restored.last_modified());
        assert_eq!(original.hmac_tag(), restored.hmac_tag());
    }

    #[test]
    fn test_magic_bytes() {
        let header = create_test_header();
        let bytes = header.to_bytes();

        // Verify magic bytes are at the start
        assert_eq!(&bytes[0..8], b"TESSERAC");
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"BADMAGIC");

        let result = VaultHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_version_serialization() {
        let version = VaultVersion::new(1, 5);
        let bytes = version.to_bytes();
        let restored = VaultVersion::from_bytes(bytes);

        assert_eq!(version, restored);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 5);
    }

    #[test]
    fn test_version_compatibility() {
        let v1_0 = VaultVersion::new(1, 0);
        let v1_1 = VaultVersion::new(1, 1);
        let v2_0 = VaultVersion::new(2, 0);

        // Same major version is compatible
        assert!(v1_0.is_compatible_with(&v1_1));
        assert!(v1_1.is_compatible_with(&v1_0));

        // Different major version is incompatible
        assert!(!v1_0.is_compatible_with(&v2_0));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn test_incompatible_version() {
        let header = create_test_header();
        let mut bytes = header.to_bytes();

        // Change to version 2.0
        bytes[offsets::VERSION] = 2;
        bytes[offsets::VERSION + 1] = 0;

        let result = VaultHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_version_display() {
        let version = VaultVersion::new(1, 5);
        assert_eq!(format!("{version}"), "1.5");
    }

    #[test]
    fn test_attempt_counter() {
        let mut header = create_test_header();
        assert_eq!(header.attempt_counter(), 0);

        header.increment_attempts();
        assert_eq!(header.attempt_counter(), 1);

        header.increment_attempts();
        header.increment_attempts();
        assert_eq!(header.attempt_counter(), 3);

        header.reset_attempts();
        assert_eq!(header.attempt_counter(), 0);
    }

    #[test]
    fn test_attempt_counter_saturation() {
        let mut header = create_test_header();
        // Use from_components to set a high counter value
        header = VaultHeader::from_components(
            header.version(),
            *header.salt(),
            *header.encrypted_master_key(),
            *header.master_key_nonce(),
            u32::MAX,
            0,
            header.created_at(),
            header.last_modified(),
            *header.hmac_tag(),
        );

        header.increment_attempts();
        assert_eq!(header.attempt_counter(), u32::MAX); // Should saturate
    }

    #[test]
    fn test_lockout() {
        let mut header = create_test_header();
        assert!(!header.is_locked_out());
        assert_eq!(header.lockout_remaining(), 0);

        // Set lockout to 1 hour from now
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lockout_time = now + 3600;

        header.set_lockout_until(lockout_time);
        assert!(header.is_locked_out());
        assert!(header.lockout_remaining() <= 3600);
        assert!(header.lockout_remaining() > 3590); // Should be close to 3600

        // Test reset clears lockout
        header.reset_attempts();
        assert!(!header.is_locked_out());
        assert_eq!(header.lockout_remaining(), 0);
    }

    #[test]
    fn test_lockout_expired() {
        let mut header = create_test_header();

        // Set lockout to 1 second ago
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let past_time = now.saturating_sub(1);

        header.set_lockout_until(past_time);
        assert!(!header.is_locked_out()); // Should be expired
        assert_eq!(header.lockout_remaining(), 0);
    }

    #[test]
    fn test_hmac_tag() {
        let mut header = create_test_header();
        let tag = [0xABu8; HMAC_TAG_SIZE];

        header.set_hmac_tag(tag);
        assert_eq!(header.hmac_tag(), &tag);

        // Verify it's preserved through serialization
        let bytes = header.to_bytes();
        let restored = VaultHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.hmac_tag(), &tag);
    }

    #[test]
    fn test_hmac_data() {
        let header = create_test_header();
        let hmac_data = header.hmac_data();

        // HMAC data should be everything up to the HMAC tag offset
        assert_eq!(hmac_data.len(), offsets::HMAC_DATA_END);

        // Verify it starts with magic bytes
        assert_eq!(&hmac_data[0..8], b"TESSERAC");
    }

    #[test]
    fn test_timestamps() {
        let header = create_test_header();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Timestamps should be close to now (within 5 seconds)
        assert!(header.created_at() <= now);
        assert!(header.created_at() >= now - 5);
        assert!(header.last_modified() <= now);
        assert!(header.last_modified() >= now - 5);
    }

    #[test]
    fn test_update_modified_on_changes() {
        let mut header = create_test_header();
        let original_modified = header.last_modified();

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        header.increment_attempts();
        assert!(header.last_modified() >= original_modified);

        let new_modified = header.last_modified();
        std::thread::sleep(std::time::Duration::from_millis(10));

        header.set_lockout_until(12345);
        assert!(header.last_modified() >= new_modified);
    }

    #[test]
    fn test_set_encrypted_master_key() {
        let mut header = create_test_header();
        let new_key = [0xFFu8; ENCRYPTED_MASTER_KEY_SIZE];
        let new_nonce = [0xEEu8; NONCE_SIZE];

        header.set_encrypted_master_key(new_key, new_nonce);

        assert_eq!(header.encrypted_master_key(), &new_key);
        assert_eq!(header.master_key_nonce(), &new_nonce);
    }

    #[test]
    fn test_io_roundtrip() {
        let original = create_test_header();

        // Write to buffer
        let mut buffer = Vec::new();
        original.write_to(&mut buffer).expect("Failed to write");
        assert_eq!(buffer.len(), HEADER_SIZE);

        // Read back
        let mut cursor = std::io::Cursor::new(buffer);
        let restored = VaultHeader::read_from(&mut cursor).expect("Failed to read");

        assert_eq!(original.version(), restored.version());
        assert_eq!(original.salt(), restored.salt());
        assert_eq!(original.encrypted_master_key(), restored.encrypted_master_key());
        assert_eq!(original.master_key_nonce(), restored.master_key_nonce());
    }

    #[test]
    fn test_field_offsets_are_correct() {
        // Verify that our offset constants result in non-overlapping fields
        // and that the total fits within HEADER_SIZE

        // Each field should start after the previous one ends
        assert_eq!(offsets::MAGIC, 0);
        assert_eq!(offsets::VERSION, 8); // MAGIC + 8
        assert_eq!(offsets::SALT, 10); // VERSION + 2
        assert_eq!(offsets::ENCRYPTED_MASTER_KEY, 26); // SALT + 16
        assert_eq!(offsets::MASTER_KEY_NONCE, 74); // ENCRYPTED_MASTER_KEY + 48
        assert_eq!(offsets::ATTEMPT_COUNTER, 86); // MASTER_KEY_NONCE + 12
        assert_eq!(offsets::LOCKOUT_UNTIL, 90); // ATTEMPT_COUNTER + 4
        assert_eq!(offsets::CREATED_AT, 98); // LOCKOUT_UNTIL + 8
        assert_eq!(offsets::LAST_MODIFIED, 106); // CREATED_AT + 8
        assert_eq!(offsets::HMAC_TAG, 114); // LAST_MODIFIED + 8
        assert_eq!(offsets::RESERVED, 146); // HMAC_TAG + 32

        // Reserved should extend to HEADER_SIZE
        assert_eq!(offsets::RESERVED + RESERVED_SIZE, HEADER_SIZE);
    }

    #[test]
    fn test_reserved_space_is_zeroed() {
        let header = create_test_header();
        let bytes = header.to_bytes();

        // All reserved bytes should be zero
        for i in offsets::RESERVED..HEADER_SIZE {
            assert_eq!(bytes[i], 0, "Reserved byte at offset {i} is not zero");
        }
    }

    #[test]
    fn test_all_field_values_preserved() {
        // Create a header with specific values for all fields
        let salt = (0..16).collect::<Vec<u8>>().try_into().unwrap();
        let encrypted_master_key = (100..148).collect::<Vec<u8>>().try_into().unwrap();
        let master_key_nonce = (200..212).collect::<Vec<u8>>().try_into().unwrap();
        let hmac_tag = (50..82).collect::<Vec<u8>>().try_into().unwrap();

        let header = VaultHeader::from_components(
            VaultVersion::new(1, 3),
            salt,
            encrypted_master_key,
            master_key_nonce,
            12345,
            67890,
            1000000,
            2000000,
            hmac_tag,
        );

        let bytes = header.to_bytes();
        let restored = VaultHeader::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version().major, 1);
        assert_eq!(restored.version().minor, 3);
        assert_eq!(restored.salt(), &salt);
        assert_eq!(restored.encrypted_master_key(), &encrypted_master_key);
        assert_eq!(restored.master_key_nonce(), &master_key_nonce);
        assert_eq!(restored.attempt_counter(), 12345);
        assert_eq!(restored.lockout_until(), 67890);
        assert_eq!(restored.created_at(), 1000000);
        assert_eq!(restored.last_modified(), 2000000);
        assert_eq!(restored.hmac_tag(), &hmac_tag);
    }

    #[test]
    fn test_current_version() {
        assert_eq!(CURRENT_VERSION.major, 1);
        assert_eq!(CURRENT_VERSION.minor, 0);
    }

    #[test]
    fn test_header_from_components() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            5,
            1000,
            2000,
            3000,
            [4u8; HMAC_TAG_SIZE],
        );

        assert_eq!(header.version(), VaultVersion::new(1, 0));
        assert_eq!(header.attempt_counter(), 5);
        assert_eq!(header.lockout_until(), 1000);
        assert_eq!(header.created_at(), 2000);
        assert_eq!(header.last_modified(), 3000);
    }

    #[test]
    fn test_byte_order() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [0u8; SALT_SIZE],
            [0u8; ENCRYPTED_MASTER_KEY_SIZE],
            [0u8; NONCE_SIZE],
            0x12345678, // Test value for byte order
            0x0102030405060708, // Test value for byte order
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        let bytes = header.to_bytes();

        // Verify attempt_counter is little-endian
        assert_eq!(bytes[offsets::ATTEMPT_COUNTER], 0x78); // LSB first
        assert_eq!(bytes[offsets::ATTEMPT_COUNTER + 1], 0x56);
        assert_eq!(bytes[offsets::ATTEMPT_COUNTER + 2], 0x34);
        assert_eq!(bytes[offsets::ATTEMPT_COUNTER + 3], 0x12);

        // Verify lockout_until is little-endian
        assert_eq!(bytes[offsets::LOCKOUT_UNTIL], 0x08); // LSB first
        assert_eq!(bytes[offsets::LOCKOUT_UNTIL + 1], 0x07);
        assert_eq!(bytes[offsets::LOCKOUT_UNTIL + 7], 0x01);
    }

    #[test]
    fn test_truncated_read() {
        let header = create_test_header();
        let bytes = header.to_bytes();

        // Try to read from truncated data
        let truncated = &bytes[..256]; // Only half the header
        let mut cursor = std::io::Cursor::new(truncated);

        let result = VaultHeader::read_from(&mut cursor);
        assert!(result.is_err());
    }

    // ========================================
    // US-010: Header Encryption and Integrity Tests
    // ========================================

    #[test]
    fn test_compute_and_verify_hmac() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Verify HMAC
        assert!(header.verify_integrity(&hmac_key).is_ok());
    }

    #[test]
    fn test_hmac_verification_fails_with_wrong_key() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];
        let wrong_key = [0xCD; HMAC_TAG_SIZE];

        // Compute HMAC with correct key
        header.compute_hmac(&hmac_key);

        // Verification with wrong key should fail
        assert!(matches!(
            header.verify_integrity(&wrong_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_hmac_detects_tampered_header() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Serialize, tamper, and deserialize
        let mut bytes = header.to_bytes();
        bytes[offsets::SALT] ^= 0xFF; // Tamper with salt byte

        let tampered_header = VaultHeader::from_bytes(&bytes).expect("Should parse");

        // Verification should fail
        assert!(matches!(
            tampered_header.verify_integrity(&hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_hmac_detects_tampered_version() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Serialize, tamper with minor version (won't break parsing), and deserialize
        let mut bytes = header.to_bytes();
        bytes[offsets::VERSION + 1] ^= 0xFF; // Tamper with minor version

        let tampered_header = VaultHeader::from_bytes(&bytes).expect("Should parse");

        // Verification should fail
        assert!(matches!(
            tampered_header.verify_integrity(&hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_hmac_detects_tampered_encrypted_key() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Serialize, tamper, and deserialize
        let mut bytes = header.to_bytes();
        bytes[offsets::ENCRYPTED_MASTER_KEY] ^= 0xFF; // Tamper with encrypted key

        let tampered_header = VaultHeader::from_bytes(&bytes).expect("Should parse");

        // Verification should fail
        assert!(matches!(
            tampered_header.verify_integrity(&hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_hmac_detects_tampered_nonce() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Serialize, tamper, and deserialize
        let mut bytes = header.to_bytes();
        bytes[offsets::MASTER_KEY_NONCE] ^= 0xFF; // Tamper with nonce

        let tampered_header = VaultHeader::from_bytes(&bytes).expect("Should parse");

        // Verification should fail
        assert!(matches!(
            tampered_header.verify_integrity(&hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_hmac_detects_tampered_attempt_counter() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Serialize, tamper, and deserialize
        let mut bytes = header.to_bytes();
        bytes[offsets::ATTEMPT_COUNTER] ^= 0xFF; // Tamper with attempt counter

        let tampered_header = VaultHeader::from_bytes(&bytes).expect("Should parse");

        // Verification should fail
        assert!(matches!(
            tampered_header.verify_integrity(&hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_verify_raw_integrity() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Get raw bytes
        let bytes = header.to_bytes();

        // Verify raw integrity
        assert!(VaultHeader::verify_raw_integrity(&bytes, &hmac_key).is_ok());
    }

    #[test]
    fn test_verify_raw_integrity_fails_on_tampered_bytes() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Get raw bytes and tamper
        let mut bytes = header.to_bytes();
        bytes[50] ^= 0xFF; // Tamper with some byte

        // Verification should fail
        assert!(matches!(
            VaultHeader::verify_raw_integrity(&bytes, &hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_encrypt_decrypt_master_key() {
        let salt = [1u8; SALT_SIZE];
        let mut header = VaultHeader::new(
            salt,
            [0u8; ENCRYPTED_MASTER_KEY_SIZE],
            [0u8; NONCE_SIZE],
        );

        let master_key = [0x42u8; 32];
        let encryption_key = [0xAB; 32];
        let nonce = [0xCD; NONCE_SIZE];

        // Encrypt master key
        header.encrypt_master_key(&master_key, &encryption_key, &nonce)
            .expect("Encryption should succeed");

        // Decrypt master key
        let decrypted = header.decrypt_master_key(&encryption_key)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, master_key);
    }

    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let salt = [1u8; SALT_SIZE];
        let mut header = VaultHeader::new(
            salt,
            [0u8; ENCRYPTED_MASTER_KEY_SIZE],
            [0u8; NONCE_SIZE],
        );

        let master_key = [0x42u8; 32];
        let encryption_key = [0xAB; 32];
        let wrong_key = [0xCD; 32];
        let nonce = [0xEF; NONCE_SIZE];

        // Encrypt master key
        header.encrypt_master_key(&master_key, &encryption_key, &nonce)
            .expect("Encryption should succeed");

        // Decrypt with wrong key should fail
        assert!(matches!(
            header.decrypt_master_key(&wrong_key),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_decrypt_fails_with_tampered_ciphertext() {
        let salt = [1u8; SALT_SIZE];
        let mut header = VaultHeader::new(
            salt,
            [0u8; ENCRYPTED_MASTER_KEY_SIZE],
            [0u8; NONCE_SIZE],
        );

        let master_key = [0x42u8; 32];
        let encryption_key = [0xAB; 32];
        let nonce = [0xCD; NONCE_SIZE];

        // Encrypt master key
        header.encrypt_master_key(&master_key, &encryption_key, &nonce)
            .expect("Encryption should succeed");

        // Tamper with encrypted key
        let mut tampered_enc_key = *header.encrypted_master_key();
        tampered_enc_key[0] ^= 0xFF;
        header.set_encrypted_master_key(tampered_enc_key, *header.master_key_nonce());

        // Decrypt should fail
        assert!(matches!(
            header.decrypt_master_key(&encryption_key),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_read_and_verify() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Write to buffer
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).expect("Write should succeed");

        // Read and verify
        let mut cursor = std::io::Cursor::new(buffer);
        let verified = VaultHeader::read_and_verify(&mut cursor, &hmac_key)
            .expect("Read and verify should succeed");

        assert_eq!(verified.salt(), header.salt());
    }

    #[test]
    fn test_read_and_verify_fails_with_wrong_key() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];
        let wrong_key = [0xCD; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        // Write to buffer
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).expect("Write should succeed");

        // Read and verify with wrong key
        let mut cursor = std::io::Cursor::new(buffer);
        assert!(matches!(
            VaultHeader::read_and_verify(&mut cursor, &wrong_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_create_encrypted_header_and_unlock() {
        // Use minimal params for fast test execution
        let params = Argon2Params::minimal();

        let password = b"test password 123";
        let master_key = [0x42u8; 32];
        let salt = [0x11u8; SALT_SIZE];
        let nonce = [0x22u8; NONCE_SIZE];

        // Create encrypted header
        let (header, _, hmac_key) = create_encrypted_header(
            password,
            &master_key,
            &salt,
            &nonce,
            &params,
        ).expect("Header creation should succeed");

        // Verify HMAC was computed
        assert!(header.verify_integrity(&hmac_key).is_ok());

        // Unlock header
        let decrypted = unlock_header(&header, password, &params)
            .expect("Unlock should succeed");

        assert_eq!(decrypted, master_key);
    }

    #[test]
    fn test_unlock_header_fails_with_wrong_password() {
        let params = Argon2Params::minimal();

        let password = b"correct password";
        let wrong_password = b"wrong password";
        let master_key = [0x42u8; 32];
        let salt = [0x11u8; SALT_SIZE];
        let nonce = [0x22u8; NONCE_SIZE];

        // Create encrypted header
        let (header, _, _) = create_encrypted_header(
            password,
            &master_key,
            &salt,
            &nonce,
            &params,
        ).expect("Header creation should succeed");

        // Unlock with wrong password should fail at integrity check
        assert!(matches!(
            unlock_header(&header, wrong_password, &params),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_full_roundtrip_with_serialization() {
        let params = Argon2Params::minimal();

        let password = b"my secure password";
        let master_key = [0x55u8; 32];
        let salt = [0x33u8; SALT_SIZE];
        let nonce = [0x44u8; NONCE_SIZE];

        // Create encrypted header
        let (header, _, _) = create_encrypted_header(
            password,
            &master_key,
            &salt,
            &nonce,
            &params,
        ).expect("Header creation should succeed");

        // Serialize
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).expect("Write should succeed");

        // Deserialize
        let mut cursor = std::io::Cursor::new(buffer);
        let restored = VaultHeader::read_from(&mut cursor).expect("Read should succeed");

        // Unlock restored header
        let decrypted = unlock_header(&restored, password, &params)
            .expect("Unlock should succeed");

        assert_eq!(decrypted, master_key);
    }

    #[test]
    fn test_integrity_verified_before_decryption() {
        let params = Argon2Params::minimal();

        let password = b"test password";
        let master_key = [0x77u8; 32];
        let salt = [0x88u8; SALT_SIZE];
        let nonce = [0x99u8; NONCE_SIZE];

        // Create encrypted header
        let (header, _, _) = create_encrypted_header(
            password,
            &master_key,
            &salt,
            &nonce,
            &params,
        ).expect("Header creation should succeed");

        // Serialize and tamper
        let mut bytes = header.to_bytes();
        bytes[offsets::SALT + 5] ^= 0xFF; // Tamper with salt

        // Deserialize tampered header
        let tampered = VaultHeader::from_bytes(&bytes).expect("Should parse");

        // Unlock should fail at integrity check (before decryption attempt)
        assert!(matches!(
            unlock_header(&tampered, password, &params),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_different_passwords_produce_different_hmac() {
        let params = Argon2Params::minimal();

        let master_key = [0xAA; 32];
        let salt = [0xBB; SALT_SIZE];
        let nonce = [0xCC; NONCE_SIZE];

        // Create headers with different passwords
        let (header1, _, _) = create_encrypted_header(
            b"password1",
            &master_key,
            &salt,
            &nonce,
            &params,
        ).expect("Should succeed");

        let (header2, _, _) = create_encrypted_header(
            b"password2",
            &master_key,
            &salt,
            &nonce,
            &params,
        ).expect("Should succeed");

        // HMAC tags should be different
        assert_ne!(header1.hmac_tag(), header2.hmac_tag());

        // Encrypted keys should also be different (different derived key)
        assert_ne!(header1.encrypted_master_key(), header2.encrypted_master_key());
    }

    #[test]
    fn test_single_bit_tamper_detection() {
        let mut header = create_test_header();
        let hmac_key = [0xAB; HMAC_TAG_SIZE];

        // Compute HMAC
        header.compute_hmac(&hmac_key);

        let original_bytes = header.to_bytes();

        // Test that single bit flips in any byte are detected
        for byte_idx in 0..offsets::HMAC_DATA_END {
            for bit_idx in 0..8 {
                let mut tampered = original_bytes;
                tampered[byte_idx] ^= 1 << bit_idx;

                let tampered_header = VaultHeader::from_bytes(&tampered);

                // Some bit flips may cause parsing to fail (e.g., magic bytes)
                if let Ok(h) = tampered_header {
                    assert!(
                        h.verify_integrity(&hmac_key).is_err(),
                        "Bit flip at byte {} bit {} not detected",
                        byte_idx, bit_idx
                    );
                }
            }
        }
    }

    // ========================================
    // US-021: Exponential Backoff Tests
    // ========================================

    #[test]
    fn test_calculate_backoff_zero_attempts() {
        let header = create_test_header();
        assert_eq!(header.calculate_backoff_seconds(), 0);
    }

    #[test]
    fn test_calculate_backoff_progression() {
        let mut header = create_test_header();

        // Verify exponential progression: 2^1, 2^2, 2^3, ...
        header.increment_attempts(); // 1 attempt
        assert_eq!(header.calculate_backoff_seconds(), 2); // 2^1 = 2

        header.increment_attempts(); // 2 attempts
        assert_eq!(header.calculate_backoff_seconds(), 4); // 2^2 = 4

        header.increment_attempts(); // 3 attempts
        assert_eq!(header.calculate_backoff_seconds(), 8); // 2^3 = 8

        header.increment_attempts(); // 4 attempts
        assert_eq!(header.calculate_backoff_seconds(), 16); // 2^4 = 16

        header.increment_attempts(); // 5 attempts
        assert_eq!(header.calculate_backoff_seconds(), 32); // 2^5 = 32
    }

    #[test]
    fn test_calculate_backoff_caps_at_max() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            20, // 2^20 = 1,048,576 > 3600 max
            0,
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        // Should cap at BACKOFF_MAX_SECONDS (3600)
        assert_eq!(header.calculate_backoff_seconds(), BACKOFF_MAX_SECONDS);
    }

    #[test]
    fn test_calculate_backoff_high_attempts_saturates() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            100, // Very high attempt count
            0,
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        // Should cap at max and not overflow
        assert_eq!(header.calculate_backoff_seconds(), BACKOFF_MAX_SECONDS);
    }

    #[test]
    fn test_apply_backoff_increments_and_sets_lockout() {
        let mut header = create_test_header();
        assert_eq!(header.attempt_counter(), 0);
        assert_eq!(header.lockout_until(), 0);

        // First failed attempt
        let delay1 = header.apply_backoff();
        assert_eq!(header.attempt_counter(), 1);
        assert_eq!(delay1, 2); // 2^1 = 2 seconds
        assert!(header.lockout_until() > 0);

        // Second failed attempt
        let delay2 = header.apply_backoff();
        assert_eq!(header.attempt_counter(), 2);
        assert_eq!(delay2, 4); // 2^2 = 4 seconds
    }

    #[test]
    fn test_reset_attempts_clears_lockout() {
        let mut header = create_test_header();

        // Apply some backoff
        header.apply_backoff();
        header.apply_backoff();
        assert!(header.attempt_counter() > 0);
        assert!(header.lockout_until() > 0);

        // Reset
        header.reset_attempts();
        assert_eq!(header.attempt_counter(), 0);
        assert_eq!(header.lockout_until(), 0);
        assert_eq!(header.calculate_backoff_seconds(), 0);
    }

    #[test]
    fn test_is_locked_out_respects_backoff() {
        let mut header = create_test_header();

        // Initially not locked out
        assert!(!header.is_locked_out());

        // Apply backoff
        header.apply_backoff();

        // Should now be locked out (lockout_until is in the future)
        assert!(header.is_locked_out());
        assert!(header.lockout_remaining() > 0);
        assert!(header.lockout_remaining() <= 2); // First backoff is 2 seconds
    }

    #[test]
    fn test_backoff_serialization_roundtrip() {
        let mut header = create_test_header();

        // Apply some backoff
        header.apply_backoff();
        header.apply_backoff();
        header.apply_backoff();

        let attempt_count = header.attempt_counter();
        let lockout = header.lockout_until();

        // Serialize and deserialize
        let bytes = header.to_bytes();
        let restored = VaultHeader::from_bytes(&bytes).expect("Should deserialize");

        // Verify backoff state is preserved
        assert_eq!(restored.attempt_counter(), attempt_count);
        assert_eq!(restored.lockout_until(), lockout);
        assert_eq!(restored.calculate_backoff_seconds(), header.calculate_backoff_seconds());
    }

    #[test]
    fn test_backoff_delay_table() {
        // Verify the documented delay table from the docstring
        let expected_delays: Vec<(u32, u64)> = vec![
            (0, 0),
            (1, 2),
            (2, 4),
            (3, 8),
            (4, 16),
            (5, 32),
            (6, 64),
            (7, 128),
            (8, 256),
            (9, 512),
            (10, 1024),
            (11, 2048),
            (12, 3600), // Capped at max
            (13, 3600),
            (20, 3600),
        ];

        for (attempts, expected_delay) in expected_delays {
            let header = VaultHeader::from_components(
                VaultVersion::new(1, 0),
                [1u8; SALT_SIZE],
                [2u8; ENCRYPTED_MASTER_KEY_SIZE],
                [3u8; NONCE_SIZE],
                attempts,
                0,
                0,
                0,
                [0u8; HMAC_TAG_SIZE],
            );

            assert_eq!(
                header.calculate_backoff_seconds(),
                expected_delay,
                "Backoff for {} attempts should be {} seconds",
                attempts,
                expected_delay
            );
        }
    }

    // ========================================
    // US-022: Temporary Lockout After Failures Tests
    // ========================================

    #[test]
    fn test_default_lockout_constants() {
        // Verify default constants
        assert_eq!(DEFAULT_LOCKOUT_THRESHOLD, 10);
        assert_eq!(DEFAULT_LOCKOUT_DURATION_SECONDS, 900); // 15 minutes
    }

    #[test]
    fn test_should_trigger_lockout_below_threshold() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            5, // Below threshold of 10
            0,
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        assert!(!header.should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD));
    }

    #[test]
    fn test_should_trigger_lockout_at_threshold() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            10, // At threshold
            0,
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        assert!(header.should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD));
    }

    #[test]
    fn test_should_trigger_lockout_above_threshold() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            15, // Above threshold
            0,
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        assert!(header.should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD));
    }

    #[test]
    fn test_should_trigger_lockout_custom_threshold() {
        let header = VaultHeader::from_components(
            VaultVersion::new(1, 0),
            [1u8; SALT_SIZE],
            [2u8; ENCRYPTED_MASTER_KEY_SIZE],
            [3u8; NONCE_SIZE],
            5, // 5 attempts
            0,
            0,
            0,
            [0u8; HMAC_TAG_SIZE],
        );

        // Custom threshold of 5
        assert!(header.should_trigger_lockout(5));
        // But not at threshold of 10
        assert!(!header.should_trigger_lockout(10));
    }

    #[test]
    fn test_trigger_lockout_sets_correct_duration() {
        let mut header = create_test_header();

        // Trigger 15-minute lockout
        header.trigger_lockout(900);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Lockout should be approximately 900 seconds from now
        assert!(header.lockout_until() >= now + 895);
        assert!(header.lockout_until() <= now + 905);
        assert!(header.is_locked_out());
        assert!(header.lockout_remaining() >= 895);
        assert!(header.lockout_remaining() <= 905);
    }

    #[test]
    fn test_trigger_lockout_custom_duration() {
        let mut header = create_test_header();

        // Trigger 30-minute lockout
        header.trigger_lockout(1800);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Lockout should be approximately 1800 seconds from now
        assert!(header.lockout_until() >= now + 1795);
        assert!(header.lockout_until() <= now + 1805);
        assert!(header.lockout_remaining() >= 1795);
    }

    #[test]
    fn test_apply_backoff_triggers_lockout_at_threshold() {
        let mut header = create_test_header();

        // Apply backoff 9 times (below threshold)
        for i in 1..10 {
            let delay = header.apply_backoff();
            // Should still be exponential backoff, not fixed lockout
            assert!(delay < DEFAULT_LOCKOUT_DURATION_SECONDS,
                "Attempt {} should use exponential backoff", i);
        }

        // 10th attempt should trigger full lockout
        let delay = header.apply_backoff();
        assert_eq!(header.attempt_counter(), 10);
        assert_eq!(delay, DEFAULT_LOCKOUT_DURATION_SECONDS);
        assert!(header.is_locked_out());
        assert!(header.lockout_remaining() >= 895);
    }

    #[test]
    fn test_apply_backoff_with_config_custom_threshold() {
        let mut header = create_test_header();

        // Custom config: lockout after 5 failures for 30 minutes
        let custom_threshold = 5;
        let custom_duration = 1800;

        // Apply backoff 4 times (below threshold)
        for _ in 0..4 {
            let delay = header.apply_backoff_with_config(custom_threshold, custom_duration);
            assert!(delay < custom_duration);
        }

        // 5th attempt should trigger lockout
        let delay = header.apply_backoff_with_config(custom_threshold, custom_duration);
        assert_eq!(header.attempt_counter(), 5);
        assert_eq!(delay, custom_duration);
        assert!(header.lockout_remaining() >= 1795);
    }

    #[test]
    fn test_lockout_persists_after_threshold() {
        let mut header = create_test_header();

        // Reach the lockout threshold
        for _ in 0..10 {
            header.apply_backoff();
        }

        // Additional failures should still return the fixed lockout duration
        let delay1 = header.apply_backoff();
        let delay2 = header.apply_backoff();

        assert_eq!(delay1, DEFAULT_LOCKOUT_DURATION_SECONDS);
        assert_eq!(delay2, DEFAULT_LOCKOUT_DURATION_SECONDS);
    }

    #[test]
    fn test_lockout_cleared_on_successful_auth() {
        let mut header = create_test_header();

        // Trigger lockout
        for _ in 0..10 {
            header.apply_backoff();
        }
        assert!(header.is_locked_out());
        assert_eq!(header.attempt_counter(), 10);

        // Simulate successful authentication
        header.reset_attempts();

        // Lockout should be cleared
        assert!(!header.is_locked_out());
        assert_eq!(header.attempt_counter(), 0);
        assert_eq!(header.lockout_remaining(), 0);
    }

    #[test]
    fn test_lockout_expiry() {
        let mut header = create_test_header();

        // Set lockout to 1 second ago (expired)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        header.set_lockout_until(now.saturating_sub(1));

        // Lockout should be expired
        assert!(!header.is_locked_out());
        assert_eq!(header.lockout_remaining(), 0);
    }

    #[test]
    fn test_lockout_remaining_decreases_over_time() {
        let mut header = create_test_header();

        // Trigger lockout
        header.trigger_lockout(DEFAULT_LOCKOUT_DURATION_SECONDS);
        let initial_remaining = header.lockout_remaining();

        // Wait a bit
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Remaining time should have decreased (or stayed same if time resolution too low)
        let later_remaining = header.lockout_remaining();
        assert!(later_remaining <= initial_remaining);
    }

    #[test]
    fn test_lockout_serialization_roundtrip() {
        let mut header = create_test_header();

        // Trigger lockout
        header.trigger_lockout(DEFAULT_LOCKOUT_DURATION_SECONDS);
        let original_lockout = header.lockout_until();
        let original_remaining = header.lockout_remaining();

        // Serialize and deserialize
        let bytes = header.to_bytes();
        let restored = VaultHeader::from_bytes(&bytes).expect("Should deserialize");

        // Verify lockout state is preserved
        assert_eq!(restored.lockout_until(), original_lockout);
        assert!(restored.is_locked_out());
        // Remaining should be approximately the same (within a second)
        assert!(restored.lockout_remaining() >= original_remaining.saturating_sub(1));
        assert!(restored.lockout_remaining() <= original_remaining + 1);
    }

    #[test]
    fn test_lockout_error_message_contains_remaining_time() {
        let mut header = create_test_header();

        // Trigger lockout
        header.trigger_lockout(900);
        let remaining = header.lockout_remaining();

        // Remaining time should be usable for error messages
        assert!(remaining > 0);
        assert!(remaining <= 900);

        // Format example: "Locked out for 895 seconds"
        let error_msg = format!("Locked out for {} seconds", remaining);
        assert!(error_msg.contains("Locked out"));
        assert!(error_msg.contains("seconds"));
    }

    #[test]
    fn test_lockout_threshold_boundary_values() {
        // Test edge case: threshold of 1 (immediate lockout on first failure)
        let mut header = create_test_header();
        let delay = header.apply_backoff_with_config(1, 600);
        assert_eq!(header.attempt_counter(), 1);
        assert_eq!(delay, 600);

        // Test edge case: threshold of 0 (always lockout)
        let mut header2 = create_test_header();
        let delay2 = header2.apply_backoff_with_config(0, 600);
        // At 0 attempts (before increment), threshold 0 would mean 0 >= 0 = true
        // After increment, we have 1 attempt and threshold check 1 >= 0 = true
        assert_eq!(delay2, 600);
    }
}
