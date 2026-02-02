//! Access level management.
//!
//! Provides multi-level access control with hierarchical visibility for TESSERACT vaults.
//! Each access level has its own password, keystore, and configurable properties.
//!
//! # Access Level Structure
//!
//! Each level contains:
//! - **id**: Unique numeric identifier (1-10)
//! - **name**: Human-readable name (e.g., "Confidential", "Secret", "Top Secret")
//! - **password_hash**: Argon2id hash of the level password for verification
//! - **keystore**: Reference to the L{n}.keys.enc file
//!
//! # Configuration
//!
//! - Minimum 3 levels required (MIN_LEVEL_COUNT)
//! - Maximum 10 levels supported (MAX_LEVEL_COUNT)
//! - Default configuration creates 3 levels with standard names
//!
//! # Encrypted Storage
//!
//! Level configuration is stored encrypted in `.levels/levels.enc` within the vault:
//! - Encrypted with AES-256-GCM using master key
//! - HMAC-SHA256 integrity tag
//! - Includes all level metadata except the keystore contents
//!
//! # Security
//!
//! - Password hashes stored using Argon2id with configurable parameters
//! - Level configuration encrypted at rest
//! - Empty levels can be deleted; levels with files cannot

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::VaultError;

/// Custom serialization module for Option<[u8; ENCRYPTED_KEK_SIZE]>.
/// Serde doesn't support arrays > 32 elements by default.
mod option_encrypted_kek {
    use super::ENCRYPTED_KEK_SIZE;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; ENCRYPTED_KEK_SIZE]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&bytes.to_vec()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; ENCRYPTED_KEK_SIZE]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            Some(vec) => {
                if vec.len() != ENCRYPTED_KEK_SIZE {
                    return Err(serde::de::Error::invalid_length(
                        vec.len(),
                        &"60 bytes for encrypted KEK",
                    ));
                }
                let mut arr = [0u8; ENCRYPTED_KEK_SIZE];
                arr.copy_from_slice(&vec);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}
use crate::keystore::{create_keystore, Keystore};
use crate::vault::{keystore_path, list_keystores, MAX_LEVEL_COUNT, MIN_LEVEL_COUNT};
use tesseract_crypto::{
    aes::{decrypt, encrypt},
    generate_nonce, generate_salt,
    kdf::{derive_key, Argon2Params},
};

/// Directory name for level configuration storage.
pub const LEVELS_DIR: &str = ".levels";

/// Filename for encrypted level configuration.
pub const LEVELS_CONFIG_FILE: &str = "levels.enc";

/// Default names for access levels.
pub const DEFAULT_LEVEL_NAMES: [&str; 10] = [
    "Public",
    "Internal",
    "Confidential",
    "Restricted",
    "Secret",
    "Top Secret",
    "Compartmented",
    "Special Access",
    "Critical",
    "Maximum",
];

/// Minimum metadata size for level config (nonce + some ciphertext + tag).
pub const MIN_LEVELS_CONFIG_SIZE: usize = 12 + 1 + 16;

/// Size of the encrypted KEK blob (nonce + ciphertext + tag = 12 + 32 + 16 = 60 bytes).
pub const ENCRYPTED_KEK_SIZE: usize = 60;

/// An individual access level definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLevel {
    /// Unique identifier for this level (1-based).
    id: u32,
    /// Human-readable name for this level.
    name: String,
    /// Argon2id hash of the level password (32 bytes).
    /// Used to verify password before attempting keystore decryption.
    password_hash: [u8; 32],
    /// Salt used for password hashing.
    password_salt: [u8; 16],
    /// Whether this level is enabled (can be temporarily disabled).
    enabled: bool,
    /// Optional description for this level.
    description: Option<String>,
    /// Creation timestamp (Unix epoch seconds).
    created_at: u64,
    /// Last modification timestamp (Unix epoch seconds).
    modified_at: u64,
    /// The KEK encrypted with the master key (for recovery purposes).
    /// Format: [nonce:12][ciphertext:32][tag:16] = 60 bytes.
    /// This allows recovery sessions to decrypt the KEK without knowing the password.
    #[serde(with = "option_encrypted_kek", default)]
    encrypted_kek: Option<[u8; ENCRYPTED_KEK_SIZE]>,
}

impl AccessLevel {
    /// Creates a new access level with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique level identifier (1-10)
    /// * `name` - Human-readable level name
    /// * `password` - Password for this level
    /// * `argon2_params` - Parameters for password hashing
    ///
    /// # Errors
    ///
    /// Returns error if id is out of valid range or password hashing fails.
    pub fn new(
        id: u32,
        name: impl Into<String>,
        password: &[u8],
        argon2_params: &Argon2Params,
    ) -> Result<Self, VaultError> {
        if id < 1 || id > MAX_LEVEL_COUNT {
            return Err(VaultError::InvalidFormat(format!(
                "Level ID must be between 1 and {}, got {}",
                MAX_LEVEL_COUNT, id
            )));
        }

        let name = name.into();
        if name.is_empty() {
            return Err(VaultError::InvalidFormat(
                "Level name cannot be empty".to_string(),
            ));
        }

        // Generate salt and hash password
        let password_salt: [u8; 16] = generate_salt()?;
        let password_hash = derive_key(password, &password_salt, argon2_params)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            id,
            name,
            password_hash,
            password_salt,
            enabled: true,
            description: None,
            created_at: now,
            modified_at: now,
            encrypted_kek: None,
        })
    }

    /// Creates an access level with a specific timestamp (for testing).
    #[cfg(test)]
    pub fn new_with_timestamp(
        id: u32,
        name: impl Into<String>,
        password: &[u8],
        argon2_params: &Argon2Params,
        timestamp: u64,
    ) -> Result<Self, VaultError> {
        let mut level = Self::new(id, name, password, argon2_params)?;
        level.created_at = timestamp;
        level.modified_at = timestamp;
        Ok(level)
    }

    /// Returns the level ID.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the level name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the level is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the level description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the modification timestamp.
    #[must_use]
    pub fn modified_at(&self) -> u64 {
        self.modified_at
    }

    /// Returns the password salt.
    #[must_use]
    pub fn password_salt(&self) -> &[u8; 16] {
        &self.password_salt
    }

    /// Sets the level name.
    pub fn set_name(&mut self, name: impl Into<String>) -> Result<(), VaultError> {
        let name = name.into();
        if name.is_empty() {
            return Err(VaultError::InvalidFormat(
                "Level name cannot be empty".to_string(),
            ));
        }
        self.name = name;
        self.touch();
        Ok(())
    }

    /// Sets the level description.
    pub fn set_description(&mut self, description: Option<String>) {
        self.description = description;
        self.touch();
    }

    /// Enables or disables the level.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.touch();
    }

    /// Updates the modification timestamp to now.
    fn touch(&mut self) {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Verifies if the provided password matches this level's password.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_password(
        &self,
        password: &[u8],
        argon2_params: &Argon2Params,
    ) -> Result<bool, VaultError> {
        let hash = derive_key(password, &self.password_salt, argon2_params)?;

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in self.password_hash.iter().zip(hash.iter()) {
            diff |= a ^ b;
        }

        Ok(diff == 0)
    }

    /// Changes the password for this level.
    ///
    /// # Arguments
    ///
    /// * `old_password` - Current password (for verification)
    /// * `new_password` - New password to set
    /// * `argon2_params` - Parameters for password hashing
    ///
    /// # Errors
    ///
    /// Returns error if old password is incorrect or hashing fails.
    pub fn change_password(
        &mut self,
        old_password: &[u8],
        new_password: &[u8],
        argon2_params: &Argon2Params,
    ) -> Result<(), VaultError> {
        // Verify old password
        if !self.verify_password(old_password, argon2_params)? {
            return Err(VaultError::AuthenticationFailed);
        }

        // Generate new salt and hash
        self.password_salt = generate_salt()?;
        self.password_hash = derive_key(new_password, &self.password_salt, argon2_params)?;
        self.touch();

        Ok(())
    }

    /// Sets the password hash directly (for recovery).
    ///
    /// This method bypasses password verification and directly sets a new
    /// password hash. It is intended for use during recovery operations
    /// when the old password is unknown.
    ///
    /// # Arguments
    ///
    /// * `new_password` - The new password to set
    /// * `argon2_params` - Parameters for password hashing
    ///
    /// # Errors
    ///
    /// Returns error if password hashing fails.
    pub fn set_password_hash(
        &mut self,
        new_password: &[u8],
        argon2_params: &Argon2Params,
    ) -> Result<(), VaultError> {
        // Generate new salt and hash
        self.password_salt = generate_salt()?;
        self.password_hash = derive_key(new_password, &self.password_salt, argon2_params)?;
        self.touch();

        Ok(())
    }

    /// Sets the encrypted KEK for this level.
    ///
    /// The encrypted KEK is stored as part of the level config and allows
    /// recovery sessions to decrypt the KEK without knowing the password.
    ///
    /// # Arguments
    ///
    /// * `kek` - The 32-byte Key Encryption Key to encrypt
    /// * `master_key` - The 32-byte master key to encrypt with
    ///
    /// # Errors
    ///
    /// Returns error if encryption fails.
    pub fn set_encrypted_kek(
        &mut self,
        kek: &[u8; 32],
        master_key: &[u8; 32],
    ) -> Result<(), VaultError> {
        let nonce: [u8; 12] = generate_nonce()?;

        // AAD includes level ID to bind the encryption to this level
        let aad = self.id.to_le_bytes();

        let ciphertext = encrypt(master_key, &nonce, kek, &aad)?;

        // Build encrypted blob: [nonce:12][ciphertext+tag:48]
        // Wait, the ciphertext includes the tag already, so it's 32 + 16 = 48
        // Total: 12 + 48 = 60 bytes
        let mut encrypted_kek = [0u8; ENCRYPTED_KEK_SIZE];
        encrypted_kek[..12].copy_from_slice(&nonce);
        encrypted_kek[12..].copy_from_slice(&ciphertext);

        self.encrypted_kek = Some(encrypted_kek);
        self.touch();

        Ok(())
    }

    /// Returns the encrypted KEK if present.
    #[must_use]
    pub fn encrypted_kek(&self) -> Option<&[u8; ENCRYPTED_KEK_SIZE]> {
        self.encrypted_kek.as_ref()
    }

    /// Decrypts the KEK using the master key.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The 32-byte master key to decrypt with
    ///
    /// # Returns
    ///
    /// The decrypted 32-byte KEK.
    ///
    /// # Errors
    ///
    /// * `VaultError::InvalidFormat` - No encrypted KEK present
    /// * `VaultError::CryptoError` - Decryption failed (wrong key or corrupted data)
    pub fn decrypt_kek(&self, master_key: &[u8; 32]) -> Result<[u8; 32], VaultError> {
        let encrypted_kek = self.encrypted_kek.as_ref().ok_or_else(|| {
            VaultError::InvalidFormat(
                "No encrypted KEK present for this level (vault may predate recovery support)"
                    .to_string(),
            )
        })?;

        let nonce: [u8; 12] = encrypted_kek[..12].try_into().unwrap();
        let ciphertext = &encrypted_kek[12..];

        // AAD includes level ID to verify binding
        let aad = self.id.to_le_bytes();

        let plaintext = decrypt(master_key, &nonce, ciphertext, &aad)?;

        if plaintext.len() != 32 {
            return Err(VaultError::InvalidFormat(format!(
                "Decrypted KEK has wrong size: expected 32, got {}",
                plaintext.len()
            )));
        }

        let mut kek = [0u8; 32];
        kek.copy_from_slice(&plaintext);
        Ok(kek)
    }

    /// Returns whether this level has an encrypted KEK stored.
    ///
    /// Levels created before recovery support was added may not have
    /// an encrypted KEK.
    #[must_use]
    pub fn has_encrypted_kek(&self) -> bool {
        self.encrypted_kek.is_some()
    }
}

/// Configuration for all access levels in a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelConfig {
    /// Version of the level configuration format.
    version: LevelConfigVersion,
    /// Map of level ID to access level.
    levels: HashMap<u32, AccessLevel>,
    /// Argon2 parameters used for password hashing.
    argon2_params: Argon2Params,
}

/// Version for level configuration format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelConfigVersion {
    /// Major version (breaking changes).
    pub major: u8,
    /// Minor version (backwards-compatible changes).
    pub minor: u8,
}

impl LevelConfigVersion {
    /// Current version.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Creates a new version.
    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Checks compatibility.
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl Default for LevelConfigVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl LevelConfig {
    /// Creates a new empty level configuration.
    #[must_use]
    pub fn new(argon2_params: Argon2Params) -> Self {
        Self {
            version: LevelConfigVersion::CURRENT,
            levels: HashMap::new(),
            argon2_params,
        }
    }

    /// Creates a default level configuration with the specified number of levels.
    ///
    /// All levels will use the same password initially.
    pub fn with_default_levels(
        level_count: u32,
        password: &[u8],
        argon2_params: Argon2Params,
    ) -> Result<Self, VaultError> {
        if level_count < MIN_LEVEL_COUNT || level_count > MAX_LEVEL_COUNT {
            return Err(VaultError::InvalidFormat(format!(
                "Level count must be between {} and {}, got {}",
                MIN_LEVEL_COUNT, MAX_LEVEL_COUNT, level_count
            )));
        }

        let mut config = Self::new(argon2_params.clone());

        for id in 1..=level_count {
            let name = DEFAULT_LEVEL_NAMES
                .get(id as usize - 1)
                .unwrap_or(&"Level")
                .to_string();

            let level = AccessLevel::new(id, name, password, &argon2_params)?;
            config.levels.insert(id, level);
        }

        Ok(config)
    }

    /// Stores encrypted KEKs for all levels.
    ///
    /// This method encrypts each level's KEK with the master key and stores
    /// it in the corresponding `AccessLevel`. This enables recovery sessions
    /// to decrypt the KEK without knowing the level password.
    ///
    /// # Arguments
    ///
    /// * `keks` - A slice of (level_id, kek) pairs to encrypt
    /// * `master_key` - The 32-byte master key to encrypt with
    ///
    /// # Errors
    ///
    /// Returns error if encryption fails.
    pub fn store_encrypted_keks(
        &mut self,
        keks: &[(u32, [u8; 32])],
        master_key: &[u8; 32],
    ) -> Result<(), VaultError> {
        for (level_id, kek) in keks {
            if let Some(level) = self.levels.get_mut(level_id) {
                level.set_encrypted_kek(kek, master_key)?;
            }
        }
        Ok(())
    }

    /// Returns the number of levels.
    #[must_use]
    pub fn level_count(&self) -> usize {
        self.levels.len()
    }

    /// Returns whether a level exists.
    #[must_use]
    pub fn has_level(&self, id: u32) -> bool {
        self.levels.contains_key(&id)
    }

    /// Gets a level by ID.
    #[must_use]
    pub fn get_level(&self, id: u32) -> Option<&AccessLevel> {
        self.levels.get(&id)
    }

    /// Gets a mutable level by ID.
    pub fn get_level_mut(&mut self, id: u32) -> Option<&mut AccessLevel> {
        self.levels.get_mut(&id)
    }

    /// Returns all level IDs in sorted order.
    #[must_use]
    pub fn level_ids(&self) -> Vec<u32> {
        let mut ids: Vec<_> = self.levels.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Lists all levels in sorted order by ID.
    #[must_use]
    pub fn list_levels(&self) -> Vec<&AccessLevel> {
        let mut levels: Vec<_> = self.levels.values().collect();
        levels.sort_by_key(|l| l.id);
        levels
    }

    /// Returns the Argon2 parameters.
    #[must_use]
    pub fn argon2_params(&self) -> &Argon2Params {
        &self.argon2_params
    }

    /// Returns the configuration version.
    #[must_use]
    pub fn version(&self) -> LevelConfigVersion {
        self.version
    }

    /// Adds a new access level.
    ///
    /// # Arguments
    ///
    /// * `id` - Level ID (must not already exist)
    /// * `name` - Level name
    /// * `password` - Level password
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Level ID already exists
    /// - Level ID is out of valid range
    /// - Maximum level count would be exceeded
    pub fn create_level(
        &mut self,
        id: u32,
        name: impl Into<String>,
        password: &[u8],
    ) -> Result<&AccessLevel, VaultError> {
        if id < 1 || id > MAX_LEVEL_COUNT {
            return Err(VaultError::InvalidFormat(format!(
                "Level ID must be between 1 and {}, got {}",
                MAX_LEVEL_COUNT, id
            )));
        }

        if self.levels.contains_key(&id) {
            return Err(VaultError::InvalidFormat(format!(
                "Level {} already exists",
                id
            )));
        }

        if self.levels.len() >= MAX_LEVEL_COUNT as usize {
            return Err(VaultError::InvalidFormat(format!(
                "Maximum of {} levels already exist",
                MAX_LEVEL_COUNT
            )));
        }

        let level = AccessLevel::new(id, name, password, &self.argon2_params)?;
        self.levels.insert(id, level);

        Ok(self.levels.get(&id).unwrap())
    }

    /// Deletes an access level.
    ///
    /// # Arguments
    ///
    /// * `id` - Level ID to delete
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Level does not exist
    /// - Deletion would leave fewer than MIN_LEVEL_COUNT levels
    pub fn delete_level(&mut self, id: u32) -> Result<AccessLevel, VaultError> {
        if !self.levels.contains_key(&id) {
            return Err(VaultError::InvalidFormat(format!(
                "Level {} does not exist",
                id
            )));
        }

        if self.levels.len() <= MIN_LEVEL_COUNT as usize {
            return Err(VaultError::InvalidFormat(format!(
                "Cannot delete level: minimum of {} levels required",
                MIN_LEVEL_COUNT
            )));
        }

        Ok(self.levels.remove(&id).unwrap())
    }

    /// Serializes the configuration to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        bincode::serialize(self).map_err(|e| {
            VaultError::SerializationError(format!("Failed to serialize level config: {}", e))
        })
    }

    /// Deserializes configuration from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        let config: Self = bincode::deserialize(bytes).map_err(|e| {
            VaultError::SerializationError(format!("Failed to deserialize level config: {}", e))
        })?;

        // Version check
        if !config.version.is_compatible_with(&LevelConfigVersion::CURRENT) {
            return Err(VaultError::InvalidFormat(format!(
                "Incompatible level config version: {}.{}",
                config.version.major, config.version.minor
            )));
        }

        Ok(config)
    }
}

/// Returns the path to the levels directory.
#[must_use]
pub fn levels_dir(vault_path: &Path) -> PathBuf {
    vault_path.join(LEVELS_DIR)
}

/// Returns the path to the encrypted levels config file.
#[must_use]
pub fn levels_config_path(vault_path: &Path) -> PathBuf {
    levels_dir(vault_path).join(LEVELS_CONFIG_FILE)
}

/// Ensures the levels directory exists.
pub fn ensure_levels_dir(vault_path: &Path) -> Result<PathBuf, VaultError> {
    let dir = levels_dir(vault_path);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Writes encrypted level configuration to the vault.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault
/// * `config` - Level configuration to write
/// * `encryption_key` - AES-256 key for encryption
///
/// # Errors
///
/// Returns error if encryption or file I/O fails.
pub fn write_levels_config(
    vault_path: &Path,
    config: &LevelConfig,
    encryption_key: &[u8; 32],
) -> Result<(), VaultError> {
    ensure_levels_dir(vault_path)?;

    let plaintext = config.to_bytes()?;
    let nonce: [u8; 12] = generate_nonce()?;

    // Encrypt with vault path as AAD
    let aad = vault_path.to_string_lossy().as_bytes().to_vec();
    let ciphertext = encrypt(encryption_key, &nonce, &plaintext, &aad)?;

    // Write: [nonce:12][ciphertext+tag:*]
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    let config_path = levels_config_path(vault_path);
    let mut file = File::create(&config_path)?;
    file.write_all(&output)?;
    file.sync_all()?;

    Ok(())
}

/// Reads and decrypts level configuration from the vault.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault
/// * `encryption_key` - AES-256 key for decryption
///
/// # Errors
///
/// Returns error if decryption or file I/O fails.
pub fn read_levels_config(
    vault_path: &Path,
    encryption_key: &[u8; 32],
) -> Result<LevelConfig, VaultError> {
    let config_path = levels_config_path(vault_path);

    if !config_path.exists() {
        return Err(VaultError::FileNotFound(
            config_path.display().to_string(),
        ));
    }

    let mut file = File::open(&config_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < MIN_LEVELS_CONFIG_SIZE {
        return Err(VaultError::InvalidFormat(
            "Level config file too small".to_string(),
        ));
    }

    let nonce: [u8; 12] = data[0..12].try_into().unwrap();
    let ciphertext = &data[12..];

    // Decrypt with vault path as AAD
    let aad = vault_path.to_string_lossy().as_bytes().to_vec();
    let plaintext = decrypt(encryption_key, &nonce, ciphertext, &aad)?;

    LevelConfig::from_bytes(&plaintext)
}

/// Checks if level configuration exists in the vault.
#[must_use]
pub fn levels_config_exists(vault_path: &Path) -> bool {
    levels_config_path(vault_path).exists()
}

/// Summary information about a level (without sensitive data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelInfo {
    /// Level ID.
    pub id: u32,
    /// Level name.
    pub name: String,
    /// Whether level is enabled.
    pub enabled: bool,
    /// Optional description.
    pub description: Option<String>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Modification timestamp.
    pub modified_at: u64,
    /// Whether keystore file exists.
    pub has_keystore: bool,
}

impl From<&AccessLevel> for LevelInfo {
    fn from(level: &AccessLevel) -> Self {
        Self {
            id: level.id,
            name: level.name.clone(),
            enabled: level.enabled,
            description: level.description.clone(),
            created_at: level.created_at,
            modified_at: level.modified_at,
            has_keystore: false, // Set separately
        }
    }
}

/// Lists all levels with summary information.
///
/// This function combines level configuration with keystore existence checks.
pub fn list_levels_info(
    vault_path: &Path,
    encryption_key: &[u8; 32],
) -> Result<Vec<LevelInfo>, VaultError> {
    let config = read_levels_config(vault_path, encryption_key)?;
    let keystores = list_keystores(vault_path)?;
    let keystore_set: std::collections::HashSet<_> = keystores.into_iter().collect();

    let mut infos: Vec<LevelInfo> = config
        .list_levels()
        .into_iter()
        .map(|level| {
            let mut info = LevelInfo::from(level);
            info.has_keystore = keystore_set.contains(&level.id);
            info
        })
        .collect();

    infos.sort_by_key(|info| info.id);
    Ok(infos)
}

/// Creates a new access level in the vault.
///
/// This is a high-level function that:
/// 1. Reads existing level configuration
/// 2. Creates the new level entry
/// 3. Creates the corresponding keystore
/// 4. Writes updated configuration
///
/// # Arguments
///
/// * `vault_path` - Path to the vault
/// * `encryption_key` - Key for encrypting level config
/// * `level_id` - ID for the new level
/// * `level_name` - Name for the new level
/// * `level_password` - Password for the new level
///
/// # Errors
///
/// Returns error if level already exists or maximum levels reached.
pub fn create_level(
    vault_path: &Path,
    encryption_key: &[u8; 32],
    level_id: u32,
    level_name: impl Into<String>,
    level_password: &[u8],
) -> Result<LevelInfo, VaultError> {
    let mut config = read_levels_config(vault_path, encryption_key)?;

    // Create level in config
    let level = config.create_level(level_id, level_name, level_password)?;
    let info = LevelInfo::from(level);

    // Derive ALK for keystore creation
    let salt = level.password_salt();
    let mut level_salt = *salt;
    let level_bytes = level_id.to_le_bytes();
    for (i, &b) in level_bytes.iter().enumerate() {
        level_salt[i] ^= b;
    }

    let alk = derive_key(level_password, &level_salt, config.argon2_params())?;

    // Create HMAC key for keystore
    let mut hmac_salt = level_salt;
    for b in &mut hmac_salt {
        *b ^= 0x80;
    }
    let keystore_hmac_key = derive_key(level_password, &hmac_salt, config.argon2_params())?;

    // Create keystore
    let (keystore, _kek) = create_keystore(level_id, &alk, &keystore_hmac_key)?;

    // Write keystore to disk
    let ks_path = keystore_path(vault_path, level_id);
    let mut file = File::create(&ks_path)?;
    file.write_all(&keystore.to_bytes())?;
    file.sync_all()?;

    // Write updated config
    write_levels_config(vault_path, &config, encryption_key)?;

    let mut result = info;
    result.has_keystore = true;
    Ok(result)
}

/// Deletes an access level from the vault.
///
/// This function:
/// 1. Verifies the level exists and is empty (no files)
/// 2. Removes the keystore file
/// 3. Removes the level from configuration
/// 4. Writes updated configuration
///
/// # Arguments
///
/// * `vault_path` - Path to the vault
/// * `encryption_key` - Key for encrypting level config
/// * `level_id` - ID of the level to delete
///
/// # Errors
///
/// Returns error if:
/// - Level does not exist
/// - Level contains files (non-empty keystore)
/// - Minimum level count would be violated
pub fn delete_level(
    vault_path: &Path,
    encryption_key: &[u8; 32],
    level_id: u32,
) -> Result<(), VaultError> {
    let mut config = read_levels_config(vault_path, encryption_key)?;

    // Check keystore is empty before deletion
    let ks_path = keystore_path(vault_path, level_id);
    if ks_path.exists() {
        let mut file = File::open(&ks_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let keystore = Keystore::from_bytes(&data)?;
        if keystore.dek_count() > 0 {
            return Err(VaultError::InvalidFormat(format!(
                "Cannot delete level {}: contains {} file(s)",
                level_id,
                keystore.dek_count()
            )));
        }

        // Remove keystore file
        fs::remove_file(&ks_path)?;
    }

    // Remove from config
    config.delete_level(level_id)?;

    // Write updated config
    write_levels_config(vault_path, &config, encryption_key)?;

    Ok(())
}

/// Initializes the level configuration during vault creation.
///
/// This function creates a LevelConfig with all access levels and stores the
/// encrypted KEKs for each level. This enables recovery sessions to decrypt
/// the KEK without knowing the level password.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
/// * `level_count` - Number of access levels
/// * `password` - The password used for all levels
/// * `keks` - A slice of (level_id, kek) pairs from vault creation
/// * `master_key` - The master key for encrypting the level config and KEKs
/// * `argon2_params` - Argon2 parameters for password hashing
///
/// # Errors
///
/// Returns error if level config creation or encryption fails.
pub fn initialize_level_config(
    vault_path: &Path,
    level_count: u32,
    password: &[u8],
    keks: &[(u32, [u8; 32])],
    master_key: &[u8; 32],
    argon2_params: &Argon2Params,
) -> Result<(), VaultError> {
    // Create the level config with default levels
    let mut config = LevelConfig::with_default_levels(
        level_count,
        password,
        argon2_params.clone(),
    )?;

    // Store encrypted KEKs for all levels
    config.store_encrypted_keks(keks, master_key)?;

    // Ensure levels directory exists
    ensure_levels_dir(vault_path)?;

    // Write the level config encrypted with the master key
    write_levels_config(vault_path, &config, master_key)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::vault::{create_vault, VaultConfig};

    /// Creates a test vault with levels config.
    fn create_test_vault_with_levels() -> (TempDir, PathBuf, [u8; 32]) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test password", Some(config))
            .expect("Vault creation should succeed");

        // Create levels config
        let level_config = LevelConfig::with_default_levels(
            3,
            b"test password",
            Argon2Params::minimal(),
        ).expect("Should create level config");

        write_levels_config(&vault_path, &level_config, &result.encryption_key)
            .expect("Should write levels config");

        (temp_dir, vault_path, result.encryption_key)
    }

    // ========== AccessLevel tests ==========

    #[test]
    fn test_access_level_new() {
        let level = AccessLevel::new(1, "Test Level", b"password", &Argon2Params::minimal())
            .expect("Should create level");

        assert_eq!(level.id(), 1);
        assert_eq!(level.name(), "Test Level");
        assert!(level.is_enabled());
        assert!(level.description().is_none());
        assert!(level.created_at() > 0);
        assert!(level.modified_at() > 0);
    }

    #[test]
    fn test_access_level_invalid_id() {
        let result = AccessLevel::new(0, "Test", b"password", &Argon2Params::minimal());
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));

        let result = AccessLevel::new(11, "Test", b"password", &Argon2Params::minimal());
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_access_level_empty_name() {
        let result = AccessLevel::new(1, "", b"password", &Argon2Params::minimal());
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_access_level_verify_password() {
        let level = AccessLevel::new(1, "Test", b"correct", &Argon2Params::minimal())
            .expect("Should create level");

        assert!(level.verify_password(b"correct", &Argon2Params::minimal()).unwrap());
        assert!(!level.verify_password(b"wrong", &Argon2Params::minimal()).unwrap());
    }

    #[test]
    fn test_access_level_change_password() {
        let mut level = AccessLevel::new(1, "Test", b"oldpass", &Argon2Params::minimal())
            .expect("Should create level");

        // Wrong old password should fail
        let result = level.change_password(b"wrong", b"newpass", &Argon2Params::minimal());
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));

        // Correct old password should succeed
        level.change_password(b"oldpass", b"newpass", &Argon2Params::minimal())
            .expect("Should change password");

        // Old password no longer works
        assert!(!level.verify_password(b"oldpass", &Argon2Params::minimal()).unwrap());
        // New password works
        assert!(level.verify_password(b"newpass", &Argon2Params::minimal()).unwrap());
    }

    #[test]
    fn test_access_level_set_name() {
        let mut level = AccessLevel::new(1, "Original", b"pass", &Argon2Params::minimal())
            .expect("Should create level");

        level.set_name("Updated").expect("Should set name");
        assert_eq!(level.name(), "Updated");
    }

    #[test]
    fn test_access_level_set_empty_name_fails() {
        let mut level = AccessLevel::new(1, "Original", b"pass", &Argon2Params::minimal())
            .expect("Should create level");

        let result = level.set_name("");
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_access_level_set_description() {
        let mut level = AccessLevel::new(1, "Test", b"pass", &Argon2Params::minimal())
            .expect("Should create level");

        assert!(level.description().is_none());

        level.set_description(Some("A description".to_string()));
        assert_eq!(level.description(), Some("A description"));

        level.set_description(None);
        assert!(level.description().is_none());
    }

    #[test]
    fn test_access_level_enable_disable() {
        let mut level = AccessLevel::new(1, "Test", b"pass", &Argon2Params::minimal())
            .expect("Should create level");

        assert!(level.is_enabled());

        level.set_enabled(false);
        assert!(!level.is_enabled());

        level.set_enabled(true);
        assert!(level.is_enabled());
    }

    // ========== LevelConfig tests ==========

    #[test]
    fn test_level_config_new() {
        let config = LevelConfig::new(Argon2Params::minimal());

        assert_eq!(config.level_count(), 0);
        assert_eq!(config.version(), LevelConfigVersion::CURRENT);
    }

    #[test]
    fn test_level_config_with_default_levels() {
        let config = LevelConfig::with_default_levels(3, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        assert_eq!(config.level_count(), 3);

        let ids = config.level_ids();
        assert_eq!(ids, vec![1, 2, 3]);

        // Check default names
        assert_eq!(config.get_level(1).unwrap().name(), "Public");
        assert_eq!(config.get_level(2).unwrap().name(), "Internal");
        assert_eq!(config.get_level(3).unwrap().name(), "Confidential");
    }

    #[test]
    fn test_level_config_invalid_count() {
        let result = LevelConfig::with_default_levels(0, b"pass", Argon2Params::minimal());
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));

        let result = LevelConfig::with_default_levels(11, b"pass", Argon2Params::minimal());
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_level_config_create_level() {
        let mut config = LevelConfig::with_default_levels(3, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        let level = config.create_level(4, "New Level", b"newpass")
            .expect("Should create level");

        assert_eq!(level.id(), 4);
        assert_eq!(level.name(), "New Level");
        assert_eq!(config.level_count(), 4);
    }

    #[test]
    fn test_level_config_create_duplicate_fails() {
        let mut config = LevelConfig::with_default_levels(3, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        let result = config.create_level(1, "Duplicate", b"pass");
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_level_config_delete_level() {
        let mut config = LevelConfig::with_default_levels(4, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        let deleted = config.delete_level(4).expect("Should delete level");
        assert_eq!(deleted.id(), 4);
        assert_eq!(config.level_count(), 3);
    }

    #[test]
    fn test_level_config_delete_nonexistent_fails() {
        let mut config = LevelConfig::with_default_levels(3, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        let result = config.delete_level(99);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_level_config_delete_below_minimum_fails() {
        // Start with 2 levels so we can delete one
        let mut config = LevelConfig::with_default_levels(2, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        // Delete one level (2 -> 1), should succeed
        config.delete_level(2).expect("Deleting level 2 should succeed");
        assert_eq!(config.level_count(), 1);

        // Now try to delete the last level - should fail because MIN_LEVEL_COUNT is 1
        let result = config.delete_level(1);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_level_config_list_levels() {
        let config = LevelConfig::with_default_levels(3, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        let levels = config.list_levels();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0].id(), 1);
        assert_eq!(levels[1].id(), 2);
        assert_eq!(levels[2].id(), 3);
    }

    #[test]
    fn test_level_config_serialization() {
        let config = LevelConfig::with_default_levels(3, b"pass", Argon2Params::minimal())
            .expect("Should create config");

        let bytes = config.to_bytes().expect("Should serialize");
        let restored = LevelConfig::from_bytes(&bytes).expect("Should deserialize");

        assert_eq!(restored.level_count(), 3);
        assert_eq!(restored.level_ids(), vec![1, 2, 3]);
    }

    // ========== Encrypted storage tests ==========

    #[test]
    fn test_write_read_levels_config() {
        let (temp_dir, vault_path, encryption_key) = create_test_vault_with_levels();

        // Read back
        let config = read_levels_config(&vault_path, &encryption_key)
            .expect("Should read config");

        assert_eq!(config.level_count(), 3);
        assert_eq!(config.level_ids(), vec![1, 2, 3]);
    }

    #[test]
    fn test_read_levels_config_wrong_key_fails() {
        let (_temp_dir, vault_path, _encryption_key) = create_test_vault_with_levels();

        let wrong_key = [0u8; 32];
        let result = read_levels_config(&vault_path, &wrong_key);

        // Should fail with crypto error
        assert!(result.is_err());
    }

    #[test]
    fn test_levels_config_exists() {
        let (_temp_dir, vault_path, _encryption_key) = create_test_vault_with_levels();

        assert!(levels_config_exists(&vault_path));
    }

    #[test]
    fn test_levels_config_not_exists() {
        let temp_dir = TempDir::new().unwrap();
        assert!(!levels_config_exists(temp_dir.path()));
    }

    #[test]
    fn test_list_levels_info() {
        let (_temp_dir, vault_path, encryption_key) = create_test_vault_with_levels();

        let infos = list_levels_info(&vault_path, &encryption_key)
            .expect("Should list levels");

        assert_eq!(infos.len(), 3);
        assert_eq!(infos[0].id, 1);
        assert_eq!(infos[0].name, "Public");
        assert!(infos[0].has_keystore);
    }

    // ========== High-level CRUD tests ==========

    #[test]
    fn test_create_level_high_level() {
        let (_temp_dir, vault_path, encryption_key) = create_test_vault_with_levels();

        let info = create_level(&vault_path, &encryption_key, 4, "Secret", b"secret_pass")
            .expect("Should create level");

        assert_eq!(info.id, 4);
        assert_eq!(info.name, "Secret");
        assert!(info.has_keystore);

        // Verify persisted
        let config = read_levels_config(&vault_path, &encryption_key).unwrap();
        assert_eq!(config.level_count(), 4);
        assert!(config.has_level(4));
    }

    #[test]
    fn test_delete_level_high_level() {
        // First create a vault with 4 levels so we can delete one
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(4)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test password", Some(config))
            .expect("Vault creation should succeed");

        let level_config = LevelConfig::with_default_levels(
            4,
            b"test password",
            Argon2Params::minimal(),
        ).expect("Should create level config");

        write_levels_config(&vault_path, &level_config, &result.encryption_key)
            .expect("Should write levels config");

        // Now delete level 4
        delete_level(&vault_path, &result.encryption_key, 4)
            .expect("Should delete level");

        // Verify deletion
        let config = read_levels_config(&vault_path, &result.encryption_key).unwrap();
        assert_eq!(config.level_count(), 3);
        assert!(!config.has_level(4));

        // Verify keystore file removed
        assert!(!keystore_path(&vault_path, 4).exists());
    }

    #[test]
    fn test_cannot_delete_last_minimum_levels() {
        // Create vault with only 1 level (the minimum)
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(1)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test password", Some(config))
            .expect("Vault creation should succeed");

        // Create levels config with 1 level
        let level_config = LevelConfig::with_default_levels(
            1,
            b"test password",
            Argon2Params::minimal(),
        ).expect("Should create level config");

        write_levels_config(&vault_path, &level_config, &result.encryption_key)
            .expect("Should write levels config");

        // Try to delete when only 1 level exists (the minimum)
        let delete_result = delete_level(&vault_path, &result.encryption_key, 1);
        assert!(matches!(delete_result, Err(VaultError::InvalidFormat(_))));
    }

    // ========== LevelInfo tests ==========

    #[test]
    fn test_level_info_from_access_level() {
        let level = AccessLevel::new(1, "Test", b"pass", &Argon2Params::minimal())
            .expect("Should create level");

        let info = LevelInfo::from(&level);

        assert_eq!(info.id, 1);
        assert_eq!(info.name, "Test");
        assert!(info.enabled);
        assert!(info.description.is_none());
        assert!(!info.has_keystore); // Default false
    }

    // ========== Version tests ==========

    #[test]
    fn test_level_config_version_compatibility() {
        let v1 = LevelConfigVersion::new(1, 0);
        let v2 = LevelConfigVersion::new(1, 1);
        let v3 = LevelConfigVersion::new(2, 0);

        assert!(v1.is_compatible_with(&v2));
        assert!(v2.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v3));
    }

    // ========== Path utility tests ==========

    #[test]
    fn test_levels_dir_path() {
        let vault_path = Path::new("/vault");
        assert_eq!(levels_dir(vault_path), PathBuf::from("/vault/.levels"));
    }

    #[test]
    fn test_levels_config_path() {
        let vault_path = Path::new("/vault");
        assert_eq!(
            levels_config_path(vault_path),
            PathBuf::from("/vault/.levels/levels.enc")
        );
    }

    // ========== Maximum level tests ==========

    #[test]
    fn test_create_max_levels() {
        let config = LevelConfig::with_default_levels(10, b"pass", Argon2Params::minimal())
            .expect("Should create max levels");

        assert_eq!(config.level_count(), 10);
    }

    #[test]
    fn test_cannot_exceed_max_levels() {
        let mut config = LevelConfig::with_default_levels(10, b"pass", Argon2Params::minimal())
            .expect("Should create max levels");

        let result = config.create_level(11, "Too many", b"pass");
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    // ========== Empty password tests ==========

    #[test]
    fn test_empty_password() {
        // Empty password should still work (user's choice)
        let level = AccessLevel::new(1, "Test", b"", &Argon2Params::minimal())
            .expect("Should allow empty password");

        assert!(level.verify_password(b"", &Argon2Params::minimal()).unwrap());
    }

    // ========== Unicode name tests ==========

    #[test]
    fn test_unicode_level_name() {
        let level = AccessLevel::new(1, "機密レベル", b"pass", &Argon2Params::minimal())
            .expect("Should allow unicode name");

        assert_eq!(level.name(), "機密レベル");
    }

    // ========== Long name tests ==========

    #[test]
    fn test_long_level_name() {
        let long_name = "A".repeat(1000);
        let level = AccessLevel::new(1, &long_name, b"pass", &Argon2Params::minimal())
            .expect("Should allow long name");

        assert_eq!(level.name(), long_name);
    }
}
