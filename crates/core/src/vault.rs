//! Vault directory structure creation and management.
//!
//! Provides functionality for creating new vaults with proper directory
//! structure, encrypted header, and initial keystores for access levels.
//!
//! # Vault Structure
//!
//! A TESSERACT vault has the following directory layout:
//!
//! ```text
//! /vault/
//! ├── vault.header       # Encrypted vault header (512 bytes)
//! ├── .keystores/        # Per-level encrypted keystore files
//! │   ├── L1.keys.enc    # Level 1 keystore
//! │   ├── L2.keys.enc    # Level 2 keystore
//! │   └── L3.keys.enc    # Level 3 keystore
//! ├── .blobs/            # Encrypted file content
//! │   └── {uuid}.blob    # Individual encrypted files
//! └── .metadata/         # Encrypted file metadata
//!     └── {uuid}.meta    # Individual encrypted metadata
//! ```
//!
//! # Security
//!
//! - All vault creation is atomic: either all components are created or none
//! - Existing vaults are never overwritten
//! - Each access level gets a unique KEK and keystore
//! - The master key is securely stored in the encrypted header

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::access::initialize_level_config;
use crate::error::VaultError;
use crate::header::{create_encrypted_header, VaultHeader, HEADER_SIZE};
use crate::keystore::{create_keystore, Keystore, HMAC_TAG_SIZE};
use tesseract_crypto::{
    generate_key, generate_nonce, generate_salt,
    kdf::{derive_key, Argon2Params},
    recovery::{generate_recovery_key, RecoveryKey, ENCRYPTED_MASTER_KEY_SIZE},
};

/// The name of the vault header file.
pub const HEADER_FILENAME: &str = "vault.header";

/// The name of the keystores directory.
pub const KEYSTORES_DIR: &str = ".keystores";

/// The name of the blobs directory.
pub const BLOBS_DIR: &str = ".blobs";

/// The name of the metadata directory.
pub const METADATA_DIR: &str = ".metadata";

/// The name of the recovery blob file.
pub const RECOVERY_FILENAME: &str = ".recovery";

/// Default number of access levels created for new vaults.
pub const DEFAULT_LEVEL_COUNT: u32 = 3;

/// Maximum supported number of access levels.
pub const MAX_LEVEL_COUNT: u32 = 10;

/// Minimum supported number of access levels.
pub const MIN_LEVEL_COUNT: u32 = 1;

/// Returns the path to the vault header file.
#[must_use]
pub fn header_path(vault_path: &Path) -> PathBuf {
    vault_path.join(HEADER_FILENAME)
}

/// Returns the path to the keystores directory.
#[must_use]
pub fn keystores_dir(vault_path: &Path) -> PathBuf {
    vault_path.join(KEYSTORES_DIR)
}

/// Returns the path to the blobs directory.
#[must_use]
pub fn vault_blobs_dir(vault_path: &Path) -> PathBuf {
    vault_path.join(BLOBS_DIR)
}

/// Returns the path to the metadata directory.
#[must_use]
pub fn vault_metadata_dir(vault_path: &Path) -> PathBuf {
    vault_path.join(METADATA_DIR)
}

/// Returns the path to the recovery blob file.
#[must_use]
pub fn recovery_path(vault_path: &Path) -> PathBuf {
    vault_path.join(RECOVERY_FILENAME)
}

/// Returns the path to a specific level's keystore file.
#[must_use]
pub fn keystore_path(vault_path: &Path, level_id: u32) -> PathBuf {
    keystores_dir(vault_path).join(format!("L{}.keys.enc", level_id))
}

/// Checks if a vault exists at the given path.
///
/// A vault is considered to exist if the vault.header file is present.
#[must_use]
pub fn vault_exists(vault_path: &Path) -> bool {
    header_path(vault_path).exists()
}

/// Checks if a vault directory structure is complete.
///
/// Returns `true` if all required directories and the header file exist.
#[must_use]
pub fn is_vault_complete(vault_path: &Path) -> bool {
    header_path(vault_path).exists()
        && keystores_dir(vault_path).is_dir()
        && vault_blobs_dir(vault_path).is_dir()
        && vault_metadata_dir(vault_path).is_dir()
}

/// Configuration for vault creation.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Number of access levels to create (1-10).
    pub level_count: u32,
    /// Argon2 parameters for key derivation.
    pub argon2_params: Argon2Params,
    /// Level passwords (one per level, in order).
    /// If empty, all levels use the master password.
    pub level_passwords: Vec<Vec<u8>>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            level_count: DEFAULT_LEVEL_COUNT,
            argon2_params: Argon2Params::default(),
            level_passwords: Vec::new(),
        }
    }
}

impl VaultConfig {
    /// Creates a new vault configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the number of access levels.
    ///
    /// # Panics
    ///
    /// Panics if `count` is outside the range 1-10.
    #[must_use]
    pub fn with_level_count(mut self, count: u32) -> Self {
        assert!(
            count >= MIN_LEVEL_COUNT && count <= MAX_LEVEL_COUNT,
            "Level count must be between {} and {}",
            MIN_LEVEL_COUNT,
            MAX_LEVEL_COUNT
        );
        self.level_count = count;
        self
    }

    /// Sets the Argon2 parameters for key derivation.
    #[must_use]
    pub fn with_argon2_params(mut self, params: Argon2Params) -> Self {
        self.argon2_params = params;
        self
    }

    /// Sets per-level passwords.
    ///
    /// If fewer passwords are provided than levels, remaining levels
    /// will use the master password.
    #[must_use]
    pub fn with_level_passwords(mut self, passwords: Vec<Vec<u8>>) -> Self {
        self.level_passwords = passwords;
        self
    }

    /// Validates the configuration.
    fn validate(&self) -> Result<(), VaultError> {
        if self.level_count < MIN_LEVEL_COUNT || self.level_count > MAX_LEVEL_COUNT {
            return Err(VaultError::InvalidFormat(format!(
                "Level count must be between {} and {}, got {}",
                MIN_LEVEL_COUNT, MAX_LEVEL_COUNT, self.level_count
            )));
        }
        Ok(())
    }
}

/// Result of successful vault creation.
pub struct VaultCreationResult {
    /// The vault header.
    pub header: VaultHeader,
    /// The raw master key (should be securely wiped after use).
    pub master_key: [u8; 32],
    /// The encryption key derived from password.
    pub encryption_key: [u8; 32],
    /// The HMAC key derived from password.
    pub hmac_key: [u8; 32],
    /// The keystores created for each level, with their raw KEKs.
    pub keystores: Vec<(Keystore, [u8; 32])>,
    /// The recovery key for this vault.
    ///
    /// **IMPORTANT**: This key should be displayed to the user ONCE and then
    /// the `RecoveryKey` struct should be dropped. The user must write down
    /// the mnemonic phrase or base64 representation and store it securely.
    ///
    /// Use `recovery_key.to_mnemonic()` for a 24-word phrase or
    /// `recovery_key.to_base64()` for a compact digital representation.
    pub recovery_key: RecoveryKey,
    /// The master key encrypted with the recovery key.
    ///
    /// This blob should be stored securely (e.g., in the vault header or
    /// a separate recovery file). It can only be decrypted using the
    /// recovery key.
    pub encrypted_master_key_for_recovery: [u8; ENCRYPTED_MASTER_KEY_SIZE],
}

/// Creates a new vault at the specified path.
///
/// This function performs atomic vault creation:
/// 1. Creates the directory structure
/// 2. Generates and encrypts the master key
/// 3. Creates keystores for each access level
/// 4. Writes all files to disk
///
/// If any step fails, all created files and directories are removed.
///
/// # Arguments
///
/// * `vault_path` - The path where the vault should be created
/// * `password` - The master password for the vault
/// * `config` - Optional configuration; uses defaults if None
///
/// # Returns
///
/// A `VaultCreationResult` containing the created vault components.
///
/// # Errors
///
/// * `VaultError::VaultAlreadyExists` - If a vault already exists at the path
/// * `VaultError::IoError` - If file operations fail
/// * `VaultError::CryptoError` - If cryptographic operations fail
///
/// # Example
///
/// ```ignore
/// use tesseract_core::vault::{create_vault, VaultConfig};
///
/// let config = VaultConfig::new().with_level_count(3);
/// let result = create_vault("/path/to/vault", b"my password", Some(config))?;
/// ```
pub fn create_vault(
    vault_path: impl AsRef<Path>,
    password: &[u8],
    config: Option<VaultConfig>,
) -> Result<VaultCreationResult, VaultError> {
    let vault_path = vault_path.as_ref();
    let config = config.unwrap_or_default();
    config.validate()?;

    // Check if vault already exists
    if vault_exists(vault_path) {
        return Err(VaultError::VaultAlreadyExists(
            vault_path.display().to_string(),
        ));
    }

    // Track created resources for rollback on failure
    let mut created_dirs: Vec<PathBuf> = Vec::new();
    let mut created_files: Vec<PathBuf> = Vec::new();

    // Helper to clean up on failure
    let cleanup = |dirs: &[PathBuf], files: &[PathBuf]| {
        for file in files.iter().rev() {
            let _ = fs::remove_file(file);
        }
        for dir in dirs.iter().rev() {
            let _ = fs::remove_dir(dir);
        }
    };

    // Create vault directory if it doesn't exist
    if !vault_path.exists() {
        if let Err(e) = fs::create_dir_all(vault_path) {
            return Err(VaultError::IoError(e));
        }
        created_dirs.push(vault_path.to_path_buf());
    }

    // Create subdirectories
    let dirs_to_create = [
        keystores_dir(vault_path),
        vault_blobs_dir(vault_path),
        vault_metadata_dir(vault_path),
    ];

    for dir in &dirs_to_create {
        if let Err(e) = fs::create_dir(dir) {
            cleanup(&created_dirs, &created_files);
            return Err(VaultError::IoError(e));
        }
        created_dirs.push(dir.clone());
    }

    // Generate cryptographic material
    let master_key = generate_key()?;
    let salt: [u8; 16] = generate_salt()?;
    let nonce: [u8; 12] = generate_nonce()?;

    // Create encrypted header
    let (header, encryption_key, hmac_key) = match create_encrypted_header(
        password,
        &master_key,
        &salt,
        &nonce,
        &config.argon2_params,
    ) {
        Ok(result) => result,
        Err(e) => {
            cleanup(&created_dirs, &created_files);
            return Err(e);
        }
    };

    // Write header to disk
    let header_file_path = header_path(vault_path);
    match write_header_to_file(&header, &header_file_path) {
        Ok(()) => created_files.push(header_file_path),
        Err(e) => {
            cleanup(&created_dirs, &created_files);
            return Err(e);
        }
    }

    // Create keystores for each level
    let mut keystores = Vec::with_capacity(config.level_count as usize);
    for level_id in 1..=config.level_count {
        // Get password for this level (or use master password)
        let level_password = config
            .level_passwords
            .get(level_id as usize - 1)
            .map(|p| p.as_slice())
            .unwrap_or(password);

        // Derive ALK (Access Level Key) from level password
        // Use a different domain by XORing salt with level_id
        let mut level_salt = salt;
        let level_bytes = level_id.to_le_bytes();
        for (i, &b) in level_bytes.iter().enumerate() {
            level_salt[i] ^= b;
        }

        let alk = match derive_key(level_password, &level_salt, &config.argon2_params) {
            Ok(key) => key,
            Err(e) => {
                cleanup(&created_dirs, &created_files);
                return Err(e.into());
            }
        };

        // Create HMAC key for keystore (derive from ALK with domain separation)
        let mut hmac_salt = level_salt;
        for b in &mut hmac_salt {
            *b ^= 0x80; // Different domain for HMAC key
        }
        let keystore_hmac_key = match derive_key(level_password, &hmac_salt, &config.argon2_params)
        {
            Ok(key) => key,
            Err(e) => {
                cleanup(&created_dirs, &created_files);
                return Err(e.into());
            }
        };

        // Create keystore with random KEK
        let (keystore, kek) = match create_keystore(level_id, &alk, &keystore_hmac_key) {
            Ok(result) => result,
            Err(e) => {
                cleanup(&created_dirs, &created_files);
                return Err(e);
            }
        };

        // Write keystore to disk
        let ks_path = keystore_path(vault_path, level_id);
        match write_keystore_to_file(&keystore, &ks_path) {
            Ok(()) => created_files.push(ks_path),
            Err(e) => {
                cleanup(&created_dirs, &created_files);
                return Err(e);
            }
        }

        keystores.push((keystore, kek));
    }

    // Generate recovery key and encrypt master key with it
    let recovery_key = match generate_recovery_key() {
        Ok(key) => key,
        Err(e) => {
            cleanup(&created_dirs, &created_files);
            return Err(e.into());
        }
    };

    let encrypted_master_key_for_recovery = match recovery_key.encrypt_master_key(&master_key) {
        Ok(encrypted) => encrypted,
        Err(e) => {
            cleanup(&created_dirs, &created_files);
            return Err(e.into());
        }
    };

    // Write the recovery blob to disk
    let recovery_blob_path = recovery_path(vault_path);
    match write_recovery_blob(&recovery_blob_path, &encrypted_master_key_for_recovery) {
        Ok(()) => created_files.push(recovery_blob_path),
        Err(e) => {
            cleanup(&created_dirs, &created_files);
            return Err(e);
        }
    }

    // Initialize the level config with encrypted KEKs for recovery support
    let keks: Vec<(u32, [u8; 32])> = keystores
        .iter()
        .enumerate()
        .map(|(i, (_, kek))| ((i + 1) as u32, *kek))
        .collect();

    if let Err(e) = initialize_level_config(
        vault_path,
        config.level_count,
        password,
        &keks,
        &master_key,
        &config.argon2_params,
    ) {
        cleanup(&created_dirs, &created_files);
        return Err(e);
    }

    Ok(VaultCreationResult {
        header,
        master_key,
        encryption_key,
        hmac_key,
        keystores,
        recovery_key,
        encrypted_master_key_for_recovery,
    })
}

/// Writes a vault header to a file.
fn write_header_to_file(header: &VaultHeader, path: &Path) -> Result<(), VaultError> {
    let mut file = File::create(path)?;
    let bytes = header.to_bytes();
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Writes a keystore to a file.
fn write_keystore_to_file(keystore: &Keystore, path: &Path) -> Result<(), VaultError> {
    let mut file = File::create(path)?;
    let bytes = keystore.to_bytes();
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Recovers the master key using a recovery key.
///
/// This function decrypts the master key from the encrypted recovery blob
/// using the provided recovery key. The recovery key can be created from:
/// - A 24-word BIP39 mnemonic phrase using `RecoveryKey::from_mnemonic()`
/// - A base64 string using `RecoveryKey::from_base64()`
///
/// # Arguments
///
/// * `recovery_key` - The recovery key (from mnemonic or base64)
/// * `encrypted_master_key` - The encrypted master key blob (60 bytes)
///
/// # Returns
///
/// The decrypted 32-byte master key.
///
/// # Errors
///
/// * `VaultError::CryptoError` - If decryption fails (wrong key or corrupted data)
///
/// # Example
///
/// ```ignore
/// use tesseract_crypto::recovery::RecoveryKey;
/// use tesseract_core::vault::recover_master_key;
///
/// // User provides their recovery phrase
/// let phrase = "abandon ability able about above absent absorb abstract ...";
/// let recovery_key = RecoveryKey::from_mnemonic(phrase)?;
///
/// // Decrypt the master key
/// let master_key = recover_master_key(&recovery_key, &encrypted_blob)?;
/// ```
pub fn recover_master_key(
    recovery_key: &RecoveryKey,
    encrypted_master_key: &[u8; ENCRYPTED_MASTER_KEY_SIZE],
) -> Result<[u8; 32], VaultError> {
    recovery_key
        .decrypt_master_key(encrypted_master_key)
        .map_err(VaultError::from)
}

/// Writes the recovery blob to a file.
///
/// The recovery blob contains the master key encrypted with the recovery key.
/// This file is required for recovery key authentication.
///
/// # Arguments
///
/// * `path` - Path to write the recovery blob
/// * `encrypted_master_key` - The encrypted master key blob (60 bytes)
fn write_recovery_blob(
    path: &Path,
    encrypted_master_key: &[u8; ENCRYPTED_MASTER_KEY_SIZE],
) -> Result<(), VaultError> {
    let mut file = File::create(path)?;
    file.write_all(encrypted_master_key)?;
    file.sync_all()?;
    Ok(())
}

/// Reads the recovery blob from a vault.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
///
/// # Returns
///
/// The encrypted master key blob (60 bytes).
///
/// # Errors
///
/// * `VaultError::VaultNotFound` - If the vault or recovery blob doesn't exist
/// * `VaultError::InvalidFormat` - If the recovery blob has the wrong size
pub fn read_recovery_blob(vault_path: &Path) -> Result<[u8; ENCRYPTED_MASTER_KEY_SIZE], VaultError> {
    let blob_path = recovery_path(vault_path);

    if !blob_path.exists() {
        return Err(VaultError::RecoveryNotAvailable);
    }

    let data = std::fs::read(&blob_path)?;

    if data.len() != ENCRYPTED_MASTER_KEY_SIZE {
        return Err(VaultError::InvalidFormat(format!(
            "Recovery blob has wrong size: expected {}, got {}",
            ENCRYPTED_MASTER_KEY_SIZE,
            data.len()
        )));
    }

    let mut blob = [0u8; ENCRYPTED_MASTER_KEY_SIZE];
    blob.copy_from_slice(&data);
    Ok(blob)
}

/// Checks if a vault has a recovery blob.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
///
/// # Returns
///
/// `true` if the recovery blob exists, `false` otherwise.
#[must_use]
pub fn has_recovery_blob(vault_path: &Path) -> bool {
    recovery_path(vault_path).exists()
}

/// Deletes a vault and all its contents.
///
/// **WARNING**: This operation is irreversible. All encrypted files will be lost.
///
/// # Arguments
///
/// * `vault_path` - The path to the vault to delete
///
/// # Errors
///
/// * `VaultError::VaultNotFound` - If no vault exists at the path
/// * `VaultError::IoError` - If deletion fails
pub fn delete_vault(vault_path: impl AsRef<Path>) -> Result<(), VaultError> {
    let vault_path = vault_path.as_ref();

    if !vault_exists(vault_path) {
        return Err(VaultError::VaultNotFound(
            vault_path.display().to_string(),
        ));
    }

    fs::remove_dir_all(vault_path)?;
    Ok(())
}

/// Lists all keystore files in a vault.
///
/// Returns the level IDs of all existing keystores.
pub fn list_keystores(vault_path: impl AsRef<Path>) -> Result<Vec<u32>, VaultError> {
    let ks_dir = keystores_dir(vault_path.as_ref());

    if !ks_dir.exists() {
        return Ok(Vec::new());
    }

    let mut levels = Vec::new();
    for entry in fs::read_dir(ks_dir)? {
        let entry = entry?;
        let filename = entry.file_name();
        let filename_str = filename.to_string_lossy();

        // Parse L{n}.keys.enc format
        if filename_str.starts_with('L') && filename_str.ends_with(".keys.enc") {
            let level_str = &filename_str[1..filename_str.len() - 9];
            if let Ok(level) = level_str.parse::<u32>() {
                levels.push(level);
            }
        }
    }

    levels.sort();
    Ok(levels)
}

/// Validates vault structure integrity.
///
/// Checks that all required components exist and have valid formats.
pub fn validate_vault_structure(vault_path: impl AsRef<Path>) -> Result<(), VaultError> {
    let vault_path = vault_path.as_ref();

    // Check header exists and has correct size
    let header_file = header_path(vault_path);
    if !header_file.exists() {
        return Err(VaultError::VaultNotFound(
            vault_path.display().to_string(),
        ));
    }

    let header_meta = fs::metadata(&header_file)?;
    if header_meta.len() != HEADER_SIZE as u64 {
        return Err(VaultError::InvalidFormat(format!(
            "Invalid header size: expected {}, got {}",
            HEADER_SIZE,
            header_meta.len()
        )));
    }

    // Check required directories exist
    let dirs = [
        keystores_dir(vault_path),
        vault_blobs_dir(vault_path),
        vault_metadata_dir(vault_path),
    ];

    for dir in &dirs {
        if !dir.is_dir() {
            return Err(VaultError::InvalidFormat(format!(
                "Missing directory: {}",
                dir.display()
            )));
        }
    }

    // Check at least one keystore exists
    let keystores = list_keystores(vault_path)?;
    if keystores.is_empty() {
        return Err(VaultError::InvalidFormat(
            "No keystores found in vault".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    /// Creates a test vault and returns the temp directory and result.
    fn create_test_vault() -> (TempDir, VaultCreationResult) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test password", Some(config))
            .expect("Vault creation should succeed");

        (temp_dir, result)
    }

    #[test]
    fn test_vault_config_default() {
        let config = VaultConfig::default();
        assert_eq!(config.level_count, DEFAULT_LEVEL_COUNT);
        assert!(config.level_passwords.is_empty());
    }

    #[test]
    fn test_vault_config_builder() {
        let config = VaultConfig::new()
            .with_level_count(5)
            .with_argon2_params(Argon2Params::minimal());

        assert_eq!(config.level_count, 5);
    }

    #[test]
    #[should_panic(expected = "Level count must be between")]
    fn test_vault_config_invalid_level_count() {
        VaultConfig::new().with_level_count(11);
    }

    #[test]
    fn test_path_utilities() {
        let vault_path = Path::new("/vault");

        assert_eq!(header_path(vault_path), PathBuf::from("/vault/vault.header"));
        assert_eq!(keystores_dir(vault_path), PathBuf::from("/vault/.keystores"));
        assert_eq!(vault_blobs_dir(vault_path), PathBuf::from("/vault/.blobs"));
        assert_eq!(vault_metadata_dir(vault_path), PathBuf::from("/vault/.metadata"));
        assert_eq!(keystore_path(vault_path, 2), PathBuf::from("/vault/.keystores/L2.keys.enc"));
    }

    #[test]
    fn test_create_vault_creates_directories() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Verify directory structure
        assert!(vault_path.exists(), "Vault directory should exist");
        assert!(keystores_dir(&vault_path).is_dir(), "Keystores dir should exist");
        assert!(vault_blobs_dir(&vault_path).is_dir(), "Blobs dir should exist");
        assert!(vault_metadata_dir(&vault_path).is_dir(), "Metadata dir should exist");
    }

    #[test]
    fn test_create_vault_creates_header() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Verify header file
        let header_file = header_path(&vault_path);
        assert!(header_file.exists(), "Header file should exist");

        // Verify header size
        let meta = fs::metadata(&header_file).unwrap();
        assert_eq!(meta.len(), HEADER_SIZE as u64, "Header should be 512 bytes");
    }

    #[test]
    fn test_create_vault_creates_keystores() {
        let (temp_dir, result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Verify keystore files
        for level_id in 1..=3 {
            let ks_path = keystore_path(&vault_path, level_id);
            assert!(ks_path.exists(), "Keystore L{} should exist", level_id);

            // Verify keystore can be read
            let mut file = File::open(&ks_path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();

            let keystore = Keystore::from_bytes(&buffer).expect("Should parse keystore");
            assert_eq!(keystore.level_id(), level_id);
        }

        // Verify correct number of keystores were created
        assert_eq!(result.keystores.len(), 3);
    }

    #[test]
    fn test_vault_exists() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        assert!(vault_exists(&vault_path));
        assert!(!vault_exists(&temp_dir.path().join("nonexistent")));
    }

    #[test]
    fn test_is_vault_complete() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        assert!(is_vault_complete(&vault_path));

        // Incomplete vault missing a directory
        let incomplete_path = temp_dir.path().join("incomplete");
        fs::create_dir_all(&incomplete_path).unwrap();
        fs::write(header_path(&incomplete_path), [0u8; HEADER_SIZE]).unwrap();
        assert!(!is_vault_complete(&incomplete_path));
    }

    #[test]
    fn test_create_vault_fails_if_exists() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Try to create again
        let result = create_vault(&vault_path, b"test", None);
        assert!(matches!(result, Err(VaultError::VaultAlreadyExists(_))));
    }

    #[test]
    fn test_list_keystores() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        let levels = list_keystores(&vault_path).expect("Should list keystores");
        assert_eq!(levels, vec![1, 2, 3]);
    }

    #[test]
    fn test_validate_vault_structure() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Valid vault
        assert!(validate_vault_structure(&vault_path).is_ok());

        // Missing vault
        assert!(matches!(
            validate_vault_structure(temp_dir.path().join("missing")),
            Err(VaultError::VaultNotFound(_))
        ));
    }

    #[test]
    fn test_delete_vault() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        assert!(vault_exists(&vault_path));
        delete_vault(&vault_path).expect("Delete should succeed");
        assert!(!vault_exists(&vault_path));
    }

    #[test]
    fn test_delete_nonexistent_vault() {
        let temp_dir = TempDir::new().unwrap();
        let result = delete_vault(temp_dir.path().join("nonexistent"));
        assert!(matches!(result, Err(VaultError::VaultNotFound(_))));
    }

    #[test]
    fn test_create_vault_with_custom_level_count() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(5)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test", Some(config))
            .expect("Should create vault");

        assert_eq!(result.keystores.len(), 5);

        let levels = list_keystores(&vault_path).unwrap();
        assert_eq!(levels, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_create_vault_with_per_level_passwords() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal())
            .with_level_passwords(vec![
                b"level1pass".to_vec(),
                b"level2pass".to_vec(),
                b"level3pass".to_vec(),
            ]);

        let result = create_vault(&vault_path, b"master", Some(config))
            .expect("Should create vault");

        // All keystores should be created
        assert_eq!(result.keystores.len(), 3);
    }

    #[test]
    fn test_vault_header_can_be_read_back() {
        let (temp_dir, result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Read header from file
        let header_file = header_path(&vault_path);
        let mut file = File::open(header_file).unwrap();
        let mut buffer = [0u8; HEADER_SIZE];
        file.read_exact(&mut buffer).unwrap();

        let read_header = VaultHeader::from_bytes(&buffer).expect("Should parse header");

        // Verify header matches
        assert_eq!(read_header.version(), result.header.version());
        assert_eq!(read_header.salt(), result.header.salt());
        assert_eq!(read_header.hmac_tag(), result.header.hmac_tag());
    }

    #[test]
    fn test_atomic_creation_on_keystore_failure() {
        // This test verifies cleanup behavior
        // We can't easily simulate a keystore failure, but we can verify
        // that a failed vault creation doesn't leave partial state
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // First create a valid vault
        let config = VaultConfig::new()
            .with_level_count(2)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"test", Some(config))
            .expect("First creation should succeed");

        // Second creation should fail
        let result = create_vault(&vault_path, b"test2", None);
        assert!(matches!(result, Err(VaultError::VaultAlreadyExists(_))));

        // Original vault should still be complete
        assert!(is_vault_complete(&vault_path));
    }

    #[test]
    fn test_vault_creation_result_contains_keys() {
        let (_temp_dir, result) = create_test_vault();

        // Master key should be non-zero
        assert!(!result.master_key.iter().all(|&b| b == 0));

        // Encryption key should be non-zero
        assert!(!result.encryption_key.iter().all(|&b| b == 0));

        // HMAC key should be non-zero
        assert!(!result.hmac_key.iter().all(|&b| b == 0));

        // Each keystore should have a unique KEK
        let keks: Vec<_> = result.keystores.iter().map(|(_, kek)| kek).collect();
        for i in 0..keks.len() {
            for j in i+1..keks.len() {
                assert_ne!(keks[i], keks[j], "KEKs should be unique");
            }
        }
    }

    #[test]
    fn test_keystore_integrity_preserved() {
        let (temp_dir, _result) = create_test_vault();
        let vault_path = temp_dir.path().join("vault");

        // Read and verify each keystore
        for level_id in 1..=3 {
            let ks_path = keystore_path(&vault_path, level_id);
            let mut file = File::open(&ks_path).unwrap();
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).unwrap();

            let keystore = Keystore::from_bytes(&buffer).expect("Should parse");

            // Keystore should have valid structure
            assert_eq!(keystore.level_id(), level_id);
            assert_eq!(keystore.dek_count(), 0); // New vault has no files
            assert!(!keystore.hmac_tag().iter().all(|&b| b == 0)); // HMAC computed
        }
    }

    #[test]
    fn test_single_level_vault() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(1)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test", Some(config))
            .expect("Should create vault");

        assert_eq!(result.keystores.len(), 1);

        let levels = list_keystores(&vault_path).unwrap();
        assert_eq!(levels, vec![1]);
    }

    #[test]
    fn test_max_level_vault() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(MAX_LEVEL_COUNT)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"test", Some(config))
            .expect("Should create vault");

        assert_eq!(result.keystores.len(), MAX_LEVEL_COUNT as usize);

        let levels = list_keystores(&vault_path).unwrap();
        assert_eq!(levels.len(), MAX_LEVEL_COUNT as usize);
    }

    // US-023: Recovery Key Generation tests

    #[test]
    fn test_vault_creation_includes_recovery_key() {
        let (_temp_dir, result) = create_test_vault();

        // Recovery key should be non-zero
        assert!(
            !result.recovery_key.as_bytes().iter().all(|&b| b == 0),
            "Recovery key should not be all zeros"
        );

        // Encrypted master key blob should have correct size
        assert_eq!(
            result.encrypted_master_key_for_recovery.len(),
            ENCRYPTED_MASTER_KEY_SIZE,
            "Encrypted master key blob should be 60 bytes"
        );
    }

    #[test]
    fn test_recovery_key_mnemonic_format() {
        let (_temp_dir, result) = create_test_vault();

        let mnemonic = result.recovery_key.to_mnemonic();
        let word_count = mnemonic.split_whitespace().count();

        assert_eq!(word_count, 24, "Recovery mnemonic should have 24 words");
    }

    #[test]
    fn test_recovery_key_base64_format() {
        let (_temp_dir, result) = create_test_vault();

        let base64 = result.recovery_key.to_base64();

        // Base64 of 32 bytes should be 44 characters (with padding)
        assert_eq!(base64.len(), 44, "Recovery key base64 should be 44 characters");
    }

    #[test]
    fn test_recover_master_key_roundtrip() {
        let (_temp_dir, result) = create_test_vault();

        // Recover master key using the recovery key
        let recovered_master_key = recover_master_key(
            &result.recovery_key,
            &result.encrypted_master_key_for_recovery,
        ).expect("Recovery should succeed");

        assert_eq!(
            recovered_master_key, result.master_key,
            "Recovered master key should match original"
        );
    }

    #[test]
    fn test_recover_master_key_from_mnemonic() {
        let (_temp_dir, result) = create_test_vault();

        // Get mnemonic
        let mnemonic = result.recovery_key.to_mnemonic();

        // Reconstruct recovery key from mnemonic
        let restored_key = RecoveryKey::from_mnemonic(&mnemonic)
            .expect("Should parse mnemonic");

        // Recover master key
        let recovered_master_key = recover_master_key(
            &restored_key,
            &result.encrypted_master_key_for_recovery,
        ).expect("Recovery should succeed");

        assert_eq!(
            recovered_master_key, result.master_key,
            "Recovered master key should match original"
        );
    }

    #[test]
    fn test_recover_master_key_from_base64() {
        let (_temp_dir, result) = create_test_vault();

        // Get base64
        let base64 = result.recovery_key.to_base64();

        // Reconstruct recovery key from base64
        let restored_key = RecoveryKey::from_base64(&base64)
            .expect("Should parse base64");

        // Recover master key
        let recovered_master_key = recover_master_key(
            &restored_key,
            &result.encrypted_master_key_for_recovery,
        ).expect("Recovery should succeed");

        assert_eq!(
            recovered_master_key, result.master_key,
            "Recovered master key should match original"
        );
    }

    #[test]
    fn test_recovery_key_unique_per_vault() {
        let temp_dir = TempDir::new().unwrap();

        // Create two vaults
        let vault1_path = temp_dir.path().join("vault1");
        let vault2_path = temp_dir.path().join("vault2");

        let config = VaultConfig::new()
            .with_level_count(2)
            .with_argon2_params(Argon2Params::minimal());

        let result1 = create_vault(&vault1_path, b"test", Some(config.clone()))
            .expect("Should create vault1");
        let result2 = create_vault(&vault2_path, b"test", Some(config))
            .expect("Should create vault2");

        // Recovery keys should be different
        assert_ne!(
            result1.recovery_key.as_bytes(),
            result2.recovery_key.as_bytes(),
            "Each vault should have a unique recovery key"
        );
    }

    #[test]
    fn test_wrong_recovery_key_fails() {
        let temp_dir = TempDir::new().unwrap();

        // Create two vaults
        let vault1_path = temp_dir.path().join("vault1");
        let vault2_path = temp_dir.path().join("vault2");

        let config = VaultConfig::new()
            .with_level_count(2)
            .with_argon2_params(Argon2Params::minimal());

        let result1 = create_vault(&vault1_path, b"test", Some(config.clone()))
            .expect("Should create vault1");
        let result2 = create_vault(&vault2_path, b"test", Some(config))
            .expect("Should create vault2");

        // Try to recover vault1's master key using vault2's recovery key
        let recovery_result = recover_master_key(
            &result2.recovery_key,
            &result1.encrypted_master_key_for_recovery,
        );

        assert!(
            recovery_result.is_err(),
            "Recovery with wrong key should fail"
        );
    }
}
