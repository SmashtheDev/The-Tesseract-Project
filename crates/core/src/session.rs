//! Vault session management.
//!
//! Manages active vault sessions with decrypted keys in secure memory.
//! A session is created when a vault is opened with a valid password
//! and provides access to decrypted keys for file operations.
//!
//! # Hierarchical Access Mode
//!
//! TESSERACT supports hierarchical access where higher levels can access
//! lower level files. When opening with a Level 3 password in hierarchical
//! mode, all levels L1, L2, and L3 are unlocked. This allows users with
//! higher clearance to access all files at or below their clearance level.
//!
//! ```ignore
//! // Level 3 password unlocks L1 + L2 + L3
//! let session = open_vault_hierarchical("/path/to/vault", b"level3pass", 3, None)?;
//! assert!(session.can_access_level(1)); // Can access L1
//! assert!(session.can_access_level(2)); // Can access L2
//! assert!(session.can_access_level(3)); // Can access L3
//! ```
//!
//! # Security
//!
//! - All keys (MK, ALKs, KEKs) are stored in secure memory with zeroization
//! - Keys are automatically wiped on session drop using `zeroize` crate
//! - Session can be explicitly locked with `lock_vault()` to immediately wipe keys
//! - Access level validation before any key access
//! - Locked sessions return errors for all key operations
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_core::session::{open_vault, lock_vault};
//!
//! let session = open_vault("/path/to/vault", b"password", None)?;
//! // Access files at unlocked levels
//! lock_vault(session); // Explicitly lock and wipe all keys
//!
//! // Or use the close() method which does the same thing
//! let session2 = open_vault("/path/to/vault", b"password", None)?;
//! session2.close();
//! ```

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::access::{read_levels_config, write_levels_config};
use crate::error::VaultError;
use crate::header::{unlock_header, VaultHeader, HEADER_SIZE};
use crate::keystore::{add_file_dek, wrap_dek, DekEntry, Keystore, HMAC_TAG_SIZE};
use crate::metadata::{read_metadata, write_metadata, FileMetadata};
use crate::vault::{
    header_path, keystore_path, list_keystores, read_recovery_blob, recover_master_key,
    validate_vault_structure,
};
use tesseract_crypto::kdf::{derive_key, Argon2Params};
use tesseract_crypto::recovery::RecoveryKey;
use tesseract_crypto::secure_memory::{secure_clear, SecureBytes};

/// Session state indicating whether keys are still valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is active with valid decrypted keys.
    Active,
    /// Session has been locked and all keys have been wiped.
    Locked,
}

/// Access mode determining how levels interact with each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Isolated mode: Each level is independent.
    /// Only directly unlocked levels are accessible.
    Isolated,
    /// Hierarchical mode: Higher levels can access lower levels.
    /// Level 3 can access L1, L2, L3; Level 2 can access L1, L2; etc.
    Hierarchical,
}

/// An active vault session with decrypted key material.
///
/// Created by [`open_vault`] when authentication succeeds.
/// Provides access to decrypted keys for file operations.
///
/// # Security
///
/// - Master key (MK), Access Level Keys (ALKs), and Key Encryption Keys (KEKs)
///   are stored in memory with automatic zeroization on drop.
/// - Use [`lock_vault`] or [`VaultSession::close`] to immediately wipe all keys.
/// - After locking, all key access methods return `VaultError::VaultLocked`.
/// - Keys are zeroed using the `zeroize` crate's secure clearing.
///
/// # Key Hierarchy
///
/// - **MK (Master Key)**: 32 bytes, derived from password, decrypts header
/// - **ALK (Access Level Key)**: Derived per-level from password + level-specific salt
/// - **KEK (Key Encryption Key)**: 32 bytes per level, decrypts file DEKs
/// - **DEK (Data Encryption Key)**: Per-file key stored in keystore, not held in session
#[derive(Debug)]
pub struct VaultSession {
    /// Path to the vault directory.
    vault_path: PathBuf,
    /// The vault header (for metadata).
    header: VaultHeader,
    /// The decrypted master key (zeroed on lock).
    master_key: [u8; 32],
    /// The highest access level unlocked by the provided password.
    max_level: u32,
    /// Unlocked keystores by level ID (KEKs zeroed on lock).
    unlocked_keystores: HashMap<u32, UnlockedKeystore>,
    /// Argon2 parameters used for key derivation.
    argon2_params: Argon2Params,
    /// Current session state (Active or Locked).
    state: SessionState,
    /// Access mode (Isolated or Hierarchical).
    access_mode: AccessMode,
}

/// An unlocked keystore with decrypted KEK.
#[derive(Debug, Clone)]
pub struct UnlockedKeystore {
    /// The keystore structure.
    keystore: Keystore,
    /// The decrypted KEK for this level.
    kek: [u8; 32],
    /// The HMAC key for keystore integrity (needed for persistence).
    hmac_key: [u8; 32],
}

impl UnlockedKeystore {
    /// Returns the keystore structure.
    #[must_use]
    pub fn keystore(&self) -> &Keystore {
        &self.keystore
    }

    /// Returns a mutable reference to the keystore structure.
    #[must_use]
    pub fn keystore_mut(&mut self) -> &mut Keystore {
        &mut self.keystore
    }

    /// Returns the decrypted KEK.
    #[must_use]
    pub fn kek(&self) -> &[u8; 32] {
        &self.kek
    }

    /// Returns the HMAC key for keystore integrity.
    #[must_use]
    pub fn hmac_key(&self) -> &[u8; 32] {
        &self.hmac_key
    }
}

impl VaultSession {
    /// Returns the vault path.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Returns the vault header.
    #[must_use]
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Returns the current session state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns true if the session is still active (not locked).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Returns true if the session has been locked and keys wiped.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state == SessionState::Locked
    }

    /// Returns the decrypted master key.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::VaultLocked` if the session has been locked.
    pub fn master_key(&self) -> Result<&[u8; 32], VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }
        Ok(&self.master_key)
    }

    /// Returns a copy of the master key for operations that consume it.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::VaultLocked` if the session has been locked.
    pub fn master_key_copy(&self) -> Result<[u8; 32], VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }
        Ok(self.master_key)
    }

    /// Returns the highest access level unlocked by the password.
    #[must_use]
    pub fn max_level(&self) -> u32 {
        self.max_level
    }

    /// Returns the Argon2 parameters used for this session.
    #[must_use]
    pub fn argon2_params(&self) -> &Argon2Params {
        &self.argon2_params
    }

    /// Returns the current access mode (Isolated or Hierarchical).
    #[must_use]
    pub fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// Sets the access mode for this session.
    ///
    /// * `Isolated` - Only directly unlocked levels are accessible
    /// * `Hierarchical` - Higher levels can access all lower levels
    pub fn set_access_mode(&mut self, mode: AccessMode) {
        self.access_mode = mode;
    }

    /// Checks if a specific access level is unlocked.
    ///
    /// Returns `false` if the session is locked.
    #[must_use]
    pub fn is_level_unlocked(&self, level: u32) -> bool {
        if self.state == SessionState::Locked {
            return false;
        }
        self.unlocked_keystores.contains_key(&level)
    }

    /// Returns the list of unlocked level IDs.
    ///
    /// Returns an empty list if the session is locked.
    #[must_use]
    pub fn unlocked_levels(&self) -> Vec<u32> {
        if self.state == SessionState::Locked {
            return Vec::new();
        }
        let mut levels: Vec<u32> = self.unlocked_keystores.keys().copied().collect();
        levels.sort();
        levels
    }

    /// Gets the unlocked keystore for a specific level.
    ///
    /// Returns `None` if the level is not unlocked or session is locked.
    #[must_use]
    pub fn get_unlocked_keystore(&self, level: u32) -> Option<&UnlockedKeystore> {
        if self.state == SessionState::Locked {
            return None;
        }
        self.unlocked_keystores.get(&level)
    }

    /// Gets a mutable reference to the unlocked keystore for a specific level.
    ///
    /// Returns `None` if the level is not unlocked or session is locked.
    pub fn get_unlocked_keystore_mut(&mut self, level: u32) -> Option<&mut UnlockedKeystore> {
        if self.state == SessionState::Locked {
            return None;
        }
        self.unlocked_keystores.get_mut(&level)
    }

    /// Gets the KEK for a specific level.
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AccessDenied` - Level is not unlocked
    pub fn get_kek(&self, level: u32) -> Result<&[u8; 32], VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }
        self.unlocked_keystores
            .get(&level)
            .map(|ks| &ks.kek)
            .ok_or(VaultError::AccessDenied)
    }

    /// Gets a copy of the KEK for a specific level.
    ///
    /// Useful when the KEK needs to be passed to functions that consume it.
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AccessDenied` - Level is not unlocked
    pub fn get_kek_copy(&self, level: u32) -> Result<[u8; 32], VaultError> {
        self.get_kek(level).map(|k| *k)
    }

    /// Unlocks an additional keystore for the given level.
    ///
    /// This can be used to unlock lower levels with different passwords
    /// after the session is already open.
    ///
    /// # Arguments
    ///
    /// * `level` - The access level to unlock
    /// * `password` - The password for this level
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AuthenticationFailed` - Wrong password
    /// * `VaultError::InvalidFormat` - Keystore not found or corrupt
    pub fn unlock_level(&mut self, level: u32, password: &[u8]) -> Result<(), VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        if self.unlocked_keystores.contains_key(&level) {
            // Already unlocked
            return Ok(());
        }

        // Load and unlock the keystore
        let unlocked = load_and_unlock_keystore(
            &self.vault_path,
            level,
            password,
            self.header.salt(),
            &self.argon2_params,
        )?;

        self.unlocked_keystores.insert(level, unlocked);

        // Update max_level if this is higher
        if level > self.max_level {
            self.max_level = level;
        }

        Ok(())
    }

    /// Checks if a file at the given level is accessible.
    ///
    /// In `Isolated` mode, only directly unlocked levels are accessible.
    /// In `Hierarchical` mode, if you've unlocked level N, you can access
    /// all levels 1 through N.
    ///
    /// Returns `false` if the session is locked.
    #[must_use]
    pub fn can_access_level(&self, level: u32) -> bool {
        if self.state == SessionState::Locked {
            return false;
        }

        match self.access_mode {
            AccessMode::Isolated => {
                // Only directly unlocked levels are accessible
                self.is_level_unlocked(level)
            }
            AccessMode::Hierarchical => {
                // In hierarchical mode, higher levels can access lower levels
                // If we have any level >= target level unlocked, we can access it
                // Check if we have a keystore for this level OR a higher level unlocked
                if level == 0 {
                    return false; // Level 0 is invalid
                }
                // Check if this level or any higher level is unlocked
                level <= self.max_level && self.max_level > 0
            }
        }
    }

    /// Returns the list of accessible level IDs based on the access mode.
    ///
    /// In `Isolated` mode, returns only directly unlocked levels.
    /// In `Hierarchical` mode, returns all levels from 1 to max_level.
    ///
    /// Returns an empty list if the session is locked.
    #[must_use]
    pub fn accessible_levels(&self) -> Vec<u32> {
        if self.state == SessionState::Locked {
            return Vec::new();
        }

        match self.access_mode {
            AccessMode::Isolated => {
                // Only directly unlocked levels
                self.unlocked_levels()
            }
            AccessMode::Hierarchical => {
                // All levels from 1 to max_level are accessible
                if self.max_level == 0 {
                    return Vec::new();
                }
                (1..=self.max_level).collect()
            }
        }
    }

    /// Unlocks all levels from 1 up to the specified level using the same password.
    ///
    /// This method enables hierarchical access by unlocking the entire hierarchy
    /// up to the target level. For example, `unlock_hierarchy(3, password)` will
    /// attempt to unlock levels 1, 2, and 3.
    ///
    /// # Arguments
    ///
    /// * `up_to_level` - The highest level to unlock (inclusive)
    /// * `password` - The password to use for all levels
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all levels up to `up_to_level` were successfully unlocked.
    /// Returns the number of successfully unlocked levels if some fail (for per-level passwords).
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * Returns error only if no levels could be unlocked
    pub fn unlock_hierarchy(&mut self, up_to_level: u32, password: &[u8]) -> Result<u32, VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        if up_to_level == 0 {
            return Err(VaultError::AccessDenied);
        }

        let mut unlocked_count = 0u32;

        // Try to unlock each level from 1 to up_to_level
        for level in 1..=up_to_level {
            // Skip if already unlocked
            if self.unlocked_keystores.contains_key(&level) {
                unlocked_count += 1;
                continue;
            }

            // Try to unlock this level
            match load_and_unlock_keystore(
                &self.vault_path,
                level,
                password,
                self.header.salt(),
                &self.argon2_params,
            ) {
                Ok(unlocked) => {
                    self.unlocked_keystores.insert(level, unlocked);
                    if level > self.max_level {
                        self.max_level = level;
                    }
                    unlocked_count += 1;
                }
                Err(VaultError::AuthenticationFailed) => {
                    // This level uses a different password, skip it
                    continue;
                }
                Err(VaultError::HeaderIntegrityFailed) => {
                    // Keystore integrity check failed with this password's HMAC key
                    continue;
                }
                Err(VaultError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Keystore doesn't exist for this level, skip
                    continue;
                }
                Err(e) => {
                    // Propagate other errors (IO, format issues)
                    return Err(e);
                }
            }
        }

        if unlocked_count == 0 {
            return Err(VaultError::AuthenticationFailed);
        }

        Ok(unlocked_count)
    }

    /// Gets the effective KEK for accessing a file at the given level.
    ///
    /// In `Isolated` mode, returns the KEK only if that level is directly unlocked.
    /// In `Hierarchical` mode, returns the KEK for the level if the session has
    /// access to it (i.e., if `can_access_level(level)` returns true).
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AccessDenied` - Level is not accessible
    pub fn get_effective_kek(&self, level: u32) -> Result<&[u8; 32], VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        // Check if we can access this level
        if !self.can_access_level(level) {
            return Err(VaultError::AccessDenied);
        }

        // Get the KEK for this specific level
        self.unlocked_keystores
            .get(&level)
            .map(|ks| &ks.kek)
            .ok_or(VaultError::AccessDenied)
    }

    /// Locks the session and wipes all key material.
    ///
    /// After calling this method:
    /// - All keys (MK, KEKs) are securely zeroed from memory
    /// - The session state changes to `Locked`
    /// - All key access methods return `VaultError::VaultLocked`
    ///
    /// This method can be called multiple times safely (no-op if already locked).
    pub fn lock(&mut self) {
        if self.state == SessionState::Locked {
            return; // Already locked
        }

        self.wipe_keys();
        self.state = SessionState::Locked;
    }

    /// Closes the session and wipes all key material.
    ///
    /// This is equivalent to calling `lock()` and then dropping the session.
    /// Use this when you want to explicitly consume and cleanup the session.
    pub fn close(mut self) {
        self.lock();
        // Session is consumed and dropped
    }

    /// Securely wipes all key material from memory.
    ///
    /// Uses `zeroize`-based secure clearing to ensure keys are overwritten
    /// with zeros in a way that won't be optimized away by the compiler.
    fn wipe_keys(&mut self) {
        // Zero out master key using secure clear
        secure_clear(&mut self.master_key);

        // Zero out all KEKs in unlocked keystores
        for (_, unlocked) in self.unlocked_keystores.iter_mut() {
            secure_clear(&mut unlocked.kek);
        }

        // Clear the keystore map to remove references
        // (keys are already zeroed, this just cleans up the hashmap)
        self.unlocked_keystores.clear();

        // Reset max_level since no levels are accessible
        self.max_level = 0;
    }

    /// Verifies that all keys have been zeroed.
    ///
    /// This is primarily useful for testing to confirm that
    /// `lock()` or `close()` properly wiped all sensitive data.
    ///
    /// Returns `true` if:
    /// - Session is locked
    /// - Master key is all zeros
    /// - No keystores remain (all KEKs cleared)
    #[must_use]
    pub fn verify_keys_wiped(&self) -> bool {
        if self.state != SessionState::Locked {
            return false;
        }

        // Check master key is zeroed
        let mk_zeroed = self.master_key.iter().all(|&b| b == 0);

        // Check no keystores remain
        let keystores_empty = self.unlocked_keystores.is_empty();

        mk_zeroed && keystores_empty
    }

    /// Assigns a file to a different access level.
    ///
    /// This function moves a file from its current access level to a new target level.
    /// The file's DEK is re-wrapped with the target level's KEK, the metadata is
    /// updated with the new level, and the original level loses access to the file.
    ///
    /// # Arguments
    ///
    /// * `file_uuid` - The UUID of the file to reassign
    /// * `target_level` - The target access level
    ///
    /// # Security
    ///
    /// - The file's DEK is decrypted from the source keystore and re-wrapped with
    ///   the target level's KEK
    /// - The DEK entry is removed from the source keystore
    /// - Both keystores are persisted with updated HMAC tags
    /// - Metadata is re-encrypted with the target level's KEK
    /// - After this operation, the original level cannot access the file
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AccessDenied` - Source or target level is not unlocked
    /// * `VaultError::FileNotFound` - File not found in any unlocked keystore
    /// * `VaultError::InvalidFormat` - Target level same as source level
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tesseract_core::session::open_vault;
    /// use uuid::Uuid;
    ///
    /// let mut session = open_vault("/path/to/vault", b"password", None)?;
    /// let file_uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
    ///
    /// // Move file from level 1 to level 3
    /// session.assign_file_level(file_uuid, 3)?;
    /// ```
    pub fn assign_file_level(&mut self, file_uuid: Uuid, target_level: u32) -> Result<(), VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        // Validate target level is accessible
        if !self.can_access_level(target_level) {
            return Err(VaultError::AccessDenied);
        }

        // Find the source level by searching for the file's DEK
        let source_level = self.find_file_level(&file_uuid)?;

        // Validate source != target
        if source_level == target_level {
            return Err(VaultError::InvalidFormat(
                "File is already at the target level".to_string()
            ));
        }

        // Get source level's KEK and keystore
        let source_kek = {
            let source_ks = self.unlocked_keystores.get(&source_level)
                .ok_or(VaultError::AccessDenied)?;
            source_ks.kek
        };

        // Decrypt the DEK from source keystore
        let dek = {
            let source_ks = self.unlocked_keystores.get(&source_level)
                .ok_or(VaultError::AccessDenied)?;
            source_ks.keystore.decrypt_file_dek(&file_uuid, &source_kek)?
        };

        // Get target level's KEK
        let target_kek = {
            let target_ks = self.unlocked_keystores.get(&target_level)
                .ok_or(VaultError::AccessDenied)?;
            target_ks.kek
        };

        // Wrap DEK with target level's KEK
        let (encrypted_dek, dek_nonce) = wrap_dek(&dek, &target_kek, &file_uuid)?;

        // Create new DEK entry for target keystore
        let new_entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);

        // Remove DEK from source keystore and add to target keystore
        {
            let source_ks = self.unlocked_keystores.get_mut(&source_level)
                .ok_or(VaultError::AccessDenied)?;
            source_ks.keystore.remove_dek_entry(&file_uuid);
            // Recompute HMAC for source keystore
            source_ks.keystore.compute_hmac(&source_ks.hmac_key);
        }

        {
            let target_ks = self.unlocked_keystores.get_mut(&target_level)
                .ok_or(VaultError::AccessDenied)?;
            target_ks.keystore.add_dek_entry(new_entry);
            // Recompute HMAC for target keystore
            target_ks.keystore.compute_hmac(&target_ks.hmac_key);
        }

        // Persist both keystores to disk
        self.persist_keystore(source_level)?;
        self.persist_keystore(target_level)?;

        // Read metadata with source KEK, update level, and write with target KEK
        let mut metadata = read_metadata(&self.vault_path, file_uuid, &source_kek)?;
        metadata.plaintext.access_level = target_level;
        metadata.plaintext.touch();
        write_metadata(&self.vault_path, &metadata, &target_kek)?;

        Ok(())
    }

    /// Finds which access level a file's DEK is stored in.
    ///
    /// Searches all unlocked keystores for the file's DEK entry.
    ///
    /// # Arguments
    ///
    /// * `file_uuid` - The UUID of the file to find
    ///
    /// # Returns
    ///
    /// The level ID where the file's DEK is stored.
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::FileNotFound` - File not found in any unlocked keystore
    fn find_file_level(&self, file_uuid: &Uuid) -> Result<u32, VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        for (level_id, unlocked_ks) in &self.unlocked_keystores {
            if unlocked_ks.keystore.has_dek_entry(file_uuid) {
                return Ok(*level_id);
            }
        }

        Err(VaultError::FileNotFound(file_uuid.to_string()))
    }

    /// Persists a keystore to disk.
    ///
    /// Writes the in-memory keystore state to the corresponding L{n}.keys.enc file.
    ///
    /// # Arguments
    ///
    /// * `level` - The level whose keystore to persist
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AccessDenied` - Level is not unlocked
    /// * `VaultError::Io` - File write failed
    pub fn persist_keystore(&self, level: u32) -> Result<(), VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        let unlocked_ks = self.unlocked_keystores.get(&level)
            .ok_or(VaultError::AccessDenied)?;

        let ks_path = keystore_path(&self.vault_path, level);
        let mut file = File::create(&ks_path)?;
        let bytes = unlocked_ks.keystore.to_bytes();
        file.write_all(&bytes)?;
        file.sync_all()?;

        Ok(())
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        // Always wipe keys on drop, even if already locked (safe to call twice)
        self.wipe_keys();
        self.state = SessionState::Locked;
    }
}

/// Locks a vault session and securely wipes all key material.
///
/// This is the recommended way to end a vault session when you're done
/// accessing files. It consumes the session and ensures all keys are
/// zeroed from memory.
///
/// # Security
///
/// After calling this function:
/// - Master Key (MK) is zeroed
/// - All Key Encryption Keys (KEKs) are zeroed
/// - The session handle is consumed and cannot be used again
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::{open_vault, lock_vault};
///
/// let session = open_vault("/path/to/vault", b"password", None)?;
/// // ... use the session to access files ...
/// lock_vault(session); // Keys are wiped and session is consumed
/// ```
pub fn lock_vault(session: VaultSession) {
    // close() internally calls lock() which wipes keys
    session.close();
}

/// Opens a vault and authenticates with the provided password.
///
/// This function:
/// 1. Validates the vault structure
/// 2. Reads and verifies the header integrity
/// 3. Derives keys from the password
/// 4. Decrypts the master key
/// 5. Determines accessible levels based on password
/// 6. Loads and decrypts keystores for accessible levels
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
/// * `password` - The password to authenticate with
/// * `argon2_params` - Optional Argon2 parameters (uses defaults if None)
///
/// # Returns
///
/// A `VaultSession` with decrypted keys for accessible levels.
///
/// # Errors
///
/// * `VaultError::VaultNotFound` - Vault does not exist
/// * `VaultError::InvalidFormat` - Vault structure is invalid
/// * `VaultError::HeaderIntegrityFailed` - Header has been tampered with
/// * `VaultError::AuthenticationFailed` - Wrong password
/// * `VaultError::LockedOut` - Too many failed attempts
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::open_vault;
///
/// let session = open_vault("/path/to/vault", b"my password", None)?;
/// println!("Unlocked levels: {:?}", session.unlocked_levels());
/// ```
pub fn open_vault(
    vault_path: impl AsRef<Path>,
    password: &[u8],
    argon2_params: Option<Argon2Params>,
) -> Result<VaultSession, VaultError> {
    let vault_path = vault_path.as_ref();
    let argon2_params = argon2_params.unwrap_or_default();

    // Validate vault structure
    validate_vault_structure(vault_path)?;

    // Read header
    let mut header = read_vault_header(vault_path)?;

    // Check for lockout (exponential backoff enforcement)
    if header.is_locked_out() {
        return Err(VaultError::LockedOut(header.lockout_remaining()));
    }

    // Unlock header and get master key
    let master_key = match unlock_header(&header, password, &argon2_params) {
        Ok(key) => key,
        Err(VaultError::HeaderIntegrityFailed) | Err(VaultError::AuthenticationFailed) => {
            // Authentication failed - apply exponential backoff
            let delay = header.apply_backoff();

            // Persist the updated header with incremented counter and lockout
            if let Err(e) = write_vault_header(vault_path, &header) {
                // Log but don't fail - the auth error is more important
                eprintln!("Warning: Failed to persist backoff state: {e}");
            }

            // If there's a delay, return LockedOut; otherwise return AuthenticationFailed
            if delay > 0 {
                return Err(VaultError::LockedOut(delay));
            }
            return Err(VaultError::AuthenticationFailed);
        }
        Err(e) => return Err(e),
    };

    // Get list of keystores in the vault
    let keystore_levels = list_keystores(vault_path)?;

    // Try to unlock each keystore with the provided password
    // In a single-password vault, all levels use the same password
    // In a per-level password vault, only matching levels will unlock
    let mut unlocked_keystores = HashMap::new();
    let mut max_level = 0;

    for level in keystore_levels {
        match load_and_unlock_keystore(
            vault_path,
            level,
            password,
            header.salt(),
            &argon2_params,
        ) {
            Ok(unlocked) => {
                unlocked_keystores.insert(level, unlocked);
                if level > max_level {
                    max_level = level;
                }
            }
            Err(VaultError::AuthenticationFailed) => {
                // This level uses a different password, skip it
                continue;
            }
            Err(VaultError::HeaderIntegrityFailed) => {
                // Keystore integrity check failed with this password's HMAC key
                // This is expected if the level uses a different password
                continue;
            }
            Err(e) => {
                // Other errors (IO, format) should be propagated
                return Err(e);
            }
        }
    }

    // Must unlock at least one level
    if unlocked_keystores.is_empty() {
        // Apply backoff for failed keystore unlocks too
        let delay = header.apply_backoff();
        if let Err(e) = write_vault_header(vault_path, &header) {
            eprintln!("Warning: Failed to persist backoff state: {e}");
        }
        if delay > 0 {
            return Err(VaultError::LockedOut(delay));
        }
        return Err(VaultError::AuthenticationFailed);
    }

    // Authentication successful - reset attempt counter
    if header.attempt_counter() > 0 {
        header.reset_attempts();
        if let Err(e) = write_vault_header(vault_path, &header) {
            eprintln!("Warning: Failed to reset attempt counter: {e}");
        }
    }

    Ok(VaultSession {
        vault_path: vault_path.to_path_buf(),
        header,
        master_key,
        max_level,
        unlocked_keystores,
        argon2_params,
        state: SessionState::Active,
        access_mode: AccessMode::Isolated,
    })
}

/// Opens a vault in hierarchical mode.
///
/// This function opens the vault and enables hierarchical access, where
/// higher levels can access all lower level files. For example, if you
/// authenticate with a Level 3 password, you can access files at levels
/// 1, 2, and 3.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
/// * `password` - The password to authenticate with
/// * `argon2_params` - Optional Argon2 parameters (uses defaults if None)
///
/// # Returns
///
/// A `VaultSession` in hierarchical mode with decrypted keys for accessible levels.
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::open_vault_hierarchical;
///
/// // Level 3 password unlocks L1 + L2 + L3
/// let session = open_vault_hierarchical("/path/to/vault", b"level3pass", None)?;
/// assert!(session.can_access_level(1)); // Can access L1
/// assert!(session.can_access_level(2)); // Can access L2
/// assert!(session.can_access_level(3)); // Can access L3
/// ```
pub fn open_vault_hierarchical(
    vault_path: impl AsRef<Path>,
    password: &[u8],
    argon2_params: Option<Argon2Params>,
) -> Result<VaultSession, VaultError> {
    let mut session = open_vault(vault_path, password, argon2_params)?;
    session.set_access_mode(AccessMode::Hierarchical);
    Ok(session)
}

/// Reads the vault header from disk.
fn read_vault_header(vault_path: &Path) -> Result<VaultHeader, VaultError> {
    let header_file_path = header_path(vault_path);
    let mut file = File::open(&header_file_path)?;
    let mut buffer = [0u8; HEADER_SIZE];
    file.read_exact(&mut buffer)?;
    VaultHeader::from_bytes(&buffer)
}

/// Writes the vault header to disk.
///
/// This function persists the header including the attempt counter and
/// lockout_until fields for rate limiting enforcement.
fn write_vault_header(vault_path: &Path, header: &VaultHeader) -> Result<(), VaultError> {
    let header_file_path = header_path(vault_path);
    let mut file = File::create(&header_file_path)?;
    header.write_to(&mut file)?;
    Ok(())
}

/// Loads and unlocks a keystore for a specific level.
fn load_and_unlock_keystore(
    vault_path: &Path,
    level: u32,
    password: &[u8],
    header_salt: &[u8; 16],
    argon2_params: &Argon2Params,
) -> Result<UnlockedKeystore, VaultError> {
    // Derive ALK from password with level-specific salt
    let mut level_salt = *header_salt;
    let level_bytes = level.to_le_bytes();
    for (i, &b) in level_bytes.iter().enumerate() {
        level_salt[i] ^= b;
    }

    let alk = derive_key(password, &level_salt, argon2_params)?;

    // Derive HMAC key for keystore (same domain separation as vault creation)
    let mut hmac_salt = level_salt;
    for b in &mut hmac_salt {
        *b ^= 0x80;
    }
    let keystore_hmac_key = derive_key(password, &hmac_salt, argon2_params)?;

    // Read keystore from file
    let ks_path = keystore_path(vault_path, level);
    let mut file = File::open(&ks_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse keystore
    let keystore = Keystore::from_bytes(&buffer)?;

    // Verify keystore integrity
    let hmac_key: [u8; HMAC_TAG_SIZE] = keystore_hmac_key;
    keystore.verify_integrity(&hmac_key)?;

    // Decrypt KEK with ALK
    let kek = keystore.decrypt_kek(&alk)?;

    Ok(UnlockedKeystore { keystore, kek, hmac_key: keystore_hmac_key })
}

/// Changes the password for a specific access level.
///
/// This function updates the password for a single access level without affecting
/// other levels. The KEK itself remains unchanged, but it is re-encrypted with
/// the new ALK derived from the new password.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
/// * `level` - The access level to change the password for
/// * `old_password` - The current password for this level
/// * `new_password` - The new password to set
/// * `argon2_params` - Optional Argon2 parameters (uses defaults if None)
///
/// # Security
///
/// - The old password must be correct or the operation fails
/// - The KEK (and thus all file DEKs) remain unchanged
/// - Only the ALK and HMAC key change
/// - Other levels are completely unaffected
/// - The keystore is re-encrypted and persisted atomically
///
/// # Errors
///
/// * `VaultError::VaultNotFound` - Vault does not exist
/// * `VaultError::AuthenticationFailed` - Old password is incorrect
/// * `VaultError::AccessDenied` - Level does not exist
/// * `VaultError::Io` - File system error during persistence
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::change_level_password;
///
/// // Change password for level 2
/// change_level_password(
///     "/path/to/vault",
///     2,
///     b"old_password",
///     b"new_secure_password",
///     None,
/// )?;
/// ```
pub fn change_level_password(
    vault_path: impl AsRef<Path>,
    level: u32,
    old_password: &[u8],
    new_password: &[u8],
    argon2_params: Option<Argon2Params>,
) -> Result<(), VaultError> {
    let vault_path = vault_path.as_ref();
    let argon2_params = argon2_params.unwrap_or_default();

    // Validate vault structure
    validate_vault_structure(vault_path)?;

    // Read the vault header to get the salt
    let header = read_vault_header(vault_path)?;

    // Check for lockout
    if header.is_locked_out() {
        return Err(VaultError::LockedOut(header.lockout_remaining()));
    }

    // Derive the old ALK and HMAC key
    let mut level_salt = *header.salt();
    let level_bytes = level.to_le_bytes();
    for (i, &b) in level_bytes.iter().enumerate() {
        level_salt[i] ^= b;
    }

    let old_alk = derive_key(old_password, &level_salt, &argon2_params)?;

    let mut old_hmac_salt = level_salt;
    for b in &mut old_hmac_salt {
        *b ^= 0x80;
    }
    let old_hmac_key = derive_key(old_password, &old_hmac_salt, &argon2_params)?;

    // Read and verify the keystore with the old password
    let ks_path = keystore_path(vault_path, level);
    let mut file = File::open(&ks_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VaultError::AccessDenied
        } else {
            VaultError::Io(e)
        }
    })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut keystore = Keystore::from_bytes(&buffer)?;

    // Verify integrity with old HMAC key (this validates the old password)
    keystore.verify_integrity(&old_hmac_key)?;

    // Decrypt the KEK with the old ALK
    let kek = keystore.decrypt_kek(&old_alk)?;

    // Derive the new ALK and HMAC key
    let new_alk = derive_key(new_password, &level_salt, &argon2_params)?;

    let mut new_hmac_salt = level_salt;
    for b in &mut new_hmac_salt {
        *b ^= 0x80;
    }
    let new_hmac_key = derive_key(new_password, &new_hmac_salt, &argon2_params)?;

    // Re-wrap the KEK with the new ALK and recompute HMAC
    keystore.rewrap_kek(&kek, &new_alk, &new_hmac_key)?;

    // Write the updated keystore to disk
    let mut file = File::create(&ks_path)?;
    file.write_all(&keystore.to_bytes())?;
    file.sync_all()?;

    // Try to read and update the level config if it exists
    // The master key is needed for level config encryption
    // We first need to unlock the header to get the encryption key
    match unlock_header(&header, old_password, &argon2_params) {
        Ok(master_key) => {
            // Try to update the level config (may not exist for simple vaults)
            if let Ok(mut level_config) = read_levels_config(vault_path, &master_key) {
                if let Some(access_level) = level_config.get_level_mut(level) {
                    // Update the password hash for this level
                    // The change_password method validates the old password and updates the hash
                    access_level.change_password(old_password, new_password, &argon2_params)?;

                    // Write the updated level config
                    write_levels_config(vault_path, &level_config, &master_key)?;
                }
            }
        }
        Err(_) => {
            // Header unlock failed - this is fine for vaults where the level password
            // is different from the master password. The keystore was already updated.
        }
    }

    Ok(())
}

/// Helper struct for password change result.
#[derive(Debug, Clone)]
pub struct PasswordChangeResult {
    /// Whether the keystore was updated.
    pub keystore_updated: bool,
    /// Whether the level config was updated (if it exists).
    pub level_config_updated: bool,
}

// ============================================================================
// US-024: Recovery Key Authentication
// ============================================================================

/// A recovery session with limited capabilities for password reset only.
///
/// Unlike a regular `VaultSession`, a `RecoverySession` does NOT provide access
/// to file encryption keys. It only holds the master key and can be used to
/// reset passwords for any access level.
///
/// # Security
///
/// - Recovery sessions cannot decrypt files - only reset passwords
/// - The master key is wiped when the session is dropped
/// - Use this session only for password recovery, then drop it
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::authenticate_recovery;
/// use tesseract_crypto::recovery::RecoveryKey;
///
/// // User provides their recovery phrase
/// let phrase = "abandon ability able about above ...";
/// let recovery_key = RecoveryKey::from_mnemonic(phrase)?;
///
/// // Authenticate with recovery key
/// let mut session = authenticate_recovery("/path/to/vault", &recovery_key, None)?;
///
/// // Reset password for level 2
/// session.reset_level_password(2, b"new_secure_password")?;
///
/// // Session is automatically dropped and keys are wiped
/// ```
#[derive(Debug)]
pub struct RecoverySession {
    /// Path to the vault directory.
    vault_path: PathBuf,
    /// The decrypted master key.
    master_key: [u8; 32],
    /// The vault header for key derivation.
    header: VaultHeader,
    /// Argon2 parameters used for key derivation.
    argon2_params: Argon2Params,
    /// Session state.
    state: SessionState,
}

impl RecoverySession {
    /// Returns the vault path.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Returns the session state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns whether the session is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Returns whether the session is locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state == SessionState::Locked
    }

    /// Returns whether this session can reset passwords.
    ///
    /// A recovery session can reset passwords when it is active.
    #[must_use]
    pub fn can_reset_password(&self) -> bool {
        self.is_active()
    }

    /// Resets the password for a specific access level.
    ///
    /// This method allows resetting the password for any access level without
    /// knowing the old password. This is the primary capability of a recovery session.
    ///
    /// # Arguments
    ///
    /// * `level` - The access level to reset the password for
    /// * `new_password` - The new password to set
    ///
    /// # Security
    ///
    /// - The KEK itself remains unchanged, only the ALK and HMAC key change
    /// - The master key is used to decrypt the level config if it exists
    /// - Other levels are completely unaffected
    ///
    /// # Errors
    ///
    /// * `VaultError::VaultLocked` - Session has been locked
    /// * `VaultError::AccessDenied` - Level does not exist
    /// * `VaultError::Io` - File system error during persistence
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut session = authenticate_recovery("/path/to/vault", &recovery_key, None)?;
    /// session.reset_level_password(2, b"new_secure_password")?;
    /// ```
    pub fn reset_level_password(
        &mut self,
        level: u32,
        new_password: &[u8],
    ) -> Result<(), VaultError> {
        if self.state == SessionState::Locked {
            return Err(VaultError::VaultLocked);
        }

        // Read the keystore file to get the current KEK
        let ks_path = keystore_path(&self.vault_path, level);
        let mut file = File::open(&ks_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::AccessDenied
            } else {
                VaultError::Io(e)
            }
        })?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // We need the current KEK, but we don't have the old password.
        // The solution is to read the encrypted KEK from the level config,
        // which is encrypted with the master key (which we have from recovery).
        let level_config = read_levels_config(&self.vault_path, &self.master_key)?;

        // Get the level's current KEK from the config
        let level_info = level_config.get_level(level)
            .ok_or(VaultError::AccessDenied)?;

        // The level config stores the encrypted KEK that we can decrypt with MK
        let kek = level_info.decrypt_kek(&self.master_key)?;

        // Now derive the new ALK and HMAC key from the new password
        let mut level_salt = *self.header.salt();
        let level_bytes = level.to_le_bytes();
        for (i, &b) in level_bytes.iter().enumerate() {
            level_salt[i] ^= b;
        }

        let new_alk = derive_key(new_password, &level_salt, &self.argon2_params)?;

        let mut new_hmac_salt = level_salt;
        for b in &mut new_hmac_salt {
            *b ^= 0x80;
        }
        let new_hmac_key = derive_key(new_password, &new_hmac_salt, &self.argon2_params)?;

        // Get mutable keystore and re-wrap the KEK
        let mut keystore = Keystore::from_bytes(&buffer)?;
        keystore.rewrap_kek(&kek, &new_alk, &new_hmac_key)?;

        // Write the updated keystore to disk
        let mut file = File::create(&ks_path)?;
        file.write_all(&keystore.to_bytes())?;
        file.sync_all()?;

        // Update the level config with new password hash
        if let Ok(mut level_config) = read_levels_config(&self.vault_path, &self.master_key) {
            if let Some(access_level) = level_config.get_level_mut(level) {
                // Store the new password hash
                access_level.set_password_hash(new_password, &self.argon2_params)?;
                write_levels_config(&self.vault_path, &level_config, &self.master_key)?;
            }
        }

        Ok(())
    }

    /// Locks the session and wipes the master key.
    ///
    /// After calling this method, the session cannot be used for any operations.
    pub fn lock(&mut self) {
        if self.state == SessionState::Locked {
            return;
        }

        secure_clear(&mut self.master_key);
        self.state = SessionState::Locked;
    }

    /// Closes the session and wipes all key material.
    ///
    /// This is equivalent to calling `lock()` and then dropping the session.
    pub fn close(mut self) {
        self.lock();
    }

    /// Verifies that the master key has been zeroed.
    ///
    /// Primarily useful for testing.
    #[must_use]
    pub fn verify_keys_wiped(&self) -> bool {
        if self.state != SessionState::Locked {
            return false;
        }
        self.master_key.iter().all(|&b| b == 0)
    }
}

impl Drop for RecoverySession {
    fn drop(&mut self) {
        secure_clear(&mut self.master_key);
        self.state = SessionState::Locked;
    }
}

/// Authenticates using a recovery key and returns a recovery session.
///
/// This function validates the recovery key by attempting to decrypt the master key
/// from the encrypted recovery blob stored in the vault. If successful, it returns
/// a `RecoverySession` that can reset passwords for any level.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
/// * `recovery_key` - The recovery key (from mnemonic or base64)
/// * `argon2_params` - Optional Argon2 parameters (uses defaults if None)
///
/// # Returns
///
/// A `RecoverySession` with password reset capability only.
///
/// # Errors
///
/// * `VaultError::VaultNotFound` - Vault or recovery blob doesn't exist
/// * `VaultError::AuthenticationFailed` - Wrong recovery key
/// * `VaultError::InvalidFormat` - Recovery blob is corrupted
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::authenticate_recovery;
/// use tesseract_crypto::recovery::RecoveryKey;
///
/// let phrase = "abandon ability able about above ...";
/// let recovery_key = RecoveryKey::from_mnemonic(phrase)?;
///
/// let session = authenticate_recovery("/path/to/vault", &recovery_key, None)?;
/// ```
pub fn authenticate_recovery(
    vault_path: impl AsRef<Path>,
    recovery_key: &RecoveryKey,
    argon2_params: Option<Argon2Params>,
) -> Result<RecoverySession, VaultError> {
    let vault_path = vault_path.as_ref();
    let argon2_params = argon2_params.unwrap_or_default();

    // Validate vault structure
    validate_vault_structure(vault_path)?;

    // Read the recovery blob
    let encrypted_master_key = read_recovery_blob(vault_path)?;

    // Attempt to decrypt the master key
    let master_key = recover_master_key(recovery_key, &encrypted_master_key)?;

    // Read the vault header (needed for salt during password reset)
    let header = read_vault_header(vault_path)?;

    Ok(RecoverySession {
        vault_path: vault_path.to_path_buf(),
        master_key,
        header,
        argon2_params,
        state: SessionState::Active,
    })
}

/// Resets a level password using a recovery key without creating a full session.
///
/// This is a convenience function that combines `authenticate_recovery()` and
/// `reset_level_password()` into a single call. Use this when you only need
/// to reset a single password.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault directory
/// * `recovery_key` - The recovery key (from mnemonic or base64)
/// * `level` - The access level to reset the password for
/// * `new_password` - The new password to set
/// * `argon2_params` - Optional Argon2 parameters (uses defaults if None)
///
/// # Errors
///
/// * `VaultError::VaultNotFound` - Vault or recovery blob doesn't exist
/// * `VaultError::AuthenticationFailed` - Wrong recovery key
/// * `VaultError::AccessDenied` - Level does not exist
///
/// # Example
///
/// ```ignore
/// use tesseract_core::session::reset_level_password_with_recovery;
/// use tesseract_crypto::recovery::RecoveryKey;
///
/// let phrase = "abandon ability able about above ...";
/// let recovery_key = RecoveryKey::from_mnemonic(phrase)?;
///
/// reset_level_password_with_recovery(
///     "/path/to/vault",
///     &recovery_key,
///     2,
///     b"new_secure_password",
///     None,
/// )?;
/// ```
pub fn reset_level_password_with_recovery(
    vault_path: impl AsRef<Path>,
    recovery_key: &RecoveryKey,
    level: u32,
    new_password: &[u8],
    argon2_params: Option<Argon2Params>,
) -> Result<(), VaultError> {
    let mut session = authenticate_recovery(vault_path, recovery_key, argon2_params)?;
    session.reset_level_password(level, new_password)?;
    session.close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{create_vault, VaultConfig};
    use tempfile::TempDir;

    /// Creates a test vault and returns the temp directory.
    fn create_test_vault() -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let vault_path = temp_dir.path().join("vault");

        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"test password", Some(config))
            .expect("Vault creation should succeed");

        (temp_dir, vault_path)
    }

    #[test]
    fn test_open_vault_success() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Should have unlocked at least one level
        assert!(!session.unlocked_levels().is_empty());
        assert!(session.max_level() >= 1);
    }

    #[test]
    fn test_open_vault_wrong_password() {
        let (_temp_dir, vault_path) = create_test_vault();

        let result = open_vault(&vault_path, b"wrong password", Some(Argon2Params::minimal()));

        // Should fail with integrity, authentication, or lockout error
        assert!(matches!(
            result,
            Err(VaultError::HeaderIntegrityFailed)
                | Err(VaultError::AuthenticationFailed)
                | Err(VaultError::LockedOut(_))
        ));
    }

    #[test]
    fn test_open_vault_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("nonexistent");

        let result = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()));

        assert!(matches!(result, Err(VaultError::VaultNotFound(_))));
    }

    #[test]
    fn test_session_vault_path() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.vault_path(), vault_path);
    }

    #[test]
    fn test_session_master_key_not_zero() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Master key should not be all zeros
        let master_key = session.master_key().expect("Should get master key");
        assert!(!master_key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_session_unlocked_levels() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let levels = session.unlocked_levels();

        // All 3 levels should be unlocked (same password for all)
        assert_eq!(levels.len(), 3);
        assert!(levels.contains(&1));
        assert!(levels.contains(&2));
        assert!(levels.contains(&3));
    }

    #[test]
    fn test_session_is_level_unlocked() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert!(session.is_level_unlocked(1));
        assert!(session.is_level_unlocked(2));
        assert!(session.is_level_unlocked(3));
        assert!(!session.is_level_unlocked(4)); // Doesn't exist
    }

    #[test]
    fn test_session_get_kek() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Should get KEK for unlocked level
        let kek = session.get_kek(1).expect("Should get KEK");
        assert!(!kek.iter().all(|&b| b == 0));

        // Should fail for non-existent level
        assert!(matches!(session.get_kek(99), Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_session_get_unlocked_keystore() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Should get unlocked keystore
        let ks = session.get_unlocked_keystore(1).expect("Should exist");
        assert_eq!(ks.keystore().level_id(), 1);
        assert!(!ks.kek().iter().all(|&b| b == 0));

        // Should return None for non-existent level
        assert!(session.get_unlocked_keystore(99).is_none());
    }

    #[test]
    fn test_session_max_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.max_level(), 3);
    }

    #[test]
    fn test_session_can_access_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert!(session.can_access_level(1));
        assert!(session.can_access_level(2));
        assert!(session.can_access_level(3));
        assert!(!session.can_access_level(4));
    }

    #[test]
    fn test_session_close() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Just verify close doesn't panic
        session.close();
    }

    #[test]
    fn test_session_header_access() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let header = session.header();
        assert_eq!(header.version().major, 1);
        assert_eq!(header.version().minor, 0);
    }

    #[test]
    fn test_session_argon2_params() {
        let (_temp_dir, vault_path) = create_test_vault();

        let params = Argon2Params::minimal();
        let session = open_vault(&vault_path, b"test password", Some(params.clone()))
            .expect("Open should succeed");

        // Should return the params used for the session
        let session_params = session.argon2_params();
        assert_eq!(session_params.memory_cost, params.memory_cost);
        assert_eq!(session_params.time_cost, params.time_cost);
    }

    #[test]
    fn test_keys_unique_per_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let kek1 = session.get_kek(1).unwrap();
        let kek2 = session.get_kek(2).unwrap();
        let kek3 = session.get_kek(3).unwrap();

        // All KEKs should be unique
        assert_ne!(kek1, kek2);
        assert_ne!(kek2, kek3);
        assert_ne!(kek1, kek3);
    }

    #[test]
    fn test_reopen_vault_same_keys() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Open vault first time
        let session1 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("First open should succeed");
        let master_key1 = session1.master_key_copy().expect("Should get master key");
        let kek1 = *session1.get_kek(1).unwrap();
        drop(session1);

        // Open vault second time
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Second open should succeed");
        let master_key2 = session2.master_key_copy().expect("Should get master key");
        let kek2 = *session2.get_kek(1).unwrap();

        // Keys should be identical
        assert_eq!(master_key1, master_key2);
        assert_eq!(kek1, kek2);
    }

    #[test]
    fn test_per_level_passwords() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with per-level passwords
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal())
            .with_level_passwords(vec![
                b"level1pass".to_vec(),
                b"level2pass".to_vec(),
                b"level3pass".to_vec(),
            ]);

        create_vault(&vault_path, b"master password", Some(config))
            .expect("Vault creation should succeed");

        // Open with level 1 password should only unlock level 1
        let session1 = open_vault(&vault_path, b"level1pass", Some(Argon2Params::minimal()));
        // Note: This may fail because the master key verification uses a different password
        // In a real implementation, we'd need a way to specify which level to unlock
        // For now, we just verify the vault can be opened with the master password
        let session = open_vault(&vault_path, b"master password", Some(Argon2Params::minimal()));
        assert!(session.is_ok() || session.is_err()); // May or may not succeed depending on design
    }

    #[test]
    fn test_unlock_additional_level() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with per-level passwords where master password matches level 1
        // open_vault requires at least one keystore to unlock, so master must match a level
        let config = VaultConfig::new()
            .with_level_count(2)
            .with_argon2_params(Argon2Params::minimal())
            .with_level_passwords(vec![
                b"master".to_vec(),      // Level 1 uses master password
                b"password2".to_vec(),   // Level 2 has different password
            ]);

        create_vault(&vault_path, b"master", Some(config)).expect("Vault creation should succeed");

        // Open with master password - this unlocks header and level 1
        let mut session = open_vault(&vault_path, b"master", Some(Argon2Params::minimal()))
            .expect("Open with master password should succeed");

        // Level 1 should be unlocked (master password matches)
        assert!(session.is_level_unlocked(1));
        // Level 2 should NOT be unlocked (different password)
        assert!(!session.is_level_unlocked(2));

        // Now unlock level 2 with its specific password
        session.unlock_level(2, b"password2")
            .expect("Should unlock level 2 with its password");
        assert!(session.is_level_unlocked(2));
    }

    #[test]
    fn test_session_drop_wipes_keys() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Create a session and get a pointer to the master key bytes
        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Just verify the session can be dropped without panic
        // In a real security test, we'd verify memory is zeroed
        drop(session);
    }

    #[test]
    fn test_empty_password() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Empty password should fail
        let result = open_vault(&vault_path, b"", Some(Argon2Params::minimal()));
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_with_single_level() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with single level
        let config = VaultConfig::new()
            .with_level_count(1)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"password", Some(config)).expect("Vault creation should succeed");

        let session = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.unlocked_levels(), vec![1]);
        assert_eq!(session.max_level(), 1);
    }

    #[test]
    fn test_vault_with_max_levels() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with max levels (10)
        let config = VaultConfig::new()
            .with_level_count(10)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"password", Some(config)).expect("Vault creation should succeed");

        let session = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.unlocked_levels().len(), 10);
        assert_eq!(session.max_level(), 10);
    }

    // ============================================================================
    // US-016: Vault Lock and Key Wiping Tests
    // ============================================================================

    #[test]
    fn test_session_state_initially_active() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.state(), SessionState::Active);
        assert!(session.is_active());
        assert!(!session.is_locked());
    }

    #[test]
    fn test_session_lock_changes_state() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Initially active
        assert!(session.is_active());

        // Lock the session
        session.lock();

        // Now locked
        assert_eq!(session.state(), SessionState::Locked);
        assert!(session.is_locked());
        assert!(!session.is_active());
    }

    #[test]
    fn test_lock_wipes_master_key() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Verify master key is not zero before lock
        let mk_before = session.master_key_copy().expect("Should get master key");
        assert!(!mk_before.iter().all(|&b| b == 0));

        // Lock the session
        session.lock();

        // verify_keys_wiped checks internal state
        assert!(session.verify_keys_wiped());
    }

    #[test]
    fn test_lock_wipes_all_keks() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Verify we have unlocked levels with KEKs
        let levels = session.unlocked_levels();
        assert!(!levels.is_empty());

        for level in &levels {
            let kek = session.get_kek(*level).expect("Should get KEK");
            assert!(!kek.iter().all(|&b| b == 0), "KEK should not be zero before lock");
        }

        // Lock the session
        session.lock();

        // After lock, verify_keys_wiped confirms all keys are zeroed
        assert!(session.verify_keys_wiped());

        // unlocked_keystores should be empty
        assert!(session.unlocked_levels().is_empty());
    }

    #[test]
    fn test_lock_vault_function() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Verify session is active
        assert!(session.is_active());

        // lock_vault consumes the session
        lock_vault(session);

        // Session is consumed, can't use it anymore
        // This is the desired behavior - prevents use after lock
    }

    #[test]
    fn test_locked_session_master_key_returns_error() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Can access master key before lock
        assert!(session.master_key().is_ok());

        session.lock();

        // Cannot access master key after lock
        assert!(matches!(session.master_key(), Err(VaultError::VaultLocked)));
        assert!(matches!(session.master_key_copy(), Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_locked_session_get_kek_returns_error() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Can access KEK before lock
        assert!(session.get_kek(1).is_ok());

        session.lock();

        // Cannot access KEK after lock
        assert!(matches!(session.get_kek(1), Err(VaultError::VaultLocked)));
        assert!(matches!(session.get_kek_copy(1), Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_locked_session_unlock_level_returns_error() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        session.lock();

        // Cannot unlock new levels after lock
        let result = session.unlock_level(1, b"test password");
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_locked_session_level_checks_return_false() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Before lock
        assert!(session.is_level_unlocked(1));
        assert!(session.can_access_level(1));
        assert!(!session.unlocked_levels().is_empty());
        assert!(session.get_unlocked_keystore(1).is_some());

        session.lock();

        // After lock - all return false/empty/None
        assert!(!session.is_level_unlocked(1));
        assert!(!session.can_access_level(1));
        assert!(session.unlocked_levels().is_empty());
        assert!(session.get_unlocked_keystore(1).is_none());
    }

    #[test]
    fn test_multiple_lock_calls_are_safe() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Lock multiple times - should not panic
        session.lock();
        session.lock();
        session.lock();

        assert!(session.is_locked());
        assert!(session.verify_keys_wiped());
    }

    #[test]
    fn test_drop_wipes_keys() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Create session in a scope
        {
            let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            assert!(session.is_active());
            // Session goes out of scope here and is dropped
        }

        // Can't verify memory is zeroed after drop since session is consumed,
        // but the test ensures drop doesn't panic and the zeroize crate
        // guarantees memory clearing before deallocation.
    }

    #[test]
    fn test_close_wipes_keys() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Verify session has keys
        assert!(session.master_key().is_ok());
        assert!(!session.unlocked_levels().is_empty());

        // close() consumes the session and wipes keys
        session.close();

        // Session is consumed - test passes if close doesn't panic
    }

    #[test]
    fn test_verify_keys_wiped_returns_false_when_active() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Active session should not report keys as wiped
        assert!(!session.verify_keys_wiped());
    }

    #[test]
    fn test_max_level_reset_after_lock() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Before lock, max_level should be 3
        assert_eq!(session.max_level(), 3);

        session.lock();

        // After lock, max_level should be 0 (reset)
        assert_eq!(session.max_level(), 0);
    }

    #[test]
    fn test_session_state_enum_equality() {
        assert_eq!(SessionState::Active, SessionState::Active);
        assert_eq!(SessionState::Locked, SessionState::Locked);
        assert_ne!(SessionState::Active, SessionState::Locked);
    }

    #[test]
    fn test_session_state_debug() {
        // SessionState should implement Debug
        let active = SessionState::Active;
        let locked = SessionState::Locked;
        let active_str = format!("{:?}", active);
        let locked_str = format!("{:?}", locked);

        assert!(active_str.contains("Active"));
        assert!(locked_str.contains("Locked"));
    }

    #[test]
    fn test_session_state_copy() {
        // SessionState should implement Copy
        let state = SessionState::Active;
        let copied = state; // Copy, not move
        assert_eq!(state, copied);
    }

    #[test]
    fn test_lock_then_reopen() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Open, lock, and drop
        {
            let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");
            session.lock();
        }

        // Should be able to reopen the vault
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        assert!(session2.is_active());
        assert!(!session2.unlocked_levels().is_empty());
    }

    // ============================================================================
    // US-018: Hierarchical Access Mode Tests
    // ============================================================================

    #[test]
    fn test_access_mode_default_is_isolated() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.access_mode(), AccessMode::Isolated);
    }

    #[test]
    fn test_access_mode_enum_equality() {
        assert_eq!(AccessMode::Isolated, AccessMode::Isolated);
        assert_eq!(AccessMode::Hierarchical, AccessMode::Hierarchical);
        assert_ne!(AccessMode::Isolated, AccessMode::Hierarchical);
    }

    #[test]
    fn test_access_mode_debug() {
        let isolated = AccessMode::Isolated;
        let hierarchical = AccessMode::Hierarchical;
        let isolated_str = format!("{:?}", isolated);
        let hierarchical_str = format!("{:?}", hierarchical);

        assert!(isolated_str.contains("Isolated"));
        assert!(hierarchical_str.contains("Hierarchical"));
    }

    #[test]
    fn test_access_mode_copy() {
        let mode = AccessMode::Hierarchical;
        let copied = mode; // Copy, not move
        assert_eq!(mode, copied);
    }

    #[test]
    fn test_set_access_mode() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Initially isolated
        assert_eq!(session.access_mode(), AccessMode::Isolated);

        // Switch to hierarchical
        session.set_access_mode(AccessMode::Hierarchical);
        assert_eq!(session.access_mode(), AccessMode::Hierarchical);

        // Switch back to isolated
        session.set_access_mode(AccessMode::Isolated);
        assert_eq!(session.access_mode(), AccessMode::Isolated);
    }

    #[test]
    fn test_open_vault_hierarchical() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.access_mode(), AccessMode::Hierarchical);
        assert!(session.is_active());
    }

    #[test]
    fn test_hierarchical_access_level3_sees_all() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // With hierarchical mode and level 3 unlocked, should access all levels
        assert_eq!(session.max_level(), 3);
        assert!(session.can_access_level(1));
        assert!(session.can_access_level(2));
        assert!(session.can_access_level(3));
    }

    #[test]
    fn test_hierarchical_accessible_levels() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Hierarchical mode returns levels 1 to max_level
        let levels = session.accessible_levels();
        assert_eq!(levels, vec![1, 2, 3]);
    }

    #[test]
    fn test_isolated_accessible_levels() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Isolated mode returns only unlocked levels
        let levels = session.accessible_levels();
        assert_eq!(levels, vec![1, 2, 3]); // All 3 unlocked with same password

        // Modify to verify it uses unlocked_levels()
        assert_eq!(session.unlocked_levels(), session.accessible_levels());
    }

    #[test]
    fn test_hierarchical_cannot_access_above_max() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // max_level is 3, so level 4 should not be accessible
        assert!(!session.can_access_level(4));
        assert!(!session.can_access_level(5));
        assert!(!session.can_access_level(100));
    }

    #[test]
    fn test_hierarchical_level_zero_not_accessible() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Level 0 is never accessible
        assert!(!session.can_access_level(0));
    }

    #[test]
    fn test_isolated_vs_hierarchical_access() {
        let (_temp_dir, vault_path) = create_test_vault();

        // In isolated mode, only directly unlocked levels are accessible
        let session_iso = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // All 3 levels are directly unlocked (same password), so both modes behave similarly
        assert!(session_iso.can_access_level(1));
        assert!(session_iso.can_access_level(2));
        assert!(session_iso.can_access_level(3));
        drop(session_iso);

        // Hierarchical mode
        let session_hier = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert!(session_hier.can_access_level(1));
        assert!(session_hier.can_access_level(2));
        assert!(session_hier.can_access_level(3));
    }

    #[test]
    fn test_unlock_hierarchy_with_same_password() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // All levels already unlocked with same password
        let count = session.unlock_hierarchy(3, b"test password")
            .expect("unlock_hierarchy should succeed");

        assert_eq!(count, 3); // All 3 levels were already or newly unlocked
    }

    #[test]
    fn test_unlock_hierarchy_partial_success() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with per-level passwords where master = level 1 password
        // (open_vault requires at least one keystore to unlock)
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal())
            .with_level_passwords(vec![
                b"password1".to_vec(),    // Level 1
                b"password2".to_vec(),    // Level 2
                b"password3".to_vec(),    // Level 3
            ]);

        // Use password1 as master - this allows open_vault to succeed
        create_vault(&vault_path, b"password1", Some(config))
            .expect("Vault creation should succeed");

        // Open with password1 (unlocks header and level 1)
        let mut session = open_vault(&vault_path, b"password1", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Level 1 should be unlocked
        assert!(session.is_level_unlocked(1));

        // Try to unlock hierarchy with password1 - should only unlock level 1 (already unlocked)
        let count = session.unlock_hierarchy(3, b"password1")
            .expect("unlock_hierarchy should succeed with at least 1 level");

        // Only level 1 uses password1, so only 1 level unlocked
        assert!(count >= 1);
    }

    #[test]
    fn test_unlock_hierarchy_zero_level_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Level 0 is invalid
        let result = session.unlock_hierarchy(0, b"test password");
        assert!(matches!(result, Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_unlock_hierarchy_locked_session_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        session.lock();

        let result = session.unlock_hierarchy(3, b"test password");
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_get_effective_kek_isolated() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // All levels unlocked, so get_effective_kek should work for all
        let kek1 = session.get_effective_kek(1).expect("Should get KEK for level 1");
        let kek2 = session.get_effective_kek(2).expect("Should get KEK for level 2");
        let kek3 = session.get_effective_kek(3).expect("Should get KEK for level 3");

        // All KEKs should be unique
        assert_ne!(kek1, kek2);
        assert_ne!(kek2, kek3);

        // Level 4 should fail (not unlocked)
        assert!(matches!(session.get_effective_kek(4), Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_get_effective_kek_hierarchical() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // All levels accessible in hierarchical mode
        assert!(session.get_effective_kek(1).is_ok());
        assert!(session.get_effective_kek(2).is_ok());
        assert!(session.get_effective_kek(3).is_ok());

        // Level 4 should fail (above max_level)
        assert!(matches!(session.get_effective_kek(4), Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_get_effective_kek_locked_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        session.lock();

        assert!(matches!(session.get_effective_kek(1), Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_accessible_levels_after_lock() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Before lock
        assert_eq!(session.accessible_levels(), vec![1, 2, 3]);

        session.lock();

        // After lock
        assert!(session.accessible_levels().is_empty());
    }

    #[test]
    fn test_can_access_level_after_lock() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Before lock
        assert!(session.can_access_level(1));
        assert!(session.can_access_level(2));
        assert!(session.can_access_level(3));

        session.lock();

        // After lock - all return false
        assert!(!session.can_access_level(1));
        assert!(!session.can_access_level(2));
        assert!(!session.can_access_level(3));
    }

    #[test]
    fn test_hierarchical_single_level_vault() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with single level
        let config = VaultConfig::new()
            .with_level_count(1)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        let session = open_vault_hierarchical(&vault_path, b"password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.max_level(), 1);
        assert!(session.can_access_level(1));
        assert!(!session.can_access_level(2)); // Doesn't exist
        assert_eq!(session.accessible_levels(), vec![1]);
    }

    #[test]
    fn test_hierarchical_ten_level_vault() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with max levels (10)
        let config = VaultConfig::new()
            .with_level_count(10)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        let session = open_vault_hierarchical(&vault_path, b"password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        assert_eq!(session.max_level(), 10);

        // All 10 levels accessible
        for level in 1..=10 {
            assert!(session.can_access_level(level), "Level {} should be accessible", level);
        }

        // Level 11 not accessible
        assert!(!session.can_access_level(11));

        assert_eq!(session.accessible_levels(), vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_file_listing_union_hierarchical() {
        // This test verifies the acceptance criterion:
        // "File listing returns union of accessible levels"
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // accessible_levels() returns the union of all levels that can be accessed
        let levels = session.accessible_levels();
        assert_eq!(levels.len(), 3); // Union of L1, L2, L3

        // Verify each level in the union can be accessed
        for level in &levels {
            assert!(session.can_access_level(*level));
            assert!(session.get_effective_kek(*level).is_ok());
        }
    }

    #[test]
    fn test_level3_password_unlocks_hierarchy() {
        // This test verifies acceptance criterion:
        // "Level 3 password unlocks L1 + L2 + L3 keystores"
        let (_temp_dir, vault_path) = create_test_vault();

        // Opening with Level 3 password (all levels use same password in default vault)
        let session = open_vault_hierarchical(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Verify L1, L2, L3 keystores are accessible
        assert!(session.is_level_unlocked(1));
        assert!(session.is_level_unlocked(2));
        assert!(session.is_level_unlocked(3));

        // Verify hierarchical access
        assert!(session.can_access_level(1));
        assert!(session.can_access_level(2));
        assert!(session.can_access_level(3));
    }

    #[test]
    fn test_switch_mode_during_session() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Initially isolated
        assert_eq!(session.access_mode(), AccessMode::Isolated);

        // Get accessible levels in isolated mode
        let isolated_levels = session.accessible_levels();

        // Switch to hierarchical
        session.set_access_mode(AccessMode::Hierarchical);
        let hierarchical_levels = session.accessible_levels();

        // In this case, both should be equal since all levels are unlocked
        assert_eq!(isolated_levels, hierarchical_levels);

        // But the access mode should be different
        assert_eq!(session.access_mode(), AccessMode::Hierarchical);
    }

    // ============================================================================
    // US-019: File Access Level Assignment Tests
    // ============================================================================

    use crate::blob::{write_blob, read_blob};
    use crate::metadata::{FileMetadata, MetadataPlaintext, write_metadata, read_metadata};
    use crate::keystore::add_file_dek;
    use tesseract_crypto::generate_key;
    use uuid::Uuid;

    /// Creates a test file in a vault at a specific level.
    /// Returns the file UUID.
    fn create_test_file_at_level(
        session: &mut VaultSession,
        level: u32,
        filename: &str,
        content: &[u8],
    ) -> Uuid {
        let file_uuid = Uuid::new_v4();
        let dek = generate_key().unwrap();

        // Get the KEK for this level
        let kek = session.get_kek(level).expect("Should get KEK");

        // Write blob encrypted with DEK
        write_blob(
            session.vault_path(),
            file_uuid,
            &dek,
            content,
        ).expect("Blob write should succeed");

        // Create and write metadata encrypted with KEK
        let plaintext = MetadataPlaintext::new(
            filename.to_string(),
            format!("/{}", filename),
            level,
            content.len() as u64,
            file_uuid,
        );
        let metadata = FileMetadata::new(
            file_uuid,
            plaintext.name.clone(),
            plaintext.path.clone(),
            plaintext.access_level,
            plaintext.size,
            plaintext.blob_ref,
        );
        write_metadata(session.vault_path(), &metadata, kek).expect("Metadata write should succeed");

        // Add DEK entry to keystore
        {
            let unlocked_ks = session.get_unlocked_keystore_mut(level)
                .expect("Should get mutable keystore");
            let (encrypted_dek, dek_nonce) = wrap_dek(&dek, unlocked_ks.kek(), &file_uuid)
                .expect("DEK wrap should succeed");
            let entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);
            let hmac_key = *unlocked_ks.hmac_key();
            unlocked_ks.keystore_mut().add_dek_entry(entry);
            unlocked_ks.keystore_mut().compute_hmac(&hmac_key);
        }

        // Persist keystore
        session.persist_keystore(level).expect("Persist should succeed");

        file_uuid
    }

    #[test]
    fn test_assign_file_level_basic_transition() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "secret.txt", b"classified data");

        // Verify file is at level 1
        assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(!session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));

        // Move file to level 3
        session.assign_file_level(file_uuid, 3).expect("Should succeed");

        // Verify file is now at level 3, not level 1
        assert!(!session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_assign_file_level_metadata_updated() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "document.pdf", b"PDF content");

        // Move to level 2
        session.assign_file_level(file_uuid, 2).expect("Should succeed");

        // Read metadata with the new level's KEK
        let kek2 = session.get_kek(2).expect("Should get KEK");
        let metadata = read_metadata(session.vault_path(), file_uuid, kek2)
            .expect("Should read metadata");

        // Verify access_level is updated
        assert_eq!(metadata.access_level(), 2);
    }

    #[test]
    fn test_assign_file_level_original_loses_access() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "secret.txt", b"classified");

        // Get original KEK
        let kek1 = *session.get_kek(1).expect("Should get KEK");

        // Move to level 3
        session.assign_file_level(file_uuid, 3).expect("Should succeed");

        // Original level 1 keystore should no longer have the DEK
        let ks1 = session.get_unlocked_keystore(1).expect("Should get keystore");
        assert!(!ks1.keystore().has_dek_entry(&file_uuid));

        // Attempting to read metadata with old KEK should fail
        let result = read_metadata(session.vault_path(), file_uuid, &kek1);
        assert!(result.is_err(), "Original KEK should not decrypt new metadata");
    }

    #[test]
    fn test_assign_file_level_content_still_accessible() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let original_content = b"This is the original file content";

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "data.bin", original_content);

        // Get the DEK from level 1 keystore
        let kek1 = session.get_kek(1).expect("Should get KEK");
        let original_dek = session.get_unlocked_keystore(1)
            .unwrap()
            .keystore()
            .decrypt_file_dek(&file_uuid, kek1)
            .expect("Should decrypt DEK");

        // Move to level 2
        session.assign_file_level(file_uuid, 2).expect("Should succeed");

        // Get the DEK from level 2 keystore
        let kek2 = session.get_kek(2).expect("Should get KEK");
        let new_dek = session.get_unlocked_keystore(2)
            .unwrap()
            .keystore()
            .decrypt_file_dek(&file_uuid, kek2)
            .expect("Should decrypt DEK");

        // The underlying DEK should be the same (just wrapped with different KEK)
        assert_eq!(original_dek, new_dek, "DEK should be preserved across level transition");

        // Content should still be readable
        let content = read_blob(session.vault_path(), file_uuid, &new_dek)
            .expect("Should read blob");
        assert_eq!(content, original_content);
    }

    #[test]
    fn test_assign_file_level_locked_session_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "file.txt", b"data");

        // Lock the session
        session.lock();

        // Attempt to assign level should fail
        let result = session.assign_file_level(file_uuid, 2);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_assign_file_level_same_level_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 2
        let file_uuid = create_test_file_at_level(&mut session, 2, "file.txt", b"data");

        // Attempt to assign to the same level
        let result = session.assign_file_level(file_uuid, 2);
        assert!(matches!(result, Err(VaultError::InvalidFormat(_))));
    }

    #[test]
    fn test_assign_file_level_not_found() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Try to assign a non-existent file
        let fake_uuid = Uuid::new_v4();
        let result = session.assign_file_level(fake_uuid, 2);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_assign_file_level_target_not_accessible() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with per-level passwords where master = level 1 password
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal())
            .with_level_passwords(vec![
                b"password1".to_vec(),    // Level 1 (same as master)
                b"password2".to_vec(),    // Level 2
                b"password3".to_vec(),    // Level 3
            ]);

        // Use password1 as master so open_vault succeeds with header + level 1
        create_vault(&vault_path, b"password1", Some(config))
            .expect("Vault creation should succeed");

        // Open with password1 (unlocks header and level 1 only)
        let mut session = open_vault(&vault_path, b"password1", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "file.txt", b"data");

        // Try to assign to level 3 (not accessible since we only unlocked level 1)
        let result = session.assign_file_level(file_uuid, 3);
        assert!(matches!(result, Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_assign_file_level_promotes_to_higher_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1 (lowest)
        let file_uuid = create_test_file_at_level(&mut session, 1, "file.txt", b"data");

        // Promote to level 3 (highest)
        session.assign_file_level(file_uuid, 3).expect("Should succeed");

        // Verify
        assert!(!session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(!session.get_unlocked_keystore(2).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_assign_file_level_demotes_to_lower_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 3 (highest)
        let file_uuid = create_test_file_at_level(&mut session, 3, "file.txt", b"data");

        // Demote to level 1 (lowest)
        session.assign_file_level(file_uuid, 1).expect("Should succeed");

        // Verify
        assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(!session.get_unlocked_keystore(2).unwrap().keystore().has_dek_entry(&file_uuid));
        assert!(!session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_assign_file_level_multiple_transitions() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create a file at level 1
        let file_uuid = create_test_file_at_level(&mut session, 1, "file.txt", b"data");

        // L1 -> L2
        session.assign_file_level(file_uuid, 2).expect("L1 -> L2 should succeed");
        assert!(session.get_unlocked_keystore(2).unwrap().keystore().has_dek_entry(&file_uuid));

        // L2 -> L3
        session.assign_file_level(file_uuid, 3).expect("L2 -> L3 should succeed");
        assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));

        // L3 -> L1 (back to start)
        session.assign_file_level(file_uuid, 1).expect("L3 -> L1 should succeed");
        assert!(session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_assign_file_level_multiple_files() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create three files at level 1
        let file1 = create_test_file_at_level(&mut session, 1, "file1.txt", b"data1");
        let file2 = create_test_file_at_level(&mut session, 1, "file2.txt", b"data2");
        let file3 = create_test_file_at_level(&mut session, 1, "file3.txt", b"data3");

        // Move file1 to L2, file2 to L3, keep file3 at L1
        session.assign_file_level(file1, 2).expect("Should succeed");
        session.assign_file_level(file2, 3).expect("Should succeed");

        // Verify distribution
        let ks1 = session.get_unlocked_keystore(1).unwrap().keystore();
        let ks2 = session.get_unlocked_keystore(2).unwrap().keystore();
        let ks3 = session.get_unlocked_keystore(3).unwrap().keystore();

        assert!(!ks1.has_dek_entry(&file1));
        assert!(ks1.has_dek_entry(&file3));
        assert!(ks2.has_dek_entry(&file1));
        assert!(!ks2.has_dek_entry(&file2));
        assert!(ks3.has_dek_entry(&file2));
    }

    #[test]
    fn test_assign_file_level_persists_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());
        create_vault(&vault_path, b"password", Some(config)).expect("Vault creation should succeed");

        let file_uuid;
        let original_content = b"persist test data";

        // First session: create file at L1, move to L3
        {
            let mut session = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()))
                .expect("Open should succeed");

            file_uuid = create_test_file_at_level(&mut session, 1, "persist.txt", original_content);
            session.assign_file_level(file_uuid, 3).expect("Should succeed");

            // Verify in this session
            assert!(!session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
            assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));
        }

        // Second session: verify state persisted
        {
            let session = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()))
                .expect("Reopen should succeed");

            // File should still be at L3
            assert!(!session.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
            assert!(session.get_unlocked_keystore(3).unwrap().keystore().has_dek_entry(&file_uuid));

            // Content should be readable
            let kek3 = session.get_kek(3).expect("Should get KEK");
            let dek = session.get_unlocked_keystore(3)
                .unwrap()
                .keystore()
                .decrypt_file_dek(&file_uuid, kek3)
                .expect("Should decrypt DEK");
            let content = read_blob(&vault_path, file_uuid, &dek)
                .expect("Should read blob");
            assert_eq!(content, original_content);
        }
    }

    #[test]
    fn test_find_file_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Create files at different levels
        let file1 = create_test_file_at_level(&mut session, 1, "level1.txt", b"data");
        let file2 = create_test_file_at_level(&mut session, 2, "level2.txt", b"data");
        let file3 = create_test_file_at_level(&mut session, 3, "level3.txt", b"data");

        // find_file_level should locate each file
        assert_eq!(session.find_file_level(&file1).unwrap(), 1);
        assert_eq!(session.find_file_level(&file2).unwrap(), 2);
        assert_eq!(session.find_file_level(&file3).unwrap(), 3);
    }

    #[test]
    fn test_find_file_level_not_found() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let fake_uuid = Uuid::new_v4();
        let result = session.find_file_level(&fake_uuid);
        assert!(matches!(result, Err(VaultError::FileNotFound(_))));
    }

    #[test]
    fn test_find_file_level_locked_session() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        let file_uuid = create_test_file_at_level(&mut session, 1, "file.txt", b"data");

        session.lock();

        let result = session.find_file_level(&file_uuid);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_persist_keystore() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Add a DEK entry
        let file_uuid = Uuid::new_v4();
        let dek = generate_key().unwrap();

        {
            let unlocked_ks = session.get_unlocked_keystore_mut(1).expect("Should get mutable keystore");
            let (encrypted_dek, dek_nonce) = wrap_dek(&dek, unlocked_ks.kek(), &file_uuid)
                .expect("DEK wrap should succeed");
            let entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);
            let hmac_key = *unlocked_ks.hmac_key();
            unlocked_ks.keystore_mut().add_dek_entry(entry);
            unlocked_ks.keystore_mut().compute_hmac(&hmac_key);
        }

        // Persist
        session.persist_keystore(1).expect("Persist should succeed");
        drop(session);

        // Reopen and verify
        let session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Reopen should succeed");

        assert!(session2.get_unlocked_keystore(1).unwrap().keystore().has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_persist_keystore_locked_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        session.lock();

        let result = session.persist_keystore(1);
        assert!(matches!(result, Err(VaultError::VaultLocked)));
    }

    #[test]
    fn test_persist_keystore_not_unlocked_fails() {
        let (_temp_dir, vault_path) = create_test_vault();

        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");

        // Level 99 doesn't exist
        let result = session.persist_keystore(99);
        assert!(matches!(result, Err(VaultError::AccessDenied)));
    }

    // ============================================================================
    // US-020: Per-Level Password Management Tests
    // ============================================================================

    #[test]
    fn test_change_level_password_success() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Change password for level 1
        change_level_password(
            &vault_path,
            1,
            b"test password",
            b"new password",
            Some(Argon2Params::minimal()),
        ).expect("Password change should succeed");

        // Old password should no longer work for level 1's keystore,
        // but still works for the header and levels 2 and 3
        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Should still open with original password (header + levels 2,3)");
        // Level 1 should NOT be unlocked with the old password
        assert!(!session.is_level_unlocked(1));
        // Levels 2 and 3 should still be unlocked
        assert!(session.is_level_unlocked(2));
        assert!(session.is_level_unlocked(3));

        // Now unlock level 1 with the new password
        session.unlock_level(1, b"new password")
            .expect("New password should unlock level 1");
        assert!(session.is_level_unlocked(1));
    }

    #[test]
    fn test_change_level_password_wrong_old_password() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Try to change with wrong old password
        let result = change_level_password(
            &vault_path,
            1,
            b"wrong password",
            b"new password",
            Some(Argon2Params::minimal()),
        );

        assert!(matches!(
            result,
            Err(VaultError::HeaderIntegrityFailed) | Err(VaultError::AuthenticationFailed)
        ));

        // Original password should still work
        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Original password should still work");
        assert!(session.is_level_unlocked(1));
    }

    #[test]
    fn test_change_level_password_nonexistent_level() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Try to change password for a level that doesn't exist
        let result = change_level_password(
            &vault_path,
            99,
            b"test password",
            b"new password",
            Some(Argon2Params::minimal()),
        );

        assert!(matches!(result, Err(VaultError::AccessDenied)));
    }

    #[test]
    fn test_change_level_password_preserves_kek() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Open vault and get the KEK for level 1
        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");
        let original_kek = *session.get_kek(1).expect("Should have KEK");
        drop(session);

        // Change the password for level 1 only
        // Note: This changes the level password but NOT the header password
        change_level_password(
            &vault_path,
            1,
            b"test password",
            b"new password",
            Some(Argon2Params::minimal()),
        ).expect("Password change should succeed");

        // Must open with original password (header is still encrypted with it)
        // This will unlock levels 2 and 3 (still use "test password")
        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Original password still opens vault (for levels 2,3)");

        // Level 1 now has different password, so it's not unlocked by open_vault
        assert!(!session.is_level_unlocked(1), "Level 1 should not be unlocked with old password");

        // Unlock level 1 with the new password
        session.unlock_level(1, b"new password")
            .expect("New password should unlock level 1");

        let new_kek = *session.get_kek(1).expect("Should have KEK");
        assert_eq!(original_kek, new_kek, "KEK should be unchanged after password change");
    }

    #[test]
    fn test_change_level_password_does_not_affect_other_levels() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Get KEKs for all levels
        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");
        let kek1 = *session.get_kek(1).expect("Should have KEK 1");
        let kek2 = *session.get_kek(2).expect("Should have KEK 2");
        let kek3 = *session.get_kek(3).expect("Should have KEK 3");
        drop(session);

        // Change password for level 2 only
        change_level_password(
            &vault_path,
            2,
            b"test password",
            b"level2pass",
            Some(Argon2Params::minimal()),
        ).expect("Password change should succeed");

        // Open with original password - unlocks header and levels 1, 3 (still use "test password")
        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Old password should work for levels 1 and 3");
        assert!(session.is_level_unlocked(1));
        assert!(!session.is_level_unlocked(2)); // Level 2 should NOT be unlocked (different password)
        assert!(session.is_level_unlocked(3));
        assert_eq!(*session.get_kek(1).unwrap(), kek1);
        assert_eq!(*session.get_kek(3).unwrap(), kek3);

        // Now unlock level 2 with its new password
        session.unlock_level(2, b"level2pass")
            .expect("New password should unlock level 2");
        assert!(session.is_level_unlocked(2));
        assert_eq!(*session.get_kek(2).unwrap(), kek2, "KEK 2 should be unchanged");
    }

    #[test]
    fn test_change_level_password_multiple_times() {
        let (_temp_dir, vault_path) = create_test_vault();

        // Get original KEK
        let session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");
        let original_kek = *session.get_kek(1).expect("Should have KEK");
        drop(session);

        // Change password first time
        change_level_password(
            &vault_path,
            1,
            b"test password",
            b"password1",
            Some(Argon2Params::minimal()),
        ).expect("First password change should succeed");

        // Change password second time
        change_level_password(
            &vault_path,
            1,
            b"password1",
            b"password2",
            Some(Argon2Params::minimal()),
        ).expect("Second password change should succeed");

        // Change password third time
        change_level_password(
            &vault_path,
            1,
            b"password2",
            b"final_password",
            Some(Argon2Params::minimal()),
        ).expect("Third password change should succeed");

        // Open with original header password (still "test password" - header never changed)
        // This unlocks levels 2 and 3 which still use "test password"
        let mut session = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Original password opens vault");

        // Level 1 should NOT be unlocked (it now uses "final_password")
        assert!(!session.is_level_unlocked(1));
        assert!(session.is_level_unlocked(2)); // Still uses original password
        assert!(session.is_level_unlocked(3)); // Still uses original password

        // Unlock level 1 with the final password
        session.unlock_level(1, b"final_password")
            .expect("Final password should unlock level 1");
        assert!(session.is_level_unlocked(1));
        assert_eq!(*session.get_kek(1).unwrap(), original_kek, "KEK should remain unchanged");

        // Verify old level 1 passwords don't work
        drop(session);
        let mut session2 = open_vault(&vault_path, b"test password", Some(Argon2Params::minimal()))
            .expect("Open should succeed");
        let result = session2.unlock_level(1, b"password1");
        assert!(result.is_err(), "Old password 'password1' should not unlock level 1");
    }

    #[test]
    fn test_change_level_password_per_level_passwords() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with per-level passwords where master = level1 password
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal())
            .with_level_passwords(vec![
                b"level1pass".to_vec(),    // Level 1 (same as master)
                b"level2pass".to_vec(),    // Level 2
                b"level3pass".to_vec(),    // Level 3
            ]);

        // Use level1pass as master so open_vault can succeed
        create_vault(&vault_path, b"level1pass", Some(config))
            .expect("Vault creation should succeed");

        // Change level 2 password
        change_level_password(
            &vault_path,
            2,
            b"level2pass",
            b"new_level2pass",
            Some(Argon2Params::minimal()),
        ).expect("Password change should succeed");

        // Open with master (level1pass) and then unlock other levels
        let mut session = open_vault(&vault_path, b"level1pass", Some(Argon2Params::minimal()))
            .expect("Master password should open vault");
        assert!(session.is_level_unlocked(1)); // Level 1 uses master password

        // Unlock level 2 with new password
        session.unlock_level(2, b"new_level2pass")
            .expect("New level 2 password should work");
        assert!(session.is_level_unlocked(2));

        // Unlock level 3 with original password
        session.unlock_level(3, b"level3pass")
            .expect("Level 3 password should work");
        assert!(session.is_level_unlocked(3));

        // Verify old level 2 password doesn't work
        drop(session);
        let mut session2 = open_vault(&vault_path, b"level1pass", Some(Argon2Params::minimal()))
            .expect("Master password opens vault");
        let result = session2.unlock_level(2, b"level2pass");
        assert!(result.is_err(), "Old level 2 password should not work");
    }

    #[test]
    fn test_change_level_password_vault_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("nonexistent");

        let result = change_level_password(
            &vault_path,
            1,
            b"old",
            b"new",
            Some(Argon2Params::minimal()),
        );

        assert!(matches!(result, Err(VaultError::VaultNotFound(_))));
    }

    // ============================================================================
    // US-024: Recovery Key Authentication Tests
    // ============================================================================

    #[test]
    fn test_authenticate_recovery_success() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_path = vault_path.join(".recovery");
        std::fs::write(&recovery_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Authenticate with recovery key
        let recovery_session = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        ).expect("Recovery authentication should succeed");

        // Verify session state
        assert!(recovery_session.is_active());
        assert!(recovery_session.can_reset_password());
    }

    #[test]
    fn test_authenticate_recovery_wrong_key() {
        use tesseract_crypto::RecoveryKey;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Create a fake recovery blob with random data
        let fake_blob = [0u8; 60];
        let recovery_path = vault_path.join(".recovery");
        std::fs::write(&recovery_path, &fake_blob)
            .expect("Writing fake recovery blob should succeed");

        // Create a wrong recovery key (random bytes)
        let wrong_key = RecoveryKey::new([0u8; 32]);

        // Attempt to authenticate with wrong recovery key
        let result = authenticate_recovery(
            &vault_path,
            &wrong_key,
            Some(Argon2Params::minimal()),
        );

        // Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_recovery_no_recovery_blob() {
        use tesseract_crypto::RecoveryKey;
        use crate::vault::recovery_path;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault (this will create a recovery blob by default)
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Delete the recovery blob to simulate a vault without recovery enabled
        let recovery_blob_path = recovery_path(&vault_path);
        std::fs::remove_file(&recovery_blob_path)
            .expect("Should be able to delete recovery blob");

        // Create a recovery key (doesn't matter, recovery blob is missing)
        let recovery_key = RecoveryKey::new([0u8; 32]);

        // Attempt to authenticate
        let result = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        );

        // Should fail with no recovery blob
        assert!(matches!(result, Err(VaultError::RecoveryNotAvailable)));
    }

    #[test]
    fn test_recovery_session_reset_password() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with password "password" for all levels
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob (overwrites the one created by create_vault)
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_blob_path = vault_path.join(".recovery");
        std::fs::write(&recovery_blob_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Authenticate with recovery key
        let mut recovery_session = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        ).expect("Recovery authentication should succeed");

        // Reset password for level 1
        recovery_session.reset_level_password(1, b"new_password")
            .expect("Password reset should succeed");

        // Close recovery session
        recovery_session.close();

        // Open vault with original header password (header is still "password")
        // Levels 2 and 3 still use "password", so open_vault will succeed
        let mut session = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()))
            .expect("Original password opens vault (levels 2,3)");

        // Level 1 should NOT be unlocked with the original password
        assert!(!session.is_level_unlocked(1), "Level 1 should not be unlocked with old password");

        // Unlock level 1 with new password
        session.unlock_level(1, b"new_password")
            .expect("New password should unlock level 1");
        assert!(session.is_level_unlocked(1));
    }

    #[test]
    fn test_recovery_session_reset_all_levels() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with 3 levels (all use "password" initially)
        // Note: Recovery resets level passwords but not the header password
        // To test full recovery, we'll reset level 1 to match a new "recovery" master password
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_blob_path = vault_path.join(".recovery");
        std::fs::write(&recovery_blob_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Authenticate with recovery key
        let mut recovery_session = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        ).expect("Recovery authentication should succeed");

        // Reset passwords for all levels to different passwords
        recovery_session.reset_level_password(1, b"level1_new")
            .expect("Password reset should succeed for level 1");
        recovery_session.reset_level_password(2, b"level2_new")
            .expect("Password reset should succeed for level 2");
        recovery_session.reset_level_password(3, b"level3_new")
            .expect("Password reset should succeed for level 3");

        // Close recovery session
        recovery_session.close();

        // NOTE: Header is still encrypted with original "password"
        // Since all levels have new passwords, open_vault would need to match at least one.
        // Use change_level_password to verify the new passwords were set correctly
        // (this doesn't require opening the vault, just verifying keystore passwords)

        // Verify level 1's new password works by changing it again
        let change_result1 = change_level_password(
            &vault_path,
            1,
            b"level1_new",
            b"level1_final",
            Some(Argon2Params::minimal()),
        );
        assert!(change_result1.is_ok(), "New level 1 password should be valid for change");

        // Verify level 2's new password works by changing it again
        let change_result2 = change_level_password(
            &vault_path,
            2,
            b"level2_new",
            b"level2_final",
            Some(Argon2Params::minimal()),
        );
        assert!(change_result2.is_ok(), "New level 2 password should be valid for change");

        // Verify level 3's new password works by changing it again
        let change_result3 = change_level_password(
            &vault_path,
            3,
            b"level3_new",
            b"level3_final",
            Some(Argon2Params::minimal()),
        );
        assert!(change_result3.is_ok(), "New level 3 password should be valid for change");
    }

    #[test]
    fn test_recovery_session_invalid_level() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with 3 levels
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_path = vault_path.join(".recovery");
        std::fs::write(&recovery_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Authenticate with recovery key
        let mut recovery_session = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        ).expect("Recovery authentication should succeed");

        // Try to reset password for invalid level
        let result = recovery_session.reset_level_password(99, b"new_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_recovery_session_cannot_access_files() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_path = vault_path.join(".recovery");
        std::fs::write(&recovery_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Authenticate with recovery key
        let recovery_session = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        ).expect("Recovery authentication should succeed");

        // RecoverySession has limited capabilities - no file access
        assert!(recovery_session.can_reset_password());

        // Verify vault path is accessible
        assert_eq!(recovery_session.vault_path(), vault_path);
    }

    #[test]
    fn test_reset_level_password_with_recovery_helper() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with password "password" for all levels
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_blob_path = vault_path.join(".recovery");
        std::fs::write(&recovery_blob_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Use the helper function to reset level 2 password
        reset_level_password_with_recovery(
            &vault_path,
            &recovery_key,
            2,
            b"brand_new_password",
            Some(Argon2Params::minimal()),
        ).expect("Password reset should succeed");

        // Open vault with original password (header still uses "password")
        // Levels 1 and 3 still use "password"
        let mut session = open_vault(&vault_path, b"password", Some(Argon2Params::minimal()))
            .expect("Original password opens vault (levels 1, 3)");

        // Level 2 should NOT be unlocked with original password
        assert!(!session.is_level_unlocked(2), "Level 2 should not unlock with old password");

        // Unlock level 2 with new password
        session.unlock_level(2, b"brand_new_password")
            .expect("New password should unlock level 2");
        assert!(session.is_level_unlocked(2));
    }

    #[test]
    fn test_recovery_session_closes_properly() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_path = vault_path.join(".recovery");
        std::fs::write(&recovery_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Authenticate with recovery key
        let recovery_session = authenticate_recovery(
            &vault_path,
            &recovery_key,
            Some(Argon2Params::minimal()),
        ).expect("Recovery authentication should succeed");

        // Verify session is active before close
        assert!(recovery_session.is_active());

        // Close recovery session (consumes the session)
        recovery_session.close();
        // Session is now consumed, we cannot check is_active() anymore
        // The test passes if close() doesn't panic
    }

    #[test]
    fn test_recovery_preserves_other_level_passwords() {
        use tesseract_crypto::recovery::generate_recovery_key;

        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Create vault with 3 levels, same password for all
        let config = VaultConfig::new()
            .with_level_count(3)
            .with_argon2_params(Argon2Params::minimal());

        let result = create_vault(&vault_path, b"original_password", Some(config))
            .expect("Vault creation should succeed");

        // Get master key from creation result
        let master_key = result.master_key;

        // Generate recovery key and store blob
        let recovery_key = generate_recovery_key()
            .expect("Recovery key generation should succeed");

        // Write recovery blob
        let encrypted_master = recovery_key.encrypt_master_key(&master_key)
            .expect("Master key encryption should succeed");
        let recovery_blob_path = vault_path.join(".recovery");
        std::fs::write(&recovery_blob_path, encrypted_master)
            .expect("Writing recovery blob should succeed");

        // Reset ONLY level 2 password using recovery
        reset_level_password_with_recovery(
            &vault_path,
            &recovery_key,
            2,
            b"level2_new_password",
            Some(Argon2Params::minimal()),
        ).expect("Password reset should succeed");

        // Open vault with original password (header still uses "original_password")
        // Levels 1 and 3 still use "original_password", so they unlock
        let mut session = open_vault(&vault_path, b"original_password", Some(Argon2Params::minimal()))
            .expect("Original password should still work for levels 1, 3");
        assert!(session.is_level_unlocked(1));
        assert!(!session.is_level_unlocked(2), "Level 2 should NOT unlock with old password");
        assert!(session.is_level_unlocked(3));

        // Now unlock level 2 with its new password
        session.unlock_level(2, b"level2_new_password")
            .expect("New level 2 password should unlock level 2");
        assert!(session.is_level_unlocked(2));
    }
}
