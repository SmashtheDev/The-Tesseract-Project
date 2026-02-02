//! Keystore management.
//!
//! Manages per-level encrypted key bundles containing KEKs and DEKs.
//! Each access level has its own keystore file stored as `L{n}.keys.enc`
//! in the `.keystores/` directory.
//!
//! # Key Hierarchy
//!
//! The keystore implements a hierarchical key structure:
//! - **ALK (Access Level Key)**: Derived from level password, wraps the KEK
//! - **KEK (Key Encryption Key)**: Stored encrypted, wraps file DEKs
//! - **DEK (Data Encryption Key)**: Per-file key for content encryption
//!
//! # Format
//!
//! Each keystore file contains:
//!
//! | Field                | Size      | Description                           |
//! |----------------------|-----------|---------------------------------------|
//! | version              | 2 bytes   | Keystore format version               |
//! | level_id             | 4 bytes   | Access level identifier               |
//! | encrypted_kek        | 48 bytes  | KEK encrypted with ALK (32 + 16 tag)  |
//! | kek_nonce            | 12 bytes  | Nonce for KEK encryption              |
//! | dek_count            | 4 bytes   | Number of DEK entries                 |
//! | dek_entries          | variable  | Array of encrypted DEK entries        |
//! | hmac_tag             | 32 bytes  | HMAC-SHA256 over all preceding data   |
//!
//! Each DEK entry:
//!
//! | Field          | Size     | Description                          |
//! |----------------|----------|--------------------------------------|
//! | file_uuid      | 16 bytes | UUID of the file this DEK belongs to |
//! | encrypted_dek  | 48 bytes | DEK encrypted with KEK (32 + 16 tag) |
//! | dek_nonce      | 12 bytes | Nonce for DEK encryption             |
//!
//! # Security
//!
//! - KEK is never stored in plaintext; always encrypted with ALK
//! - Each file DEK is encrypted individually with the KEK
//! - HMAC integrity tag covers all keystore data
//! - Nonces are unique per encryption operation

use std::collections::HashMap;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::VaultError;
use tesseract_crypto::{
    aes::{decrypt, encrypt},
    hmac::{hmac_sign, hmac_verify, HMAC_SIZE as CRYPTO_HMAC_SIZE},
    generate_nonce, NONCE_SIZE as CRYPTO_NONCE_SIZE,
};

/// Size of the HMAC-SHA256 tag.
pub const HMAC_TAG_SIZE: usize = 32;

/// Size of nonce for AES-256-GCM.
pub const NONCE_SIZE: usize = 12;

/// Size of encrypted key (32-byte key + 16-byte GCM tag).
pub const ENCRYPTED_KEY_SIZE: usize = 48;

/// Size of a UUID in bytes.
pub const UUID_SIZE: usize = 16;

/// Size of the fixed header portion (before DEK entries).
pub const HEADER_SIZE: usize = 2 + 4 + 48 + 12 + 4; // version + level_id + encrypted_kek + nonce + dek_count = 70

/// Size of each DEK entry.
pub const DEK_ENTRY_SIZE: usize = UUID_SIZE + ENCRYPTED_KEY_SIZE + NONCE_SIZE; // 16 + 48 + 12 = 76

/// Current keystore format version.
pub const CURRENT_KEYSTORE_VERSION: KeystoreVersion = KeystoreVersion { major: 1, minor: 0 };

/// Keystore format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreVersion {
    /// Major version (breaking changes).
    pub major: u8,
    /// Minor version (backwards-compatible additions).
    pub minor: u8,
}

impl KeystoreVersion {
    /// Creates a new keystore version.
    #[must_use]
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Checks if this version is compatible with another.
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

impl std::fmt::Display for KeystoreVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A single DEK entry in the keystore.
///
/// Represents an encrypted file DEK along with its associated UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DekEntry {
    /// UUID of the file this DEK belongs to.
    file_uuid: Uuid,
    /// DEK encrypted with the keystore's KEK (32-byte key + 16-byte tag).
    encrypted_dek: [u8; ENCRYPTED_KEY_SIZE],
    /// Nonce used for DEK encryption.
    dek_nonce: [u8; NONCE_SIZE],
}

impl DekEntry {
    /// Creates a new DEK entry.
    #[must_use]
    pub fn new(
        file_uuid: Uuid,
        encrypted_dek: [u8; ENCRYPTED_KEY_SIZE],
        dek_nonce: [u8; NONCE_SIZE],
    ) -> Self {
        Self {
            file_uuid,
            encrypted_dek,
            dek_nonce,
        }
    }

    /// Returns the file UUID.
    #[must_use]
    pub fn file_uuid(&self) -> Uuid {
        self.file_uuid
    }

    /// Returns the encrypted DEK.
    #[must_use]
    pub fn encrypted_dek(&self) -> &[u8; ENCRYPTED_KEY_SIZE] {
        &self.encrypted_dek
    }

    /// Returns the DEK nonce.
    #[must_use]
    pub fn dek_nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.dek_nonce
    }

    /// Serializes the DEK entry to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; DEK_ENTRY_SIZE] {
        let mut buffer = [0u8; DEK_ENTRY_SIZE];
        buffer[0..UUID_SIZE].copy_from_slice(self.file_uuid.as_bytes());
        buffer[UUID_SIZE..UUID_SIZE + ENCRYPTED_KEY_SIZE].copy_from_slice(&self.encrypted_dek);
        buffer[UUID_SIZE + ENCRYPTED_KEY_SIZE..].copy_from_slice(&self.dek_nonce);
        buffer
    }

    /// Deserializes a DEK entry from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; DEK_ENTRY_SIZE]) -> Self {
        let mut uuid_bytes = [0u8; UUID_SIZE];
        uuid_bytes.copy_from_slice(&bytes[0..UUID_SIZE]);
        let file_uuid = Uuid::from_bytes(uuid_bytes);

        let mut encrypted_dek = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_dek.copy_from_slice(&bytes[UUID_SIZE..UUID_SIZE + ENCRYPTED_KEY_SIZE]);

        let mut dek_nonce = [0u8; NONCE_SIZE];
        dek_nonce.copy_from_slice(&bytes[UUID_SIZE + ENCRYPTED_KEY_SIZE..]);

        Self {
            file_uuid,
            encrypted_dek,
            dek_nonce,
        }
    }

    /// Decrypts the DEK using the provided KEK.
    ///
    /// # Arguments
    ///
    /// * `kek` - The Key Encryption Key used to decrypt the DEK
    ///
    /// # Returns
    ///
    /// The decrypted 32-byte DEK.
    pub fn decrypt_dek(&self, kek: &[u8; 32]) -> Result<[u8; 32], VaultError> {
        // Use file UUID as AAD for domain binding
        let aad = self.file_uuid.as_bytes();

        let plaintext = decrypt(kek, &self.dek_nonce, &self.encrypted_dek, aad)
            .map_err(|_| VaultError::AuthenticationFailed)?;

        if plaintext.len() != 32 {
            return Err(VaultError::InvalidFormat(format!(
                "Decrypted DEK has wrong size: expected 32, got {}",
                plaintext.len()
            )));
        }

        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }
}

/// Keystore containing encrypted key material for an access level.
///
/// Each access level has its own keystore with:
/// - An encrypted KEK (wrapped with the ALK derived from level password)
/// - A map of file UUIDs to their encrypted DEKs (wrapped with the KEK)
#[derive(Debug, Clone)]
pub struct Keystore {
    /// Keystore format version.
    version: KeystoreVersion,
    /// Access level identifier (1-based).
    level_id: u32,
    /// KEK encrypted with ALK (32-byte key + 16-byte GCM tag).
    encrypted_kek: [u8; ENCRYPTED_KEY_SIZE],
    /// Nonce used for KEK encryption.
    kek_nonce: [u8; NONCE_SIZE],
    /// Map of file UUIDs to their DEK entries.
    dek_entries: HashMap<Uuid, DekEntry>,
    /// HMAC-SHA256 tag over all keystore data.
    hmac_tag: [u8; HMAC_TAG_SIZE],
}

impl Keystore {
    /// Creates a new keystore with an encrypted KEK.
    ///
    /// # Arguments
    ///
    /// * `level_id` - Access level identifier (1-based)
    /// * `encrypted_kek` - KEK encrypted with ALK
    /// * `kek_nonce` - Nonce used for KEK encryption
    #[must_use]
    pub fn new(
        level_id: u32,
        encrypted_kek: [u8; ENCRYPTED_KEY_SIZE],
        kek_nonce: [u8; NONCE_SIZE],
    ) -> Self {
        Self {
            version: CURRENT_KEYSTORE_VERSION,
            level_id,
            encrypted_kek,
            kek_nonce,
            dek_entries: HashMap::new(),
            hmac_tag: [0u8; HMAC_TAG_SIZE],
        }
    }

    /// Creates a keystore from raw components (for deserialization).
    #[must_use]
    pub fn from_components(
        version: KeystoreVersion,
        level_id: u32,
        encrypted_kek: [u8; ENCRYPTED_KEY_SIZE],
        kek_nonce: [u8; NONCE_SIZE],
        dek_entries: HashMap<Uuid, DekEntry>,
        hmac_tag: [u8; HMAC_TAG_SIZE],
    ) -> Self {
        Self {
            version,
            level_id,
            encrypted_kek,
            kek_nonce,
            dek_entries,
            hmac_tag,
        }
    }

    /// Returns the keystore version.
    #[must_use]
    pub fn version(&self) -> KeystoreVersion {
        self.version
    }

    /// Returns the access level ID.
    #[must_use]
    pub fn level_id(&self) -> u32 {
        self.level_id
    }

    /// Returns the encrypted KEK.
    #[must_use]
    pub fn encrypted_kek(&self) -> &[u8; ENCRYPTED_KEY_SIZE] {
        &self.encrypted_kek
    }

    /// Returns the KEK nonce.
    #[must_use]
    pub fn kek_nonce(&self) -> &[u8; NONCE_SIZE] {
        &self.kek_nonce
    }

    /// Returns the HMAC tag.
    #[must_use]
    pub fn hmac_tag(&self) -> &[u8; HMAC_TAG_SIZE] {
        &self.hmac_tag
    }

    /// Returns the number of DEK entries.
    #[must_use]
    pub fn dek_count(&self) -> usize {
        self.dek_entries.len()
    }

    /// Returns an iterator over DEK entries.
    pub fn dek_entries(&self) -> impl Iterator<Item = (&Uuid, &DekEntry)> {
        self.dek_entries.iter()
    }

    /// Gets a DEK entry by file UUID.
    #[must_use]
    pub fn get_dek_entry(&self, file_uuid: &Uuid) -> Option<&DekEntry> {
        self.dek_entries.get(file_uuid)
    }

    /// Adds a DEK entry for a file.
    ///
    /// If an entry already exists for this file, it is replaced.
    pub fn add_dek_entry(&mut self, entry: DekEntry) {
        self.dek_entries.insert(entry.file_uuid(), entry);
    }

    /// Removes a DEK entry by file UUID.
    ///
    /// Returns the removed entry if it existed.
    pub fn remove_dek_entry(&mut self, file_uuid: &Uuid) -> Option<DekEntry> {
        self.dek_entries.remove(file_uuid)
    }

    /// Checks if a DEK entry exists for a file.
    #[must_use]
    pub fn has_dek_entry(&self, file_uuid: &Uuid) -> bool {
        self.dek_entries.contains_key(file_uuid)
    }

    /// Clears all DEK entries.
    pub fn clear_dek_entries(&mut self) {
        self.dek_entries.clear();
    }

    /// Computes the serialized size of this keystore.
    #[must_use]
    pub fn serialized_size(&self) -> usize {
        HEADER_SIZE + (self.dek_entries.len() * DEK_ENTRY_SIZE) + HMAC_TAG_SIZE
    }

    /// Serializes the keystore to bytes (excluding HMAC tag for signing).
    fn serialize_data(&self) -> Vec<u8> {
        let dek_count = self.dek_entries.len();
        let data_size = HEADER_SIZE + (dek_count * DEK_ENTRY_SIZE);
        let mut buffer = Vec::with_capacity(data_size);

        // Version (2 bytes)
        buffer.extend_from_slice(&self.version.to_bytes());

        // Level ID (4 bytes, little-endian)
        buffer.extend_from_slice(&self.level_id.to_le_bytes());

        // Encrypted KEK (48 bytes)
        buffer.extend_from_slice(&self.encrypted_kek);

        // KEK nonce (12 bytes)
        buffer.extend_from_slice(&self.kek_nonce);

        // DEK count (4 bytes, little-endian)
        buffer.extend_from_slice(&(dek_count as u32).to_le_bytes());

        // DEK entries (sorted by UUID for deterministic serialization)
        let mut entries: Vec<_> = self.dek_entries.values().collect();
        entries.sort_by(|a, b| a.file_uuid().cmp(&b.file_uuid()));
        for entry in entries {
            buffer.extend_from_slice(&entry.to_bytes());
        }

        buffer
    }

    /// Serializes the keystore to bytes (including HMAC tag).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = self.serialize_data();
        buffer.extend_from_slice(&self.hmac_tag);
        buffer
    }

    /// Computes and sets the HMAC-SHA256 integrity tag.
    ///
    /// # Arguments
    ///
    /// * `hmac_key` - The key for HMAC computation (typically derived from ALK)
    pub fn compute_hmac(&mut self, hmac_key: &[u8; HMAC_TAG_SIZE]) {
        let data = self.serialize_data();
        self.hmac_tag = hmac_sign(hmac_key, &data);
    }

    /// Verifies the HMAC-SHA256 integrity tag.
    ///
    /// # Arguments
    ///
    /// * `hmac_key` - The key for HMAC verification
    ///
    /// # Returns
    ///
    /// * `Ok(())` if verification succeeds
    /// * `Err(VaultError::HeaderIntegrityFailed)` if verification fails
    pub fn verify_integrity(&self, hmac_key: &[u8; HMAC_TAG_SIZE]) -> Result<(), VaultError> {
        let data = self.serialize_data();
        hmac_verify(hmac_key, &data, &self.hmac_tag)
            .map_err(|_| VaultError::HeaderIntegrityFailed)
    }

    /// Deserializes a keystore from bytes.
    ///
    /// # Errors
    ///
    /// Returns `VaultError::InvalidFormat` if:
    /// - The buffer is too small
    /// - Version is incompatible
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, VaultError> {
        // Minimum size check
        if buffer.len() < HEADER_SIZE + HMAC_TAG_SIZE {
            return Err(VaultError::InvalidFormat(
                "Keystore data too small".to_string(),
            ));
        }

        // Parse version
        let version = KeystoreVersion::from_bytes([buffer[0], buffer[1]]);
        if !version.is_compatible_with(&CURRENT_KEYSTORE_VERSION) {
            return Err(VaultError::InvalidFormat(format!(
                "Incompatible keystore version: found {version}, expected {CURRENT_KEYSTORE_VERSION}.x"
            )));
        }

        // Parse level ID
        let level_id = u32::from_le_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]);

        // Parse encrypted KEK
        let mut encrypted_kek = [0u8; ENCRYPTED_KEY_SIZE];
        encrypted_kek.copy_from_slice(&buffer[6..6 + ENCRYPTED_KEY_SIZE]);

        // Parse KEK nonce
        let mut kek_nonce = [0u8; NONCE_SIZE];
        kek_nonce.copy_from_slice(&buffer[6 + ENCRYPTED_KEY_SIZE..6 + ENCRYPTED_KEY_SIZE + NONCE_SIZE]);

        // Parse DEK count
        let dek_count_offset = 6 + ENCRYPTED_KEY_SIZE + NONCE_SIZE;
        let dek_count = u32::from_le_bytes([
            buffer[dek_count_offset],
            buffer[dek_count_offset + 1],
            buffer[dek_count_offset + 2],
            buffer[dek_count_offset + 3],
        ]) as usize;

        // Verify buffer size
        let expected_size = HEADER_SIZE + (dek_count * DEK_ENTRY_SIZE) + HMAC_TAG_SIZE;
        if buffer.len() < expected_size {
            return Err(VaultError::InvalidFormat(format!(
                "Keystore buffer too small: expected {expected_size}, got {}",
                buffer.len()
            )));
        }

        // Parse DEK entries
        let mut dek_entries = HashMap::with_capacity(dek_count);
        let entries_start = HEADER_SIZE;
        for i in 0..dek_count {
            let entry_start = entries_start + (i * DEK_ENTRY_SIZE);
            let entry_bytes: &[u8; DEK_ENTRY_SIZE] = buffer[entry_start..entry_start + DEK_ENTRY_SIZE]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat("DEK entry parse error".to_string()))?;
            let entry = DekEntry::from_bytes(entry_bytes);
            dek_entries.insert(entry.file_uuid(), entry);
        }

        // Parse HMAC tag
        let hmac_offset = HEADER_SIZE + (dek_count * DEK_ENTRY_SIZE);
        let mut hmac_tag = [0u8; HMAC_TAG_SIZE];
        hmac_tag.copy_from_slice(&buffer[hmac_offset..hmac_offset + HMAC_TAG_SIZE]);

        Ok(Self {
            version,
            level_id,
            encrypted_kek,
            kek_nonce,
            dek_entries,
            hmac_tag,
        })
    }

    /// Writes the keystore to a writer.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), VaultError> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(())
    }

    /// Reads a keystore from a reader.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, VaultError> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        Self::from_bytes(&buffer)
    }

    /// Reads a keystore from a reader and verifies its integrity.
    pub fn read_and_verify<R: Read>(
        reader: &mut R,
        hmac_key: &[u8; HMAC_TAG_SIZE],
    ) -> Result<Self, VaultError> {
        let keystore = Self::read_from(reader)?;
        keystore.verify_integrity(hmac_key)?;
        Ok(keystore)
    }

    /// Decrypts the KEK using the provided ALK.
    ///
    /// # Arguments
    ///
    /// * `alk` - The Access Level Key used to decrypt the KEK
    ///
    /// # Returns
    ///
    /// The decrypted 32-byte KEK.
    pub fn decrypt_kek(&self, alk: &[u8; 32]) -> Result<[u8; 32], VaultError> {
        // Use level ID as AAD for domain binding
        let aad = self.level_id.to_le_bytes();

        let plaintext = decrypt(alk, &self.kek_nonce, &self.encrypted_kek, &aad)
            .map_err(|_| VaultError::AuthenticationFailed)?;

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

    /// Decrypts a file's DEK using the KEK.
    ///
    /// # Arguments
    ///
    /// * `file_uuid` - The UUID of the file
    /// * `kek` - The decrypted Key Encryption Key
    ///
    /// # Returns
    ///
    /// The decrypted 32-byte DEK for the file.
    pub fn decrypt_file_dek(&self, file_uuid: &Uuid, kek: &[u8; 32]) -> Result<[u8; 32], VaultError> {
        let entry = self.dek_entries.get(file_uuid).ok_or_else(|| {
            VaultError::FileNotFound(file_uuid.to_string())
        })?;

        entry.decrypt_dek(kek)
    }

    /// Returns the filename for this keystore.
    ///
    /// Format: `L{level_id}.keys.enc`
    #[must_use]
    pub fn filename(&self) -> String {
        format!("L{}.keys.enc", self.level_id)
    }

    /// Re-wraps the KEK with a new ALK.
    ///
    /// This is used when changing the level password. The KEK itself does not change,
    /// but its encryption wrapper is updated to use the new ALK.
    ///
    /// # Arguments
    ///
    /// * `kek` - The decrypted Key Encryption Key
    /// * `new_alk` - The new Access Level Key derived from the new password
    /// * `new_hmac_key` - The new HMAC key derived from the new password
    ///
    /// # Security
    ///
    /// After calling this method, the keystore must be persisted to disk.
    /// The old password will no longer be able to decrypt this keystore.
    pub fn rewrap_kek(
        &mut self,
        kek: &[u8; 32],
        new_alk: &[u8; 32],
        new_hmac_key: &[u8; 32],
    ) -> Result<(), VaultError> {
        // Re-encrypt the KEK with the new ALK
        let (encrypted_kek, kek_nonce) = wrap_kek(kek, new_alk, self.level_id)?;

        // Update the keystore fields
        self.encrypted_kek = encrypted_kek;
        self.kek_nonce = kek_nonce;

        // Recompute the HMAC with the new key
        self.compute_hmac(new_hmac_key);

        Ok(())
    }
}

/// Encrypts a KEK with an ALK for storage in a keystore.
///
/// # Arguments
///
/// * `kek` - The raw 32-byte Key Encryption Key
/// * `alk` - The Access Level Key derived from the level password
/// * `level_id` - The access level identifier (used as AAD)
///
/// # Returns
///
/// A tuple of (encrypted_kek, nonce).
pub fn wrap_kek(
    kek: &[u8; 32],
    alk: &[u8; 32],
    level_id: u32,
) -> Result<([u8; ENCRYPTED_KEY_SIZE], [u8; NONCE_SIZE]), VaultError> {
    let nonce = generate_nonce()?;
    let aad = level_id.to_le_bytes();

    let ciphertext = encrypt(alk, &nonce, kek, &aad)?;

    if ciphertext.len() != ENCRYPTED_KEY_SIZE {
        return Err(VaultError::InvalidFormat(format!(
            "Encrypted KEK has wrong size: expected {ENCRYPTED_KEY_SIZE}, got {}",
            ciphertext.len()
        )));
    }

    let mut encrypted_kek = [0u8; ENCRYPTED_KEY_SIZE];
    encrypted_kek.copy_from_slice(&ciphertext);

    Ok((encrypted_kek, nonce))
}

/// Encrypts a DEK with a KEK for storage in a keystore.
///
/// # Arguments
///
/// * `dek` - The raw 32-byte Data Encryption Key
/// * `kek` - The Key Encryption Key
/// * `file_uuid` - The UUID of the file (used as AAD)
///
/// # Returns
///
/// A tuple of (encrypted_dek, nonce).
pub fn wrap_dek(
    dek: &[u8; 32],
    kek: &[u8; 32],
    file_uuid: &Uuid,
) -> Result<([u8; ENCRYPTED_KEY_SIZE], [u8; NONCE_SIZE]), VaultError> {
    let nonce = generate_nonce()?;
    let aad = file_uuid.as_bytes();

    let ciphertext = encrypt(kek, &nonce, dek, aad)?;

    if ciphertext.len() != ENCRYPTED_KEY_SIZE {
        return Err(VaultError::InvalidFormat(format!(
            "Encrypted DEK has wrong size: expected {ENCRYPTED_KEY_SIZE}, got {}",
            ciphertext.len()
        )));
    }

    let mut encrypted_dek = [0u8; ENCRYPTED_KEY_SIZE];
    encrypted_dek.copy_from_slice(&ciphertext);

    Ok((encrypted_dek, nonce))
}

/// Decrypts a DEK that was encrypted with wrap_dek.
///
/// # Arguments
///
/// * `encrypted_dek` - The encrypted DEK (48 bytes: 32 bytes key + 16 bytes tag)
/// * `nonce` - The 12-byte nonce used during encryption
/// * `kek` - The Key Encryption Key
/// * `file_uuid` - The UUID of the file (used as AAD)
///
/// # Returns
///
/// The decrypted 32-byte DEK.
pub fn unwrap_dek(
    encrypted_dek: &[u8; ENCRYPTED_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    kek: &[u8; 32],
    file_uuid: &Uuid,
) -> Result<[u8; 32], VaultError> {
    let aad = file_uuid.as_bytes();

    let plaintext = decrypt(kek, nonce, encrypted_dek, aad)?;

    if plaintext.len() != 32 {
        return Err(VaultError::InvalidFormat(format!(
            "Decrypted DEK has wrong size: expected 32, got {}",
            plaintext.len()
        )));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

/// Creates a new keystore with a fresh KEK for an access level.
///
/// # Arguments
///
/// * `level_id` - The access level identifier
/// * `alk` - The Access Level Key derived from the level password
/// * `hmac_key` - The key for HMAC computation (typically derived from ALK)
///
/// # Returns
///
/// A tuple of (keystore, raw_kek) where raw_kek is the unencrypted KEK.
pub fn create_keystore(
    level_id: u32,
    alk: &[u8; 32],
    hmac_key: &[u8; 32],
) -> Result<(Keystore, [u8; 32]), VaultError> {
    // Generate a random KEK for this level
    let kek = tesseract_crypto::generate_key()?;

    // Wrap the KEK with the ALK
    let (encrypted_kek, kek_nonce) = wrap_kek(&kek, alk, level_id)?;

    // Create the keystore
    let mut keystore = Keystore::new(level_id, encrypted_kek, kek_nonce);

    // Compute HMAC
    keystore.compute_hmac(hmac_key);

    Ok((keystore, kek))
}

/// Adds a file DEK to a keystore.
///
/// # Arguments
///
/// * `keystore` - The keystore to add the DEK to
/// * `file_uuid` - The UUID of the file
/// * `dek` - The raw 32-byte Data Encryption Key
/// * `kek` - The Key Encryption Key (must be decrypted first)
/// * `hmac_key` - The key for HMAC recomputation
pub fn add_file_dek(
    keystore: &mut Keystore,
    file_uuid: Uuid,
    dek: &[u8; 32],
    kek: &[u8; 32],
    hmac_key: &[u8; 32],
) -> Result<(), VaultError> {
    // Wrap the DEK with the KEK
    let (encrypted_dek, dek_nonce) = wrap_dek(dek, kek, &file_uuid)?;

    // Create and add the entry
    let entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);
    keystore.add_dek_entry(entry);

    // Recompute HMAC
    keystore.compute_hmac(hmac_key);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tesseract_crypto::{generate_key, generate_uuid};

    /// Creates a test keystore with a known KEK.
    fn create_test_keystore() -> (Keystore, [u8; 32], [u8; 32]) {
        let level_id = 1;
        let alk = [0xAB; 32];
        let hmac_key = [0xCD; 32];

        let (keystore, kek) = create_keystore(level_id, &alk, &hmac_key)
            .expect("Keystore creation should succeed");

        (keystore, kek, hmac_key)
    }

    #[test]
    fn test_keystore_version() {
        let v1 = KeystoreVersion::new(1, 0);
        let v1_1 = KeystoreVersion::new(1, 1);
        let v2 = KeystoreVersion::new(2, 0);

        assert!(v1.is_compatible_with(&v1_1));
        assert!(!v1.is_compatible_with(&v2));

        let bytes = v1_1.to_bytes();
        let restored = KeystoreVersion::from_bytes(bytes);
        assert_eq!(v1_1, restored);

        assert_eq!(format!("{v1_1}"), "1.1");
    }

    #[test]
    fn test_dek_entry_serialization() {
        let file_uuid = generate_uuid().unwrap();
        let encrypted_dek = [0x42; ENCRYPTED_KEY_SIZE];
        let dek_nonce = [0x33; NONCE_SIZE];

        let entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), DEK_ENTRY_SIZE);

        let restored = DekEntry::from_bytes(&bytes);
        assert_eq!(entry, restored);
    }

    #[test]
    fn test_keystore_creation() {
        let (keystore, _kek, _hmac_key) = create_test_keystore();

        assert_eq!(keystore.level_id(), 1);
        assert_eq!(keystore.dek_count(), 0);
        assert_eq!(keystore.version(), CURRENT_KEYSTORE_VERSION);
    }

    #[test]
    fn test_keystore_serialization_roundtrip() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        // Add some DEK entries
        for _ in 0..3 {
            let file_uuid = generate_uuid().unwrap();
            let dek = generate_key().unwrap();
            add_file_dek(&mut keystore, file_uuid, &dek, &kek, &hmac_key)
                .expect("Add DEK should succeed");
        }

        // Serialize
        let bytes = keystore.to_bytes();
        assert_eq!(bytes.len(), keystore.serialized_size());

        // Deserialize
        let restored = Keystore::from_bytes(&bytes).expect("Deserialization should succeed");

        // Verify
        assert_eq!(keystore.level_id(), restored.level_id());
        assert_eq!(keystore.version(), restored.version());
        assert_eq!(keystore.dek_count(), restored.dek_count());
        assert_eq!(keystore.encrypted_kek(), restored.encrypted_kek());
        assert_eq!(keystore.kek_nonce(), restored.kek_nonce());
        assert_eq!(keystore.hmac_tag(), restored.hmac_tag());
    }

    #[test]
    fn test_keystore_hmac_verification() {
        let (keystore, _kek, hmac_key) = create_test_keystore();

        // Verify HMAC
        assert!(keystore.verify_integrity(&hmac_key).is_ok());

        // Wrong key should fail
        let wrong_key = [0xFF; 32];
        assert!(matches!(
            keystore.verify_integrity(&wrong_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_keystore_tamper_detection() {
        let (keystore, _kek, hmac_key) = create_test_keystore();

        let mut bytes = keystore.to_bytes();
        bytes[10] ^= 0xFF; // Tamper with encrypted KEK

        let tampered = Keystore::from_bytes(&bytes).expect("Should parse");
        assert!(matches!(
            tampered.verify_integrity(&hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_kek_decryption() {
        let level_id = 2;
        let alk = [0xAB; 32];
        let hmac_key = [0xCD; 32];

        let (keystore, original_kek) = create_keystore(level_id, &alk, &hmac_key)
            .expect("Creation should succeed");

        let decrypted_kek = keystore.decrypt_kek(&alk)
            .expect("Decryption should succeed");

        assert_eq!(original_kek, decrypted_kek);
    }

    #[test]
    fn test_kek_decryption_wrong_key() {
        let (keystore, _kek, _hmac_key) = create_test_keystore();

        let wrong_alk = [0xFF; 32];
        assert!(matches!(
            keystore.decrypt_kek(&wrong_alk),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_add_and_decrypt_dek() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        let file_uuid = generate_uuid().unwrap();
        let original_dek = generate_key().unwrap();

        // Add DEK
        add_file_dek(&mut keystore, file_uuid, &original_dek, &kek, &hmac_key)
            .expect("Add DEK should succeed");

        assert_eq!(keystore.dek_count(), 1);
        assert!(keystore.has_dek_entry(&file_uuid));

        // Decrypt DEK
        let decrypted_dek = keystore.decrypt_file_dek(&file_uuid, &kek)
            .expect("Decrypt DEK should succeed");

        assert_eq!(original_dek, decrypted_dek);
    }

    #[test]
    fn test_dek_not_found() {
        let (keystore, kek, _hmac_key) = create_test_keystore();

        let missing_uuid = generate_uuid().unwrap();
        assert!(matches!(
            keystore.decrypt_file_dek(&missing_uuid, &kek),
            Err(VaultError::FileNotFound(_))
        ));
    }

    #[test]
    fn test_remove_dek() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        let file_uuid = generate_uuid().unwrap();
        let dek = generate_key().unwrap();

        add_file_dek(&mut keystore, file_uuid, &dek, &kek, &hmac_key)
            .expect("Add DEK should succeed");
        assert!(keystore.has_dek_entry(&file_uuid));

        let removed = keystore.remove_dek_entry(&file_uuid);
        assert!(removed.is_some());
        assert!(!keystore.has_dek_entry(&file_uuid));
    }

    #[test]
    fn test_keystore_filename() {
        let (keystore, _kek, _hmac_key) = create_test_keystore();
        assert_eq!(keystore.filename(), "L1.keys.enc");

        let level_3_keystore = Keystore::new(3, [0; ENCRYPTED_KEY_SIZE], [0; NONCE_SIZE]);
        assert_eq!(level_3_keystore.filename(), "L3.keys.enc");
    }

    #[test]
    fn test_keystore_io_roundtrip() {
        let (keystore, _kek, hmac_key) = create_test_keystore();

        // Write to buffer
        let mut buffer = Vec::new();
        keystore.write_to(&mut buffer).expect("Write should succeed");

        // Read back
        let mut cursor = std::io::Cursor::new(buffer);
        let restored = Keystore::read_and_verify(&mut cursor, &hmac_key)
            .expect("Read and verify should succeed");

        assert_eq!(keystore.level_id(), restored.level_id());
    }

    #[test]
    fn test_multiple_dek_entries() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        // Add 10 DEK entries
        let mut file_deks = Vec::new();
        for _ in 0..10 {
            let file_uuid = generate_uuid().unwrap();
            let dek = generate_key().unwrap();
            add_file_dek(&mut keystore, file_uuid, &dek, &kek, &hmac_key)
                .expect("Add DEK should succeed");
            file_deks.push((file_uuid, dek));
        }

        assert_eq!(keystore.dek_count(), 10);

        // Serialize and deserialize
        let bytes = keystore.to_bytes();
        let restored = Keystore::from_bytes(&bytes).expect("Deserialize should succeed");
        assert!(restored.verify_integrity(&hmac_key).is_ok());

        // Verify all DEKs can be decrypted
        for (file_uuid, original_dek) in file_deks {
            let decrypted = restored.decrypt_file_dek(&file_uuid, &kek)
                .expect("Decrypt DEK should succeed");
            assert_eq!(original_dek, decrypted);
        }
    }

    #[test]
    fn test_wrap_kek() {
        let kek = [0x42; 32];
        let alk = [0xAB; 32];
        let level_id = 1;

        let (encrypted_kek, nonce) = wrap_kek(&kek, &alk, level_id)
            .expect("Wrap should succeed");

        assert_eq!(encrypted_kek.len(), ENCRYPTED_KEY_SIZE);
        assert_eq!(nonce.len(), NONCE_SIZE);

        // Verify decryption
        let aad = level_id.to_le_bytes();
        let decrypted = decrypt(&alk, &nonce, &encrypted_kek, &aad)
            .expect("Decrypt should succeed");
        assert_eq!(decrypted.as_slice(), &kek[..]);
    }

    #[test]
    fn test_wrap_dek() {
        let dek = [0x55; 32];
        let kek = [0xAB; 32];
        let file_uuid = generate_uuid().unwrap();

        let (encrypted_dek, nonce) = wrap_dek(&dek, &kek, &file_uuid)
            .expect("Wrap should succeed");

        assert_eq!(encrypted_dek.len(), ENCRYPTED_KEY_SIZE);
        assert_eq!(nonce.len(), NONCE_SIZE);

        // Verify decryption
        let aad = file_uuid.as_bytes();
        let decrypted = decrypt(&kek, &nonce, &encrypted_dek, aad)
            .expect("Decrypt should succeed");
        assert_eq!(decrypted.as_slice(), &dek[..]);
    }

    #[test]
    fn test_invalid_keystore_buffer() {
        // Too small buffer
        let small_buffer = [0u8; 10];
        assert!(matches!(
            Keystore::from_bytes(&small_buffer),
            Err(VaultError::InvalidFormat(_))
        ));

        // Incompatible version
        let mut bad_version = vec![0u8; HEADER_SIZE + HMAC_TAG_SIZE];
        bad_version[0] = 99; // Major version 99
        assert!(matches!(
            Keystore::from_bytes(&bad_version),
            Err(VaultError::InvalidFormat(_))
        ));
    }

    #[test]
    fn test_dek_entry_decrypt_wrong_kek() {
        let file_uuid = generate_uuid().unwrap();
        let dek = [0x42; 32];
        let kek = [0xAB; 32];
        let wrong_kek = [0xFF; 32];

        let (encrypted_dek, nonce) = wrap_dek(&dek, &kek, &file_uuid)
            .expect("Wrap should succeed");

        let entry = DekEntry::new(file_uuid, encrypted_dek, nonce);

        assert!(matches!(
            entry.decrypt_dek(&wrong_kek),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_keystore_deterministic_serialization() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        // Add entries in random order
        for _ in 0..5 {
            let file_uuid = generate_uuid().unwrap();
            let dek = generate_key().unwrap();
            add_file_dek(&mut keystore, file_uuid, &dek, &kek, &hmac_key)
                .expect("Add DEK should succeed");
        }

        // Serialize twice - should produce identical bytes
        let bytes1 = keystore.to_bytes();
        let bytes2 = keystore.to_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_clear_dek_entries() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        for _ in 0..3 {
            let file_uuid = generate_uuid().unwrap();
            let dek = generate_key().unwrap();
            add_file_dek(&mut keystore, file_uuid, &dek, &kek, &hmac_key)
                .expect("Add DEK should succeed");
        }

        assert_eq!(keystore.dek_count(), 3);

        keystore.clear_dek_entries();
        assert_eq!(keystore.dek_count(), 0);
    }

    #[test]
    fn test_keystore_from_components() {
        let version = KeystoreVersion::new(1, 0);
        let level_id = 5;
        let encrypted_kek = [0xAA; ENCRYPTED_KEY_SIZE];
        let kek_nonce = [0xBB; NONCE_SIZE];
        let hmac_tag = [0xCC; HMAC_TAG_SIZE];
        let dek_entries = HashMap::new();

        let keystore = Keystore::from_components(
            version,
            level_id,
            encrypted_kek,
            kek_nonce,
            dek_entries,
            hmac_tag,
        );

        assert_eq!(keystore.version(), version);
        assert_eq!(keystore.level_id(), 5);
        assert_eq!(keystore.encrypted_kek(), &encrypted_kek);
        assert_eq!(keystore.kek_nonce(), &kek_nonce);
        assert_eq!(keystore.hmac_tag(), &hmac_tag);
    }

    #[test]
    fn test_dek_entry_getters() {
        let file_uuid = generate_uuid().unwrap();
        let encrypted_dek = [0x42; ENCRYPTED_KEY_SIZE];
        let dek_nonce = [0x33; NONCE_SIZE];

        let entry = DekEntry::new(file_uuid, encrypted_dek, dek_nonce);

        assert_eq!(entry.file_uuid(), file_uuid);
        assert_eq!(entry.encrypted_dek(), &encrypted_dek);
        assert_eq!(entry.dek_nonce(), &dek_nonce);
    }

    #[test]
    fn test_iterate_dek_entries() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        let uuids: Vec<Uuid> = (0..3).map(|_| generate_uuid().unwrap()).collect();
        for uuid in &uuids {
            let dek = generate_key().unwrap();
            add_file_dek(&mut keystore, *uuid, &dek, &kek, &hmac_key)
                .expect("Add DEK should succeed");
        }

        let mut found_uuids: Vec<Uuid> = keystore.dek_entries().map(|(uuid, _)| *uuid).collect();
        found_uuids.sort();

        let mut expected_uuids = uuids.clone();
        expected_uuids.sort();

        assert_eq!(found_uuids, expected_uuids);
    }

    #[test]
    fn test_replace_dek_entry() {
        let (mut keystore, kek, hmac_key) = create_test_keystore();

        let file_uuid = generate_uuid().unwrap();
        let dek1 = generate_key().unwrap();
        let dek2 = generate_key().unwrap();

        // Add first DEK
        add_file_dek(&mut keystore, file_uuid, &dek1, &kek, &hmac_key)
            .expect("Add DEK should succeed");

        // Replace with second DEK
        add_file_dek(&mut keystore, file_uuid, &dek2, &kek, &hmac_key)
            .expect("Add DEK should succeed");

        assert_eq!(keystore.dek_count(), 1);

        // Should decrypt to second DEK
        let decrypted = keystore.decrypt_file_dek(&file_uuid, &kek)
            .expect("Decrypt should succeed");
        assert_eq!(decrypted, dek2);
    }

    // ============================================================================
    // US-020: Per-Level Password Management - Keystore Tests
    // ============================================================================

    #[test]
    fn test_rewrap_kek_success() {
        let (mut keystore, kek, old_hmac_key) = create_test_keystore();
        let old_alk = [0xAB; 32]; // Same as create_test_keystore

        // Verify original decryption works
        let decrypted_kek = keystore.decrypt_kek(&old_alk)
            .expect("Original decryption should succeed");
        assert_eq!(decrypted_kek, kek);

        // Create new ALK and HMAC key (simulating password change)
        let new_alk = [0x12; 32];
        let new_hmac_key = [0x34; 32];

        // Re-wrap the KEK with the new ALK
        keystore.rewrap_kek(&kek, &new_alk, &new_hmac_key)
            .expect("Rewrap should succeed");

        // Old ALK should no longer work
        assert!(matches!(
            keystore.decrypt_kek(&old_alk),
            Err(VaultError::AuthenticationFailed)
        ));

        // New ALK should work
        let decrypted_kek = keystore.decrypt_kek(&new_alk)
            .expect("New decryption should succeed");
        assert_eq!(decrypted_kek, kek, "KEK should be unchanged");

        // Verify new HMAC key
        keystore.verify_integrity(&new_hmac_key)
            .expect("New HMAC should verify");

        // Old HMAC should fail
        assert!(matches!(
            keystore.verify_integrity(&old_hmac_key),
            Err(VaultError::HeaderIntegrityFailed)
        ));
    }

    #[test]
    fn test_rewrap_kek_preserves_deks() {
        let (mut keystore, kek, old_hmac_key) = create_test_keystore();
        let old_alk = [0xAB; 32];

        // Add some file DEKs
        let file_uuid1 = generate_uuid().unwrap();
        let file_uuid2 = generate_uuid().unwrap();
        let dek1 = generate_key().unwrap();
        let dek2 = generate_key().unwrap();

        add_file_dek(&mut keystore, file_uuid1, &dek1, &kek, &old_hmac_key)
            .expect("Add DEK 1 should succeed");
        add_file_dek(&mut keystore, file_uuid2, &dek2, &kek, &old_hmac_key)
            .expect("Add DEK 2 should succeed");

        // Re-wrap KEK with new ALK
        let new_alk = [0x56; 32];
        let new_hmac_key = [0x78; 32];
        keystore.rewrap_kek(&kek, &new_alk, &new_hmac_key)
            .expect("Rewrap should succeed");

        // DEKs should still be decryptable with the same KEK
        let decrypted_dek1 = keystore.decrypt_file_dek(&file_uuid1, &kek)
            .expect("DEK 1 should decrypt");
        let decrypted_dek2 = keystore.decrypt_file_dek(&file_uuid2, &kek)
            .expect("DEK 2 should decrypt");

        assert_eq!(decrypted_dek1, dek1);
        assert_eq!(decrypted_dek2, dek2);
    }

    #[test]
    fn test_rewrap_kek_roundtrip_serialization() {
        let (mut keystore, kek, _old_hmac_key) = create_test_keystore();

        // Add a file DEK
        let file_uuid = generate_uuid().unwrap();
        let dek = generate_key().unwrap();
        add_file_dek(&mut keystore, file_uuid, &dek, &kek, &[0xCD; 32])
            .expect("Add DEK should succeed");

        // Re-wrap with new credentials
        let new_alk = [0xAA; 32];
        let new_hmac_key = [0xBB; 32];
        keystore.rewrap_kek(&kek, &new_alk, &new_hmac_key)
            .expect("Rewrap should succeed");

        // Serialize and deserialize
        let bytes = keystore.to_bytes();
        let restored = Keystore::from_bytes(&bytes)
            .expect("Deserialize should succeed");

        // Verify new credentials work on restored keystore
        restored.verify_integrity(&new_hmac_key)
            .expect("HMAC should verify");
        let decrypted_kek = restored.decrypt_kek(&new_alk)
            .expect("Decrypt KEK should succeed");
        assert_eq!(decrypted_kek, kek);

        // Verify DEK still works
        let decrypted_dek = restored.decrypt_file_dek(&file_uuid, &kek)
            .expect("Decrypt DEK should succeed");
        assert_eq!(decrypted_dek, dek);
    }
}
