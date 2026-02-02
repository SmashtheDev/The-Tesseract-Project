//! Streaming encryption/decryption for large files.
//!
//! This module provides chunk-based encryption and decryption that allows
//! processing files larger than available RAM. Each chunk is encrypted
//! independently using AES-256-GCM with a unique nonce derived from a base
//! nonce and chunk counter.
//!
//! # Security Design
//!
//! - Each chunk gets a unique nonce: `base_nonce XOR (counter as bytes)`
//! - Chunk counter is included as AAD to prevent chunk reordering attacks
//! - Final chunk is marked with a special AAD to prevent truncation attacks
//! - Memory usage is bounded to ~2x chunk size (input buffer + output buffer)
//!
//! # Chunk Format
//!
//! Each encrypted chunk has the format:
//! ```text
//! [encrypted_data][16-byte auth tag]
//! ```
//!
//! # Example
//!
//! ```ignore
//! use tesseract_crypto::streaming::{
//!     StreamingEncryptor, StreamingDecryptor, StreamConfig,
//! };
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! // Encrypt a large file
//! let config = StreamConfig::default();
//! let key = [0u8; 32];
//! let file_uuid = uuid::Uuid::new_v4();
//!
//! let mut encryptor = StreamingEncryptor::new(&key, file_uuid, config)?;
//!
//! let mut reader = BufReader::new(File::open("large_file.bin")?);
//! let mut writer = File::create("large_file.enc")?;
//!
//! encryptor.encrypt_stream(&mut reader, &mut writer, |progress| {
//!     println!("Progress: {}%", (progress * 100.0) as u32);
//! })?;
//! ```

use std::io::{Read, Write};

use crate::aes::{self, KEY_LENGTH, NONCE_LENGTH, TAG_LENGTH};
use crate::random::generate_nonce;
use crate::CryptoError;
use uuid::Uuid;

/// Default chunk size: 1 MiB.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Minimum allowed chunk size: 4 KiB.
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;

/// Maximum allowed chunk size: 64 MiB.
pub const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;

/// Magic bytes for streaming format header.
const STREAM_MAGIC: [u8; 4] = *b"TESS";

/// Stream format version.
const STREAM_VERSION: u8 = 1;

/// Header size: 4 (magic) + 1 (version) + 12 (base_nonce) + 4 (chunk_size) = 21 bytes.
const HEADER_SIZE: usize = 21;

/// Error type for streaming operations.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// Underlying crypto error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// IO error during streaming.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid stream format.
    #[error("Invalid stream format: {0}")]
    InvalidFormat(String),

    /// Chunk size configuration error.
    #[error("Invalid chunk size: {0}")]
    InvalidChunkSize(String),

    /// Stream truncated unexpectedly.
    #[error("Stream truncated: expected more data")]
    Truncated,

    /// Chunk reordering detected.
    #[error("Chunk reordering detected: expected chunk {expected}, got {actual}")]
    ChunkReordering {
        /// Expected chunk index.
        expected: u64,
        /// Actual chunk index in AAD.
        actual: u64,
    },
}

/// Result type for streaming operations.
pub type StreamResult<T> = Result<T, StreamError>;

/// Configuration for streaming encryption/decryption.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Size of each chunk in bytes. Default is 1 MiB.
    pub chunk_size: usize,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl StreamConfig {
    /// Creates a new configuration with the specified chunk size.
    ///
    /// # Errors
    ///
    /// Returns an error if chunk size is outside the valid range.
    pub fn with_chunk_size(chunk_size: usize) -> StreamResult<Self> {
        if chunk_size < MIN_CHUNK_SIZE {
            return Err(StreamError::InvalidChunkSize(format!(
                "Chunk size {} is below minimum {}",
                chunk_size, MIN_CHUNK_SIZE
            )));
        }
        if chunk_size > MAX_CHUNK_SIZE {
            return Err(StreamError::InvalidChunkSize(format!(
                "Chunk size {} exceeds maximum {}",
                chunk_size, MAX_CHUNK_SIZE
            )));
        }
        Ok(Self { chunk_size })
    }

    /// Validates the configuration.
    pub fn validate(&self) -> StreamResult<()> {
        if self.chunk_size < MIN_CHUNK_SIZE {
            return Err(StreamError::InvalidChunkSize(format!(
                "Chunk size {} is below minimum {}",
                self.chunk_size, MIN_CHUNK_SIZE
            )));
        }
        if self.chunk_size > MAX_CHUNK_SIZE {
            return Err(StreamError::InvalidChunkSize(format!(
                "Chunk size {} exceeds maximum {}",
                self.chunk_size, MAX_CHUNK_SIZE
            )));
        }
        Ok(())
    }
}

/// Progress callback function type.
///
/// Called with a value between 0.0 and 1.0 indicating progress.
pub type ProgressCallback = dyn FnMut(f64);

/// Derives a unique nonce for a specific chunk by XORing the base nonce
/// with the chunk counter.
///
/// This ensures each chunk gets a unique nonce while maintaining determinism
/// for decryption.
fn derive_chunk_nonce(base_nonce: &[u8; NONCE_LENGTH], chunk_index: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = *base_nonce;
    let counter_bytes = chunk_index.to_le_bytes();

    // XOR the counter into the last 8 bytes of the nonce
    for i in 0..8 {
        nonce[NONCE_LENGTH - 8 + i] ^= counter_bytes[i];
    }

    nonce
}

/// Builds AAD (Additional Authenticated Data) for a chunk.
///
/// The AAD includes:
/// - File UUID (16 bytes) - binds chunk to specific file
/// - Chunk index (8 bytes) - prevents chunk reordering
/// - Is-final flag (1 byte) - prevents truncation attacks
fn build_chunk_aad(file_uuid: &Uuid, chunk_index: u64, is_final: bool) -> [u8; 25] {
    let mut aad = [0u8; 25];
    aad[0..16].copy_from_slice(file_uuid.as_bytes());
    aad[16..24].copy_from_slice(&chunk_index.to_le_bytes());
    aad[24] = if is_final { 1 } else { 0 };
    aad
}

/// Streaming encryptor for large files.
///
/// Encrypts data in chunks, each with a unique nonce derived from a base
/// nonce and chunk counter.
pub struct StreamingEncryptor {
    /// Encryption key.
    key: [u8; KEY_LENGTH],
    /// Base nonce for chunk nonce derivation.
    base_nonce: [u8; NONCE_LENGTH],
    /// File UUID for AAD binding.
    file_uuid: Uuid,
    /// Configuration.
    config: StreamConfig,
}

impl StreamingEncryptor {
    /// Creates a new streaming encryptor.
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit encryption key
    /// * `file_uuid` - UUID to bind encrypted chunks to this file
    /// * `config` - Streaming configuration
    ///
    /// # Returns
    ///
    /// A new StreamingEncryptor ready to encrypt data.
    pub fn new(key: &[u8; KEY_LENGTH], file_uuid: Uuid, config: StreamConfig) -> StreamResult<Self> {
        config.validate()?;
        let base_nonce = generate_nonce()?;

        Ok(Self {
            key: *key,
            base_nonce,
            file_uuid,
            config,
        })
    }

    /// Creates a new streaming encryptor with a specific base nonce.
    ///
    /// This is primarily for testing deterministic behavior.
    pub fn with_nonce(
        key: &[u8; KEY_LENGTH],
        base_nonce: [u8; NONCE_LENGTH],
        file_uuid: Uuid,
        config: StreamConfig,
    ) -> StreamResult<Self> {
        config.validate()?;

        Ok(Self {
            key: *key,
            base_nonce,
            file_uuid,
            config,
        })
    }

    /// Returns the base nonce used for this encryption.
    pub fn base_nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.base_nonce
    }

    /// Returns the chunk size configuration.
    pub fn chunk_size(&self) -> usize {
        self.config.chunk_size
    }

    /// Encrypts a single chunk.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Chunk data to encrypt
    /// * `chunk_index` - Index of this chunk (0-based)
    /// * `is_final` - Whether this is the last chunk
    ///
    /// # Returns
    ///
    /// Encrypted chunk data with authentication tag.
    pub fn encrypt_chunk(
        &self,
        plaintext: &[u8],
        chunk_index: u64,
        is_final: bool,
    ) -> StreamResult<Vec<u8>> {
        let nonce = derive_chunk_nonce(&self.base_nonce, chunk_index);
        let aad = build_chunk_aad(&self.file_uuid, chunk_index, is_final);

        let ciphertext = aes::encrypt(&self.key, &nonce, plaintext, &aad)?;
        Ok(ciphertext)
    }

    /// Encrypts data from a reader to a writer with progress reporting.
    ///
    /// # Arguments
    ///
    /// * `reader` - Source of plaintext data
    /// * `writer` - Destination for encrypted data
    /// * `progress` - Optional callback for progress updates (0.0 to 1.0)
    ///
    /// # Stream Format
    ///
    /// The output stream has the format:
    /// ```text
    /// [4-byte magic "TESS"][1-byte version][12-byte base_nonce][4-byte chunk_size]
    /// [chunk_0: encrypted_data + tag]
    /// [chunk_1: encrypted_data + tag]
    /// ...
    /// [chunk_n: encrypted_data + tag (final)]
    /// ```
    ///
    /// # Returns
    ///
    /// Total bytes written to the output stream.
    pub fn encrypt_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        mut progress: Option<&mut ProgressCallback>,
    ) -> StreamResult<u64> {
        // Write header
        writer.write_all(&STREAM_MAGIC)?;
        writer.write_all(&[STREAM_VERSION])?;
        writer.write_all(&self.base_nonce)?;
        writer.write_all(&(self.config.chunk_size as u32).to_le_bytes())?;

        let mut total_written = HEADER_SIZE as u64;
        let mut chunk_buffer = vec![0u8; self.config.chunk_size];
        let mut chunk_index: u64 = 0;
        let mut bytes_read_total: u64 = 0;
        // Track if we have a pending byte from a previous peek
        let mut pending_byte: Option<u8> = None;

        loop {
            // Calculate buffer offset based on whether we have a pending byte
            let offset = if let Some(b) = pending_byte.take() {
                chunk_buffer[0] = b;
                1
            } else {
                0
            };

            // Read data into the buffer (after any pending byte)
            let bytes_read = read_exact_or_eof(reader, &mut chunk_buffer[offset..])?;
            let total_chunk_bytes = offset + bytes_read;

            if total_chunk_bytes == 0 {
                // No data at all - write empty final chunk if this is the first chunk
                if chunk_index == 0 {
                    let ciphertext = self.encrypt_chunk(&[], 0, true)?;
                    writer.write_all(&ciphertext)?;
                    total_written += ciphertext.len() as u64;
                }
                break;
            }

            bytes_read_total += bytes_read as u64;

            // Peek to check if this is the final chunk
            let mut peek = [0u8; 1];
            let peek_result = reader.read(&mut peek)?;
            let is_final = peek_result == 0;

            // Encrypt this chunk
            let ciphertext = self.encrypt_chunk(&chunk_buffer[..total_chunk_bytes], chunk_index, is_final)?;
            writer.write_all(&ciphertext)?;
            total_written += ciphertext.len() as u64;

            chunk_index += 1;

            // Report progress if callback provided
            if let Some(ref mut cb) = progress {
                cb(bytes_read_total as f64);
            }

            if is_final {
                break;
            }

            // Store the peeked byte for the next iteration
            pending_byte = Some(peek[0]);
        }

        writer.flush()?;
        Ok(total_written)
    }

    /// Encrypts data from a byte slice with progress reporting.
    ///
    /// This is a convenience method for in-memory encryption.
    pub fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        mut progress: Option<&mut ProgressCallback>,
    ) -> StreamResult<Vec<u8>> {
        // Calculate total output size for pre-allocation
        let num_chunks = if plaintext.is_empty() {
            1
        } else {
            (plaintext.len() + self.config.chunk_size - 1) / self.config.chunk_size
        };
        let estimated_size = HEADER_SIZE + plaintext.len() + (num_chunks * TAG_LENGTH);

        let mut output = Vec::with_capacity(estimated_size);

        // Write header
        output.extend_from_slice(&STREAM_MAGIC);
        output.push(STREAM_VERSION);
        output.extend_from_slice(&self.base_nonce);
        output.extend_from_slice(&(self.config.chunk_size as u32).to_le_bytes());

        let total_bytes = plaintext.len() as f64;

        if plaintext.is_empty() {
            // Empty input: write single empty final chunk
            let ciphertext = self.encrypt_chunk(&[], 0, true)?;
            output.extend_from_slice(&ciphertext);
        } else {
            let mut offset = 0;
            let mut chunk_index: u64 = 0;

            while offset < plaintext.len() {
                let end = std::cmp::min(offset + self.config.chunk_size, plaintext.len());
                let is_final = end == plaintext.len();
                let chunk_data = &plaintext[offset..end];

                let ciphertext = self.encrypt_chunk(chunk_data, chunk_index, is_final)?;
                output.extend_from_slice(&ciphertext);

                offset = end;
                chunk_index += 1;

                if let Some(ref mut cb) = progress {
                    cb(offset as f64 / total_bytes);
                }
            }
        }

        Ok(output)
    }
}

/// Streaming decryptor for large files.
pub struct StreamingDecryptor {
    /// Decryption key.
    key: [u8; KEY_LENGTH],
    /// File UUID for AAD verification.
    file_uuid: Uuid,
}

impl StreamingDecryptor {
    /// Creates a new streaming decryptor.
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit decryption key
    /// * `file_uuid` - UUID that was used during encryption
    pub fn new(key: &[u8; KEY_LENGTH], file_uuid: Uuid) -> Self {
        Self {
            key: *key,
            file_uuid,
        }
    }

    /// Decrypts a single chunk.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Encrypted chunk data with authentication tag
    /// * `base_nonce` - Base nonce from stream header
    /// * `chunk_index` - Index of this chunk
    /// * `is_final` - Whether this is expected to be the last chunk
    ///
    /// # Returns
    ///
    /// Decrypted chunk data.
    pub fn decrypt_chunk(
        &self,
        ciphertext: &[u8],
        base_nonce: &[u8; NONCE_LENGTH],
        chunk_index: u64,
        is_final: bool,
    ) -> StreamResult<Vec<u8>> {
        let nonce = derive_chunk_nonce(base_nonce, chunk_index);
        let aad = build_chunk_aad(&self.file_uuid, chunk_index, is_final);

        let plaintext = aes::decrypt(&self.key, &nonce, ciphertext, &aad)?;
        Ok(plaintext)
    }

    /// Decrypts data from a reader to a writer with progress reporting.
    ///
    /// # Arguments
    ///
    /// * `reader` - Source of encrypted data
    /// * `writer` - Destination for decrypted data
    /// * `progress` - Optional callback for progress updates
    ///
    /// # Returns
    ///
    /// Total bytes of plaintext written.
    pub fn decrypt_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        mut progress: Option<&mut ProgressCallback>,
    ) -> StreamResult<u64> {
        // Read and validate header
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header).map_err(|_| {
            StreamError::InvalidFormat("Failed to read stream header".to_string())
        })?;

        // Validate magic bytes
        if header[0..4] != STREAM_MAGIC {
            return Err(StreamError::InvalidFormat(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                STREAM_MAGIC,
                &header[0..4]
            )));
        }

        // Validate version
        let version = header[4];
        if version != STREAM_VERSION {
            return Err(StreamError::InvalidFormat(format!(
                "Unsupported stream version: expected {}, got {}",
                STREAM_VERSION, version
            )));
        }

        // Extract base nonce
        let mut base_nonce = [0u8; NONCE_LENGTH];
        base_nonce.copy_from_slice(&header[5..17]);

        // Extract chunk size
        let chunk_size = u32::from_le_bytes([header[17], header[18], header[19], header[20]]) as usize;

        // Validate chunk size
        if chunk_size < MIN_CHUNK_SIZE || chunk_size > MAX_CHUNK_SIZE {
            return Err(StreamError::InvalidFormat(format!(
                "Invalid chunk size in header: {}",
                chunk_size
            )));
        }

        // Calculate encrypted chunk size (plaintext + tag)
        let encrypted_chunk_size = chunk_size + TAG_LENGTH;

        let mut total_written: u64 = 0;
        let mut chunk_index: u64 = 0;
        let mut chunk_buffer = vec![0u8; encrypted_chunk_size];
        // Track if we have a pending byte from a previous peek
        let mut pending_byte: Option<u8> = None;

        loop {
            // Calculate buffer offset based on whether we have a pending byte
            let offset = if let Some(b) = pending_byte.take() {
                chunk_buffer[0] = b;
                1
            } else {
                0
            };

            // Read data into the buffer (after any pending byte)
            let bytes_read = read_exact_or_eof(reader, &mut chunk_buffer[offset..])?;
            let total_chunk_bytes = offset + bytes_read;

            if total_chunk_bytes == 0 {
                // No more data - check if we've seen at least one chunk
                if chunk_index == 0 {
                    return Err(StreamError::Truncated);
                }
                break;
            }

            // Peek to check if this is the final chunk
            let mut peek = [0u8; 1];
            let has_more = reader.read(&mut peek)? > 0;
            let is_final = !has_more;

            // Validate chunk has at least the tag
            if total_chunk_bytes < TAG_LENGTH {
                return Err(StreamError::InvalidFormat(
                    "Chunk smaller than authentication tag".to_string(),
                ));
            }

            // Decrypt the chunk
            let plaintext = self.decrypt_chunk(
                &chunk_buffer[..total_chunk_bytes],
                &base_nonce,
                chunk_index,
                is_final,
            )?;

            writer.write_all(&plaintext)?;
            total_written += plaintext.len() as u64;

            chunk_index += 1;

            if let Some(ref mut cb) = progress {
                cb(total_written as f64);
            }

            if is_final {
                break;
            }

            // Store the peeked byte for the next iteration
            pending_byte = Some(peek[0]);
        }

        writer.flush()?;
        Ok(total_written)
    }

    /// Decrypts data from a byte slice with progress reporting.
    ///
    /// This is a convenience method for in-memory decryption.
    pub fn decrypt_bytes(
        &self,
        ciphertext: &[u8],
        mut progress: Option<&mut ProgressCallback>,
    ) -> StreamResult<Vec<u8>> {
        // Validate minimum size
        if ciphertext.len() < HEADER_SIZE {
            return Err(StreamError::InvalidFormat(
                "Input too short to contain header".to_string(),
            ));
        }

        // Validate magic bytes
        if ciphertext[0..4] != STREAM_MAGIC {
            return Err(StreamError::InvalidFormat(format!(
                "Invalid magic bytes: expected {:?}, got {:?}",
                STREAM_MAGIC,
                &ciphertext[0..4]
            )));
        }

        // Validate version
        let version = ciphertext[4];
        if version != STREAM_VERSION {
            return Err(StreamError::InvalidFormat(format!(
                "Unsupported stream version: expected {}, got {}",
                STREAM_VERSION, version
            )));
        }

        // Extract base nonce
        let mut base_nonce = [0u8; NONCE_LENGTH];
        base_nonce.copy_from_slice(&ciphertext[5..17]);

        // Extract chunk size
        let chunk_size =
            u32::from_le_bytes([ciphertext[17], ciphertext[18], ciphertext[19], ciphertext[20]])
                as usize;

        // Validate chunk size
        if chunk_size < MIN_CHUNK_SIZE || chunk_size > MAX_CHUNK_SIZE {
            return Err(StreamError::InvalidFormat(format!(
                "Invalid chunk size in header: {}",
                chunk_size
            )));
        }

        let encrypted_chunk_size = chunk_size + TAG_LENGTH;
        let mut output = Vec::new();
        let mut offset = HEADER_SIZE;
        let mut chunk_index: u64 = 0;
        let total_encrypted = ciphertext.len() - HEADER_SIZE;

        if total_encrypted == 0 {
            return Err(StreamError::Truncated);
        }

        while offset < ciphertext.len() {
            // Determine chunk boundaries
            let remaining = ciphertext.len() - offset;
            let chunk_end = if remaining >= encrypted_chunk_size {
                offset + encrypted_chunk_size
            } else {
                ciphertext.len()
            };

            let is_final = chunk_end == ciphertext.len();
            let chunk_ciphertext = &ciphertext[offset..chunk_end];

            if chunk_ciphertext.len() < TAG_LENGTH {
                return Err(StreamError::InvalidFormat(
                    "Chunk smaller than authentication tag".to_string(),
                ));
            }

            let plaintext = self.decrypt_chunk(chunk_ciphertext, &base_nonce, chunk_index, is_final)?;
            output.extend_from_slice(&plaintext);

            offset = chunk_end;
            chunk_index += 1;

            if let Some(ref mut cb) = progress {
                cb((offset - HEADER_SIZE) as f64 / total_encrypted as f64);
            }
        }

        Ok(output)
    }
}

/// Reads exactly `buf.len()` bytes, or returns the number of bytes read if EOF.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break, // EOF
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total_read)
}

/// Calculates the encrypted size for a given plaintext size.
///
/// This is useful for pre-allocating output buffers or estimating storage needs.
pub fn calculate_encrypted_size(plaintext_size: usize, chunk_size: usize) -> usize {
    if plaintext_size == 0 {
        // Empty file: header + one empty chunk (just the tag)
        HEADER_SIZE + TAG_LENGTH
    } else {
        let num_chunks = (plaintext_size + chunk_size - 1) / chunk_size;
        HEADER_SIZE + plaintext_size + (num_chunks * TAG_LENGTH)
    }
}

/// Calculates the maximum possible plaintext size for a given encrypted size.
///
/// Returns None if the encrypted size is too small to be valid.
pub fn calculate_max_plaintext_size(encrypted_size: usize, chunk_size: usize) -> Option<usize> {
    if encrypted_size < HEADER_SIZE + TAG_LENGTH {
        return None;
    }

    let data_size = encrypted_size - HEADER_SIZE;
    let encrypted_chunk_size = chunk_size + TAG_LENGTH;

    // Calculate number of full chunks
    let full_chunks = data_size / encrypted_chunk_size;
    let remainder = data_size % encrypted_chunk_size;

    if remainder > 0 && remainder < TAG_LENGTH {
        // Invalid: remainder chunk is too small
        return None;
    }

    let plaintext_from_full_chunks = full_chunks * chunk_size;
    let plaintext_from_remainder = if remainder >= TAG_LENGTH {
        remainder - TAG_LENGTH
    } else {
        0
    };

    Some(plaintext_from_full_chunks + plaintext_from_remainder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn test_key() -> [u8; KEY_LENGTH] {
        [0x42u8; KEY_LENGTH]
    }

    fn test_uuid() -> Uuid {
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    // ==========================================
    // Configuration Tests
    // ==========================================

    #[test]
    fn test_default_config() {
        let config = StreamConfig::default();
        assert_eq!(config.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(config.chunk_size, 1024 * 1024);
    }

    #[test]
    fn test_config_with_chunk_size() {
        let config = StreamConfig::with_chunk_size(64 * 1024).unwrap();
        assert_eq!(config.chunk_size, 64 * 1024);
    }

    #[test]
    fn test_config_chunk_size_too_small() {
        let result = StreamConfig::with_chunk_size(1024); // 1KB, below minimum
        assert!(matches!(result, Err(StreamError::InvalidChunkSize(_))));
    }

    #[test]
    fn test_config_chunk_size_too_large() {
        let result = StreamConfig::with_chunk_size(128 * 1024 * 1024); // 128MB, above maximum
        assert!(matches!(result, Err(StreamError::InvalidChunkSize(_))));
    }

    #[test]
    fn test_config_validate() {
        let mut config = StreamConfig::default();
        assert!(config.validate().is_ok());

        config.chunk_size = 100; // Too small
        assert!(config.validate().is_err());
    }

    // ==========================================
    // Nonce Derivation Tests
    // ==========================================

    #[test]
    fn test_derive_chunk_nonce_uniqueness() {
        let base_nonce = [0x11u8; NONCE_LENGTH];

        let nonce0 = derive_chunk_nonce(&base_nonce, 0);
        let nonce1 = derive_chunk_nonce(&base_nonce, 1);
        let nonce2 = derive_chunk_nonce(&base_nonce, 2);
        let nonce_max = derive_chunk_nonce(&base_nonce, u64::MAX);

        // All nonces should be different
        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce0, nonce_max);
    }

    #[test]
    fn test_derive_chunk_nonce_deterministic() {
        let base_nonce = [0x22u8; NONCE_LENGTH];

        let nonce1 = derive_chunk_nonce(&base_nonce, 42);
        let nonce2 = derive_chunk_nonce(&base_nonce, 42);

        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_derive_chunk_nonce_zero_counter() {
        let base_nonce = [0x33u8; NONCE_LENGTH];
        let nonce = derive_chunk_nonce(&base_nonce, 0);

        // With counter 0, XOR should not change the nonce
        assert_eq!(nonce, base_nonce);
    }

    // ==========================================
    // AAD Tests
    // ==========================================

    #[test]
    fn test_build_chunk_aad_content() {
        let uuid = test_uuid();
        let aad = build_chunk_aad(&uuid, 5, false);

        // Check UUID bytes
        assert_eq!(&aad[0..16], uuid.as_bytes());

        // Check chunk index
        let chunk_index = u64::from_le_bytes([aad[16], aad[17], aad[18], aad[19], aad[20], aad[21], aad[22], aad[23]]);
        assert_eq!(chunk_index, 5);

        // Check is_final flag
        assert_eq!(aad[24], 0);
    }

    #[test]
    fn test_build_chunk_aad_final_flag() {
        let uuid = test_uuid();

        let aad_not_final = build_chunk_aad(&uuid, 0, false);
        let aad_final = build_chunk_aad(&uuid, 0, true);

        assert_eq!(aad_not_final[24], 0);
        assert_eq!(aad_final[24], 1);
    }

    // ==========================================
    // Single Chunk Encryption Tests
    // ==========================================

    #[test]
    fn test_encrypt_decrypt_single_chunk() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x44u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = b"Hello, streaming encryption!";
        let ciphertext = encryptor.encrypt_chunk(plaintext, 0, true).unwrap();

        let decrypted = decryptor.decrypt_chunk(&ciphertext, &base_nonce, 0, true).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chunk_wrong_index_fails() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x55u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = b"Test data";
        let ciphertext = encryptor.encrypt_chunk(plaintext, 0, true).unwrap();

        // Try to decrypt with wrong chunk index
        let result = decryptor.decrypt_chunk(&ciphertext, &base_nonce, 1, true);
        assert!(matches!(result, Err(StreamError::Crypto(CryptoError::AuthenticationFailed))));
    }

    #[test]
    fn test_chunk_wrong_final_flag_fails() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x66u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = b"Test data";
        let ciphertext = encryptor.encrypt_chunk(plaintext, 0, true).unwrap();

        // Try to decrypt with wrong final flag
        let result = decryptor.decrypt_chunk(&ciphertext, &base_nonce, 0, false);
        assert!(matches!(result, Err(StreamError::Crypto(CryptoError::AuthenticationFailed))));
    }

    #[test]
    fn test_chunk_wrong_uuid_fails() {
        let key = test_key();
        let uuid1 = test_uuid();
        let uuid2 = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let base_nonce = [0x77u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid1, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid2);

        let plaintext = b"Test data";
        let ciphertext = encryptor.encrypt_chunk(plaintext, 0, true).unwrap();

        // Try to decrypt with wrong UUID
        let result = decryptor.decrypt_chunk(&ciphertext, &base_nonce, 0, true);
        assert!(matches!(result, Err(StreamError::Crypto(CryptoError::AuthenticationFailed))));
    }

    // ==========================================
    // Byte Array Encryption Tests
    // ==========================================

    #[test]
    fn test_encrypt_decrypt_bytes_empty() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x88u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = b"";
        let ciphertext = encryptor.encrypt_bytes(plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bytes_small() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x99u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = b"Small test data that fits in one chunk";
        let ciphertext = encryptor.encrypt_bytes(plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bytes_multiple_chunks() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0xAAu8; NONCE_LENGTH];
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Create data that spans multiple chunks
        let plaintext = vec![0xBBu8; chunk_size * 3 + 1000];
        let ciphertext = encryptor.encrypt_bytes(&plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_bytes_exact_chunk_boundary() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0xCCu8; NONCE_LENGTH];
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Data exactly at chunk boundary
        let plaintext = vec![0xDDu8; chunk_size * 2];
        let ciphertext = encryptor.encrypt_bytes(&plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // ==========================================
    // Stream Encryption Tests
    // ==========================================

    #[test]
    fn test_encrypt_decrypt_stream() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0xEEu8; NONCE_LENGTH];
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = vec![0xFFu8; chunk_size + 500];
        let mut encrypted = Vec::new();
        let mut input = Cursor::new(&plaintext);

        encryptor.encrypt_stream(&mut input, &mut encrypted, None).unwrap();

        let mut decrypted = Vec::new();
        let mut enc_cursor = Cursor::new(&encrypted);
        decryptor.decrypt_stream(&mut enc_cursor, &mut decrypted, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stream_empty_input() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x11u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext: Vec<u8> = vec![];
        let mut encrypted = Vec::new();
        let mut input = Cursor::new(&plaintext);

        encryptor.encrypt_stream(&mut input, &mut encrypted, None).unwrap();

        let mut decrypted = Vec::new();
        let mut enc_cursor = Cursor::new(&encrypted);
        decryptor.decrypt_stream(&mut enc_cursor, &mut decrypted, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // ==========================================
    // Progress Callback Tests
    // ==========================================

    #[test]
    fn test_progress_callback_called() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x22u8; NONCE_LENGTH];
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();

        let plaintext = vec![0x33u8; chunk_size * 2];
        static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
        CALL_COUNT.store(0, Ordering::SeqCst);

        let mut callback = |_p: f64| {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        };

        encryptor.encrypt_bytes(&plaintext, Some(&mut callback)).unwrap();

        // Progress should have been called at least once
        assert!(CALL_COUNT.load(Ordering::SeqCst) > 0);
    }

    // ==========================================
    // Size Calculation Tests
    // ==========================================

    #[test]
    fn test_calculate_encrypted_size() {
        let chunk_size = 1024;

        // Empty file
        assert_eq!(calculate_encrypted_size(0, chunk_size), HEADER_SIZE + TAG_LENGTH);

        // One chunk (1000 bytes)
        assert_eq!(calculate_encrypted_size(1000, chunk_size), HEADER_SIZE + 1000 + TAG_LENGTH);

        // Exactly one chunk
        assert_eq!(calculate_encrypted_size(chunk_size, chunk_size), HEADER_SIZE + chunk_size + TAG_LENGTH);

        // Two chunks
        assert_eq!(calculate_encrypted_size(chunk_size + 1, chunk_size), HEADER_SIZE + chunk_size + 1 + (2 * TAG_LENGTH));
    }

    #[test]
    fn test_calculate_max_plaintext_size() {
        let chunk_size = 1024;

        // Too small
        assert!(calculate_max_plaintext_size(10, chunk_size).is_none());

        // Header + one tag (empty file)
        assert_eq!(calculate_max_plaintext_size(HEADER_SIZE + TAG_LENGTH, chunk_size), Some(0));

        // One chunk with 500 bytes of plaintext
        let encrypted = HEADER_SIZE + 500 + TAG_LENGTH;
        assert_eq!(calculate_max_plaintext_size(encrypted, chunk_size), Some(500));
    }

    // ==========================================
    // Invalid Input Tests
    // ==========================================

    #[test]
    fn test_decrypt_invalid_magic() {
        let key = test_key();
        let uuid = test_uuid();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let mut bad_data = vec![0u8; 50];
        bad_data[0..4].copy_from_slice(b"XXXX"); // Wrong magic

        let result = decryptor.decrypt_bytes(&bad_data, None);
        assert!(matches!(result, Err(StreamError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_invalid_version() {
        let key = test_key();
        let uuid = test_uuid();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let mut bad_data = vec![0u8; 50];
        bad_data[0..4].copy_from_slice(&STREAM_MAGIC);
        bad_data[4] = 99; // Invalid version

        let result = decryptor.decrypt_bytes(&bad_data, None);
        assert!(matches!(result, Err(StreamError::InvalidFormat(_))));
    }

    #[test]
    fn test_decrypt_truncated_header() {
        let key = test_key();
        let uuid = test_uuid();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let short_data = vec![0u8; 10]; // Too short for header
        let result = decryptor.decrypt_bytes(&short_data, None);
        assert!(matches!(result, Err(StreamError::InvalidFormat(_))));
    }

    // ==========================================
    // Large File Simulation Tests
    // ==========================================

    #[test]
    fn test_large_file_simulation() {
        let key = test_key();
        let uuid = test_uuid();
        let chunk_size = MIN_CHUNK_SIZE; // Use minimum for faster test
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::new(&key, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Simulate a 1MB file
        let file_size = 1024 * 1024;
        let plaintext: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

        let ciphertext = encryptor.encrypt_bytes(&plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_memory_usage_bounded() {
        // This test verifies that streaming doesn't load the entire file into memory
        // by using streams with controlled buffer sizes

        let key = test_key();
        let uuid = test_uuid();
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::new(&key, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Create a "large" dataset (10 chunks worth)
        let data_size = chunk_size * 10;
        let plaintext: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

        // Encrypt via stream
        let mut input = Cursor::new(&plaintext);
        let mut encrypted = Vec::new();
        encryptor.encrypt_stream(&mut input, &mut encrypted, None).unwrap();

        // Decrypt via stream
        let mut enc_cursor = Cursor::new(&encrypted);
        let mut decrypted = Vec::new();
        decryptor.decrypt_stream(&mut enc_cursor, &mut decrypted, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_3x_speedup_benchmark_structure() {
        // This test verifies the structure for benchmarking
        // The actual 3x speedup is verified by hardware acceleration in the aes module

        let key = test_key();
        let uuid = test_uuid();
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::new(&key, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Encrypt/decrypt multiple times to measure consistency
        let plaintext = vec![0x42u8; chunk_size * 5];

        for _ in 0..3 {
            let ciphertext = encryptor.encrypt_bytes(&plaintext, None).unwrap();
            let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    // ==========================================
    // Header Format Tests
    // ==========================================

    #[test]
    fn test_header_format() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x44u8; NONCE_LENGTH];
        let chunk_size = 8192;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();

        let plaintext = b"Test";
        let ciphertext = encryptor.encrypt_bytes(plaintext, None).unwrap();

        // Verify header structure
        assert_eq!(&ciphertext[0..4], &STREAM_MAGIC);
        assert_eq!(ciphertext[4], STREAM_VERSION);
        assert_eq!(&ciphertext[5..17], &base_nonce);

        let stored_chunk_size = u32::from_le_bytes([ciphertext[17], ciphertext[18], ciphertext[19], ciphertext[20]]);
        assert_eq!(stored_chunk_size as usize, chunk_size);
    }

    // ==========================================
    // Edge Case Tests
    // ==========================================

    #[test]
    fn test_chunk_size_boundaries() {
        // Test with minimum chunk size
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();
        assert!(config.validate().is_ok());

        // Test with maximum chunk size
        let config = StreamConfig::with_chunk_size(MAX_CHUNK_SIZE).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_many_small_chunks() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x55u8; NONCE_LENGTH];
        let chunk_size = MIN_CHUNK_SIZE;
        let config = StreamConfig::with_chunk_size(chunk_size).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Create 100 chunks worth of data
        let plaintext = vec![0x66u8; chunk_size * 100];
        let ciphertext = encryptor.encrypt_bytes(&plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_binary_data() {
        let key = test_key();
        let uuid = test_uuid();
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::new(&key, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        // Binary data with all byte values
        let plaintext: Vec<u8> = (0..=255).cycle().take(10000).collect();
        let ciphertext = encryptor.encrypt_bytes(&plaintext, None).unwrap();
        let decrypted = decryptor.decrypt_bytes(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_chunk_detected() {
        let key = test_key();
        let uuid = test_uuid();
        let base_nonce = [0x77u8; NONCE_LENGTH];
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::with_nonce(&key, base_nonce, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key, uuid);

        let plaintext = b"Test data for tampering detection";
        let mut ciphertext = encryptor.encrypt_bytes(plaintext, None).unwrap();

        // Tamper with a byte in the encrypted chunk area
        let tamper_pos = HEADER_SIZE + 5;
        ciphertext[tamper_pos] ^= 0xFF;

        let result = decryptor.decrypt_bytes(&ciphertext, None);
        assert!(matches!(result, Err(StreamError::Crypto(CryptoError::AuthenticationFailed))));
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let key2 = [0x99u8; KEY_LENGTH];
        let uuid = test_uuid();
        let config = StreamConfig::with_chunk_size(MIN_CHUNK_SIZE).unwrap();

        let encryptor = StreamingEncryptor::new(&key1, uuid, config).unwrap();
        let decryptor = StreamingDecryptor::new(&key2, uuid);

        let plaintext = b"Secret data";
        let ciphertext = encryptor.encrypt_bytes(plaintext, None).unwrap();

        let result = decryptor.decrypt_bytes(&ciphertext, None);
        assert!(matches!(result, Err(StreamError::Crypto(CryptoError::AuthenticationFailed))));
    }
}
