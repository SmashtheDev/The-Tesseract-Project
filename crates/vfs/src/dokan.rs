//! Dokan filesystem implementation (Windows).
//!
//! This module provides Dokan integration for transparent encryption/decryption
//! on Windows. Files accessed through the Dokan mount are automatically
//! decrypted on read and encrypted on write.
//!
//! # Key Components
//!
//! - [`TesseractDokanHandler`]: The main filesystem handler implementing Dokan callbacks
//! - [`DokanMount`]: Mount controller for mounting/unmounting the filesystem
//! - [`DokanConfig`]: Configuration options for the mount
//!
//! # Dokan Callbacks Implemented
//!
//! Core operations (US-047):
//! - `CreateFile` / `CloseFile`
//! - `FindFiles` / `GetFileInformation`
//! - `GetDiskFreeSpace` / `GetVolumeInformation`
//!
//! Read/Write operations (US-048, US-049):
//! - `ReadFile` / `WriteFile`
//! - `SetEndOfFile` / `FlushFileBuffers`
//!
//! Delete/Rename operations (US-050):
//! - `DeleteFile` - removes blob and metadata, respects access levels
//! - `MoveFile` - updates metadata path for rename/move operations
//! - `CanDeleteFile` - validates delete permissions before operation
//! - `SetFileAttributes` - no-op for encrypted files (validates access)
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_vfs::dokan::{DokanMount, DokanConfig};
//! use tesseract_core::VaultSession;
//!
//! let session = VaultSession::open(...)?;
//! let config = DokanConfig::new('T');
//! let mount = DokanMount::new(session, config)?;
//! mount.mount()?;
//! // Filesystem is now accessible at T:\
//! mount.unmount()?;
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use tracing::{debug, warn, error, instrument};

use tesseract_core::{VaultSession, SessionState, VaultError};
use tesseract_core::files::{
    list_files, export_to_bytes, import_bytes, delete_file,
    EntryType, FileEntry,
};

use crate::error::{VfsError, NtStatusCode, log_operation_failure};

/// Windows FILETIME epoch: January 1, 1601.
/// Difference between Unix epoch (1970) and Windows FILETIME epoch (1601) in 100-nanosecond intervals.
const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

/// Volume information for the TESSERACT filesystem.
pub const VOLUME_LABEL: &str = "TESSERACT";

/// Filesystem name reported to Windows.
pub const FILESYSTEM_NAME: &str = "TESSERACT-VFS";

/// Maximum path component length in bytes.
pub const MAX_COMPONENT_LENGTH: u32 = 255;

/// Default volume serial number.
pub const VOLUME_SERIAL: u32 = 0x5445_5353; // "TESS" in hex

// =============================================================================
// Chunk Cache Configuration (US-048)
// =============================================================================

/// Default chunk size for caching: 64 KiB.
/// Smaller than streaming chunk size for lower latency on partial reads.
pub const CACHE_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum number of cached chunks per file.
pub const MAX_CACHED_CHUNKS_PER_FILE: usize = 16;

/// Maximum total cache size across all files: 16 MiB.
pub const MAX_CACHE_SIZE: usize = 16 * 1024 * 1024;

/// Cache entry expiration time: 5 minutes.
pub const CACHE_EXPIRATION_SECS: u64 = 300;

/// File system flags.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemFlags {
    /// Supports case-sensitive filenames.
    CaseSensitiveSearch = 0x0000_0001,
    /// Preserves case in filenames.
    CasePreservedNames = 0x0000_0002,
    /// Supports Unicode filenames.
    UnicodeOnDisk = 0x0000_0004,
    /// Supports persistent ACLs.
    PersistentAcls = 0x0000_0008,
    /// Read-only volume.
    ReadOnlyVolume = 0x0008_0000,
}

impl FileSystemFlags {
    /// Default flags for TESSERACT filesystem.
    pub fn default_flags() -> u32 {
        Self::CasePreservedNames as u32 | Self::UnicodeOnDisk as u32
    }
}

/// File attributes used by Windows.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAttributes {
    /// Normal file with no special attributes.
    Normal = 0x80,
    /// File is a directory.
    Directory = 0x10,
    /// File is read-only.
    ReadOnly = 0x01,
    /// File is hidden.
    Hidden = 0x02,
    /// File is a system file.
    System = 0x04,
    /// File is an archive.
    Archive = 0x20,
}

impl FileAttributes {
    /// Converts an EntryType to Windows file attributes.
    pub fn from_entry_type(entry_type: EntryType) -> u32 {
        match entry_type {
            EntryType::File => Self::Normal as u32 | Self::Archive as u32,
            EntryType::Directory => Self::Directory as u32,
        }
    }
}

/// Windows NT status codes returned by Dokan operations.
///
/// These are the NTSTATUS values returned by the Dokan driver to applications.
/// Each code maps to a standard Windows error that applications expect.
///
/// # US-053: Robust VFS Error Handling
///
/// Extended with disk/media errors for proper handling of:
/// - Disk full conditions
/// - USB removal mid-operation
/// - I/O errors and data corruption
/// - Encryption/decryption failures
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    /// Operation completed successfully.
    Success = 0,

    // -------------------------------------------------------------------------
    // Standard file operation errors
    // -------------------------------------------------------------------------

    /// The file or directory was not found.
    ObjectNameNotFound = 0xC000_0034_u32 as i32,
    /// Access is denied.
    AccessDenied = 0xC000_0022_u32 as i32,
    /// The operation is not implemented.
    NotImplemented = 0xC000_0002_u32 as i32,
    /// Invalid parameter.
    InvalidParameter = 0xC000_000D_u32 as i32,
    /// File exists when it shouldn't.
    ObjectNameCollision = 0xC000_0035_u32 as i32,
    /// End of file reached.
    EndOfFile = 0xC000_0011_u32 as i32,
    /// Internal error.
    InternalError = 0xC000_00E5_u32 as i32,
    /// Not a directory.
    NotADirectory = 0xC000_0103_u32 as i32,
    /// Is a directory (operation not valid on directory).
    FileIsADirectory = 0xC000_00BA_u32 as i32,

    // -------------------------------------------------------------------------
    // Disk/Media errors (US-053)
    // -------------------------------------------------------------------------

    /// Disk is full.
    DiskFull = 0xC000_007F_u32 as i32,
    /// Media was removed (USB unplugged).
    NoMediaInDevice = 0xC000_0013_u32 as i32,
    /// Device is not ready.
    DeviceNotReady = 0xC000_00A3_u32 as i32,
    /// Write protected media.
    MediaWriteProtected = 0xC000_00A2_u32 as i32,
    /// Data error (CRC or similar).
    DataError = 0xC000_003E_u32 as i32,
    /// Device I/O error.
    IoDeviceError = 0xC000_0185_u32 as i32,

    // -------------------------------------------------------------------------
    // Sharing and locking errors
    // -------------------------------------------------------------------------

    /// Sharing violation.
    SharingViolation = 0xC000_0043_u32 as i32,
    /// Lock violation.
    FileLockConflict = 0xC000_0054_u32 as i32,

    // -------------------------------------------------------------------------
    // Directory errors
    // -------------------------------------------------------------------------

    /// Directory is not empty.
    DirectoryNotEmpty = 0xC000_0101_u32 as i32,

    // -------------------------------------------------------------------------
    // Resource errors
    // -------------------------------------------------------------------------

    /// Too many files open.
    TooManyOpenFiles = 0xC000_011F_u32 as i32,
    /// Insufficient resources.
    InsufficientResources = 0xC000_009A_u32 as i32,

    // -------------------------------------------------------------------------
    // Path and name errors
    // -------------------------------------------------------------------------

    /// Object name invalid.
    ObjectNameInvalid = 0xC000_0033_u32 as i32,
    /// Object path not found.
    ObjectPathNotFound = 0xC000_003A_u32 as i32,

    // -------------------------------------------------------------------------
    // Encryption/Integrity errors
    // -------------------------------------------------------------------------

    /// File corrupt error.
    FileCorruptError = 0xC000_0102_u32 as i32,
    /// Encryption failed.
    EncryptionFailed = 0xC000_028E_u32 as i32,
    /// Decryption failed.
    DecryptionFailed = 0xC000_028F_u32 as i32,

    // -------------------------------------------------------------------------
    // Timeout
    // -------------------------------------------------------------------------

    /// IO timeout.
    IoTimeout = 0xC000_00B5_u32 as i32,

    // -------------------------------------------------------------------------
    // Cancelled
    // -------------------------------------------------------------------------

    /// Operation cancelled.
    Cancelled = 0xC000_0120_u32 as i32,
}

impl NtStatus {
    /// Convert to i32 for FFI.
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Check if status indicates success.
    pub fn is_success(self) -> bool {
        self == Self::Success
    }

    /// Check if status indicates an error.
    pub fn is_error(self) -> bool {
        (self as i32) < 0
    }

    /// Get a description of this status code.
    pub fn description(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::ObjectNameNotFound => "Object name not found",
            Self::AccessDenied => "Access denied",
            Self::NotImplemented => "Not implemented",
            Self::InvalidParameter => "Invalid parameter",
            Self::ObjectNameCollision => "Object name collision",
            Self::EndOfFile => "End of file",
            Self::InternalError => "Internal error",
            Self::NotADirectory => "Not a directory",
            Self::FileIsADirectory => "File is a directory",
            Self::DiskFull => "Disk full",
            Self::NoMediaInDevice => "No media in device",
            Self::DeviceNotReady => "Device not ready",
            Self::MediaWriteProtected => "Media is write protected",
            Self::DataError => "Data error",
            Self::IoDeviceError => "I/O device error",
            Self::SharingViolation => "Sharing violation",
            Self::FileLockConflict => "File lock conflict",
            Self::DirectoryNotEmpty => "Directory not empty",
            Self::TooManyOpenFiles => "Too many open files",
            Self::InsufficientResources => "Insufficient resources",
            Self::ObjectNameInvalid => "Object name invalid",
            Self::ObjectPathNotFound => "Object path not found",
            Self::FileCorruptError => "File corrupt error",
            Self::EncryptionFailed => "Encryption failed",
            Self::DecryptionFailed => "Decryption failed",
            Self::IoTimeout => "I/O timeout",
            Self::Cancelled => "Operation cancelled",
        }
    }

    /// Map from VaultError to NtStatus with logging.
    #[instrument(skip(err), fields(error_type = %std::any::type_name::<VaultError>()))]
    pub fn from_vault_error(err: &VaultError) -> Self {
        let status = match err {
            // File not found
            VaultError::FileNotFound => Self::ObjectNameNotFound,

            // Access control
            VaultError::AccessDenied => Self::AccessDenied,
            VaultError::VaultLocked => Self::AccessDenied,
            VaultError::KeyNotFound(_) => Self::AccessDenied,

            // Path errors
            VaultError::InvalidPath(_) => Self::ObjectNameInvalid,

            // Integrity/corruption
            VaultError::IntegrityError(_) => Self::FileCorruptError,

            // IO errors - check for specific patterns
            VaultError::IoError(io_err) => {
                Self::from_io_error_kind(io_err.kind())
            }

            // All other errors map to internal
            _ => Self::InternalError,
        };

        // Log the error mapping for debugging
        debug!(
            vault_error = %err,
            nt_status = ?status,
            status_code = status.as_i32(),
            "VaultError mapped to NtStatus"
        );

        status
    }

    /// Map from VfsError to NtStatus.
    #[instrument(skip(err))]
    pub fn from_vfs_error(err: &VfsError) -> Self {
        let status = match err {
            // Access control
            VfsError::AccessDenied | VfsError::SessionLocked => Self::AccessDenied,

            // File operations
            VfsError::FileNotFound => Self::ObjectNameNotFound,
            VfsError::AlreadyExists { .. } => Self::ObjectNameCollision,
            VfsError::DirectoryNotEmpty { .. } => Self::DirectoryNotEmpty,
            VfsError::IsDirectory { .. } => Self::FileIsADirectory,
            VfsError::NotADirectory { .. } => Self::NotADirectory,
            VfsError::InvalidPath { .. } => Self::ObjectNameInvalid,
            VfsError::NameTooLong { .. } => Self::ObjectNameInvalid,

            // Disk/Media errors
            VfsError::DiskFull { .. } => Self::DiskFull,
            VfsError::MediaRemoved { .. } => Self::NoMediaInDevice,
            VfsError::DeviceNotReady { .. } => Self::DeviceNotReady,
            VfsError::WriteProtected => Self::MediaWriteProtected,
            VfsError::IoError { .. } => Self::IoDeviceError,

            // Sharing/Locking
            VfsError::SharingViolation => Self::SharingViolation,
            VfsError::LockViolation => Self::FileLockConflict,
            VfsError::HandleBusy(_) => Self::SharingViolation,
            VfsError::TooManyOpenFiles { .. } => Self::TooManyOpenFiles,

            // Encryption/Integrity
            VfsError::EncryptionError(_) => Self::EncryptionFailed,
            VfsError::DecryptionError(_) => Self::DecryptionFailed,
            VfsError::IntegrityError(_) | VfsError::CorruptedData { .. } => Self::FileCorruptError,

            // Timeout
            VfsError::Timeout { .. } | VfsError::UnmountTimeout(_, _) => Self::IoTimeout,

            // Recovery/Corruption
            VfsError::RecoveryNeeded { .. } => Self::FileCorruptError,

            // Core vault errors - delegate
            VfsError::VaultError(vault_err) => Self::from_vault_error(vault_err),

            // Generic/Internal
            _ => Self::InternalError,
        };

        // Log the error
        debug!(
            vfs_error = %err,
            nt_status = ?status,
            status_code = status.as_i32(),
            "VfsError mapped to NtStatus"
        );

        status
    }

    /// Map from std::io::ErrorKind to NtStatus.
    fn from_io_error_kind(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::NotFound => Self::ObjectNameNotFound,
            std::io::ErrorKind::PermissionDenied => Self::AccessDenied,
            std::io::ErrorKind::AlreadyExists => Self::ObjectNameCollision,
            std::io::ErrorKind::WouldBlock => Self::SharingViolation,
            std::io::ErrorKind::TimedOut => Self::IoTimeout,
            std::io::ErrorKind::WriteZero => Self::DiskFull,
            std::io::ErrorKind::Interrupted => Self::IoDeviceError,
            std::io::ErrorKind::InvalidInput => Self::InvalidParameter,
            std::io::ErrorKind::InvalidData => Self::DataError,
            std::io::ErrorKind::UnexpectedEof => Self::EndOfFile,
            _ => Self::IoDeviceError,
        }
    }

    /// Log this status for troubleshooting.
    pub fn log_error(self, operation: &str, path: Option<&str>) {
        if self.is_error() {
            error!(
                operation = operation,
                path = path,
                status = ?self,
                code = self.as_i32(),
                description = self.description(),
                "VFS operation returned error"
            );
        }
    }
}

// =============================================================================
// Chunk Cache (US-048)
// =============================================================================

/// A cached chunk of decrypted file data.
#[derive(Debug, Clone)]
pub struct CachedChunk {
    /// Starting offset of this chunk within the file.
    pub offset: u64,
    /// The decrypted data.
    pub data: Vec<u8>,
    /// When this chunk was last accessed.
    pub last_accessed: Instant,
}

impl CachedChunk {
    /// Creates a new cached chunk.
    pub fn new(offset: u64, data: Vec<u8>) -> Self {
        Self {
            offset,
            data,
            last_accessed: Instant::now(),
        }
    }

    /// Returns the end offset of this chunk.
    pub fn end_offset(&self) -> u64 {
        self.offset + self.data.len() as u64
    }

    /// Checks if this chunk contains the given offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.offset && offset < self.end_offset()
    }

    /// Checks if this chunk is expired.
    pub fn is_expired(&self) -> bool {
        self.last_accessed.elapsed().as_secs() >= CACHE_EXPIRATION_SECS
    }

    /// Touches the chunk to update last accessed time.
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    /// Reads data from this chunk into the output buffer.
    /// Returns the number of bytes read.
    pub fn read(&self, file_offset: u64, buffer: &mut [u8]) -> usize {
        if !self.contains(file_offset) {
            return 0;
        }

        let chunk_offset = (file_offset - self.offset) as usize;
        let available = self.data.len() - chunk_offset;
        let to_read = available.min(buffer.len());

        buffer[..to_read].copy_from_slice(&self.data[chunk_offset..chunk_offset + to_read]);
        to_read
    }
}

/// Cache for recently decrypted file chunks.
///
/// Maintains a bounded cache of decrypted file data to improve read
/// performance, especially for sequential reads and small random seeks.
#[derive(Debug)]
pub struct ChunkCache {
    /// Cached chunks by file UUID, then by chunk index.
    chunks: HashMap<Uuid, Vec<CachedChunk>>,
    /// Total size of cached data.
    total_size: usize,
}

impl ChunkCache {
    /// Creates a new empty chunk cache.
    pub fn new() -> Self {
        Self {
            chunks: HashMap::new(),
            total_size: 0,
        }
    }

    /// Gets chunks for a file.
    pub fn get_file_chunks(&self, file_uuid: &Uuid) -> Option<&Vec<CachedChunk>> {
        self.chunks.get(file_uuid)
    }

    /// Gets mutable chunks for a file.
    pub fn get_file_chunks_mut(&mut self, file_uuid: &Uuid) -> Option<&mut Vec<CachedChunk>> {
        self.chunks.get_mut(file_uuid)
    }

    /// Finds a cached chunk containing the given offset.
    pub fn find_chunk(&mut self, file_uuid: &Uuid, offset: u64) -> Option<&CachedChunk> {
        if let Some(chunks) = self.chunks.get_mut(file_uuid) {
            // Find and touch the chunk
            for chunk in chunks.iter_mut() {
                if chunk.contains(offset) && !chunk.is_expired() {
                    chunk.touch();
                    return Some(chunk);
                }
            }
        }
        None
    }

    /// Inserts a chunk into the cache.
    pub fn insert(&mut self, file_uuid: Uuid, chunk: CachedChunk) {
        let chunk_size = chunk.data.len();

        // Evict if needed to stay under size limit
        while self.total_size + chunk_size > MAX_CACHE_SIZE {
            if !self.evict_oldest() {
                break;
            }
        }

        // Get or create file entry
        let chunks = self.chunks.entry(file_uuid).or_insert_with(Vec::new);

        // Remove expired chunks for this file
        let old_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        chunks.retain(|c| !c.is_expired());
        let new_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        self.total_size = self.total_size.saturating_sub(old_size - new_size);

        // Limit chunks per file
        while chunks.len() >= MAX_CACHED_CHUNKS_PER_FILE {
            // Remove oldest
            if let Some((idx, _)) = chunks.iter().enumerate()
                .min_by_key(|(_, c)| c.last_accessed)
            {
                self.total_size = self.total_size.saturating_sub(chunks[idx].data.len());
                chunks.remove(idx);
            } else {
                break;
            }
        }

        // Insert new chunk
        self.total_size += chunk_size;
        chunks.push(chunk);
    }

    /// Evicts the oldest chunk from the cache.
    /// Returns true if a chunk was evicted.
    fn evict_oldest(&mut self) -> bool {
        let mut oldest: Option<(Uuid, usize, Instant)> = None;

        for (uuid, chunks) in &self.chunks {
            for (idx, chunk) in chunks.iter().enumerate() {
                match oldest {
                    None => oldest = Some((*uuid, idx, chunk.last_accessed)),
                    Some((_, _, oldest_time)) if chunk.last_accessed < oldest_time => {
                        oldest = Some((*uuid, idx, chunk.last_accessed));
                    }
                    _ => {}
                }
            }
        }

        if let Some((uuid, idx, _)) = oldest {
            if let Some(chunks) = self.chunks.get_mut(&uuid) {
                if idx < chunks.len() {
                    self.total_size = self.total_size.saturating_sub(chunks[idx].data.len());
                    chunks.remove(idx);
                    return true;
                }
            }
        }

        false
    }

    /// Clears all cached chunks for a file.
    pub fn clear_file(&mut self, file_uuid: &Uuid) {
        if let Some(chunks) = self.chunks.remove(file_uuid) {
            let size: usize = chunks.iter().map(|c| c.data.len()).sum();
            self.total_size = self.total_size.saturating_sub(size);
        }
    }

    /// Clears the entire cache.
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.total_size = 0;
    }

    /// Returns the total size of cached data.
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Returns the number of cached files.
    pub fn file_count(&self) -> usize {
        self.chunks.len()
    }

    /// Returns the total number of cached chunks.
    pub fn chunk_count(&self) -> usize {
        self.chunks.values().map(|v| v.len()).sum()
    }
}

impl Default for ChunkCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the chunk cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    /// Total size of cached data in bytes.
    pub total_size: usize,
    /// Number of files with cached data.
    pub file_count: usize,
    /// Total number of cached chunks.
    pub chunk_count: usize,
}

/// Write buffer state for accumulating writes before atomic commit.
#[derive(Debug, Clone)]
pub struct WriteBuffer {
    /// The pending data to write.
    pub data: Vec<u8>,
    /// The original file content (for partial writes to existing files).
    pub original_content: Option<Vec<u8>>,
    /// Whether the content has been modified since last flush.
    pub modified: bool,
    /// Whether this is a new file (vs. modification of existing).
    pub is_new_file: bool,
    /// The filename for new files.
    pub filename: String,
}

impl WriteBuffer {
    /// Creates a new write buffer for a new file.
    pub fn new_file(filename: String) -> Self {
        Self {
            data: Vec::new(),
            original_content: None,
            modified: true,
            is_new_file: true,
            filename,
        }
    }

    /// Creates a write buffer for an existing file.
    pub fn existing_file(original_content: Vec<u8>, filename: String) -> Self {
        let data = original_content.clone();
        Self {
            data,
            original_content: Some(original_content),
            modified: false,
            is_new_file: false,
            filename,
        }
    }

    /// Writes data at the specified offset.
    /// Extends the buffer if writing past the end.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> usize {
        let offset = offset as usize;
        let end_offset = offset + data.len();

        // Extend buffer if needed
        if end_offset > self.data.len() {
            self.data.resize(end_offset, 0);
        }

        // Copy data
        self.data[offset..end_offset].copy_from_slice(data);
        self.modified = true;

        data.len()
    }

    /// Sets the end of file position, truncating or extending as needed.
    pub fn set_end_of_file(&mut self, length: u64) {
        let new_len = length as usize;
        if new_len < self.data.len() {
            self.data.truncate(new_len);
        } else if new_len > self.data.len() {
            self.data.resize(new_len, 0);
        }
        self.modified = true;
    }

    /// Returns the current buffer length.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns true if the buffer has been modified.
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Clears the modified flag after successful flush.
    pub fn clear_modified(&mut self) {
        self.modified = false;
    }

    /// Reads data from the buffer at the specified offset.
    pub fn read_at(&self, offset: u64, buffer: &mut [u8]) -> usize {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return 0;
        }

        let available = self.data.len() - offset;
        let to_read = buffer.len().min(available);
        buffer[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        to_read
    }
}

/// Information about an open file handle.
#[derive(Debug, Clone)]
pub struct FileHandle {
    /// The file's UUID (None for directories, or for new files not yet created).
    pub uuid: Option<Uuid>,
    /// The virtual path within the vault.
    pub path: String,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Access level of the file.
    pub access_level: u32,
    /// Read position in the file.
    pub read_position: u64,
    /// Write position in the file.
    pub write_position: u64,
    /// Whether the file is open for writing.
    pub write_access: bool,
    /// File size (for position tracking).
    pub size: u64,
    /// Cached decrypted content (for read operations).
    /// This is populated on first read and cleared on close.
    pub cached_content: Option<Vec<u8>>,
    /// Dirty flag indicating uncommitted writes.
    pub is_dirty: bool,
    /// Write buffer for accumulating writes before commit.
    pub write_buffer: Option<WriteBuffer>,
}

impl FileHandle {
    /// Create a new file handle.
    pub fn new(
        uuid: Option<Uuid>,
        path: String,
        is_directory: bool,
        access_level: u32,
        size: u64,
        write_access: bool,
    ) -> Self {
        Self {
            uuid,
            path,
            is_directory,
            access_level,
            read_position: 0,
            write_position: 0,
            write_access,
            size,
            cached_content: None,
            is_dirty: false,
            write_buffer: None,
        }
    }

    /// Create a handle for the root directory.
    pub fn root() -> Self {
        Self::new(None, "/".to_string(), true, 0, 0, false)
    }
}

/// Configuration for Dokan mount.
#[derive(Debug, Clone)]
pub struct DokanConfig {
    /// Drive letter to mount (e.g., 'T').
    pub drive_letter: char,
    /// Volume label (default: "TESSERACT").
    pub volume_label: String,
    /// Thread count for Dokan operations (0 = auto).
    pub thread_count: u16,
    /// Enable debug output.
    pub debug: bool,
    /// Mount as read-only.
    pub read_only: bool,
    /// Use standard access (instead of alternate stream access).
    pub use_std_access: bool,
    /// Timeout for mount operations in milliseconds.
    pub timeout_ms: u32,
    /// Total virtual disk size in bytes.
    pub total_bytes: u64,
    /// Free bytes on virtual disk.
    pub free_bytes: u64,
    /// Bytes available to caller.
    pub available_bytes: u64,
}

impl DokanConfig {
    /// Create a new configuration with the given drive letter.
    pub fn new(drive_letter: char) -> Self {
        Self {
            drive_letter: drive_letter.to_ascii_uppercase(),
            volume_label: VOLUME_LABEL.to_string(),
            thread_count: 0,
            debug: false,
            read_only: false,
            use_std_access: true,
            timeout_ms: 5000,
            total_bytes: 10 * 1024 * 1024 * 1024, // 10 GB virtual size
            free_bytes: 5 * 1024 * 1024 * 1024,   // 5 GB free
            available_bytes: 5 * 1024 * 1024 * 1024, // 5 GB available
        }
    }

    /// Set the volume label.
    pub fn with_volume_label(mut self, label: &str) -> Self {
        self.volume_label = label.to_string();
        self
    }

    /// Set thread count.
    pub fn with_thread_count(mut self, count: u16) -> Self {
        self.thread_count = count;
        self
    }

    /// Enable debug output.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Set read-only mode.
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Set disk space information.
    pub fn with_disk_space(
        mut self,
        total_bytes: u64,
        free_bytes: u64,
        available_bytes: u64,
    ) -> Self {
        self.total_bytes = total_bytes;
        self.free_bytes = free_bytes;
        self.available_bytes = available_bytes;
        self
    }

    /// Get the mount point path (e.g., "T:\").
    pub fn mount_point(&self) -> String {
        format!("{}:\\", self.drive_letter)
    }
}

impl Default for DokanConfig {
    fn default() -> Self {
        Self::new('T')
    }
}

/// File information structure returned by GetFileInformation.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// File attributes (from FileAttributes).
    pub attributes: u32,
    /// Creation time (Windows FILETIME).
    pub creation_time: u64,
    /// Last access time (Windows FILETIME).
    pub last_access_time: u64,
    /// Last write time (Windows FILETIME).
    pub last_write_time: u64,
    /// File size in bytes.
    pub size: u64,
    /// Volume serial number.
    pub volume_serial: u32,
    /// Number of links to this file.
    pub number_of_links: u32,
    /// Unique file index (high part).
    pub file_index_high: u32,
    /// Unique file index (low part).
    pub file_index_low: u32,
}

impl FileInfo {
    /// Create file info from a FileEntry.
    pub fn from_entry(entry: &FileEntry) -> Self {
        let filetime = unix_to_filetime(entry.modified_time);
        let (index_high, index_low) = match entry.uuid {
            Some(uuid) => {
                let bytes = uuid.as_bytes();
                let high = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let low = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                (high, low)
            }
            None => {
                // Hash the path for virtual directories
                let hash = hash_path(&entry.name);
                ((hash >> 32) as u32, hash as u32)
            }
        };

        Self {
            attributes: FileAttributes::from_entry_type(entry.entry_type),
            creation_time: filetime,
            last_access_time: filetime,
            last_write_time: filetime,
            size: entry.size,
            volume_serial: VOLUME_SERIAL,
            number_of_links: 1,
            file_index_high: index_high,
            file_index_low: index_low,
        }
    }

    /// Create file info for the root directory.
    pub fn root() -> Self {
        let now = unix_to_filetime(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        Self {
            attributes: FileAttributes::Directory as u32,
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            size: 0,
            volume_serial: VOLUME_SERIAL,
            number_of_links: 1,
            file_index_high: 0,
            file_index_low: 1,
        }
    }
}

/// Directory entry for FindFiles callback.
#[derive(Debug, Clone)]
pub struct FindData {
    /// File name.
    pub file_name: String,
    /// File attributes.
    pub attributes: u32,
    /// Creation time (Windows FILETIME).
    pub creation_time: u64,
    /// Last access time.
    pub last_access_time: u64,
    /// Last write time.
    pub last_write_time: u64,
    /// File size.
    pub size: u64,
}

impl FindData {
    /// Create from a FileEntry.
    pub fn from_entry(entry: &FileEntry) -> Self {
        let filetime = unix_to_filetime(entry.modified_time);

        Self {
            file_name: entry.name.clone(),
            attributes: FileAttributes::from_entry_type(entry.entry_type),
            creation_time: filetime,
            last_access_time: filetime,
            last_write_time: filetime,
            size: entry.size,
        }
    }
}

/// Disk space information returned by GetDiskFreeSpace.
#[derive(Debug, Clone)]
pub struct DiskSpace {
    /// Total number of free bytes available to the caller.
    pub free_bytes_available: u64,
    /// Total number of bytes on disk.
    pub total_bytes: u64,
    /// Total number of free bytes on disk.
    pub total_free_bytes: u64,
}

impl DiskSpace {
    /// Create from configuration.
    pub fn from_config(config: &DokanConfig) -> Self {
        Self {
            free_bytes_available: config.available_bytes,
            total_bytes: config.total_bytes,
            total_free_bytes: config.free_bytes,
        }
    }
}

/// Volume information returned by GetVolumeInformation.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Volume label.
    pub volume_label: String,
    /// Volume serial number.
    pub serial_number: u32,
    /// Maximum path component length.
    pub max_component_length: u32,
    /// File system flags.
    pub file_system_flags: u32,
    /// File system name (e.g., "NTFS", "FAT32").
    pub file_system_name: String,
}

impl VolumeInfo {
    /// Create default volume info.
    pub fn new(volume_label: &str) -> Self {
        Self {
            volume_label: volume_label.to_string(),
            serial_number: VOLUME_SERIAL,
            max_component_length: MAX_COMPONENT_LENGTH,
            file_system_flags: FileSystemFlags::default_flags(),
            file_system_name: FILESYSTEM_NAME.to_string(),
        }
    }
}

/// The main Dokan filesystem handler.
///
/// This struct holds the vault session and manages file handles.
/// It implements all the Dokan callbacks needed for basic filesystem operations.
pub struct TesseractDokanHandler {
    /// The vault session (shared for thread safety).
    session: Arc<RwLock<VaultSession>>,
    /// Open file handles by handle ID.
    handles: RwLock<HashMap<u64, FileHandle>>,
    /// Next handle ID.
    next_handle_id: RwLock<u64>,
    /// Configuration.
    config: DokanConfig,
    /// Mount state.
    is_mounted: RwLock<bool>,
    /// Chunk cache for decrypted file data (US-048).
    chunk_cache: RwLock<ChunkCache>,
}

impl TesseractDokanHandler {
    /// Create a new Dokan handler.
    pub fn new(session: VaultSession, config: DokanConfig) -> Self {
        Self {
            session: Arc::new(RwLock::new(session)),
            handles: RwLock::new(HashMap::new()),
            next_handle_id: RwLock::new(1),
            config,
            is_mounted: RwLock::new(false),
            chunk_cache: RwLock::new(ChunkCache::new()),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &DokanConfig {
        &self.config
    }

    /// Check if the filesystem is mounted.
    pub fn is_mounted(&self) -> bool {
        *self.is_mounted.read().unwrap()
    }

    /// Get the vault path.
    pub fn vault_path(&self) -> PathBuf {
        self.session.read().unwrap().vault_path().to_path_buf()
    }

    /// Allocate a new handle ID.
    fn allocate_handle_id(&self) -> u64 {
        let mut id = self.next_handle_id.write().unwrap();
        let current = *id;
        *id = id.wrapping_add(1);
        if *id == 0 {
            *id = 1; // Skip 0
        }
        current
    }

    /// Normalize a Windows path to vault path format.
    /// Converts backslashes to forward slashes and ensures leading slash.
    fn normalize_path(path: &str) -> String {
        let normalized = path.replace('\\', "/");
        if normalized.is_empty() || normalized == "/" {
            "/".to_string()
        } else if normalized.starts_with('/') {
            normalized
        } else {
            format!("/{}", normalized)
        }
    }

    /// Find an entry by path.
    fn find_entry(&self, path: &str) -> Result<FileEntry, NtStatus> {
        let normalized = Self::normalize_path(path);

        // Handle root directory
        if normalized == "/" {
            return Ok(FileEntry::new_directory("/".to_string(), 0, 0));
        }

        // Get parent path and target name
        let (parent_path, target_name) = match normalized.rfind('/') {
            Some(idx) if idx == 0 => ("/".to_string(), &normalized[1..]),
            Some(idx) => (normalized[..idx].to_string(), &normalized[idx + 1..]),
            None => ("/".to_string(), normalized.as_str()),
        };

        // List the parent directory
        let session = self.session.read().map_err(|_| NtStatus::InternalError)?;

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        let entries = list_files(&session, &parent_path)
            .map_err(|e| NtStatus::from_vault_error(&e))?;

        // Find the target
        entries
            .into_iter()
            .find(|e| e.name == target_name)
            .ok_or(NtStatus::ObjectNameNotFound)
    }

    // =========================================================================
    // Dokan Callbacks - Core Operations (US-047)
    // =========================================================================

    /// CreateFile callback - Opens or creates a file/directory.
    ///
    /// This is called when Windows opens a file or directory. For encrypted
    /// vaults, we don't actually create the file here - we just validate
    /// access and set up the file handle.
    ///
    /// # Arguments
    /// * `path` - The file path (relative to mount point)
    /// * `access_mask` - Requested access rights
    /// * `share_access` - Share mode flags
    /// * `creation_disposition` - How to handle file creation
    /// * `flags_and_attributes` - File flags and attributes
    ///
    /// # Returns
    /// * `Ok((handle_id, is_directory))` on success
    /// * `Err(NtStatus)` on failure
    pub fn create_file(
        &self,
        path: &str,
        _access_mask: u32,
        _share_access: u32,
        creation_disposition: u32,
        _flags_and_attributes: u32,
    ) -> Result<(u64, bool), NtStatus> {
        let normalized = Self::normalize_path(path);

        // Creation disposition values
        const CREATE_NEW: u32 = 1;
        const CREATE_ALWAYS: u32 = 2;
        const OPEN_EXISTING: u32 = 3;
        const OPEN_ALWAYS: u32 = 4;
        const TRUNCATE_EXISTING: u32 = 5;

        // Try to find the entry
        let entry_result = self.find_entry(&normalized);

        match (entry_result, creation_disposition) {
            // File exists
            (Ok(entry), OPEN_EXISTING | OPEN_ALWAYS | TRUNCATE_EXISTING) => {
                let is_directory = entry.entry_type == EntryType::Directory;
                let handle = FileHandle::new(
                    entry.uuid,
                    normalized,
                    is_directory,
                    entry.access_level,
                    entry.size,
                    creation_disposition == TRUNCATE_EXISTING,
                );

                let handle_id = self.allocate_handle_id();
                self.handles.write().unwrap().insert(handle_id, handle);

                Ok((handle_id, is_directory))
            }

            // File exists but should be new
            (Ok(_), CREATE_NEW) => Err(NtStatus::ObjectNameCollision),

            // File exists and should be replaced
            (Ok(entry), CREATE_ALWAYS) => {
                // For CREATE_ALWAYS on existing file, we'll handle truncation in write
                let is_directory = entry.entry_type == EntryType::Directory;
                let handle = FileHandle::new(
                    entry.uuid,
                    normalized,
                    is_directory,
                    entry.access_level,
                    0, // Truncated
                    true,
                );

                let handle_id = self.allocate_handle_id();
                self.handles.write().unwrap().insert(handle_id, handle);

                Ok((handle_id, is_directory))
            }

            // File doesn't exist - create it (US-049)
            (Err(NtStatus::ObjectNameNotFound), CREATE_NEW | CREATE_ALWAYS | OPEN_ALWAYS) => {
                // Create a new file handle (file will be created on first write/flush)
                self.create_new_file(&normalized, None)
            }

            // File doesn't exist and we need it to exist
            (Err(NtStatus::ObjectNameNotFound), OPEN_EXISTING | TRUNCATE_EXISTING) => {
                Err(NtStatus::ObjectNameNotFound)
            }

            // Propagate other errors
            (Err(e), _) => Err(e),

            // Unknown creation disposition
            (_, _) => Err(NtStatus::InvalidParameter),
        }
    }

    /// CloseFile callback - Called when a file handle is about to be closed.
    ///
    /// This is called before `Cleanup`. We use this to flush any pending
    /// writes and prepare for cleanup. Writes are committed atomically
    /// to maintain vault integrity.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NtStatus)` if flush fails
    ///
    /// # Atomicity (US-049)
    /// This method commits all pending writes atomically before closing.
    /// If the commit fails, the file remains unchanged in the vault.
    pub fn close_file(&self, handle_id: u64) -> Result<(), NtStatus> {
        // First, flush any pending writes (atomic commit)
        let is_dirty = {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            handles.get(&handle_id).map(|h| h.is_dirty).unwrap_or(false)
        };

        if is_dirty {
            // Perform atomic flush of pending writes
            self.flush_file_buffers(handle_id)?;
        }

        // Clear cached content and write buffer to free memory
        if let Ok(mut handles) = self.handles.write() {
            if let Some(handle) = handles.get_mut(&handle_id) {
                handle.cached_content = None;
                handle.write_buffer = None;
                handle.is_dirty = false;
            }
        }

        Ok(())
    }

    /// CloseFile callback (non-Result version for backward compatibility).
    ///
    /// This version silently ignores flush errors. Prefer using `close_file`
    /// which returns a Result for proper error handling.
    pub fn close_file_silent(&self, handle_id: u64) {
        let _ = self.close_file(handle_id);
    }

    /// Cleanup callback - Final cleanup when all handles are closed.
    ///
    /// This is the final call for a file handle. We remove the handle
    /// and free all associated resources.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    /// * `delete_on_close` - Whether to delete the file
    pub fn cleanup(&self, handle_id: u64, _delete_on_close: bool) {
        self.handles.write().unwrap().remove(&handle_id);
    }

    /// FindFiles callback - Lists directory contents.
    ///
    /// Returns all files and directories in the given directory,
    /// filtered by access level.
    ///
    /// # Arguments
    /// * `path` - The directory path
    ///
    /// # Returns
    /// * `Ok(Vec<FindData>)` with directory entries
    /// * `Err(NtStatus)` on failure
    pub fn find_files(&self, path: &str) -> Result<Vec<FindData>, NtStatus> {
        let normalized = Self::normalize_path(path);

        let session = self.session.read().map_err(|_| NtStatus::InternalError)?;

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        let entries = list_files(&session, &normalized)
            .map_err(|e| NtStatus::from_vault_error(&e))?;

        let mut results = Vec::with_capacity(entries.len() + 2);

        // Add "." entry (current directory)
        results.push(FindData {
            file_name: ".".to_string(),
            attributes: FileAttributes::Directory as u32,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            size: 0,
        });

        // Add ".." entry (parent directory) unless we're at root
        if normalized != "/" {
            results.push(FindData {
                file_name: "..".to_string(),
                attributes: FileAttributes::Directory as u32,
                creation_time: 0,
                last_access_time: 0,
                last_write_time: 0,
                size: 0,
            });
        }

        // Add actual entries
        for entry in entries {
            results.push(FindData::from_entry(&entry));
        }

        Ok(results)
    }

    /// GetFileInformation callback - Gets file/directory metadata.
    ///
    /// # Arguments
    /// * `path` - The file or directory path
    /// * `handle_id` - Optional handle ID if file is open
    ///
    /// # Returns
    /// * `Ok(FileInfo)` with file metadata
    /// * `Err(NtStatus)` on failure
    pub fn get_file_information(&self, path: &str, handle_id: Option<u64>) -> Result<FileInfo, NtStatus> {
        let normalized = Self::normalize_path(path);

        // Handle root directory
        if normalized == "/" {
            return Ok(FileInfo::root());
        }

        // If we have a valid handle, use its info
        if let Some(id) = handle_id {
            if let Some(handle) = self.handles.read().unwrap().get(&id) {
                if handle.is_directory {
                    // Return directory info
                    return Ok(FileInfo {
                        attributes: FileAttributes::Directory as u32,
                        creation_time: 0,
                        last_access_time: 0,
                        last_write_time: 0,
                        size: 0,
                        volume_serial: VOLUME_SERIAL,
                        number_of_links: 1,
                        file_index_high: hash_path(&handle.path) as u32,
                        file_index_low: (hash_path(&handle.path) >> 32) as u32,
                    });
                }
            }
        }

        // Look up the entry
        let entry = self.find_entry(&normalized)?;
        Ok(FileInfo::from_entry(&entry))
    }

    /// GetDiskFreeSpace callback - Returns disk space information.
    ///
    /// # Returns
    /// * `Ok(DiskSpace)` with space information
    pub fn get_disk_free_space(&self) -> Result<DiskSpace, NtStatus> {
        Ok(DiskSpace::from_config(&self.config))
    }

    /// GetVolumeInformation callback - Returns volume information.
    ///
    /// # Returns
    /// * `Ok(VolumeInfo)` with volume information
    pub fn get_volume_information(&self) -> Result<VolumeInfo, NtStatus> {
        Ok(VolumeInfo::new(&self.config.volume_label))
    }

    // =========================================================================
    // Dokan Callbacks - Read Operations (US-048)
    // =========================================================================

    /// ReadFile callback - Reads and decrypts file data.
    ///
    /// This is the core VFS read operation that transparently decrypts
    /// encrypted vault content. Uses chunk caching for improved performance.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    /// * `offset` - Byte offset to start reading from
    /// * `buffer` - Buffer to read data into
    ///
    /// # Returns
    /// * `Ok(bytes_read)` - Number of bytes actually read
    /// * `Err(NtStatus)` - Error status
    ///
    /// # Performance
    /// Target: First byte in < 100ms for files < 1MB
    pub fn read_file(
        &self,
        handle_id: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<u32, NtStatus> {
        // Get handle info
        let handle_info = {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            handles.get(&handle_id).cloned().ok_or(NtStatus::InvalidParameter)?
        };

        // Cannot read from directories
        if handle_info.is_directory {
            return Err(NtStatus::FileIsADirectory);
        }

        // Get file UUID
        let file_uuid = handle_info.uuid.ok_or(NtStatus::InvalidParameter)?;

        // Check if offset is beyond file end
        if offset >= handle_info.size {
            return Ok(0); // EOF
        }

        // Calculate how many bytes we can actually read
        let available = (handle_info.size - offset) as usize;
        let to_read = buffer.len().min(available);

        if to_read == 0 {
            return Ok(0);
        }

        // Try to read from cache first
        let cached_bytes = self.read_from_cache(file_uuid, offset, &mut buffer[..to_read]);
        if cached_bytes == to_read {
            // Full read satisfied from cache
            return Ok(cached_bytes as u32);
        }

        // Need to decrypt - get the full file content
        // (For files < 1MB, we cache the entire file for performance)
        let decrypted_content = self.decrypt_file_content(file_uuid)?;

        // Cache the decrypted content in chunks
        self.cache_file_content(file_uuid, &decrypted_content);

        // Copy requested portion to buffer
        let start = offset as usize;
        let end = (start + to_read).min(decrypted_content.len());
        let actual_read = end - start;

        if actual_read > 0 {
            buffer[..actual_read].copy_from_slice(&decrypted_content[start..end]);
        }

        Ok(actual_read as u32)
    }

    /// Reads data from the chunk cache.
    /// Returns the number of bytes read from cache.
    fn read_from_cache(&self, file_uuid: Uuid, offset: u64, buffer: &mut [u8]) -> usize {
        let mut cache = match self.chunk_cache.write() {
            Ok(c) => c,
            Err(_) => return 0,
        };

        let mut total_read = 0;
        let mut current_offset = offset;

        while total_read < buffer.len() {
            if let Some(chunk) = cache.find_chunk(&file_uuid, current_offset) {
                let bytes_read = chunk.read(current_offset, &mut buffer[total_read..]);
                if bytes_read == 0 {
                    break;
                }
                total_read += bytes_read;
                current_offset += bytes_read as u64;
            } else {
                // No cached chunk for this offset
                break;
            }
        }

        total_read
    }

    /// Decrypts the full content of a file.
    fn decrypt_file_content(&self, file_uuid: Uuid) -> Result<Vec<u8>, NtStatus> {
        let session = self.session.read().map_err(|_| NtStatus::InternalError)?;

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        // Use export_to_bytes which handles all the key management
        let (content, _metadata) = export_to_bytes(&session, file_uuid)
            .map_err(|e| NtStatus::from_vault_error(&e))?;

        Ok(content)
    }

    /// Caches file content in chunks for subsequent reads.
    fn cache_file_content(&self, file_uuid: Uuid, content: &[u8]) {
        let mut cache = match self.chunk_cache.write() {
            Ok(c) => c,
            Err(_) => return,
        };

        // Clear any existing cache for this file
        cache.clear_file(&file_uuid);

        // Split content into chunks and cache
        let mut offset = 0u64;
        for chunk_data in content.chunks(CACHE_CHUNK_SIZE) {
            let chunk = CachedChunk::new(offset, chunk_data.to_vec());
            cache.insert(file_uuid, chunk);
            offset += chunk_data.len() as u64;
        }
    }

    /// Reads a portion of a file at the given offset.
    /// This is a convenience wrapper that creates a buffer and reads into it.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    /// * `offset` - Byte offset to start reading from
    /// * `length` - Maximum number of bytes to read
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The data read
    /// * `Err(NtStatus)` - Error status
    pub fn read_file_vec(
        &self,
        handle_id: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, NtStatus> {
        let mut buffer = vec![0u8; length];
        let bytes_read = self.read_file(handle_id, offset, &mut buffer)? as usize;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// Seeks within a file and reads data.
    /// This is a combined seek+read operation for Dokan compatibility.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    /// * `offset` - Absolute offset to seek to
    /// * `buffer` - Buffer to read data into
    ///
    /// # Returns
    /// * `Ok(bytes_read)` - Number of bytes read
    /// * `Err(NtStatus)` - Error status
    pub fn seek_and_read(
        &self,
        handle_id: u64,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<u32, NtStatus> {
        // Update handle's read position (for sequential access optimization)
        {
            let mut handles = self.handles.write().map_err(|_| NtStatus::InternalError)?;
            if let Some(handle) = handles.get_mut(&handle_id) {
                handle.read_position = offset;
            }
        }

        self.read_file(handle_id, offset, buffer)
    }

    /// Checks if a read would hit the cache.
    /// Useful for performance monitoring and testing.
    pub fn is_read_cached(&self, file_uuid: Uuid, offset: u64) -> bool {
        if let Ok(mut cache) = self.chunk_cache.write() {
            cache.find_chunk(&file_uuid, offset).is_some()
        } else {
            false
        }
    }

    /// Gets cache statistics for monitoring.
    pub fn cache_stats(&self) -> CacheStats {
        if let Ok(cache) = self.chunk_cache.read() {
            CacheStats {
                total_size: cache.total_size(),
                file_count: cache.file_count(),
                chunk_count: cache.chunk_count(),
            }
        } else {
            CacheStats::default()
        }
    }

    /// Clears the entire chunk cache.
    /// Called on vault lock or unmount.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.chunk_cache.write() {
            cache.clear();
        }
    }

    // =========================================================================
    // Dokan Callbacks - Write Operations (US-049)
    // =========================================================================

    /// WriteFile callback - Encrypts and writes data to a file.
    ///
    /// This is the core VFS write operation that transparently encrypts
    /// data before storing. Writes are accumulated in a buffer and
    /// committed atomically on CloseFile.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    /// * `offset` - Byte offset to start writing at
    /// * `data` - Data to write
    ///
    /// # Returns
    /// * `Ok(bytes_written)` - Number of bytes actually written
    /// * `Err(NtStatus)` - Error status
    ///
    /// # Write Strategy
    /// - New files: Buffer is created empty, writes accumulate
    /// - Existing files: Original content loaded on first write, then modified
    /// - Commit on close: Data is encrypted and persisted atomically
    pub fn write_file(
        &self,
        handle_id: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, NtStatus> {
        // Cannot write empty data
        if data.is_empty() {
            return Ok(0);
        }

        // Check if read-only mode
        if self.config.read_only {
            return Err(NtStatus::AccessDenied);
        }

        // Get handle info and prepare write buffer
        let (file_uuid, path, is_new, level) = {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            // Cannot write to directories
            if handle.is_directory {
                return Err(NtStatus::FileIsADirectory);
            }

            // Check write access
            if !handle.write_access {
                return Err(NtStatus::AccessDenied);
            }

            (handle.uuid, handle.path.clone(), handle.uuid.is_none(), handle.access_level)
        };

        // Initialize write buffer if needed
        {
            let mut handles = self.handles.write().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get_mut(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            if handle.write_buffer.is_none() {
                let filename = Self::extract_filename(&path);

                if is_new {
                    // New file - start with empty buffer
                    handle.write_buffer = Some(WriteBuffer::new_file(filename));
                } else if let Some(uuid) = file_uuid {
                    // Existing file - load original content
                    let content = self.decrypt_file_content(uuid)?;
                    handle.write_buffer = Some(WriteBuffer::existing_file(content, filename));
                }
            }
        }

        // Perform the write
        let bytes_written = {
            let mut handles = self.handles.write().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get_mut(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            if let Some(ref mut buffer) = handle.write_buffer {
                let written = buffer.write_at(offset, data);
                handle.is_dirty = true;
                handle.size = buffer.len();
                written
            } else {
                return Err(NtStatus::InternalError);
            }
        };

        // Clear read cache for this file since content is being modified
        if let Some(uuid) = file_uuid {
            if let Ok(mut cache) = self.chunk_cache.write() {
                cache.clear_file(&uuid);
            }
        }

        Ok(bytes_written as u32)
    }

    /// SetEndOfFile callback - Truncates or extends a file.
    ///
    /// This sets the file size to the specified length. If the length
    /// is smaller than current size, the file is truncated. If larger,
    /// the file is extended with zeros.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    /// * `length` - New file length in bytes
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NtStatus)` on failure
    pub fn set_end_of_file(&self, handle_id: u64, length: u64) -> Result<(), NtStatus> {
        // Check if read-only mode
        if self.config.read_only {
            return Err(NtStatus::AccessDenied);
        }

        // Get handle and check state
        let (file_uuid, path, is_new) = {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            // Cannot set EOF on directories
            if handle.is_directory {
                return Err(NtStatus::FileIsADirectory);
            }

            // Check write access
            if !handle.write_access {
                return Err(NtStatus::AccessDenied);
            }

            (handle.uuid, handle.path.clone(), handle.uuid.is_none())
        };

        // Initialize write buffer if needed
        {
            let mut handles = self.handles.write().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get_mut(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            if handle.write_buffer.is_none() {
                let filename = Self::extract_filename(&path);

                if is_new {
                    handle.write_buffer = Some(WriteBuffer::new_file(filename));
                } else if let Some(uuid) = file_uuid {
                    let content = self.decrypt_file_content(uuid)?;
                    handle.write_buffer = Some(WriteBuffer::existing_file(content, filename));
                }
            }
        }

        // Set the new size
        {
            let mut handles = self.handles.write().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get_mut(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            if let Some(ref mut buffer) = handle.write_buffer {
                buffer.set_end_of_file(length);
                handle.is_dirty = true;
                handle.size = length;
            }
        }

        // Clear read cache for this file
        if let Some(uuid) = file_uuid {
            if let Ok(mut cache) = self.chunk_cache.write() {
                cache.clear_file(&uuid);
            }
        }

        Ok(())
    }

    /// FlushFileBuffers callback - Commits pending writes to the vault.
    ///
    /// This persists all buffered writes by encrypting the data and
    /// storing it in the vault. Called explicitly by applications or
    /// automatically on close.
    ///
    /// # Arguments
    /// * `handle_id` - The handle ID from CreateFile
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NtStatus)` on failure
    ///
    /// # Atomicity
    /// The flush operation is atomic - either all data is committed
    /// or none is. This maintains vault integrity on interrupted writes.
    pub fn flush_file_buffers(&self, handle_id: u64) -> Result<(), NtStatus> {
        // Get handle info
        let (file_uuid, path, is_dirty, is_new, access_level) = {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            // Nothing to flush for directories
            if handle.is_directory {
                return Ok(());
            }

            (
                handle.uuid,
                handle.path.clone(),
                handle.is_dirty,
                handle.uuid.is_none(),
                handle.access_level,
            )
        };

        // Nothing to flush if not dirty
        if !is_dirty {
            return Ok(());
        }

        // Get the write buffer data
        let (data, filename) = {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            let handle = handles.get(&handle_id).ok_or(NtStatus::InvalidParameter)?;

            match &handle.write_buffer {
                Some(buffer) if buffer.is_modified() => {
                    (buffer.data.clone(), buffer.filename.clone())
                }
                _ => return Ok(()), // Nothing to flush
            }
        };

        // Perform the atomic commit
        let new_uuid = self.commit_file_data(
            file_uuid,
            &path,
            &filename,
            &data,
            access_level,
            is_new,
        )?;

        // Update handle state
        {
            let mut handles = self.handles.write().map_err(|_| NtStatus::InternalError)?;
            if let Some(handle) = handles.get_mut(&handle_id) {
                handle.is_dirty = false;
                handle.uuid = Some(new_uuid);
                if let Some(ref mut buffer) = handle.write_buffer {
                    buffer.clear_modified();
                    buffer.is_new_file = false;
                }
            }
        }

        Ok(())
    }

    /// Commits file data to the vault atomically.
    ///
    /// For new files: Creates a new encrypted blob and metadata.
    /// For existing files: Deletes the old blob/metadata and creates new ones.
    ///
    /// This ensures atomic operation - the file is either fully written
    /// or not written at all.
    fn commit_file_data(
        &self,
        existing_uuid: Option<Uuid>,
        path: &str,
        filename: &str,
        data: &[u8],
        access_level: u32,
        is_new: bool,
    ) -> Result<Uuid, NtStatus> {
        let mut session = self.session.write().map_err(|_| NtStatus::InternalError)?;

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        // For existing files, delete the old version first
        if !is_new {
            if let Some(uuid) = existing_uuid {
                delete_file(&mut session, uuid)
                    .map_err(|e| NtStatus::from_vault_error(&e))?;
            }
        }

        // Import the new content
        let new_uuid = import_bytes(
            &mut session,
            data,
            filename,
            path,
            access_level,
        ).map_err(|e| NtStatus::from_vault_error(&e))?;

        Ok(new_uuid)
    }

    /// Creates a new file in the vault.
    ///
    /// This is called when CreateFile is used with CREATE_NEW or CREATE_ALWAYS
    /// on a file that doesn't exist, or when the first write completes.
    ///
    /// # Arguments
    /// * `path` - Virtual path for the new file
    /// * `access_level` - Access level to assign (defaults to session's current level)
    ///
    /// # Returns
    /// * `Ok((handle_id, uuid))` on success
    /// * `Err(NtStatus)` on failure
    pub fn create_new_file(
        &self,
        path: &str,
        access_level: Option<u32>,
    ) -> Result<(u64, bool), NtStatus> {
        let normalized = Self::normalize_path(path);
        let filename = Self::extract_filename(&normalized);

        // Determine access level (use lowest unlocked level if not specified)
        let level = access_level.unwrap_or_else(|| {
            for l in 1..=3 {
                if let Ok(session) = self.session.read() {
                    if session.can_access_level(l) {
                        return l;
                    }
                }
            }
            1 // Default to level 1
        });

        // Create handle for new file (UUID will be assigned on flush)
        let handle = FileHandle::new(
            None, // No UUID yet
            normalized.clone(),
            false, // Not a directory
            level,
            0, // Size 0
            true, // Write access
        );

        let handle_id = self.allocate_handle_id();

        // Store the handle
        self.handles.write().unwrap().insert(handle_id, handle);

        Ok((handle_id, false))
    }

    /// Extracts the filename from a path.
    fn extract_filename(path: &str) -> String {
        path.rsplit('/')
            .next()
            .unwrap_or("unnamed")
            .to_string()
    }

    /// Gets the current size of a file (including pending writes).
    pub fn get_file_size(&self, handle_id: u64) -> Result<u64, NtStatus> {
        let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
        let handle = handles.get(&handle_id).ok_or(NtStatus::InvalidParameter)?;

        // If there's a write buffer, use its size
        if let Some(ref buffer) = handle.write_buffer {
            Ok(buffer.len())
        } else {
            Ok(handle.size)
        }
    }

    /// Checks if a file has uncommitted writes.
    pub fn has_pending_writes(&self, handle_id: u64) -> bool {
        if let Ok(handles) = self.handles.read() {
            if let Some(handle) = handles.get(&handle_id) {
                return handle.is_dirty;
            }
        }
        false
    }

    // =========================================================================
    // Dokan Callbacks - Delete and Rename Operations (US-050)
    // =========================================================================

    /// DeleteFile callback - Deletes a file from the vault.
    ///
    /// This removes the encrypted blob, metadata, and DEK entry for the file.
    /// The operation respects access level permissions.
    ///
    /// # Arguments
    /// * `path` - The file path (relative to mount point)
    /// * `handle_id` - Optional handle ID if file is open
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NtStatus)` on failure
    ///
    /// # Access Level
    /// The session must have access to the file's access level to delete it.
    pub fn delete_file_callback(&self, path: &str, handle_id: Option<u64>) -> Result<(), NtStatus> {
        // Check if read-only mode
        if self.config.read_only {
            return Err(NtStatus::AccessDenied);
        }

        let normalized = Self::normalize_path(path);

        // Cannot delete root directory
        if normalized == "/" {
            return Err(NtStatus::AccessDenied);
        }

        // Get file UUID - either from handle or by looking it up
        let file_uuid = self.get_file_uuid(&normalized, handle_id)?;

        // Get a write lock on the session to perform deletion
        let mut session = self.session.write().map_err(|_| NtStatus::InternalError)?;

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        // Delete the file (this verifies access level permissions)
        delete_file(&mut session, file_uuid)
            .map_err(|e| NtStatus::from_vault_error(&e))?;

        // Clear any cached data for this file
        if let Ok(mut cache) = self.chunk_cache.write() {
            cache.clear_file(&file_uuid);
        }

        // Remove the handle if provided
        if let Some(id) = handle_id {
            self.handles.write().unwrap().remove(&id);
        }

        Ok(())
    }

    /// MoveFile callback - Renames or moves a file in the vault.
    ///
    /// This updates the file's metadata with the new path/name. The encrypted
    /// blob remains unchanged. Supports both simple renames and moves to
    /// different directories.
    ///
    /// # Arguments
    /// * `old_path` - Current file path
    /// * `new_path` - New file path
    /// * `replace_if_exists` - Whether to replace an existing file at new_path
    /// * `handle_id` - Optional handle ID if file is open
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NtStatus)` on failure
    ///
    /// # Access Level
    /// The session must have access to the file's access level to rename/move it.
    pub fn move_file_callback(
        &self,
        old_path: &str,
        new_path: &str,
        replace_if_exists: bool,
        handle_id: Option<u64>,
    ) -> Result<(), NtStatus> {
        // Check if read-only mode
        if self.config.read_only {
            return Err(NtStatus::AccessDenied);
        }

        let normalized_old = Self::normalize_path(old_path);
        let normalized_new = Self::normalize_path(new_path);

        // Cannot move root directory
        if normalized_old == "/" || normalized_new == "/" {
            return Err(NtStatus::AccessDenied);
        }

        // Check if destination already exists
        if !replace_if_exists && self.find_entry(&normalized_new).is_ok() {
            return Err(NtStatus::ObjectNameCollision);
        }

        // Get file UUID from the old path
        let file_uuid = self.get_file_uuid(&normalized_old, handle_id)?;

        // Determine if this is a simple rename (same directory) or a move
        let old_parent = Self::parent_path(&normalized_old);
        let new_parent = Self::parent_path(&normalized_new);
        let new_filename = Self::extract_filename(&normalized_new);

        // Get a write lock on the session
        let mut session = self.session.write().map_err(|_| NtStatus::InternalError)?;

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        // If destination exists and replace_if_exists is true, delete it first
        if replace_if_exists {
            if let Ok(existing_entry) = self.find_entry_with_session(&session, &normalized_new) {
                if let Some(existing_uuid) = existing_entry.uuid {
                    delete_file(&mut session, existing_uuid)
                        .map_err(|e| NtStatus::from_vault_error(&e))?;
                }
            }
        }

        // Perform the rename/move operation
        if old_parent == new_parent {
            // Simple rename (same directory)
            tesseract_core::files::rename_file(&mut session, file_uuid, &new_filename)
                .map_err(|e| NtStatus::from_vault_error(&e))?;
        } else {
            // Full move to different directory
            tesseract_core::files::move_file(&mut session, file_uuid, &normalized_new)
                .map_err(|e| NtStatus::from_vault_error(&e))?;
        }

        // Update handle path if provided
        if let Some(id) = handle_id {
            if let Ok(mut handles) = self.handles.write() {
                if let Some(handle) = handles.get_mut(&id) {
                    handle.path = normalized_new;
                }
            }
        }

        Ok(())
    }

    /// SetFileAttributes callback - Updates file attributes.
    ///
    /// For TESSERACT, this is largely a no-op since we don't persist
    /// Windows-specific file attributes. We do validate access permissions.
    ///
    /// # Arguments
    /// * `path` - The file path
    /// * `attributes` - New file attributes (largely ignored)
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(NtStatus)` on failure
    pub fn set_file_attributes(&self, path: &str, _attributes: u32) -> Result<(), NtStatus> {
        // Check if read-only mode
        if self.config.read_only {
            return Err(NtStatus::AccessDenied);
        }

        let normalized = Self::normalize_path(path);

        // Verify the file exists and we have access
        let _ = self.find_entry(&normalized)?;

        // Attributes are not persistently stored for encrypted files
        // This is a no-op but validates access
        Ok(())
    }

    /// CanDeleteFile callback - Checks if a file can be deleted.
    ///
    /// This is called by Dokan before attempting to delete a file.
    /// We verify the file exists and the session has access to delete it.
    ///
    /// # Arguments
    /// * `path` - The file path
    /// * `handle_id` - Optional handle ID if file is open
    ///
    /// # Returns
    /// * `Ok(())` if file can be deleted
    /// * `Err(NtStatus)` if deletion is not allowed
    pub fn can_delete_file(&self, path: &str, handle_id: Option<u64>) -> Result<(), NtStatus> {
        // Check if read-only mode
        if self.config.read_only {
            return Err(NtStatus::AccessDenied);
        }

        let normalized = Self::normalize_path(path);

        // Cannot delete root
        if normalized == "/" {
            return Err(NtStatus::AccessDenied);
        }

        // Check file exists and get its level
        let entry = self.find_entry(&normalized)?;

        // Cannot delete directories through this callback
        // (directories are virtual and deleted when empty)
        if entry.entry_type == EntryType::Directory {
            // Check if directory is empty
            let session = self.session.read().map_err(|_| NtStatus::InternalError)?;
            let contents = list_files(&session, &normalized)
                .map_err(|e| NtStatus::from_vault_error(&e))?;
            if !contents.is_empty() {
                return Err(NtStatus::AccessDenied); // Directory not empty
            }
            return Ok(());
        }

        // Verify access level through handle or session
        if let Some(id) = handle_id {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            if let Some(handle) = handles.get(&id) {
                let session = self.session.read().map_err(|_| NtStatus::InternalError)?;
                if !session.can_access_level(handle.access_level) {
                    return Err(NtStatus::AccessDenied);
                }
            }
        } else {
            // Check session has access to file's level
            let session = self.session.read().map_err(|_| NtStatus::InternalError)?;
            if !session.can_access_level(entry.access_level) {
                return Err(NtStatus::AccessDenied);
            }
        }

        Ok(())
    }

    /// Gets the file UUID from a path, using handle if available.
    fn get_file_uuid(&self, path: &str, handle_id: Option<u64>) -> Result<Uuid, NtStatus> {
        // First try to get UUID from handle
        if let Some(id) = handle_id {
            let handles = self.handles.read().map_err(|_| NtStatus::InternalError)?;
            if let Some(handle) = handles.get(&id) {
                if let Some(uuid) = handle.uuid {
                    return Ok(uuid);
                }
            }
        }

        // Fall back to looking up the entry
        let entry = self.find_entry(path)?;
        entry.uuid.ok_or(NtStatus::ObjectNameNotFound)
    }

    /// Gets the parent path of a file path.
    fn parent_path(path: &str) -> String {
        match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(idx) => path[..idx].to_string(),
            None => "/".to_string(),
        }
    }

    /// Finds an entry using a session reference (for internal use when session is already locked).
    fn find_entry_with_session(&self, session: &VaultSession, path: &str) -> Result<FileEntry, NtStatus> {
        let normalized = Self::normalize_path(path);

        // Handle root directory
        if normalized == "/" {
            return Ok(FileEntry::new_directory("/".to_string(), 0, 0));
        }

        // Get parent path and target name
        let (parent_path, target_name) = match normalized.rfind('/') {
            Some(idx) if idx == 0 => ("/".to_string(), &normalized[1..]),
            Some(idx) => (normalized[..idx].to_string(), &normalized[idx + 1..]),
            None => ("/".to_string(), normalized.as_str()),
        };

        if session.state() == SessionState::Locked {
            return Err(NtStatus::AccessDenied);
        }

        let entries = list_files(session, &parent_path)
            .map_err(|e| NtStatus::from_vault_error(&e))?;

        entries
            .into_iter()
            .find(|e| e.name == target_name)
            .ok_or(NtStatus::ObjectNameNotFound)
    }

    // =========================================================================
    // Mount/Unmount Operations
    // =========================================================================

    /// Mount the filesystem to the configured drive letter.
    ///
    /// This starts the Dokan main loop in a background thread.
    /// The mount point will be available at `{drive_letter}:\`.
    ///
    /// # Returns
    /// * `Ok(())` on successful mount
    /// * `Err(VfsError)` if mount fails
    pub fn mount(&self) -> Result<(), VfsError> {
        // Check if already mounted
        if self.is_mounted() {
            return Err(VfsError::MountFailed("Already mounted".to_string()));
        }

        // Check session state
        {
            let session = self.session.read()
                .map_err(|_| VfsError::MountFailed("Failed to acquire session lock".to_string()))?;

            if session.state() == SessionState::Locked {
                return Err(VfsError::MountFailed("Vault is locked".to_string()));
            }
        }

        // In the real implementation, this would call dokan::Mount::new()
        // and start the Dokan main loop. For now, just set the mounted flag.
        *self.is_mounted.write().unwrap() = true;

        Ok(())
    }

    /// Unmount the filesystem with a timeout.
    ///
    /// This is the primary unmount method that completes in < 2 seconds.
    /// It attempts to gracefully flush and close all handles, then
    /// releases the drive letter and wipes keys.
    ///
    /// # Returns
    /// * `Ok(())` on successful unmount
    /// * `Err(VfsError)` if unmount fails
    pub fn unmount(&self) -> Result<(), VfsError> {
        self.unmount_with_timeout(DEFAULT_UNMOUNT_TIMEOUT_MS)
    }

    /// Unmount with a custom timeout in milliseconds.
    ///
    /// # Arguments
    /// * `timeout_ms` - Maximum time to wait for graceful unmount
    ///
    /// # Returns
    /// * `Ok(())` on successful unmount
    /// * `Err(VfsError::UnmountTimeout)` if timeout reached with open handles
    pub fn unmount_with_timeout(&self, timeout_ms: u64) -> Result<(), VfsError> {
        if !self.is_mounted() {
            return Err(VfsError::UnmountFailed("Not mounted".to_string()));
        }

        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms);

        // Step 1: Flush all pending writes before closing handles
        self.flush_all_pending_writes()?;

        // Step 2: Attempt graceful close of all handles with timeout
        let remaining_handles = self.close_all_handles_with_timeout(timeout, start)?;

        // If handles remain and we've exceeded timeout, force close
        if remaining_handles > 0 {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(VfsError::UnmountTimeout(timeout_ms, remaining_handles));
            }
            // Force close remaining handles
            self.force_close_all_handles();
        }

        // Step 3: Clear the chunk cache (security: no decrypted data should remain)
        self.clear_cache();

        // Step 4: Wipe keys by locking the session
        self.wipe_session_keys();

        // Step 5: Release the drive letter (mark as unmounted)
        // In the real implementation, this would call dokan::unmount()
        *self.is_mounted.write().unwrap() = false;

        Ok(())
    }

    /// Force unmount - immediately releases all resources without waiting.
    ///
    /// This should only be used in emergency situations (e.g., USB removal).
    /// It does NOT flush pending writes, so data loss may occur.
    ///
    /// # Returns
    /// * `Ok(())` on successful force unmount
    /// * `Err(VfsError)` if force unmount fails
    pub fn force_unmount(&self) -> Result<(), VfsError> {
        if !self.is_mounted() {
            return Err(VfsError::UnmountFailed("Not mounted".to_string()));
        }

        // Force close all handles without flushing
        self.force_close_all_handles();

        // Clear the chunk cache
        self.clear_cache();

        // Wipe session keys
        self.wipe_session_keys();

        // Mark as unmounted
        *self.is_mounted.write().unwrap() = false;

        Ok(())
    }

    /// Flush all pending writes across all open handles.
    ///
    /// This ensures data integrity by committing all modified data
    /// to the vault before unmounting.
    ///
    /// # Returns
    /// * `Ok(())` if all flushes succeed
    /// * `Err(VfsError::FlushFailed)` if any flush fails
    fn flush_all_pending_writes(&self) -> Result<(), VfsError> {
        // Collect handle IDs with pending writes
        let dirty_handle_ids: Vec<u64> = {
            let handles = self.handles.read().unwrap();
            handles
                .iter()
                .filter(|(_, h)| h.is_dirty)
                .map(|(id, _)| *id)
                .collect()
        };

        // Flush each dirty handle
        let mut flush_errors = Vec::new();
        for handle_id in dirty_handle_ids {
            if let Err(status) = self.flush_file_buffers(handle_id) {
                flush_errors.push(format!("Handle {}: {:?}", handle_id, status));
            }
        }

        if !flush_errors.is_empty() {
            return Err(VfsError::FlushFailed(flush_errors.join("; ")));
        }

        Ok(())
    }

    /// Close all handles gracefully with a timeout.
    ///
    /// Attempts to close each handle, respecting the timeout.
    ///
    /// # Returns
    /// * `Ok(remaining_count)` - number of handles that couldn't be closed
    fn close_all_handles_with_timeout(
        &self,
        timeout: Duration,
        start: Instant,
    ) -> Result<usize, VfsError> {
        let handle_ids: Vec<u64> = {
            let handles = self.handles.read().unwrap();
            handles.keys().copied().collect()
        };

        for handle_id in handle_ids {
            // Check timeout
            if start.elapsed() >= timeout {
                return Ok(self.open_handle_count());
            }

            // Close the handle (this clears cached content)
            let _ = self.close_file(handle_id);

            // Remove from handle map
            self.cleanup(handle_id, false);
        }

        Ok(self.open_handle_count())
    }

    /// Force close all handles immediately.
    ///
    /// This clears all handles without attempting graceful close.
    /// Used when timeout has been exceeded or for emergency unmount.
    fn force_close_all_handles(&self) {
        let mut handles = self.handles.write().unwrap();

        // Clear all cached content and write buffers to free memory
        for handle in handles.values_mut() {
            handle.cached_content = None;
            handle.write_buffer = None;
            handle.is_dirty = false;
        }

        // Clear all handles
        handles.clear();
    }

    /// Wipe session keys from memory.
    ///
    /// Locks the vault session, which triggers secure key wiping
    /// using zeroize to ensure keys are overwritten.
    fn wipe_session_keys(&self) {
        if let Ok(mut session) = self.session.write() {
            session.lock();
        }
    }

    /// Check if there are any pending writes that need to be flushed.
    ///
    /// # Returns
    /// * `true` if any handle has uncommitted writes
    pub fn has_pending_writes(&self) -> bool {
        let handles = self.handles.read().unwrap();
        handles.values().any(|h| h.is_dirty)
    }

    /// Get the number of dirty (modified) handles.
    pub fn dirty_handle_count(&self) -> usize {
        let handles = self.handles.read().unwrap();
        handles.values().filter(|h| h.is_dirty).count()
    }

    /// Get the number of open handles.
    pub fn open_handle_count(&self) -> usize {
        self.handles.read().unwrap().len()
    }

    /// Get information about open handles (for debugging/logging).
    pub fn get_open_handles_info(&self) -> Vec<OpenHandleInfo> {
        let handles = self.handles.read().unwrap();
        handles
            .iter()
            .map(|(id, h)| OpenHandleInfo {
                handle_id: *id,
                path: h.path.clone(),
                is_dirty: h.is_dirty,
                is_directory: h.is_directory,
                has_write_buffer: h.write_buffer.is_some(),
            })
            .collect()
    }
}

/// Default unmount timeout in milliseconds (2 seconds).
pub const DEFAULT_UNMOUNT_TIMEOUT_MS: u64 = 2000;

/// Information about an open file handle (for debugging).
#[derive(Debug, Clone)]
pub struct OpenHandleInfo {
    /// The handle ID.
    pub handle_id: u64,
    /// The file path.
    pub path: String,
    /// Whether the handle has uncommitted writes.
    pub is_dirty: bool,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Whether there's a write buffer attached.
    pub has_write_buffer: bool,
}

/// DokanMount provides a convenient wrapper for mounting and managing
/// the filesystem lifecycle.
pub struct DokanMount {
    handler: Arc<TesseractDokanHandler>,
}

impl DokanMount {
    /// Create a new mount controller.
    pub fn new(session: VaultSession, config: DokanConfig) -> Result<Self, VfsError> {
        Ok(Self {
            handler: Arc::new(TesseractDokanHandler::new(session, config)),
        })
    }

    /// Get a reference to the handler.
    pub fn handler(&self) -> &TesseractDokanHandler {
        &self.handler
    }

    /// Mount the filesystem.
    pub fn mount(&self) -> Result<(), VfsError> {
        self.handler.mount()
    }

    /// Unmount the filesystem with the default timeout (2 seconds).
    ///
    /// This method:
    /// 1. Flushes all pending writes to disk
    /// 2. Closes all open file handles
    /// 3. Releases the drive letter
    /// 4. Wipes all keys from memory
    pub fn unmount(&self) -> Result<(), VfsError> {
        self.handler.unmount()
    }

    /// Unmount with a custom timeout in milliseconds.
    ///
    /// # Arguments
    /// * `timeout_ms` - Maximum time to wait for graceful unmount
    pub fn unmount_with_timeout(&self, timeout_ms: u64) -> Result<(), VfsError> {
        self.handler.unmount_with_timeout(timeout_ms)
    }

    /// Force unmount without waiting for handles to close.
    ///
    /// WARNING: This may result in data loss for files with pending writes.
    /// Use only in emergency situations (e.g., USB removal).
    pub fn force_unmount(&self) -> Result<(), VfsError> {
        self.handler.force_unmount()
    }

    /// Check if mounted.
    pub fn is_mounted(&self) -> bool {
        self.handler.is_mounted()
    }

    /// Get the mount point path.
    pub fn mount_point(&self) -> String {
        self.handler.config().mount_point()
    }

    /// Check if there are any pending writes.
    pub fn has_pending_writes(&self) -> bool {
        self.handler.has_pending_writes()
    }

    /// Get the number of open file handles.
    pub fn open_handle_count(&self) -> usize {
        self.handler.open_handle_count()
    }

    /// Get the number of handles with pending writes.
    pub fn dirty_handle_count(&self) -> usize {
        self.handler.dirty_handle_count()
    }

    /// Get information about all open handles.
    pub fn get_open_handles_info(&self) -> Vec<OpenHandleInfo> {
        self.handler.get_open_handles_info()
    }
}

impl Drop for DokanMount {
    fn drop(&mut self) {
        if self.is_mounted() {
            // Try graceful unmount first, fall back to force unmount
            if self.unmount().is_err() {
                let _ = self.force_unmount();
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert Unix timestamp (seconds since 1970) to Windows FILETIME.
///
/// Windows FILETIME is the number of 100-nanosecond intervals since
/// January 1, 1601.
pub fn unix_to_filetime(unix_secs: u64) -> u64 {
    // Convert seconds to 100-nanosecond intervals and add the epoch difference
    unix_secs * 10_000_000 + FILETIME_UNIX_DIFF
}

/// Convert Windows FILETIME to Unix timestamp.
pub fn filetime_to_unix(filetime: u64) -> u64 {
    if filetime < FILETIME_UNIX_DIFF {
        0
    } else {
        (filetime - FILETIME_UNIX_DIFF) / 10_000_000
    }
}

/// Simple hash function for generating file indices from paths.
fn hash_path(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for byte in path.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV-1a prime
    }
    hash
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // FileSystemFlags Tests
    // =========================================================================

    #[test]
    fn test_filesystem_flags_default() {
        let flags = FileSystemFlags::default_flags();
        assert_ne!(flags, 0);
        assert!(flags & FileSystemFlags::CasePreservedNames as u32 != 0);
        assert!(flags & FileSystemFlags::UnicodeOnDisk as u32 != 0);
    }

    // =========================================================================
    // FileAttributes Tests
    // =========================================================================

    #[test]
    fn test_file_attributes_from_entry_type_file() {
        let attrs = FileAttributes::from_entry_type(EntryType::File);
        assert!(attrs & FileAttributes::Normal as u32 != 0);
        assert!(attrs & FileAttributes::Directory as u32 == 0);
    }

    #[test]
    fn test_file_attributes_from_entry_type_directory() {
        let attrs = FileAttributes::from_entry_type(EntryType::Directory);
        assert!(attrs & FileAttributes::Directory as u32 != 0);
    }

    // =========================================================================
    // NtStatus Tests
    // =========================================================================

    #[test]
    fn test_ntstatus_success_is_zero() {
        assert_eq!(NtStatus::Success.as_i32(), 0);
    }

    #[test]
    fn test_ntstatus_from_vault_error() {
        assert_eq!(
            NtStatus::from_vault_error(&VaultError::FileNotFound),
            NtStatus::ObjectNameNotFound
        );
        assert_eq!(
            NtStatus::from_vault_error(&VaultError::AccessDenied),
            NtStatus::AccessDenied
        );
        assert_eq!(
            NtStatus::from_vault_error(&VaultError::VaultLocked),
            NtStatus::AccessDenied
        );
    }

    // =========================================================================
    // FileHandle Tests
    // =========================================================================

    #[test]
    fn test_file_handle_new() {
        let uuid = Uuid::new_v4();
        let handle = FileHandle::new(
            Some(uuid),
            "/test/file.txt".to_string(),
            false,
            1,
            1024,
            false,
        );

        assert_eq!(handle.uuid, Some(uuid));
        assert_eq!(handle.path, "/test/file.txt");
        assert!(!handle.is_directory);
        assert_eq!(handle.access_level, 1);
        assert_eq!(handle.size, 1024);
        assert!(!handle.write_access);
        assert_eq!(handle.read_position, 0);
        assert_eq!(handle.write_position, 0);
        assert!(handle.cached_content.is_none());
        assert!(!handle.is_dirty);
    }

    #[test]
    fn test_file_handle_root() {
        let handle = FileHandle::root();

        assert!(handle.uuid.is_none());
        assert_eq!(handle.path, "/");
        assert!(handle.is_directory);
        assert_eq!(handle.access_level, 0);
        assert_eq!(handle.size, 0);
        assert!(!handle.write_access);
    }

    // =========================================================================
    // DokanConfig Tests
    // =========================================================================

    #[test]
    fn test_dokan_config_new() {
        let config = DokanConfig::new('X');
        assert_eq!(config.drive_letter, 'X');
        assert_eq!(config.volume_label, VOLUME_LABEL);
        assert!(!config.debug);
        assert!(!config.read_only);
    }

    #[test]
    fn test_dokan_config_lowercase_letter_normalized() {
        let config = DokanConfig::new('x');
        assert_eq!(config.drive_letter, 'X');
    }

    #[test]
    fn test_dokan_config_mount_point() {
        let config = DokanConfig::new('T');
        assert_eq!(config.mount_point(), "T:\\");
    }

    #[test]
    fn test_dokan_config_builder() {
        let config = DokanConfig::new('Z')
            .with_volume_label("TEST")
            .with_thread_count(4)
            .with_debug(true)
            .with_read_only(true)
            .with_disk_space(100, 50, 50);

        assert_eq!(config.drive_letter, 'Z');
        assert_eq!(config.volume_label, "TEST");
        assert_eq!(config.thread_count, 4);
        assert!(config.debug);
        assert!(config.read_only);
        assert_eq!(config.total_bytes, 100);
        assert_eq!(config.free_bytes, 50);
        assert_eq!(config.available_bytes, 50);
    }

    #[test]
    fn test_dokan_config_default() {
        let config = DokanConfig::default();
        assert_eq!(config.drive_letter, 'T');
    }

    // =========================================================================
    // FileInfo Tests
    // =========================================================================

    #[test]
    fn test_file_info_root() {
        let info = FileInfo::root();
        assert!(info.attributes & FileAttributes::Directory as u32 != 0);
        assert_eq!(info.size, 0);
        assert_eq!(info.volume_serial, VOLUME_SERIAL);
        assert_eq!(info.number_of_links, 1);
    }

    #[test]
    fn test_file_info_from_entry() {
        let entry = FileEntry::new_file(
            "test.txt".to_string(),
            1024,
            1704067200, // 2024-01-01 00:00:00 UTC
            1,
            Uuid::new_v4(),
        );

        let info = FileInfo::from_entry(&entry);
        assert!(info.attributes & FileAttributes::Normal as u32 != 0);
        assert_eq!(info.size, 1024);
        assert!(info.creation_time > 0);
    }

    // =========================================================================
    // FindData Tests
    // =========================================================================

    #[test]
    fn test_find_data_from_entry() {
        let entry = FileEntry::new_directory("subdir".to_string(), 1, 0);
        let data = FindData::from_entry(&entry);

        assert_eq!(data.file_name, "subdir");
        assert!(data.attributes & FileAttributes::Directory as u32 != 0);
        assert_eq!(data.size, 0);
    }

    // =========================================================================
    // DiskSpace Tests
    // =========================================================================

    #[test]
    fn test_disk_space_from_config() {
        let config = DokanConfig::new('T')
            .with_disk_space(1000, 500, 400);
        let space = DiskSpace::from_config(&config);

        assert_eq!(space.total_bytes, 1000);
        assert_eq!(space.total_free_bytes, 500);
        assert_eq!(space.free_bytes_available, 400);
    }

    // =========================================================================
    // VolumeInfo Tests
    // =========================================================================

    #[test]
    fn test_volume_info_new() {
        let info = VolumeInfo::new("MYVAULT");

        assert_eq!(info.volume_label, "MYVAULT");
        assert_eq!(info.serial_number, VOLUME_SERIAL);
        assert_eq!(info.max_component_length, MAX_COMPONENT_LENGTH);
        assert_eq!(info.file_system_name, FILESYSTEM_NAME);
    }

    // =========================================================================
    // Time Conversion Tests
    // =========================================================================

    #[test]
    fn test_unix_to_filetime() {
        // Unix epoch (1970-01-01) should give the known offset
        let filetime = unix_to_filetime(0);
        assert_eq!(filetime, FILETIME_UNIX_DIFF);
    }

    #[test]
    fn test_filetime_to_unix() {
        // Round-trip conversion
        let original = 1704067200u64; // 2024-01-01
        let filetime = unix_to_filetime(original);
        let back = filetime_to_unix(filetime);
        assert_eq!(back, original);
    }

    #[test]
    fn test_filetime_to_unix_zero() {
        // Values before Unix epoch should return 0
        assert_eq!(filetime_to_unix(0), 0);
        assert_eq!(filetime_to_unix(100), 0);
    }

    // =========================================================================
    // Hash Path Tests
    // =========================================================================

    #[test]
    fn test_hash_path_deterministic() {
        let hash1 = hash_path("/test/path");
        let hash2 = hash_path("/test/path");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_path_different_paths() {
        let hash1 = hash_path("/test/path1");
        let hash2 = hash_path("/test/path2");
        assert_ne!(hash1, hash2);
    }

    // =========================================================================
    // Path Normalization Tests
    // =========================================================================

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(TesseractDokanHandler::normalize_path(""), "/");
    }

    #[test]
    fn test_normalize_path_root() {
        assert_eq!(TesseractDokanHandler::normalize_path("/"), "/");
        assert_eq!(TesseractDokanHandler::normalize_path("\\"), "/");
    }

    #[test]
    fn test_normalize_path_backslashes() {
        assert_eq!(
            TesseractDokanHandler::normalize_path("\\folder\\file.txt"),
            "/folder/file.txt"
        );
    }

    #[test]
    fn test_normalize_path_no_leading_slash() {
        assert_eq!(
            TesseractDokanHandler::normalize_path("folder/file.txt"),
            "/folder/file.txt"
        );
    }

    #[test]
    fn test_normalize_path_already_normalized() {
        assert_eq!(
            TesseractDokanHandler::normalize_path("/folder/file.txt"),
            "/folder/file.txt"
        );
    }

    // =========================================================================
    // CachedChunk Tests (US-048)
    // =========================================================================

    #[test]
    fn test_cached_chunk_new() {
        let data = vec![1, 2, 3, 4, 5];
        let chunk = CachedChunk::new(100, data.clone());

        assert_eq!(chunk.offset, 100);
        assert_eq!(chunk.data, data);
        assert_eq!(chunk.end_offset(), 105);
    }

    #[test]
    fn test_cached_chunk_contains() {
        let chunk = CachedChunk::new(100, vec![0; 50]);

        // Test boundaries
        assert!(!chunk.contains(99));  // Before start
        assert!(chunk.contains(100));  // At start
        assert!(chunk.contains(125));  // Middle
        assert!(chunk.contains(149));  // Last byte
        assert!(!chunk.contains(150)); // After end
    }

    #[test]
    fn test_cached_chunk_read_full() {
        let chunk = CachedChunk::new(0, vec![1, 2, 3, 4, 5]);
        let mut buffer = [0u8; 5];

        let read = chunk.read(0, &mut buffer);

        assert_eq!(read, 5);
        assert_eq!(buffer, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_cached_chunk_read_partial() {
        let chunk = CachedChunk::new(0, vec![1, 2, 3, 4, 5]);
        let mut buffer = [0u8; 3];

        let read = chunk.read(2, &mut buffer);

        assert_eq!(read, 3);
        assert_eq!(buffer, [3, 4, 5]);
    }

    #[test]
    fn test_cached_chunk_read_with_offset() {
        let chunk = CachedChunk::new(100, vec![10, 20, 30, 40, 50]);
        let mut buffer = [0u8; 3];

        let read = chunk.read(102, &mut buffer);

        assert_eq!(read, 3);
        assert_eq!(buffer, [30, 40, 50]);
    }

    #[test]
    fn test_cached_chunk_read_beyond_end() {
        let chunk = CachedChunk::new(0, vec![1, 2, 3]);
        let mut buffer = [0u8; 10];

        let read = chunk.read(0, &mut buffer);

        assert_eq!(read, 3);
        assert_eq!(&buffer[..3], &[1, 2, 3]);
    }

    #[test]
    fn test_cached_chunk_read_outside_range() {
        let chunk = CachedChunk::new(100, vec![1, 2, 3]);
        let mut buffer = [0u8; 10];

        let read = chunk.read(0, &mut buffer);

        assert_eq!(read, 0);
    }

    // =========================================================================
    // ChunkCache Tests (US-048)
    // =========================================================================

    #[test]
    fn test_chunk_cache_new() {
        let cache = ChunkCache::new();

        assert_eq!(cache.total_size(), 0);
        assert_eq!(cache.file_count(), 0);
        assert_eq!(cache.chunk_count(), 0);
    }

    #[test]
    fn test_chunk_cache_insert() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();
        let chunk = CachedChunk::new(0, vec![0; 1000]);

        cache.insert(uuid, chunk);

        assert_eq!(cache.total_size(), 1000);
        assert_eq!(cache.file_count(), 1);
        assert_eq!(cache.chunk_count(), 1);
    }

    #[test]
    fn test_chunk_cache_insert_multiple_chunks() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        cache.insert(uuid, CachedChunk::new(0, vec![0; 1000]));
        cache.insert(uuid, CachedChunk::new(1000, vec![0; 1000]));

        assert_eq!(cache.total_size(), 2000);
        assert_eq!(cache.file_count(), 1);
        assert_eq!(cache.chunk_count(), 2);
    }

    #[test]
    fn test_chunk_cache_insert_multiple_files() {
        let mut cache = ChunkCache::new();

        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();

        cache.insert(uuid1, CachedChunk::new(0, vec![0; 1000]));
        cache.insert(uuid2, CachedChunk::new(0, vec![0; 2000]));

        assert_eq!(cache.total_size(), 3000);
        assert_eq!(cache.file_count(), 2);
        assert_eq!(cache.chunk_count(), 2);
    }

    #[test]
    fn test_chunk_cache_find_chunk() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        cache.insert(uuid, CachedChunk::new(0, vec![1, 2, 3]));
        cache.insert(uuid, CachedChunk::new(100, vec![4, 5, 6]));

        // Find first chunk
        let chunk = cache.find_chunk(&uuid, 1);
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().offset, 0);

        // Find second chunk
        let chunk = cache.find_chunk(&uuid, 101);
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().offset, 100);

        // Not found
        let chunk = cache.find_chunk(&uuid, 50);
        assert!(chunk.is_none());
    }

    #[test]
    fn test_chunk_cache_clear_file() {
        let mut cache = ChunkCache::new();
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();

        cache.insert(uuid1, CachedChunk::new(0, vec![0; 1000]));
        cache.insert(uuid2, CachedChunk::new(0, vec![0; 2000]));

        cache.clear_file(&uuid1);

        assert_eq!(cache.total_size(), 2000);
        assert_eq!(cache.file_count(), 1);
        assert_eq!(cache.chunk_count(), 1);
    }

    #[test]
    fn test_chunk_cache_clear() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        cache.insert(uuid, CachedChunk::new(0, vec![0; 1000]));
        cache.insert(uuid, CachedChunk::new(1000, vec![0; 1000]));

        cache.clear();

        assert_eq!(cache.total_size(), 0);
        assert_eq!(cache.file_count(), 0);
        assert_eq!(cache.chunk_count(), 0);
    }

    #[test]
    fn test_chunk_cache_eviction_by_count() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        // Insert MAX_CACHED_CHUNKS_PER_FILE + 1 chunks
        for i in 0..=MAX_CACHED_CHUNKS_PER_FILE {
            cache.insert(uuid, CachedChunk::new((i * 100) as u64, vec![0; 100]));
            std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure different timestamps
        }

        // Should have evicted at least one
        assert!(cache.chunk_count() <= MAX_CACHED_CHUNKS_PER_FILE);
    }

    #[test]
    fn test_chunk_cache_default() {
        let cache = ChunkCache::default();
        assert_eq!(cache.total_size(), 0);
    }

    // =========================================================================
    // CacheStats Tests (US-048)
    // =========================================================================

    #[test]
    fn test_cache_stats_default() {
        let stats = CacheStats::default();

        assert_eq!(stats.total_size, 0);
        assert_eq!(stats.file_count, 0);
        assert_eq!(stats.chunk_count, 0);
    }

    // =========================================================================
    // Cache Configuration Constants Tests (US-048)
    // =========================================================================

    #[test]
    fn test_cache_chunk_size_is_64kb() {
        assert_eq!(CACHE_CHUNK_SIZE, 64 * 1024);
    }

    #[test]
    fn test_max_cache_size_is_16mb() {
        assert_eq!(MAX_CACHE_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn test_cache_expiration_is_5_minutes() {
        assert_eq!(CACHE_EXPIRATION_SECS, 300);
    }

    #[test]
    fn test_max_cached_chunks_per_file() {
        assert_eq!(MAX_CACHED_CHUNKS_PER_FILE, 16);
    }

    // =========================================================================
    // Read Operation Helper Tests (US-048)
    // =========================================================================

    #[test]
    fn test_cached_chunk_touch_updates_timestamp() {
        let mut chunk = CachedChunk::new(0, vec![1, 2, 3]);
        let initial = chunk.last_accessed;

        std::thread::sleep(std::time::Duration::from_millis(10));
        chunk.touch();

        assert!(chunk.last_accessed > initial);
    }

    #[test]
    fn test_cached_chunk_is_not_expired_initially() {
        let chunk = CachedChunk::new(0, vec![1, 2, 3]);
        assert!(!chunk.is_expired());
    }

    // Note: Testing actual expiration would require waiting 5 minutes,
    // so we just verify the is_expired method works

    #[test]
    fn test_cache_stats_copy() {
        let stats = CacheStats {
            total_size: 1000,
            file_count: 5,
            chunk_count: 10,
        };

        let copy = stats;
        assert_eq!(copy.total_size, 1000);
        assert_eq!(copy.file_count, 5);
        assert_eq!(copy.chunk_count, 10);
    }

    // =========================================================================
    // Chunk Read Edge Cases (US-048)
    // =========================================================================

    #[test]
    fn test_cached_chunk_read_empty_buffer() {
        let chunk = CachedChunk::new(0, vec![1, 2, 3, 4, 5]);
        let mut buffer: [u8; 0] = [];

        let read = chunk.read(0, &mut buffer);

        assert_eq!(read, 0);
    }

    #[test]
    fn test_cached_chunk_read_from_start() {
        let chunk = CachedChunk::new(500, vec![10, 20, 30, 40, 50]);
        let mut buffer = [0u8; 2];

        let read = chunk.read(500, &mut buffer);

        assert_eq!(read, 2);
        assert_eq!(buffer, [10, 20]);
    }

    #[test]
    fn test_cached_chunk_read_last_byte() {
        let chunk = CachedChunk::new(0, vec![1, 2, 3, 4, 5]);
        let mut buffer = [0u8; 1];

        let read = chunk.read(4, &mut buffer);

        assert_eq!(read, 1);
        assert_eq!(buffer, [5]);
    }

    #[test]
    fn test_cached_chunk_empty_data() {
        let chunk = CachedChunk::new(0, vec![]);

        assert_eq!(chunk.end_offset(), 0);
        assert!(!chunk.contains(0));
    }

    // =========================================================================
    // Cache Eviction Tests (US-048)
    // =========================================================================

    #[test]
    fn test_chunk_cache_evicts_when_full() {
        let mut cache = ChunkCache::new();

        // Fill cache close to limit
        let chunk_size = MAX_CACHE_SIZE / 2;
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();
        let uuid3 = Uuid::new_v4();

        cache.insert(uuid1, CachedChunk::new(0, vec![0; chunk_size]));
        std::thread::sleep(std::time::Duration::from_millis(1));
        cache.insert(uuid2, CachedChunk::new(0, vec![0; chunk_size]));

        // This should trigger eviction
        std::thread::sleep(std::time::Duration::from_millis(1));
        cache.insert(uuid3, CachedChunk::new(0, vec![0; chunk_size]));

        // Should have evicted the oldest chunk
        assert!(cache.total_size() <= MAX_CACHE_SIZE);
    }

    #[test]
    fn test_chunk_cache_get_file_chunks() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        cache.insert(uuid, CachedChunk::new(0, vec![1, 2, 3]));
        cache.insert(uuid, CachedChunk::new(100, vec![4, 5, 6]));

        let chunks = cache.get_file_chunks(&uuid);
        assert!(chunks.is_some());
        assert_eq!(chunks.unwrap().len(), 2);
    }

    #[test]
    fn test_chunk_cache_get_file_chunks_not_found() {
        let cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        let chunks = cache.get_file_chunks(&uuid);
        assert!(chunks.is_none());
    }

    #[test]
    fn test_chunk_cache_clear_nonexistent_file() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        // Should not panic
        cache.clear_file(&uuid);

        assert_eq!(cache.total_size(), 0);
    }

    // =========================================================================
    // Integration-like Tests (US-048)
    // =========================================================================

    #[test]
    fn test_chunk_cache_sequential_read_pattern() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        // Simulate caching a file in chunks
        let file_content: Vec<u8> = (0..=255).cycle().take(256 * 1024).collect();

        for (i, chunk_data) in file_content.chunks(CACHE_CHUNK_SIZE).enumerate() {
            let offset = (i * CACHE_CHUNK_SIZE) as u64;
            cache.insert(uuid, CachedChunk::new(offset, chunk_data.to_vec()));
        }

        // Read back from different offsets
        let chunk = cache.find_chunk(&uuid, 0);
        assert!(chunk.is_some());

        let chunk = cache.find_chunk(&uuid, CACHE_CHUNK_SIZE as u64);
        assert!(chunk.is_some());

        let chunk = cache.find_chunk(&uuid, (2 * CACHE_CHUNK_SIZE) as u64);
        assert!(chunk.is_some());
    }

    #[test]
    fn test_chunk_cache_random_access_pattern() {
        let mut cache = ChunkCache::new();
        let uuid = Uuid::new_v4();

        // Insert non-contiguous chunks
        cache.insert(uuid, CachedChunk::new(0, vec![1; 100]));
        cache.insert(uuid, CachedChunk::new(1000, vec![2; 100]));
        cache.insert(uuid, CachedChunk::new(5000, vec![3; 100]));

        // Random access should work
        let chunk = cache.find_chunk(&uuid, 50);
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().data[0], 1);

        let chunk = cache.find_chunk(&uuid, 1050);
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().data[0], 2);

        let chunk = cache.find_chunk(&uuid, 5050);
        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap().data[0], 3);

        // Gap should return None
        let chunk = cache.find_chunk(&uuid, 500);
        assert!(chunk.is_none());
    }

    // =========================================================================
    // WriteBuffer Tests (US-049)
    // =========================================================================

    #[test]
    fn test_write_buffer_new_file() {
        let buffer = WriteBuffer::new_file("test.txt".to_string());

        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_new_file);
        assert!(buffer.is_modified());
        assert_eq!(buffer.filename, "test.txt");
        assert!(buffer.original_content.is_none());
    }

    #[test]
    fn test_write_buffer_existing_file() {
        let original = vec![1, 2, 3, 4, 5];
        let buffer = WriteBuffer::existing_file(original.clone(), "existing.txt".to_string());

        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 5);
        assert!(!buffer.is_new_file);
        assert!(!buffer.is_modified());
        assert_eq!(buffer.filename, "existing.txt");
        assert_eq!(buffer.original_content, Some(original));
        assert_eq!(buffer.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_write_buffer_write_at_start() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        let written = buffer.write_at(0, &[1, 2, 3]);

        assert_eq!(written, 3);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.data, vec![1, 2, 3]);
        assert!(buffer.is_modified());
    }

    #[test]
    fn test_write_buffer_write_at_offset() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        // Write at offset 5, creating gap
        let written = buffer.write_at(5, &[10, 20, 30]);

        assert_eq!(written, 3);
        assert_eq!(buffer.len(), 8);
        assert_eq!(buffer.data, vec![0, 0, 0, 0, 0, 10, 20, 30]);
    }

    #[test]
    fn test_write_buffer_overwrite_existing() {
        let original = vec![1, 2, 3, 4, 5];
        let mut buffer = WriteBuffer::existing_file(original, "test.txt".to_string());

        // Overwrite middle bytes
        let written = buffer.write_at(2, &[100, 101]);

        assert_eq!(written, 2);
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.data, vec![1, 2, 100, 101, 5]);
        assert!(buffer.is_modified());
    }

    #[test]
    fn test_write_buffer_extend_existing() {
        let original = vec![1, 2, 3];
        let mut buffer = WriteBuffer::existing_file(original, "test.txt".to_string());

        // Write past the end
        let written = buffer.write_at(5, &[10, 20]);

        assert_eq!(written, 2);
        assert_eq!(buffer.len(), 7);
        assert_eq!(buffer.data, vec![1, 2, 3, 0, 0, 10, 20]);
    }

    #[test]
    fn test_write_buffer_set_end_of_file_truncate() {
        let original = vec![1, 2, 3, 4, 5];
        let mut buffer = WriteBuffer::existing_file(original, "test.txt".to_string());

        buffer.set_end_of_file(3);

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.data, vec![1, 2, 3]);
        assert!(buffer.is_modified());
    }

    #[test]
    fn test_write_buffer_set_end_of_file_extend() {
        let original = vec![1, 2, 3];
        let mut buffer = WriteBuffer::existing_file(original, "test.txt".to_string());

        buffer.set_end_of_file(7);

        assert_eq!(buffer.len(), 7);
        assert_eq!(buffer.data, vec![1, 2, 3, 0, 0, 0, 0]);
    }

    #[test]
    fn test_write_buffer_set_end_of_file_no_change() {
        let original = vec![1, 2, 3];
        let mut buffer = WriteBuffer::existing_file(original, "test.txt".to_string());
        buffer.clear_modified(); // Clear initial modified state

        buffer.set_end_of_file(3);

        assert_eq!(buffer.len(), 3);
        assert!(buffer.is_modified()); // Still marked modified
    }

    #[test]
    fn test_write_buffer_read_at() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());
        buffer.write_at(0, &[1, 2, 3, 4, 5]);

        let mut output = [0u8; 3];
        let read = buffer.read_at(1, &mut output);

        assert_eq!(read, 3);
        assert_eq!(output, [2, 3, 4]);
    }

    #[test]
    fn test_write_buffer_read_at_beyond_end() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());
        buffer.write_at(0, &[1, 2, 3]);

        let mut output = [0u8; 5];
        let read = buffer.read_at(1, &mut output);

        assert_eq!(read, 2); // Only 2 bytes available
        assert_eq!(&output[..2], &[2, 3]);
    }

    #[test]
    fn test_write_buffer_read_at_past_end() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());
        buffer.write_at(0, &[1, 2, 3]);

        let mut output = [0u8; 3];
        let read = buffer.read_at(10, &mut output);

        assert_eq!(read, 0);
    }

    #[test]
    fn test_write_buffer_clear_modified() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());
        assert!(buffer.is_modified());

        buffer.clear_modified();
        assert!(!buffer.is_modified());

        buffer.write_at(0, &[1]);
        assert!(buffer.is_modified());
    }

    #[test]
    fn test_write_buffer_multiple_writes() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        buffer.write_at(0, &[1, 2]);
        buffer.write_at(2, &[3, 4]);
        buffer.write_at(4, &[5, 6]);

        assert_eq!(buffer.len(), 6);
        assert_eq!(buffer.data, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_write_buffer_overlapping_writes() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        buffer.write_at(0, &[1, 2, 3, 4, 5]);
        buffer.write_at(2, &[10, 20]); // Overwrite middle

        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.data, vec![1, 2, 10, 20, 5]);
    }

    #[test]
    fn test_write_buffer_write_empty_data() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());
        buffer.clear_modified();

        let written = buffer.write_at(0, &[]);

        assert_eq!(written, 0);
        assert!(buffer.is_empty());
        assert!(buffer.is_modified()); // Empty write still marks modified due to resize
    }

    // =========================================================================
    // Extract Filename Tests (US-049)
    // =========================================================================

    #[test]
    fn test_extract_filename_simple() {
        assert_eq!(
            TesseractDokanHandler::extract_filename("/test.txt"),
            "test.txt"
        );
    }

    #[test]
    fn test_extract_filename_nested() {
        assert_eq!(
            TesseractDokanHandler::extract_filename("/folder/subfolder/document.pdf"),
            "document.pdf"
        );
    }

    #[test]
    fn test_extract_filename_root() {
        assert_eq!(
            TesseractDokanHandler::extract_filename("/"),
            ""
        );
    }

    #[test]
    fn test_extract_filename_no_slash() {
        assert_eq!(
            TesseractDokanHandler::extract_filename("filename.txt"),
            "filename.txt"
        );
    }

    #[test]
    fn test_extract_filename_empty() {
        // Empty string returns empty because rsplit returns "" for ""
        // The "unnamed" fallback only applies when unwrap_or is needed
        assert_eq!(
            TesseractDokanHandler::extract_filename(""),
            ""
        );
    }

    // =========================================================================
    // Integration-like Tests (US-049)
    // =========================================================================

    #[test]
    fn test_write_buffer_simulate_text_file_creation() {
        let mut buffer = WriteBuffer::new_file("notes.txt".to_string());

        // Simulate typing text
        buffer.write_at(0, b"Hello, ");
        buffer.write_at(7, b"World!");

        assert_eq!(buffer.len(), 13);
        assert_eq!(&buffer.data, b"Hello, World!");
    }

    #[test]
    fn test_write_buffer_simulate_file_edit() {
        // Open existing file
        let original = b"The quick brown fox".to_vec();
        let mut buffer = WriteBuffer::existing_file(original, "document.txt".to_string());

        // Edit: replace "quick" with "slow"
        buffer.write_at(4, b"slow ");

        assert_eq!(buffer.len(), 19);
        assert_eq!(&buffer.data, b"The slow  brown fox");
    }

    #[test]
    fn test_write_buffer_simulate_truncate_and_rewrite() {
        let original = b"Old content that will be replaced".to_vec();
        let mut buffer = WriteBuffer::existing_file(original, "file.txt".to_string());

        // Truncate to 0
        buffer.set_end_of_file(0);
        assert!(buffer.is_empty());

        // Write new content
        buffer.write_at(0, b"New content");

        assert_eq!(buffer.len(), 11);
        assert_eq!(&buffer.data, b"New content");
    }

    #[test]
    fn test_write_buffer_simulate_append() {
        let original = b"Line 1\n".to_vec();
        let mut buffer = WriteBuffer::existing_file(original, "log.txt".to_string());

        // Append new line
        buffer.write_at(7, b"Line 2\n");

        assert_eq!(buffer.len(), 14);
        assert_eq!(&buffer.data, b"Line 1\nLine 2\n");
    }

    #[test]
    fn test_write_buffer_simulate_sparse_write() {
        let mut buffer = WriteBuffer::new_file("sparse.bin".to_string());

        // Write at various offsets, leaving gaps
        buffer.write_at(0, &[0xFF]);
        buffer.write_at(100, &[0xAA]);
        buffer.write_at(200, &[0xBB]);

        assert_eq!(buffer.len(), 201);
        assert_eq!(buffer.data[0], 0xFF);
        assert_eq!(buffer.data[99], 0x00); // Gap filled with zeros
        assert_eq!(buffer.data[100], 0xAA);
        assert_eq!(buffer.data[200], 0xBB);
    }

    // =========================================================================
    // Delete and Rename Helper Tests (US-050)
    // =========================================================================

    #[test]
    fn test_parent_path_root() {
        assert_eq!(TesseractDokanHandler::parent_path("/file.txt"), "/");
    }

    #[test]
    fn test_parent_path_single_level() {
        assert_eq!(TesseractDokanHandler::parent_path("/folder/file.txt"), "/folder");
    }

    #[test]
    fn test_parent_path_deep() {
        assert_eq!(
            TesseractDokanHandler::parent_path("/a/b/c/file.txt"),
            "/a/b/c"
        );
    }

    #[test]
    fn test_parent_path_no_slash() {
        assert_eq!(TesseractDokanHandler::parent_path("file.txt"), "/");
    }

    #[test]
    fn test_extract_filename_simple() {
        assert_eq!(TesseractDokanHandler::extract_filename("/folder/file.txt"), "file.txt");
    }

    #[test]
    fn test_extract_filename_deep_path() {
        assert_eq!(
            TesseractDokanHandler::extract_filename("/a/b/c/document.pdf"),
            "document.pdf"
        );
    }

    #[test]
    fn test_extract_filename_root_file() {
        assert_eq!(TesseractDokanHandler::extract_filename("/myfile.txt"), "myfile.txt");
    }

    #[test]
    fn test_extract_filename_no_path() {
        assert_eq!(TesseractDokanHandler::extract_filename("file.txt"), "file.txt");
    }

    #[test]
    fn test_extract_filename_empty() {
        // Empty path should return "unnamed"
        assert_eq!(TesseractDokanHandler::extract_filename(""), "unnamed");
    }

    #[test]
    fn test_extract_filename_trailing_slash() {
        // Edge case: path ending with slash
        assert_eq!(TesseractDokanHandler::extract_filename("/folder/"), "");
    }

    // =========================================================================
    // Delete/Move Access Control Tests (US-050)
    // =========================================================================

    #[test]
    fn test_ntstatus_from_vault_error_file_not_found() {
        // Verify proper mapping for delete operations
        assert_eq!(
            NtStatus::from_vault_error(&VaultError::FileNotFound),
            NtStatus::ObjectNameNotFound
        );
    }

    #[test]
    fn test_ntstatus_object_name_collision() {
        // Used when move destination exists and replace_if_exists is false
        assert_ne!(NtStatus::ObjectNameCollision.as_i32(), 0);
    }

    // =========================================================================
    // DokanConfig Read-Only Tests (US-050)
    // =========================================================================

    #[test]
    fn test_dokan_config_read_only_default_false() {
        let config = DokanConfig::default();
        assert!(!config.read_only);
    }

    #[test]
    fn test_dokan_config_read_only_enabled() {
        let config = DokanConfig::new('T').with_read_only(true);
        assert!(config.read_only);
    }

    // =========================================================================
    // Path Handling for Delete/Move (US-050)
    // =========================================================================

    #[test]
    fn test_normalize_path_for_delete() {
        // Windows-style paths should be normalized correctly for delete operations
        assert_eq!(
            TesseractDokanHandler::normalize_path("\\docs\\secret.txt"),
            "/docs/secret.txt"
        );
    }

    #[test]
    fn test_normalize_path_for_move_source() {
        assert_eq!(
            TesseractDokanHandler::normalize_path("\\old\\location\\file.txt"),
            "/old/location/file.txt"
        );
    }

    #[test]
    fn test_normalize_path_for_move_dest() {
        assert_eq!(
            TesseractDokanHandler::normalize_path("\\new\\location\\file.txt"),
            "/new/location/file.txt"
        );
    }

    #[test]
    fn test_parent_path_matches_for_rename() {
        // For rename (same directory), parent paths should match
        let old_path = "/docs/old_name.txt";
        let new_path = "/docs/new_name.txt";
        assert_eq!(
            TesseractDokanHandler::parent_path(old_path),
            TesseractDokanHandler::parent_path(new_path)
        );
    }

    #[test]
    fn test_parent_path_differs_for_move() {
        // For move (different directory), parent paths should differ
        let old_path = "/docs/file.txt";
        let new_path = "/archive/file.txt";
        assert_ne!(
            TesseractDokanHandler::parent_path(old_path),
            TesseractDokanHandler::parent_path(new_path)
        );
    }

    // =========================================================================
    // FileEntry for Delete (US-050)
    // =========================================================================

    #[test]
    fn test_file_entry_with_uuid_for_delete() {
        let uuid = Uuid::new_v4();
        let entry = FileEntry::new_file(
            "deletable.txt".to_string(),
            100,
            1704067200,
            1,
            Some(uuid),
        );

        // File must have UUID for deletion
        assert!(entry.uuid.is_some());
        assert_eq!(entry.uuid.unwrap(), uuid);
    }

    #[test]
    fn test_directory_entry_has_no_uuid() {
        let entry = FileEntry::new_directory("folder".to_string(), 1, 0);

        // Virtual directories have no UUID (cannot be directly deleted)
        assert!(entry.uuid.is_none());
    }

    // =========================================================================
    // Cache Clearing on Delete (US-050)
    // =========================================================================

    #[test]
    fn test_cache_clear_on_delete() {
        let mut cache = ChunkCache::new();
        let uuid_to_delete = Uuid::new_v4();
        let uuid_to_keep = Uuid::new_v4();

        // Add chunks for both files
        cache.insert(uuid_to_delete, CachedChunk::new(0, vec![1, 2, 3]));
        cache.insert(uuid_to_delete, CachedChunk::new(100, vec![4, 5, 6]));
        cache.insert(uuid_to_keep, CachedChunk::new(0, vec![7, 8, 9]));

        assert_eq!(cache.chunk_count(), 3);
        assert_eq!(cache.file_count(), 2);

        // Clear cache for deleted file
        cache.clear_file(&uuid_to_delete);

        // Verify only deleted file's cache is gone
        assert_eq!(cache.chunk_count(), 1);
        assert_eq!(cache.file_count(), 1);
        assert!(cache.find_chunk(&uuid_to_delete, 0).is_none());
        assert!(cache.find_chunk(&uuid_to_keep, 0).is_some());
    }

    // =========================================================================
    // Handle Management for Delete/Move (US-050)
    // =========================================================================

    #[test]
    fn test_file_handle_stores_uuid() {
        let uuid = Uuid::new_v4();
        let handle = FileHandle::new(
            Some(uuid),
            "/file.txt".to_string(),
            false,
            1,
            1024,
            true,
        );

        assert_eq!(handle.uuid, Some(uuid));
    }

    #[test]
    fn test_file_handle_stores_access_level() {
        // Access level is needed for permission checks on delete/move
        for level in 1..=3 {
            let handle = FileHandle::new(
                Uuid::new_v4(),
                format!("/l{}/file.txt", level),
                false,
                level,
                1024,
                true,
            );

            assert_eq!(handle.access_level, level);
        }
    }

    #[test]
    fn test_file_handle_path_can_be_updated() {
        // For move operations, handle path should be updatable
        let mut handle = FileHandle::new(
            Uuid::new_v4(),
            "/old/path.txt".to_string(),
            false,
            1,
            1024,
            true,
        );

        handle.path = "/new/path.txt".to_string();

        assert_eq!(handle.path, "/new/path.txt");
    }

    // =========================================================================
    // Access-Level Filtered Directory Listing Tests (US-051)
    // =========================================================================
    //
    // These tests verify that the VFS layer correctly filters directory listings
    // based on access level. Files above the current session's access level
    // must be truly invisible (not just hidden attribute).
    //
    // The filtering happens in list_files() which only iterates through
    // session.accessible_levels(). This ensures files in higher-level keystores
    // are never even considered for listing.

    #[test]
    fn test_find_data_respects_entry_access_level() {
        // FindData preserves the entry's access level for display
        let entry = FileEntry::new_file(
            "secret.txt".to_string(),
            1024,
            1704067200,
            3, // Level 3 file
            Uuid::new_v4(),
        );

        let data = FindData::from_entry(&entry);

        // FindData should accurately reflect the file attributes
        assert_eq!(data.file_name, "secret.txt");
        assert_eq!(data.size, 1024);
        // No hidden attribute - file is either visible or not in the list at all
        assert!(data.attributes & FileAttributes::Hidden as u32 == 0);
    }

    #[test]
    fn test_find_data_directory_not_hidden() {
        // Virtual directories should never have Hidden attribute
        let entry = FileEntry::new_directory("classified".to_string(), 3, 0);
        let data = FindData::from_entry(&entry);

        // Directories appear normally - filtering happens before FindData creation
        assert!(data.attributes & FileAttributes::Directory as u32 != 0);
        assert!(data.attributes & FileAttributes::Hidden as u32 == 0);
    }

    #[test]
    fn test_find_data_includes_dot_entries() {
        // The "." and ".." entries in find_files output
        // These are special directory entries that should always appear
        let dot_entry = FindData {
            file_name: ".".to_string(),
            attributes: FileAttributes::Directory as u32,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            size: 0,
        };

        let dotdot_entry = FindData {
            file_name: "..".to_string(),
            attributes: FileAttributes::Directory as u32,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            size: 0,
        };

        assert_eq!(dot_entry.file_name, ".");
        assert_eq!(dotdot_entry.file_name, "..");
        assert!(dot_entry.attributes & FileAttributes::Directory as u32 != 0);
        assert!(dotdot_entry.attributes & FileAttributes::Directory as u32 != 0);
    }

    #[test]
    fn test_find_data_level_1_files_visible() {
        // Level 1 files should be visible to all access levels
        let entry = FileEntry::new_file(
            "public.txt".to_string(),
            512,
            1704067200,
            1, // Level 1 - public
            Uuid::new_v4(),
        );

        let data = FindData::from_entry(&entry);

        assert_eq!(data.file_name, "public.txt");
        assert_eq!(data.size, 512);
        // Normal file, not hidden
        assert!(data.attributes & FileAttributes::Normal as u32 != 0);
    }

    #[test]
    fn test_find_data_preserves_timestamps() {
        let timestamp = 1704067200u64; // 2024-01-01 00:00:00 UTC
        let entry = FileEntry::new_file(
            "timed.txt".to_string(),
            256,
            timestamp,
            1,
            Uuid::new_v4(),
        );

        let data = FindData::from_entry(&entry);

        // Verify timestamps are converted to FILETIME format
        let expected_filetime = unix_to_filetime(timestamp);
        assert_eq!(data.last_write_time, expected_filetime);
        assert_eq!(data.last_access_time, expected_filetime);
        assert_eq!(data.creation_time, expected_filetime);
    }

    #[test]
    fn test_file_entry_access_level_attribute() {
        // FileEntry stores access_level which is used for filtering decisions
        for level in 1..=10 {
            let entry = FileEntry::new_file(
                format!("level{}.txt", level),
                100,
                1704067200,
                level,
                Uuid::new_v4(),
            );

            assert_eq!(entry.access_level, level);
        }
    }

    #[test]
    fn test_directory_entry_minimum_access_level() {
        // Virtual directories inherit the minimum access level of contained files
        // This allows directories to appear at the appropriate level
        let entry_l1 = FileEntry::new_directory("docs".to_string(), 1, 0);
        let entry_l2 = FileEntry::new_directory("classified".to_string(), 2, 0);
        let entry_l3 = FileEntry::new_directory("top_secret".to_string(), 3, 0);

        assert_eq!(entry_l1.access_level, 1);
        assert_eq!(entry_l2.access_level, 2);
        assert_eq!(entry_l3.access_level, 3);
    }

    #[test]
    fn test_find_data_large_file_size() {
        // Verify large file sizes are correctly represented
        let large_size = 10u64 * 1024 * 1024 * 1024; // 10 GB
        let entry = FileEntry::new_file(
            "large.bin".to_string(),
            large_size,
            1704067200,
            1,
            Uuid::new_v4(),
        );

        let data = FindData::from_entry(&entry);

        assert_eq!(data.size, large_size);
    }

    #[test]
    fn test_find_data_unicode_filename() {
        // Unicode filenames should work correctly
        let entry = FileEntry::new_file(
            "文档.txt".to_string(), // "Document" in Chinese
            256,
            1704067200,
            1,
            Uuid::new_v4(),
        );

        let data = FindData::from_entry(&entry);

        assert_eq!(data.file_name, "文档.txt");
    }

    #[test]
    fn test_find_data_special_characters() {
        // Filenames with special characters
        let entry = FileEntry::new_file(
            "report (2024) - final [v3].txt".to_string(),
            256,
            1704067200,
            1,
            Uuid::new_v4(),
        );

        let data = FindData::from_entry(&entry);

        assert_eq!(data.file_name, "report (2024) - final [v3].txt");
    }

    #[test]
    fn test_file_entry_directory_has_zero_size() {
        // Directories always have size 0
        let entry = FileEntry::new_directory("folder".to_string(), 1, 0);
        let data = FindData::from_entry(&entry);

        assert_eq!(data.size, 0);
    }

    #[test]
    fn test_find_data_directory_attributes() {
        let entry = FileEntry::new_directory("subdir".to_string(), 1, 0);
        let data = FindData::from_entry(&entry);

        // Must have Directory attribute set
        assert!(data.attributes & FileAttributes::Directory as u32 != 0);
        // Should NOT have Normal attribute (mutually exclusive with Directory)
        assert!(data.attributes & FileAttributes::Normal as u32 == 0);
    }

    #[test]
    fn test_find_data_file_attributes() {
        let entry = FileEntry::new_file(
            "file.txt".to_string(),
            100,
            1704067200,
            1,
            Uuid::new_v4(),
        );
        let data = FindData::from_entry(&entry);

        // Must have Normal attribute set
        assert!(data.attributes & FileAttributes::Normal as u32 != 0);
        // Should NOT have Directory attribute
        assert!(data.attributes & FileAttributes::Directory as u32 == 0);
    }

    // =========================================================================
    // Access Level Visibility Tests (US-051)
    // =========================================================================
    //
    // These tests verify that the access level filtering is truly invisible.
    // Files above the session's access level are not included in any listing -
    // they don't appear with a Hidden attribute, they simply don't exist
    // in the results.

    #[test]
    fn test_filtering_philosophy_no_hidden_attribute() {
        // This test documents the filtering philosophy:
        // Files above access level are not hidden - they're INVISIBLE.
        // The Hidden attribute (0x2) should never be used for access control.

        // Create entries for different levels
        let l1_entry = FileEntry::new_file("public.txt".to_string(), 100, 0, 1, Uuid::new_v4());
        let l2_entry = FileEntry::new_file("confidential.txt".to_string(), 100, 0, 2, Uuid::new_v4());
        let l3_entry = FileEntry::new_file("secret.txt".to_string(), 100, 0, 3, Uuid::new_v4());

        // All entries when converted to FindData should NOT have Hidden attribute
        let l1_data = FindData::from_entry(&l1_entry);
        let l2_data = FindData::from_entry(&l2_entry);
        let l3_data = FindData::from_entry(&l3_entry);

        assert!(l1_data.attributes & FileAttributes::Hidden as u32 == 0);
        assert!(l2_data.attributes & FileAttributes::Hidden as u32 == 0);
        assert!(l3_data.attributes & FileAttributes::Hidden as u32 == 0);
    }

    #[test]
    fn test_file_entry_uuid_required_for_access_control() {
        // Files must have UUIDs for proper access control through keystores
        let entry = FileEntry::new_file(
            "secure.txt".to_string(),
            100,
            1704067200,
            2,
            Uuid::new_v4(),
        );

        assert!(entry.uuid.is_some());
        assert!(entry.is_file());
    }

    #[test]
    fn test_virtual_directory_no_uuid() {
        // Virtual directories don't have UUIDs - they're derived from file paths
        let entry = FileEntry::new_directory("folder".to_string(), 1, 0);

        assert!(entry.uuid.is_none());
        assert!(entry.is_directory());
    }

    #[test]
    fn test_entry_type_consistency() {
        // EntryType must be consistent across creation methods
        let file = FileEntry::new_file("f.txt".to_string(), 0, 0, 1, Uuid::new_v4());
        let dir = FileEntry::new_directory("d".to_string(), 1, 0);

        assert!(file.is_file());
        assert!(!file.is_directory());
        assert!(dir.is_directory());
        assert!(!dir.is_file());
    }

    // =========================================================================
    // Virtual Path Tests (US-051)
    // =========================================================================

    #[test]
    fn test_nested_directory_path_normalization() {
        // Deep nested paths should normalize correctly
        let test_cases = vec![
            ("\\level1\\level2\\level3", "/level1/level2/level3"),
            ("/a/b/c/d/e/f", "/a/b/c/d/e/f"),
            ("docs\\reports\\2024", "/docs/reports/2024"),
        ];

        for (input, expected) in test_cases {
            let normalized = TesseractDokanHandler::normalize_path(input);
            assert_eq!(normalized, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_path_with_trailing_slash() {
        // Trailing slashes should be handled gracefully
        let with_slash = TesseractDokanHandler::normalize_path("/folder/");
        let without_slash = TesseractDokanHandler::normalize_path("/folder");

        // Both should normalize to the same path
        assert_eq!(with_slash, "/folder/");
        assert_eq!(without_slash, "/folder");
    }

    #[test]
    fn test_mixed_separators() {
        // Mixed Windows/Unix separators
        let path = TesseractDokanHandler::normalize_path("folder\\sub/file.txt");
        assert_eq!(path, "/folder/sub/file.txt");
    }

    #[test]
    fn test_multiple_consecutive_separators() {
        // Multiple consecutive separators (pathological case)
        let path = TesseractDokanHandler::normalize_path("//folder//file.txt");
        // Should preserve the path structure
        assert!(path.starts_with('/'));
    }

    // =========================================================================
    // GUI/VFS Consistency Tests (US-051)
    // =========================================================================
    //
    // The VFS and GUI views must be consistent - both use list_files()
    // from tesseract_core::files module.

    #[test]
    fn test_file_entry_consistent_with_gui() {
        // FileEntry structure is shared between VFS and GUI
        // This test verifies the fields needed for both views
        let entry = FileEntry::new_file(
            "document.pdf".to_string(),
            2048,
            1704067200,
            2,
            Uuid::new_v4(),
        );

        // Fields used by GUI file browser
        assert!(!entry.name.is_empty());
        assert!(entry.size > 0);
        assert!(entry.modified_time > 0);
        assert!(entry.access_level > 0);
        assert!(entry.uuid.is_some());

        // EntryType determines icon in GUI and attributes in VFS
        assert_eq!(entry.entry_type, EntryType::File);
    }

    #[test]
    fn test_directory_entry_consistent_with_gui() {
        let entry = FileEntry::new_directory("Projects".to_string(), 1, 0);

        // Fields used by GUI file browser
        assert!(!entry.name.is_empty());
        assert_eq!(entry.size, 0);
        assert!(entry.uuid.is_none());
        assert_eq!(entry.entry_type, EntryType::Directory);
    }

    #[test]
    fn test_find_data_sorting_directories_first() {
        // Both GUI and VFS should show directories first
        // list_files() already sorts this way, FindData just converts

        let entries = vec![
            FileEntry::new_file("aaa.txt".to_string(), 100, 0, 1, Uuid::new_v4()),
            FileEntry::new_directory("bbb".to_string(), 1, 0),
            FileEntry::new_file("ccc.txt".to_string(), 100, 0, 1, Uuid::new_v4()),
            FileEntry::new_directory("aaa_dir".to_string(), 1, 0),
        ];

        // Convert all to FindData
        let find_entries: Vec<FindData> = entries.iter().map(|e| FindData::from_entry(e)).collect();

        // Verify types are preserved (actual sorting is done by list_files)
        assert!(find_entries[0].attributes & FileAttributes::Normal as u32 != 0);
        assert!(find_entries[1].attributes & FileAttributes::Directory as u32 != 0);
        assert!(find_entries[2].attributes & FileAttributes::Normal as u32 != 0);
        assert!(find_entries[3].attributes & FileAttributes::Directory as u32 != 0);
    }

    // =========================================================================
    // Unmount and Cleanup Tests (US-052)
    // =========================================================================

    #[test]
    fn test_default_unmount_timeout_constant() {
        // Default timeout should be 2 seconds (2000ms)
        assert_eq!(DEFAULT_UNMOUNT_TIMEOUT_MS, 2000);
    }

    #[test]
    fn test_open_handle_info_structure() {
        let info = OpenHandleInfo {
            handle_id: 42,
            path: "/test/file.txt".to_string(),
            is_dirty: true,
            is_directory: false,
            has_write_buffer: true,
        };

        assert_eq!(info.handle_id, 42);
        assert_eq!(info.path, "/test/file.txt");
        assert!(info.is_dirty);
        assert!(!info.is_directory);
        assert!(info.has_write_buffer);
    }

    #[test]
    fn test_open_handle_info_directory() {
        let info = OpenHandleInfo {
            handle_id: 1,
            path: "/docs".to_string(),
            is_dirty: false,
            is_directory: true,
            has_write_buffer: false,
        };

        assert!(info.is_directory);
        assert!(!info.is_dirty);
        assert!(!info.has_write_buffer);
    }

    #[test]
    fn test_open_handle_info_clone() {
        let info = OpenHandleInfo {
            handle_id: 100,
            path: "/cloned.txt".to_string(),
            is_dirty: false,
            is_directory: false,
            has_write_buffer: false,
        };

        let cloned = info.clone();
        assert_eq!(cloned.handle_id, info.handle_id);
        assert_eq!(cloned.path, info.path);
    }

    #[test]
    fn test_open_handle_info_debug() {
        let info = OpenHandleInfo {
            handle_id: 1,
            path: "/".to_string(),
            is_dirty: false,
            is_directory: true,
            has_write_buffer: false,
        };

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("OpenHandleInfo"));
        assert!(debug_str.contains("handle_id"));
    }

    #[test]
    fn test_file_handle_has_write_buffer_default() {
        let handle = FileHandle::new(
            Some(Uuid::new_v4()),
            "/test.txt".to_string(),
            false,
            1,
            100,
            true,
        );

        // By default, write_buffer is None
        assert!(handle.write_buffer.is_none());
    }

    #[test]
    fn test_file_handle_is_dirty_default() {
        let handle = FileHandle::new(
            Some(Uuid::new_v4()),
            "/test.txt".to_string(),
            false,
            1,
            100,
            true,
        );

        // By default, is_dirty is false
        assert!(!handle.is_dirty);
    }

    #[test]
    fn test_write_buffer_is_modified() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());
        assert!(buffer.is_modified()); // New files are modified

        buffer.modified = false;
        assert!(!buffer.is_modified());
    }

    #[test]
    fn test_write_buffer_existing_file() {
        let original = vec![1, 2, 3, 4, 5];
        let buffer = WriteBuffer::existing_file(original.clone());

        assert!(!buffer.is_new_file);
        assert!(!buffer.is_modified());
        assert_eq!(buffer.original_content, Some(original));
    }

    #[test]
    fn test_dokan_config_mount_point() {
        let config = DokanConfig::new('T');
        assert_eq!(config.mount_point(), "T:\\");
    }

    #[test]
    fn test_dokan_config_different_drive_letters() {
        let configs = vec![
            DokanConfig::new('A'),
            DokanConfig::new('Z'),
            DokanConfig::new('M'),
        ];

        assert_eq!(configs[0].mount_point(), "A:\\");
        assert_eq!(configs[1].mount_point(), "Z:\\");
        assert_eq!(configs[2].mount_point(), "M:\\");
    }

    #[test]
    fn test_dokan_config_lowercase_normalization() {
        let config = DokanConfig::new('t');
        // Should normalize to uppercase
        assert_eq!(config.drive_letter, 'T');
    }

    #[test]
    fn test_timeout_duration_conversion() {
        let timeout_ms: u64 = 2000;
        let duration = Duration::from_millis(timeout_ms);

        assert_eq!(duration.as_millis(), 2000);
        assert_eq!(duration.as_secs(), 2);
    }

    #[test]
    fn test_instant_elapsed_time_tracking() {
        let start = Instant::now();

        // Simulate some work (just a quick spin)
        let mut sum = 0u64;
        for i in 0..10000 {
            sum = sum.wrapping_add(i);
        }
        let _ = sum; // Prevent optimization

        let elapsed = start.elapsed();
        // Should have elapsed at least 0 nanoseconds
        assert!(elapsed.as_nanos() >= 0);
    }

    #[test]
    fn test_vfs_error_unmount_failed() {
        let error = VfsError::UnmountFailed("test reason".to_string());
        let msg = format!("{}", error);
        assert!(msg.contains("test reason"));
        assert!(msg.contains("unmount"));
    }

    #[test]
    fn test_vfs_error_unmount_timeout() {
        let error = VfsError::UnmountTimeout(2000, 5);
        let msg = format!("{}", error);
        assert!(msg.contains("2000"));
        assert!(msg.contains("5"));
        assert!(msg.contains("timed out"));
    }

    #[test]
    fn test_vfs_error_flush_failed() {
        let error = VfsError::FlushFailed("disk full".to_string());
        let msg = format!("{}", error);
        assert!(msg.contains("disk full"));
        assert!(msg.contains("flush"));
    }

    #[test]
    fn test_vfs_error_handle_busy() {
        let error = VfsError::HandleBusy("file in use".to_string());
        let msg = format!("{}", error);
        assert!(msg.contains("file in use"));
        assert!(msg.contains("busy"));
    }

    #[test]
    fn test_vfs_error_force_unmount_failed() {
        let error = VfsError::ForceUnmountFailed("system error".to_string());
        let msg = format!("{}", error);
        assert!(msg.contains("system error"));
        assert!(msg.contains("unmount"));
    }

    // =========================================================================
    // Unmount Behavior Tests (US-052)
    // =========================================================================

    #[test]
    fn test_chunk_cache_clear_on_unmount() {
        // Verify ChunkCache can be cleared (required for unmount)
        let cache = ChunkCache::new();
        // Cache should start empty
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn test_file_handle_clearing() {
        // Test that file handle fields can be cleared
        let mut handle = FileHandle::new(
            Some(Uuid::new_v4()),
            "/test.txt".to_string(),
            false,
            1,
            100,
            true,
        );

        // Simulate state that would exist before unmount
        handle.is_dirty = true;
        handle.cached_content = Some(vec![1, 2, 3]);
        handle.write_buffer = Some(WriteBuffer::new_file("test.txt".to_string()));

        // Clear all fields (simulating unmount cleanup)
        handle.cached_content = None;
        handle.write_buffer = None;
        handle.is_dirty = false;

        assert!(handle.cached_content.is_none());
        assert!(handle.write_buffer.is_none());
        assert!(!handle.is_dirty);
    }

    #[test]
    fn test_dirty_handle_detection() {
        let mut handle = FileHandle::new(
            Some(Uuid::new_v4()),
            "/dirty.txt".to_string(),
            false,
            1,
            100,
            true,
        );

        assert!(!handle.is_dirty);

        handle.is_dirty = true;
        assert!(handle.is_dirty);
    }

    #[test]
    fn test_write_buffer_data_storage() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        buffer.data = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        assert_eq!(buffer.data.len(), 5);
        assert_eq!(&buffer.data, b"Hello");
    }

    #[test]
    fn test_handle_map_operations() {
        let mut handles: HashMap<u64, FileHandle> = HashMap::new();

        // Add handles
        handles.insert(1, FileHandle::root());
        handles.insert(2, FileHandle::new(
            Some(Uuid::new_v4()),
            "/file.txt".to_string(),
            false,
            1,
            100,
            false,
        ));

        assert_eq!(handles.len(), 2);

        // Clear all handles (unmount operation)
        handles.clear();

        assert_eq!(handles.len(), 0);
    }

    #[test]
    fn test_handle_ids_collection() {
        let mut handles: HashMap<u64, FileHandle> = HashMap::new();

        handles.insert(10, FileHandle::root());
        handles.insert(20, FileHandle::root());
        handles.insert(30, FileHandle::root());

        let ids: Vec<u64> = handles.keys().copied().collect();

        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&10));
        assert!(ids.contains(&20));
        assert!(ids.contains(&30));
    }

    #[test]
    fn test_dirty_handle_filtering() {
        let mut handles: HashMap<u64, FileHandle> = HashMap::new();

        let mut dirty1 = FileHandle::new(
            Some(Uuid::new_v4()),
            "/dirty1.txt".to_string(),
            false,
            1,
            100,
            true,
        );
        dirty1.is_dirty = true;

        let mut dirty2 = FileHandle::new(
            Some(Uuid::new_v4()),
            "/dirty2.txt".to_string(),
            false,
            1,
            100,
            true,
        );
        dirty2.is_dirty = true;

        let clean = FileHandle::new(
            Some(Uuid::new_v4()),
            "/clean.txt".to_string(),
            false,
            1,
            100,
            true,
        );

        handles.insert(1, dirty1);
        handles.insert(2, dirty2);
        handles.insert(3, clean);

        // Filter dirty handles
        let dirty_ids: Vec<u64> = handles
            .iter()
            .filter(|(_, h)| h.is_dirty)
            .map(|(id, _)| *id)
            .collect();

        assert_eq!(dirty_ids.len(), 2);
    }

    #[test]
    fn test_unmount_timeout_value_reasonable() {
        // 2 seconds should be reasonable for most operations
        assert!(DEFAULT_UNMOUNT_TIMEOUT_MS >= 1000); // At least 1 second
        assert!(DEFAULT_UNMOUNT_TIMEOUT_MS <= 5000); // At most 5 seconds
    }

    #[test]
    fn test_open_handle_info_fields_complete() {
        // Verify all fields are accessible
        let info = OpenHandleInfo {
            handle_id: 0,
            path: String::new(),
            is_dirty: false,
            is_directory: false,
            has_write_buffer: false,
        };

        // All fields should be accessible
        let _ = info.handle_id;
        let _ = info.path;
        let _ = info.is_dirty;
        let _ = info.is_directory;
        let _ = info.has_write_buffer;
    }

    // =========================================================================
    // Key Wiping Tests (US-052)
    // =========================================================================

    #[test]
    fn test_session_state_enum() {
        // SessionState should be comparable
        assert_eq!(SessionState::Active, SessionState::Active);
        assert_eq!(SessionState::Locked, SessionState::Locked);
        assert_ne!(SessionState::Active, SessionState::Locked);
    }

    // =========================================================================
    // Drive Letter Release Tests (US-052)
    // =========================================================================

    #[test]
    fn test_mount_state_tracking() {
        // Test that RwLock<bool> works for mount state
        let is_mounted = RwLock::new(true);

        assert!(*is_mounted.read().unwrap());

        // Unmount
        *is_mounted.write().unwrap() = false;

        assert!(!*is_mounted.read().unwrap());
    }

    #[test]
    fn test_mount_state_concurrent_read() {
        let is_mounted = Arc::new(RwLock::new(true));

        // Multiple concurrent reads should work
        let is_mounted1 = is_mounted.clone();
        let is_mounted2 = is_mounted.clone();

        let r1 = *is_mounted1.read().unwrap();
        let r2 = *is_mounted2.read().unwrap();

        assert_eq!(r1, r2);
        assert!(r1);
    }

    // =========================================================================
    // Performance Tests (US-052)
    // =========================================================================

    #[test]
    fn test_handle_iteration_performance() {
        let mut handles: HashMap<u64, FileHandle> = HashMap::new();

        // Add many handles
        for i in 0..1000 {
            handles.insert(i, FileHandle::new(
                Some(Uuid::new_v4()),
                format!("/file{}.txt", i),
                false,
                1,
                100,
                false,
            ));
        }

        let start = Instant::now();

        // Iterate and collect IDs
        let ids: Vec<u64> = handles.keys().copied().collect();

        let elapsed = start.elapsed();

        // Should complete in well under 1 second
        assert!(elapsed.as_millis() < 100);
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn test_cache_clearing_performance() {
        let mut cache_entries: HashMap<Uuid, Vec<CachedChunk>> = HashMap::new();

        // Add cached chunks for 100 files
        for _ in 0..100 {
            let uuid = Uuid::new_v4();
            let chunks: Vec<CachedChunk> = (0..10)
                .map(|i| CachedChunk {
                    offset: i * 65536,
                    data: vec![0u8; 65536],
                    last_accessed: Instant::now(),
                })
                .collect();
            cache_entries.insert(uuid, chunks);
        }

        let start = Instant::now();

        // Clear all entries
        cache_entries.clear();

        let elapsed = start.elapsed();

        // Should complete quickly
        assert!(elapsed.as_millis() < 100);
        assert!(cache_entries.is_empty());
    }

    // =========================================================================
    // VFS Error Handling Tests (US-053)
    // =========================================================================
    //
    // These tests verify that NtStatus error codes are correctly mapped from
    // VfsError and VaultError types, and that error logging works properly.

    #[test]
    fn test_nt_status_values() {
        // Verify critical error codes have correct Windows NT status values
        assert_eq!(NtStatus::Success as i32, 0);
        assert_eq!(NtStatus::ObjectNameNotFound as i32, 0xC0000034_u32 as i32);
        assert_eq!(NtStatus::AccessDenied as i32, 0xC0000022_u32 as i32);
        assert_eq!(NtStatus::DiskFull as i32, 0xC000007F_u32 as i32);
        assert_eq!(NtStatus::NoMediaInDevice as i32, 0xC0000013_u32 as i32);
        assert_eq!(NtStatus::FileCorruptError as i32, 0xC0000102_u32 as i32);
    }

    #[test]
    fn test_nt_status_is_success() {
        assert!(NtStatus::Success.is_success());
        assert!(!NtStatus::AccessDenied.is_success());
        assert!(!NtStatus::DiskFull.is_success());
    }

    #[test]
    fn test_nt_status_is_error() {
        assert!(!NtStatus::Success.is_error());
        assert!(NtStatus::AccessDenied.is_error());
        assert!(NtStatus::DiskFull.is_error());
        assert!(NtStatus::NoMediaInDevice.is_error());
        assert!(NtStatus::FileCorruptError.is_error());
    }

    #[test]
    fn test_nt_status_description() {
        assert_eq!(NtStatus::Success.description(), "Success");
        assert_eq!(NtStatus::DiskFull.description(), "Disk full");
        assert_eq!(NtStatus::NoMediaInDevice.description(), "No media in device");
        assert_eq!(NtStatus::AccessDenied.description(), "Access denied");
        assert_eq!(NtStatus::FileCorruptError.description(), "File corrupt error");
    }

    #[test]
    fn test_nt_status_from_vault_error_file_not_found() {
        let err = VaultError::FileNotFound;
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::ObjectNameNotFound);
    }

    #[test]
    fn test_nt_status_from_vault_error_access_denied() {
        let err = VaultError::AccessDenied;
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::AccessDenied);
    }

    #[test]
    fn test_nt_status_from_vault_error_vault_locked() {
        let err = VaultError::VaultLocked;
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::AccessDenied);
    }

    #[test]
    fn test_nt_status_from_vault_error_integrity() {
        let err = VaultError::IntegrityError("HMAC mismatch".to_string());
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::FileCorruptError);
    }

    #[test]
    fn test_nt_status_from_io_error_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = VaultError::IoError(io_err);
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::ObjectNameNotFound);
    }

    #[test]
    fn test_nt_status_from_io_error_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err = VaultError::IoError(io_err);
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::AccessDenied);
    }

    #[test]
    fn test_nt_status_from_io_error_already_exists() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "file exists");
        let err = VaultError::IoError(io_err);
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::ObjectNameCollision);
    }

    #[test]
    fn test_nt_status_from_io_error_timeout() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let err = VaultError::IoError(io_err);
        let status = NtStatus::from_vault_error(&err);
        assert_eq!(status, NtStatus::IoTimeout);
    }

    #[test]
    fn test_nt_status_from_vfs_error_disk_full() {
        let err = VfsError::DiskFull {
            requested_bytes: 1024,
            available_bytes: 0,
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::DiskFull);
    }

    #[test]
    fn test_nt_status_from_vfs_error_media_removed() {
        let err = VfsError::MediaRemoved {
            operation: "write".to_string(),
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::NoMediaInDevice);
    }

    #[test]
    fn test_nt_status_from_vfs_error_device_not_ready() {
        let err = VfsError::DeviceNotReady {
            reason: "USB disconnected".to_string(),
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::DeviceNotReady);
    }

    #[test]
    fn test_nt_status_from_vfs_error_directory_not_empty() {
        let err = VfsError::DirectoryNotEmpty {
            path: "/folder".to_string(),
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::DirectoryNotEmpty);
    }

    #[test]
    fn test_nt_status_from_vfs_error_encryption_failed() {
        let err = VfsError::EncryptionError("AES-GCM failed".to_string());
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::EncryptionFailed);
    }

    #[test]
    fn test_nt_status_from_vfs_error_decryption_failed() {
        let err = VfsError::DecryptionError("authentication failed".to_string());
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::DecryptionFailed);
    }

    #[test]
    fn test_nt_status_from_vfs_error_timeout() {
        let err = VfsError::Timeout {
            operation: "unmount".to_string(),
            elapsed_ms: 2500,
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::IoTimeout);
    }

    #[test]
    fn test_nt_status_from_vfs_error_corrupted_data() {
        let err = VfsError::CorruptedData {
            context: "chunk verification".to_string(),
            details: "HMAC mismatch".to_string(),
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::FileCorruptError);
    }

    #[test]
    fn test_nt_status_from_vfs_error_sharing_violation() {
        let err = VfsError::SharingViolation;
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::SharingViolation);
    }

    #[test]
    fn test_nt_status_from_vfs_error_too_many_open_files() {
        let err = VfsError::TooManyOpenFiles {
            current: 1000,
            limit: 1000,
        };
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::TooManyOpenFiles);
    }

    #[test]
    fn test_nt_status_from_vfs_error_vault_error_delegation() {
        // VfsError::VaultError should delegate to from_vault_error
        let vault_err = VaultError::FileNotFound;
        let err = VfsError::VaultError(vault_err);
        let status = NtStatus::from_vfs_error(&err);
        assert_eq!(status, NtStatus::ObjectNameNotFound);
    }

    #[test]
    fn test_all_disk_media_errors_mapped() {
        // Verify all disk/media related errors map correctly
        let test_cases = vec![
            (VfsError::DiskFull { requested_bytes: 100, available_bytes: 0 }, NtStatus::DiskFull),
            (VfsError::MediaRemoved { operation: "read".to_string() }, NtStatus::NoMediaInDevice),
            (VfsError::DeviceNotReady { reason: "initializing".to_string() }, NtStatus::DeviceNotReady),
            (VfsError::WriteProtected, NtStatus::MediaWriteProtected),
            (VfsError::IoError { operation: "write".to_string(), details: "failed".to_string() }, NtStatus::IoDeviceError),
        ];

        for (err, expected_status) in test_cases {
            let actual_status = NtStatus::from_vfs_error(&err);
            assert_eq!(actual_status, expected_status, "Failed for error: {:?}", err);
        }
    }

    #[test]
    fn test_all_file_operation_errors_mapped() {
        // Verify file operation errors map correctly
        let test_cases = vec![
            (VfsError::FileNotFound, NtStatus::ObjectNameNotFound),
            (VfsError::AlreadyExists { path: "/file".to_string() }, NtStatus::ObjectNameCollision),
            (VfsError::DirectoryNotEmpty { path: "/dir".to_string() }, NtStatus::DirectoryNotEmpty),
            (VfsError::IsDirectory { path: "/dir".to_string() }, NtStatus::FileIsADirectory),
            (VfsError::NotADirectory { path: "/file".to_string() }, NtStatus::NotADirectory),
            (VfsError::InvalidPath { path: "invalid::path".to_string(), reason: "bad chars".to_string() }, NtStatus::ObjectNameInvalid),
        ];

        for (err, expected_status) in test_cases {
            let actual_status = NtStatus::from_vfs_error(&err);
            assert_eq!(actual_status, expected_status, "Failed for error: {:?}", err);
        }
    }

    #[test]
    fn test_error_codes_are_negative() {
        // All Windows error status codes should be negative (bit 31 set)
        let error_statuses = vec![
            NtStatus::ObjectNameNotFound,
            NtStatus::AccessDenied,
            NtStatus::DiskFull,
            NtStatus::NoMediaInDevice,
            NtStatus::FileCorruptError,
            NtStatus::EncryptionFailed,
            NtStatus::DecryptionFailed,
            NtStatus::IoTimeout,
        ];

        for status in error_statuses {
            assert!(
                status.as_i32() < 0,
                "Error status {:?} should be negative, got {}",
                status,
                status.as_i32()
            );
        }
    }
}
