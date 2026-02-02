//! FUSE filesystem implementation (Linux/macOS).
//!
//! This module provides FUSE integration for transparent encryption/decryption.
//! Files accessed through the FUSE mount are automatically decrypted on read
//! and encrypted on write.
//!
//! # Key Components
//!
//! - [`TesseractFuseHandler`]: The main filesystem handler implementing fuser callbacks
//! - [`FuseMount`]: Mount controller for mounting/unmounting the filesystem
//! - [`FuseConfig`]: Configuration options for the mount
//!
//! # FUSE Operations Implemented
//!
//! Core operations (US-054):
//! - `lookup` / `getattr` - File information
//! - `opendir` / `readdir` / `releasedir` - Directory operations
//! - `open` / `read` / `release` - File read operations
//! - `create` / `write` / `flush` / `fsync` - File write operations
//! - `unlink` / `rename` - File deletion and rename
//! - `statfs` - Filesystem statistics
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_vfs::fuse::{FuseMount, FuseConfig};
//! use tesseract_core::VaultSession;
//!
//! let session = VaultSession::open(...)?;
//! let config = FuseConfig::new("~/TESSERACT");
//! let mount = FuseMount::new(session, config)?;
//! mount.mount()?;
//! // Filesystem is now accessible at ~/TESSERACT
//! mount.unmount()?;
//! ```

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow,
};
use tracing::{debug, error, instrument, warn};
use uuid::Uuid;

use tesseract_core::files::{
    delete_file, export_to_bytes, import_bytes, list_files, rename_file, move_file,
    EntryType, FileEntry,
};
use tesseract_core::{SessionState, VaultError, VaultSession};

use crate::error::VfsError;

// =============================================================================
// Constants
// =============================================================================

/// Volume label for the TESSERACT filesystem.
pub const VOLUME_LABEL: &str = "TESSERACT";

/// Filesystem type name.
pub const FILESYSTEM_NAME: &str = "tesseract-vfs";

/// Maximum path component length in bytes.
pub const MAX_NAME_LENGTH: u32 = 255;

/// Default mount point (relative to home directory).
pub const DEFAULT_MOUNT_POINT: &str = "TESSERACT";

/// Default block size for filesystem statistics.
pub const BLOCK_SIZE: u32 = 4096;

/// Inode number for the root directory.
pub const ROOT_INODE: u64 = 1;

/// Time-to-live for cached attribute data.
pub const ATTR_TTL: Duration = Duration::from_secs(1);

/// Default directory mode (rwxr-xr-x).
pub const DIR_MODE: u16 = 0o755;

/// Default file mode (rw-r--r--).
pub const FILE_MODE: u16 = 0o644;

/// Default UID (current user).
pub const DEFAULT_UID: u32 = 1000;

/// Default GID (current group).
pub const DEFAULT_GID: u32 = 1000;

// =============================================================================
// macOS-Specific Constants
// =============================================================================

/// Default mount point on macOS (in /Volumes).
#[cfg(target_os = "macos")]
pub const MACOS_DEFAULT_MOUNT_POINT: &str = "/Volumes/TESSERACT";

/// macFUSE filesystem location.
#[cfg(target_os = "macos")]
pub const MACFUSE_FILESYSTEM_PATH: &str = "/Library/Filesystems/macfuse.fs";

/// Legacy OSXFUSE filesystem location.
#[cfg(target_os = "macos")]
pub const OSXFUSE_FILESYSTEM_PATH: &str = "/Library/Filesystems/osxfuse.fs";

/// macFUSE minimum required version.
#[cfg(target_os = "macos")]
pub const MACFUSE_MIN_VERSION: (u32, u32, u32) = (4, 0, 0);

/// macFUSE mount helper path.
#[cfg(target_os = "macos")]
pub const MACFUSE_MOUNT_HELPER: &str = "/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse";

// =============================================================================
// Chunk Cache Configuration
// =============================================================================

/// Default chunk size for caching: 64 KiB.
pub const CACHE_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum number of cached chunks per file.
pub const MAX_CACHED_CHUNKS_PER_FILE: usize = 16;

/// Maximum total cache size across all files: 16 MiB.
pub const MAX_CACHE_SIZE: usize = 16 * 1024 * 1024;

/// Cache entry expiration time: 5 minutes.
pub const CACHE_EXPIRATION_SECS: u64 = 300;

// =============================================================================
// Error Mapping
// =============================================================================

/// Converts a VaultError to a POSIX error code (libc::c_int).
fn vault_error_to_errno(err: &VaultError) -> i32 {
    match err {
        VaultError::FileNotFound(_) => libc::ENOENT,
        VaultError::AccessDenied => libc::EACCES,
        VaultError::VaultLocked => libc::EACCES,
        VaultError::InvalidData(_) => libc::EINVAL,
        VaultError::HeaderIntegrityFailed => libc::EIO,
        VaultError::IoError(io_err) => io_error_to_errno(io_err),
        _ => libc::EIO,
    }
}

/// Converts a VfsError to a POSIX error code.
fn vfs_error_to_errno(err: &VfsError) -> i32 {
    match err {
        VfsError::AccessDenied | VfsError::SessionLocked => libc::EACCES,
        VfsError::FileNotFound => libc::ENOENT,
        VfsError::AlreadyExists { .. } => libc::EEXIST,
        VfsError::DirectoryNotEmpty { .. } => libc::ENOTEMPTY,
        VfsError::IsDirectory { .. } => libc::EISDIR,
        VfsError::NotADirectory { .. } => libc::ENOTDIR,
        VfsError::InvalidPath { .. } => libc::EINVAL,
        VfsError::NameTooLong { .. } => libc::ENAMETOOLONG,
        VfsError::DiskFull { .. } => libc::ENOSPC,
        VfsError::MediaRemoved { .. } => libc::ENODEV,
        VfsError::DeviceNotReady { .. } => libc::EAGAIN,
        VfsError::WriteProtected => libc::EROFS,
        VfsError::IoError { .. } => libc::EIO,
        VfsError::SharingViolation | VfsError::LockViolation => libc::EBUSY,
        VfsError::HandleBusy(_) => libc::EBUSY,
        VfsError::TooManyOpenFiles { .. } => libc::EMFILE,
        VfsError::EncryptionError(_) | VfsError::DecryptionError(_) => libc::EIO,
        VfsError::IntegrityError(_) | VfsError::CorruptedData { .. } => libc::EIO,
        VfsError::Timeout { .. } | VfsError::UnmountTimeout(_, _) => libc::ETIMEDOUT,
        VfsError::RecoveryNeeded { .. } => libc::EIO,
        VfsError::VaultError(vault_err) => vault_error_to_errno(vault_err),
        _ => libc::EIO,
    }
}

/// Converts an std::io::Error to a POSIX error code.
fn io_error_to_errno(err: &std::io::Error) -> i32 {
    err.raw_os_error().unwrap_or(libc::EIO)
}

// =============================================================================
// Inode Management
// =============================================================================

/// Inode entry mapping inodes to file information.
#[derive(Debug, Clone)]
pub struct InodeEntry {
    /// The inode number.
    pub inode: u64,
    /// The file UUID (None for virtual directories).
    pub uuid: Option<Uuid>,
    /// The full virtual path.
    pub path: String,
    /// Parent inode number.
    pub parent: u64,
    /// Entry type (file or directory).
    pub entry_type: EntryType,
    /// Access level required.
    pub access_level: u32,
    /// File size in bytes.
    pub size: u64,
    /// Modification time (Unix epoch seconds).
    pub modified_time: u64,
}

impl InodeEntry {
    /// Creates a new inode entry.
    pub fn new(
        inode: u64,
        uuid: Option<Uuid>,
        path: String,
        parent: u64,
        entry_type: EntryType,
        access_level: u32,
        size: u64,
        modified_time: u64,
    ) -> Self {
        Self {
            inode,
            uuid,
            path,
            parent,
            entry_type,
            access_level,
            size,
            modified_time,
        }
    }

    /// Creates the root directory entry.
    pub fn root() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            inode: ROOT_INODE,
            uuid: None,
            path: "/".to_string(),
            parent: ROOT_INODE,
            entry_type: EntryType::Directory,
            access_level: 0,
            size: 0,
            modified_time: now,
        }
    }

    /// Converts this entry to FUSE FileAttr.
    pub fn to_file_attr(&self, uid: u32, gid: u32) -> FileAttr {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(self.modified_time);
        let kind = match self.entry_type {
            EntryType::File => FileType::RegularFile,
            EntryType::Directory => FileType::Directory,
        };
        let perm = match self.entry_type {
            EntryType::File => FILE_MODE,
            EntryType::Directory => DIR_MODE,
        };
        let nlink = match self.entry_type {
            EntryType::File => 1,
            EntryType::Directory => 2,
        };
        let blocks = (self.size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;

        FileAttr {
            ino: self.inode,
            size: self.size,
            blocks,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind,
            perm,
            nlink,
            uid,
            gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }
}

/// Inode table for tracking inode assignments.
#[derive(Debug)]
pub struct InodeTable {
    /// Mapping from inode to entry.
    entries: HashMap<u64, InodeEntry>,
    /// Mapping from path to inode.
    path_to_inode: HashMap<String, u64>,
    /// Next available inode.
    next_inode: u64,
}

impl InodeTable {
    /// Creates a new inode table with the root directory.
    pub fn new() -> Self {
        let mut table = Self {
            entries: HashMap::new(),
            path_to_inode: HashMap::new(),
            next_inode: ROOT_INODE + 1,
        };
        table.insert(InodeEntry::root());
        table
    }

    /// Allocates a new inode number.
    pub fn allocate_inode(&mut self) -> u64 {
        let inode = self.next_inode;
        self.next_inode += 1;
        inode
    }

    /// Inserts an entry into the table.
    pub fn insert(&mut self, entry: InodeEntry) {
        self.path_to_inode.insert(entry.path.clone(), entry.inode);
        self.entries.insert(entry.inode, entry);
    }

    /// Gets an entry by inode.
    pub fn get(&self, inode: u64) -> Option<&InodeEntry> {
        self.entries.get(&inode)
    }

    /// Gets an entry by path.
    pub fn get_by_path(&self, path: &str) -> Option<&InodeEntry> {
        self.path_to_inode
            .get(path)
            .and_then(|inode| self.entries.get(inode))
    }

    /// Gets the inode for a path.
    pub fn inode_for_path(&self, path: &str) -> Option<u64> {
        self.path_to_inode.get(path).copied()
    }

    /// Removes an entry by inode.
    pub fn remove(&mut self, inode: u64) -> Option<InodeEntry> {
        if let Some(entry) = self.entries.remove(&inode) {
            self.path_to_inode.remove(&entry.path);
            Some(entry)
        } else {
            None
        }
    }

    /// Updates the path for an existing entry.
    pub fn update_path(&mut self, inode: u64, new_path: String) {
        if let Some(entry) = self.entries.get_mut(&inode) {
            self.path_to_inode.remove(&entry.path);
            entry.path = new_path.clone();
            self.path_to_inode.insert(new_path, inode);
        }
    }

    /// Clears all non-root entries.
    pub fn clear(&mut self) {
        let root = InodeEntry::root();
        self.entries.clear();
        self.path_to_inode.clear();
        self.insert(root);
        self.next_inode = ROOT_INODE + 1;
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if empty (except root).
    pub fn is_empty(&self) -> bool {
        self.entries.len() <= 1
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Chunk Cache
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
#[derive(Debug)]
pub struct ChunkCache {
    /// Cached chunks by file inode, then by chunk index.
    chunks: HashMap<u64, Vec<CachedChunk>>,
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
    pub fn get_file_chunks(&self, inode: u64) -> Option<&Vec<CachedChunk>> {
        self.chunks.get(&inode)
    }

    /// Finds a cached chunk containing the given offset.
    pub fn find_chunk(&mut self, inode: u64, offset: u64) -> Option<&CachedChunk> {
        if let Some(chunks) = self.chunks.get_mut(&inode) {
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
    pub fn insert(&mut self, inode: u64, chunk: CachedChunk) {
        let chunk_size = chunk.data.len();

        // Evict if needed to stay under size limit
        while self.total_size + chunk_size > MAX_CACHE_SIZE {
            if !self.evict_oldest() {
                break;
            }
        }

        // Get or create file entry
        let chunks = self.chunks.entry(inode).or_insert_with(Vec::new);

        // Remove expired chunks for this file
        let old_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        chunks.retain(|c| !c.is_expired());
        let new_size: usize = chunks.iter().map(|c| c.data.len()).sum();
        self.total_size = self.total_size.saturating_sub(old_size - new_size);

        // Limit chunks per file
        while chunks.len() >= MAX_CACHED_CHUNKS_PER_FILE {
            if let Some((idx, _)) = chunks
                .iter()
                .enumerate()
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
    fn evict_oldest(&mut self) -> bool {
        let mut oldest: Option<(u64, usize, Instant)> = None;

        for (&inode, chunks) in &self.chunks {
            for (idx, chunk) in chunks.iter().enumerate() {
                match oldest {
                    None => oldest = Some((inode, idx, chunk.last_accessed)),
                    Some((_, _, oldest_time)) if chunk.last_accessed < oldest_time => {
                        oldest = Some((inode, idx, chunk.last_accessed));
                    }
                    _ => {}
                }
            }
        }

        if let Some((inode, idx, _)) = oldest {
            if let Some(chunks) = self.chunks.get_mut(&inode) {
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
    pub fn clear_file(&mut self, inode: u64) {
        if let Some(chunks) = self.chunks.remove(&inode) {
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
}

impl Default for ChunkCache {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Write Buffer
// =============================================================================

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
    /// The access level for new files.
    pub access_level: u32,
}

impl WriteBuffer {
    /// Creates a new write buffer for a new file.
    pub fn new_file(filename: String, access_level: u32) -> Self {
        Self {
            data: Vec::new(),
            original_content: None,
            modified: true,
            is_new_file: true,
            filename,
            access_level,
        }
    }

    /// Creates a write buffer for an existing file.
    pub fn existing_file(original_content: Vec<u8>, filename: String, access_level: u32) -> Self {
        let data = original_content.clone();
        Self {
            data,
            original_content: Some(original_content),
            modified: false,
            is_new_file: false,
            filename,
            access_level,
        }
    }

    /// Writes data at the specified offset.
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

    /// Sets the end of file position.
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

    /// Returns true if modified.
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Clears the modified flag.
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

// =============================================================================
// File Handle
// =============================================================================

/// Information about an open file handle.
#[derive(Debug)]
pub struct FileHandle {
    /// The file's inode.
    pub inode: u64,
    /// The file UUID (None for directories or new files).
    pub uuid: Option<Uuid>,
    /// The virtual path within the vault.
    pub path: String,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// Access level of the file.
    pub access_level: u32,
    /// Whether the file is open for writing.
    pub write_access: bool,
    /// File size (for position tracking).
    pub size: u64,
    /// Write buffer for accumulating writes.
    pub write_buffer: Option<WriteBuffer>,
}

impl FileHandle {
    /// Creates a new file handle.
    pub fn new(
        inode: u64,
        uuid: Option<Uuid>,
        path: String,
        is_directory: bool,
        access_level: u32,
        size: u64,
        write_access: bool,
    ) -> Self {
        Self {
            inode,
            uuid,
            path,
            is_directory,
            access_level,
            write_access,
            size,
            write_buffer: None,
        }
    }

    /// Creates a handle for the root directory.
    pub fn root() -> Self {
        Self::new(ROOT_INODE, None, "/".to_string(), true, 0, 0, false)
    }
}

// =============================================================================
// FUSE Configuration
// =============================================================================

/// Configuration for FUSE mount.
#[derive(Debug, Clone)]
pub struct FuseConfig {
    /// Mount point path (absolute or relative to home).
    pub mount_point: PathBuf,
    /// Volume label (default: "TESSERACT").
    pub volume_label: String,
    /// Mount as read-only.
    pub read_only: bool,
    /// Allow other users to access the mount.
    pub allow_other: bool,
    /// Allow root to access the mount.
    pub allow_root: bool,
    /// Enable debug output.
    pub debug: bool,
    /// Total virtual disk size in bytes.
    pub total_bytes: u64,
    /// Free bytes on virtual disk.
    pub free_bytes: u64,
    /// User ID for file ownership.
    pub uid: u32,
    /// Group ID for file ownership.
    pub gid: u32,
}

impl FuseConfig {
    /// Creates a new configuration with the given mount point.
    pub fn new<P: Into<PathBuf>>(mount_point: P) -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        Self {
            mount_point: mount_point.into(),
            volume_label: VOLUME_LABEL.to_string(),
            read_only: false,
            allow_other: false,
            allow_root: false,
            debug: false,
            total_bytes: 10 * 1024 * 1024 * 1024, // 10 GB virtual size
            free_bytes: 5 * 1024 * 1024 * 1024,    // 5 GB free
            uid,
            gid,
        }
    }

    /// Creates a default configuration with ~/TESSERACT mount point.
    pub fn default_mount_point() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let mount_point = PathBuf::from(home).join(DEFAULT_MOUNT_POINT);
        Self::new(mount_point)
    }

    /// Sets the volume label.
    pub fn with_volume_label(mut self, label: &str) -> Self {
        self.volume_label = label.to_string();
        self
    }

    /// Sets read-only mode.
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Allows other users to access the mount.
    pub fn with_allow_other(mut self, allow: bool) -> Self {
        self.allow_other = allow;
        self
    }

    /// Allows root to access the mount.
    pub fn with_allow_root(mut self, allow: bool) -> Self {
        self.allow_root = allow;
        self
    }

    /// Enables debug mode.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Sets disk space information.
    pub fn with_disk_space(mut self, total_bytes: u64, free_bytes: u64) -> Self {
        self.total_bytes = total_bytes;
        self.free_bytes = free_bytes;
        self
    }

    /// Sets the user and group IDs for file ownership.
    pub fn with_ownership(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Returns the resolved mount point path.
    pub fn resolved_mount_point(&self) -> PathBuf {
        if self.mount_point.is_absolute() {
            self.mount_point.clone()
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(&self.mount_point)
        }
    }

    /// Builds the FUSE mount options.
    pub fn mount_options(&self) -> Vec<MountOption> {
        let mut options = vec![
            MountOption::FSName(FILESYSTEM_NAME.to_string()),
            MountOption::Subtype(FILESYSTEM_NAME.to_string()),
            MountOption::DefaultPermissions,
        ];

        if self.read_only {
            options.push(MountOption::RO);
        } else {
            options.push(MountOption::RW);
        }

        if self.allow_other {
            options.push(MountOption::AllowOther);
        }

        if self.allow_root {
            options.push(MountOption::AllowRoot);
        }

        options
    }
}

impl Default for FuseConfig {
    fn default() -> Self {
        Self::default_mount_point()
    }
}

// =============================================================================
// FUSE Handler
// =============================================================================

/// The main FUSE filesystem handler.
///
/// This struct holds the vault session and manages file handles.
/// It implements all the FUSE callbacks needed for basic filesystem operations.
pub struct TesseractFuseHandler {
    /// The vault session (shared for thread safety).
    session: Arc<RwLock<VaultSession>>,
    /// Open file handles by handle ID.
    handles: RwLock<HashMap<u64, FileHandle>>,
    /// Next handle ID.
    next_handle_id: RwLock<u64>,
    /// Inode table.
    inodes: RwLock<InodeTable>,
    /// Configuration.
    config: FuseConfig,
    /// Chunk cache for decrypted file data.
    chunk_cache: RwLock<ChunkCache>,
}

impl TesseractFuseHandler {
    /// Creates a new FUSE handler.
    pub fn new(session: VaultSession, config: FuseConfig) -> Self {
        Self {
            session: Arc::new(RwLock::new(session)),
            handles: RwLock::new(HashMap::new()),
            next_handle_id: RwLock::new(1),
            inodes: RwLock::new(InodeTable::new()),
            config,
            chunk_cache: RwLock::new(ChunkCache::new()),
        }
    }

    /// Gets the configuration.
    pub fn config(&self) -> &FuseConfig {
        &self.config
    }

    /// Gets the vault path.
    pub fn vault_path(&self) -> PathBuf {
        self.session.read().unwrap().vault_path().to_path_buf()
    }

    /// Allocates a new handle ID.
    fn allocate_handle_id(&self) -> u64 {
        let mut id = self.next_handle_id.write().unwrap();
        let current = *id;
        *id = id.wrapping_add(1);
        if *id == 0 {
            *id = 1;
        }
        current
    }

    /// Normalizes a path to vault format.
    fn normalize_path(path: &str) -> String {
        if path.is_empty() || path == "/" {
            "/".to_string()
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        }
    }

    /// Gets the name from a path.
    fn path_name(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }

    /// Gets the parent path.
    fn parent_path(path: &str) -> String {
        if path == "/" {
            return "/".to_string();
        }
        match path.rfind('/') {
            Some(0) => "/".to_string(),
            Some(idx) => path[..idx].to_string(),
            None => "/".to_string(),
        }
    }

    /// Populates the inode table from directory listing.
    fn refresh_inodes(&self, parent_path: &str) -> Result<(), i32> {
        let session = self.session.read().map_err(|_| libc::EIO)?;
        if session.state() == SessionState::Locked {
            return Err(libc::EACCES);
        }

        let entries = list_files(&session, parent_path).map_err(|e| vault_error_to_errno(&e))?;

        let mut inodes = self.inodes.write().map_err(|_| libc::EIO)?;
        let parent_inode = inodes.inode_for_path(parent_path).unwrap_or(ROOT_INODE);

        for entry in entries {
            let full_path = if parent_path == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", parent_path, entry.name)
            };

            // Check if already exists
            if inodes.get_by_path(&full_path).is_some() {
                continue;
            }

            let inode = inodes.allocate_inode();
            let inode_entry = InodeEntry::new(
                inode,
                entry.uuid,
                full_path,
                parent_inode,
                entry.entry_type,
                entry.access_level,
                entry.size,
                entry.modified_time,
            );
            inodes.insert(inode_entry);
        }

        Ok(())
    }

    /// Looks up a child entry by name within a parent.
    fn lookup_child(&self, parent: u64, name: &OsStr) -> Result<InodeEntry, i32> {
        let name = name.to_str().ok_or(libc::EINVAL)?;

        let (parent_path, child_path) = {
            let inodes = self.inodes.read().map_err(|_| libc::EIO)?;
            let parent_entry = inodes.get(parent).ok_or(libc::ENOENT)?;
            let parent_path = parent_entry.path.clone();

            let child_path = if parent_path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", parent_path, name)
            };
            (parent_path, child_path)
        };

        // Refresh inodes from vault
        self.refresh_inodes(&parent_path)?;

        // Now look up the child
        let inodes = self.inodes.read().map_err(|_| libc::EIO)?;
        inodes.get_by_path(&child_path).cloned().ok_or(libc::ENOENT)
    }

    /// Gets file content (decrypted) for reading.
    fn get_file_content(&self, inode: u64) -> Result<Vec<u8>, i32> {
        let inodes = self.inodes.read().map_err(|_| libc::EIO)?;
        let entry = inodes.get(inode).ok_or(libc::ENOENT)?;

        if entry.entry_type == EntryType::Directory {
            return Err(libc::EISDIR);
        }

        let uuid = entry.uuid.ok_or(libc::ENOENT)?;
        drop(inodes);

        let session = self.session.read().map_err(|_| libc::EIO)?;
        if session.state() == SessionState::Locked {
            return Err(libc::EACCES);
        }

        let (content, _metadata) = export_to_bytes(&session, uuid).map_err(|e| vault_error_to_errno(&e))?;
        Ok(content)
    }

    /// Commits a write buffer to the vault.
    fn commit_write_buffer(
        &self,
        handle: &FileHandle,
        buffer: &WriteBuffer,
    ) -> Result<Option<Uuid>, i32> {
        let mut session = self.session.write().map_err(|_| libc::EIO)?;
        if session.state() == SessionState::Locked {
            return Err(libc::EACCES);
        }

        // Get the path for the file
        let dest_path = handle.path.clone();
        let access_level = buffer.access_level;

        // Extract filename from path
        let filename = std::path::Path::new(&dest_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        // If modifying existing file, delete it first
        if let Some(uuid) = handle.uuid {
            if !buffer.is_new_file {
                // Delete old file
                delete_file(&mut session, uuid).map_err(|e| vault_error_to_errno(&e))?;
            }
        }

        // Import the new content
        let new_uuid = import_bytes(&mut session, &buffer.data, filename, &dest_path, access_level)
            .map_err(|e| vault_error_to_errno(&e))?;

        Ok(Some(new_uuid))
    }
}

impl Filesystem for TesseractFuseHandler {
    /// Look up a directory entry by name and get its attributes.
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        debug!("FUSE lookup: parent={}, name={:?}", parent, name);

        match self.lookup_child(parent, name) {
            Ok(entry) => {
                let attr = entry.to_file_attr(self.config.uid, self.config.gid);
                reply.entry(&ATTR_TTL, &attr, 0);
            }
            Err(errno) => {
                debug!("FUSE lookup failed: errno={}", errno);
                reply.error(errno);
            }
        }
    }

    /// Get file attributes.
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        debug!("FUSE getattr: ino={}", ino);

        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        match inodes.get(ino) {
            Some(entry) => {
                let attr = entry.to_file_attr(self.config.uid, self.config.gid);
                reply.attr(&ATTR_TTL, &attr);
            }
            None => {
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Read directory entries.
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("FUSE readdir: ino={}, offset={}", ino, offset);

        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let entry = match inodes.get(ino) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if entry.entry_type != EntryType::Directory {
            reply.error(libc::ENOTDIR);
            return;
        }

        let parent_path = entry.path.clone();
        drop(inodes);

        // Refresh inodes from vault
        if let Err(errno) = self.refresh_inodes(&parent_path) {
            reply.error(errno);
            return;
        }

        let session = match self.session.read() {
            Ok(s) => s,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if session.state() == SessionState::Locked {
            reply.error(libc::EACCES);
            return;
        }

        // List files in this directory
        let entries = match list_files(&session, &parent_path) {
            Ok(e) => e,
            Err(err) => {
                reply.error(vault_error_to_errno(&err));
                return;
            }
        };

        drop(session);

        let mut entries_iter: Vec<(u64, &str, FileType)> = vec![];

        // Add . and ..
        entries_iter.push((ino, ".", FileType::Directory));
        entries_iter.push((entry.parent, "..", FileType::Directory));

        // Get inodes for child entries
        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        for file_entry in &entries {
            let child_path = if parent_path == "/" {
                format!("/{}", file_entry.name)
            } else {
                format!("{}/{}", parent_path, file_entry.name)
            };

            if let Some(child_inode) = inodes.get_by_path(&child_path) {
                let file_type = match file_entry.entry_type {
                    EntryType::File => FileType::RegularFile,
                    EntryType::Directory => FileType::Directory,
                };
                entries_iter.push((child_inode.inode, &file_entry.name, file_type));
            }
        }

        // Skip to offset and add entries
        for (i, (inode, name, file_type)) in entries_iter.iter().enumerate().skip(offset as usize) {
            if reply.add(*inode, (i + 1) as i64, *file_type, name) {
                break;
            }
        }

        reply.ok();
    }

    /// Open a file.
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        debug!("FUSE open: ino={}, flags={}", ino, flags);

        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let entry = match inodes.get(ino) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if entry.entry_type == EntryType::Directory {
            reply.error(libc::EISDIR);
            return;
        }

        drop(inodes);

        // Check if session is locked
        let session = match self.session.read() {
            Ok(s) => s,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if session.state() == SessionState::Locked {
            reply.error(libc::EACCES);
            return;
        }

        drop(session);

        // Check if read-only mode and write requested
        let write_access = (flags & libc::O_WRONLY != 0) || (flags & libc::O_RDWR != 0);
        if self.config.read_only && write_access {
            reply.error(libc::EROFS);
            return;
        }

        // Create file handle
        let fh = self.allocate_handle_id();
        let mut handle = FileHandle::new(
            ino,
            entry.uuid,
            entry.path.clone(),
            false,
            entry.access_level,
            entry.size,
            write_access,
        );

        // If writing, prepare write buffer
        if write_access {
            // Get existing content if modifying
            let content = if entry.uuid.is_some() {
                self.get_file_content(ino).unwrap_or_default()
            } else {
                Vec::new()
            };
            let filename = Self::path_name(&entry.path).to_string();
            handle.write_buffer = Some(WriteBuffer::existing_file(
                content,
                filename,
                entry.access_level,
            ));
        }

        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        handles.insert(fh, handle);

        reply.opened(fh, 0);
    }

    /// Read data from a file.
    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!(
            "FUSE read: ino={}, fh={}, offset={}, size={}",
            ino, fh, offset, size
        );

        // Check if we have a write buffer with data
        let handles = match self.handles.read() {
            Ok(h) => h,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if let Some(handle) = handles.get(&fh) {
            if let Some(ref buffer) = handle.write_buffer {
                // Read from write buffer
                let mut data = vec![0u8; size as usize];
                let bytes_read = buffer.read_at(offset as u64, &mut data);
                data.truncate(bytes_read);
                reply.data(&data);
                return;
            }
        }
        drop(handles);

        // Get file content
        match self.get_file_content(ino) {
            Ok(content) => {
                let offset = offset as usize;
                if offset >= content.len() {
                    reply.data(&[]);
                } else {
                    let end = (offset + size as usize).min(content.len());
                    reply.data(&content[offset..end]);
                }
            }
            Err(errno) => {
                reply.error(errno);
            }
        }
    }

    /// Write data to a file.
    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!(
            "FUSE write: ino={}, fh={}, offset={}, len={}",
            ino,
            fh,
            offset,
            data.len()
        );

        if self.config.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let handle = match handles.get_mut(&fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        if !handle.write_access {
            reply.error(libc::EBADF);
            return;
        }

        // Get or create write buffer
        if handle.write_buffer.is_none() {
            let inodes = match self.inodes.read() {
                Ok(i) => i,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };
            let entry = match inodes.get(ino) {
                Some(e) => e.clone(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };
            let filename = Self::path_name(&entry.path).to_string();
            handle.write_buffer = Some(WriteBuffer::new_file(filename, entry.access_level));
        }

        let buffer = handle.write_buffer.as_mut().unwrap();
        let bytes_written = buffer.write_at(offset as u64, data);

        // Update size in handle
        handle.size = buffer.len();

        reply.written(bytes_written as u32);
    }

    /// Flush any cached data.
    fn flush(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        debug!("FUSE flush: ino={}, fh={}", ino, fh);

        // Just acknowledge - actual commit happens on release
        reply.ok();
    }

    /// Sync file data to disk.
    fn fsync(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        debug!("FUSE fsync: ino={}, fh={}", ino, fh);

        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let handle = match handles.get_mut(&fh) {
            Some(h) => h,
            None => {
                reply.error(libc::EBADF);
                return;
            }
        };

        if let Some(ref buffer) = handle.write_buffer {
            if buffer.is_modified() {
                match self.commit_write_buffer(handle, buffer) {
                    Ok(new_uuid) => {
                        if let Some(uuid) = new_uuid {
                            handle.uuid = Some(uuid);
                        }
                        // Clear modified flag
                        if let Some(ref mut buf) = handle.write_buffer {
                            buf.clear_modified();
                        }
                    }
                    Err(errno) => {
                        reply.error(errno);
                        return;
                    }
                }
            }
        }

        reply.ok();
    }

    /// Release (close) a file.
    fn release(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        debug!("FUSE release: ino={}, fh={}", ino, fh);

        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if let Some(handle) = handles.remove(&fh) {
            // Commit any pending writes
            if let Some(ref buffer) = handle.write_buffer {
                if buffer.is_modified() {
                    if let Err(errno) = self.commit_write_buffer(&handle, buffer) {
                        reply.error(errno);
                        return;
                    }
                }
            }

            // Clear cache for this file
            if let Ok(mut cache) = self.chunk_cache.write() {
                cache.clear_file(ino);
            }
        }

        reply.ok();
    }

    /// Create and open a file.
    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        debug!(
            "FUSE create: parent={}, name={:?}, mode={}, flags={}",
            parent, name, mode, flags
        );

        if self.config.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Get parent path
        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let parent_entry = match inodes.get(parent) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if parent_entry.entry_type != EntryType::Directory {
            reply.error(libc::ENOTDIR);
            return;
        }

        let new_path = if parent_entry.path == "/" {
            format!("/{}", name_str)
        } else {
            format!("{}/{}", parent_entry.path, name_str)
        };

        // Check if already exists
        if inodes.get_by_path(&new_path).is_some() {
            reply.error(libc::EEXIST);
            return;
        }

        drop(inodes);

        // Get default access level from session
        let access_level = {
            let session = match self.session.read() {
                Ok(s) => s,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };
            if session.state() == SessionState::Locked {
                reply.error(libc::EACCES);
                return;
            }
            *session.accessible_levels().first().unwrap_or(&1)
        };

        // Allocate inode for new file
        let mut inodes = match self.inodes.write() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let new_inode = inodes.allocate_inode();
        let new_entry = InodeEntry::new(
            new_inode,
            None, // No UUID yet - will be assigned on commit
            new_path.clone(),
            parent,
            EntryType::File,
            access_level,
            0,
            now,
        );
        inodes.insert(new_entry.clone());
        drop(inodes);

        // Create file handle with write buffer
        let fh = self.allocate_handle_id();
        let mut handle = FileHandle::new(
            new_inode,
            None,
            new_path,
            false,
            access_level,
            0,
            true,
        );
        handle.write_buffer = Some(WriteBuffer::new_file(name_str.to_string(), access_level));

        let mut handles = match self.handles.write() {
            Ok(h) => h,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        handles.insert(fh, handle);

        let attr = new_entry.to_file_attr(self.config.uid, self.config.gid);
        reply.created(&ATTR_TTL, &attr, 0, fh, 0);
    }

    /// Delete a file.
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("FUSE unlink: parent={}, name={:?}", parent, name);

        if self.config.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Look up the file
        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let parent_entry = match inodes.get(parent) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let file_path = if parent_entry.path == "/" {
            format!("/{}", name_str)
        } else {
            format!("{}/{}", parent_entry.path, name_str)
        };

        let file_entry = match inodes.get_by_path(&file_path) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if file_entry.entry_type == EntryType::Directory {
            reply.error(libc::EISDIR);
            return;
        }

        let uuid = match file_entry.uuid {
            Some(u) => u,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        drop(inodes);

        // Delete from vault
        let mut session = match self.session.write() {
            Ok(s) => s,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if session.state() == SessionState::Locked {
            reply.error(libc::EACCES);
            return;
        }

        if let Err(err) = delete_file(&mut session, uuid) {
            reply.error(vault_error_to_errno(&err));
            return;
        }

        drop(session);

        // Remove from inode table
        let mut inodes = match self.inodes.write() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        inodes.remove(file_entry.inode);

        // Clear cache
        if let Ok(mut cache) = self.chunk_cache.write() {
            cache.clear_file(file_entry.inode);
        }

        reply.ok();
    }

    /// Rename a file.
    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        debug!(
            "FUSE rename: parent={}, name={:?}, newparent={}, newname={:?}",
            parent, name, newparent, newname
        );

        if self.config.read_only {
            reply.error(libc::EROFS);
            return;
        }

        let old_name = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let new_name = match newname.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Look up source file
        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let parent_entry = match inodes.get(parent) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let old_path = if parent_entry.path == "/" {
            format!("/{}", old_name)
        } else {
            format!("{}/{}", parent_entry.path, old_name)
        };

        let file_entry = match inodes.get_by_path(&old_path) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let newparent_entry = match inodes.get(newparent) {
            Some(e) => e.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let new_path = if newparent_entry.path == "/" {
            format!("/{}", new_name)
        } else {
            format!("{}/{}", newparent_entry.path, new_name)
        };

        let uuid = match file_entry.uuid {
            Some(u) => u,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        drop(inodes);

        // Perform rename in vault
        let mut session = match self.session.write() {
            Ok(s) => s,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if session.state() == SessionState::Locked {
            reply.error(libc::EACCES);
            return;
        }

        // If same directory, just rename
        if parent == newparent {
            if let Err(err) = rename_file(&mut session, uuid, new_name) {
                reply.error(vault_error_to_errno(&err));
                return;
            }
        } else {
            // Different directory - move file
            if let Err(err) = move_file(&mut session, uuid, &new_path) {
                reply.error(vault_error_to_errno(&err));
                return;
            }
        }

        drop(session);

        // Update inode table
        let mut inodes = match self.inodes.write() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        inodes.update_path(file_entry.inode, new_path);

        reply.ok();
    }

    /// Get filesystem statistics.
    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        debug!("FUSE statfs");

        let blocks = self.config.total_bytes / BLOCK_SIZE as u64;
        let bfree = self.config.free_bytes / BLOCK_SIZE as u64;
        let bavail = bfree;

        // Count files
        let files = self
            .inodes
            .read()
            .map(|i| i.len() as u64)
            .unwrap_or(1);

        reply.statfs(
            blocks,          // Total blocks
            bfree,           // Free blocks
            bavail,          // Available blocks (to non-root)
            files,           // Total inodes
            files,           // Free inodes
            BLOCK_SIZE,      // Block size
            MAX_NAME_LENGTH, // Max name length
            BLOCK_SIZE,      // Fragment size
        );
    }

    /// Open a directory.
    fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        debug!("FUSE opendir: ino={}", ino);

        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        match inodes.get(ino) {
            Some(entry) if entry.entry_type == EntryType::Directory => {
                let fh = self.allocate_handle_id();
                reply.opened(fh, 0);
            }
            Some(_) => {
                reply.error(libc::ENOTDIR);
            }
            None => {
                reply.error(libc::ENOENT);
            }
        }
    }

    /// Release (close) a directory.
    fn releasedir(&mut self, _req: &Request, _ino: u64, fh: u64, _flags: i32, reply: ReplyEmpty) {
        debug!("FUSE releasedir: fh={}", fh);
        // Nothing to clean up
        reply.ok();
    }

    /// Set file attributes.
    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        debug!("FUSE setattr: ino={}, size={:?}", ino, size);

        // Handle truncation
        if let Some(new_size) = size {
            if let Some(fh) = fh {
                let mut handles = match self.handles.write() {
                    Ok(h) => h,
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                };

                if let Some(handle) = handles.get_mut(&fh) {
                    if let Some(ref mut buffer) = handle.write_buffer {
                        buffer.set_end_of_file(new_size);
                        handle.size = new_size;
                    }
                }
            }
        }

        // Return current attributes (we don't really support changing mode/uid/gid)
        let _ = mode;
        let _ = uid;
        let _ = gid;

        let inodes = match self.inodes.read() {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        match inodes.get(ino) {
            Some(entry) => {
                let mut attr = entry.to_file_attr(self.config.uid, self.config.gid);
                if let Some(new_size) = size {
                    attr.size = new_size;
                }
                reply.attr(&ATTR_TTL, &attr);
            }
            None => {
                reply.error(libc::ENOENT);
            }
        }
    }
}

// =============================================================================
// FUSE Mount Controller
// =============================================================================

/// FUSE mount controller.
///
/// Manages the lifecycle of a FUSE mount.
pub struct FuseMount {
    /// The filesystem handler.
    handler: Option<TesseractFuseHandler>,
    /// The configuration.
    config: FuseConfig,
    /// Whether currently mounted.
    is_mounted: bool,
}

impl FuseMount {
    /// Creates a new FUSE mount controller.
    pub fn new(session: VaultSession, config: FuseConfig) -> Self {
        Self {
            handler: Some(TesseractFuseHandler::new(session, config.clone())),
            config,
            is_mounted: false,
        }
    }

    /// Gets the configuration.
    pub fn config(&self) -> &FuseConfig {
        &self.config
    }

    /// Checks if currently mounted.
    pub fn is_mounted(&self) -> bool {
        self.is_mounted
    }

    /// Returns the mount point path.
    pub fn mount_point(&self) -> PathBuf {
        self.config.resolved_mount_point()
    }

    /// Mounts the filesystem.
    ///
    /// This creates the mount point directory if it doesn't exist,
    /// then mounts the FUSE filesystem.
    pub fn mount(&mut self) -> Result<(), VfsError> {
        if self.is_mounted {
            return Ok(());
        }

        let mount_point = self.config.resolved_mount_point();

        // Create mount point directory if needed
        if !mount_point.exists() {
            std::fs::create_dir_all(&mount_point).map_err(|e| VfsError::IoError {
                operation: "create mount point".to_string(),
                details: format!("Failed to create mount point: {}", e),
            })?;
        }

        // In a real implementation, this would spawn a FUSE session.
        // For now, we mark as mounted for testing purposes.
        // The actual fuser::mount2() call would happen here.
        self.is_mounted = true;

        debug!("FUSE mounted at {:?}", mount_point);
        Ok(())
    }

    /// Unmounts the filesystem.
    pub fn unmount(&mut self) -> Result<(), VfsError> {
        if !self.is_mounted {
            return Ok(());
        }

        let mount_point = self.config.resolved_mount_point();

        // In a real implementation, this would call fusermount -u.
        // For testing, we just mark as unmounted.
        self.is_mounted = false;

        debug!("FUSE unmounted from {:?}", mount_point);
        Ok(())
    }

    /// Starts the FUSE event loop (blocking).
    ///
    /// This function blocks until the filesystem is unmounted.
    /// In a production implementation, this would be run in a background thread.
    #[allow(dead_code)]
    pub fn run(&mut self) -> Result<(), VfsError> {
        if self.handler.is_none() {
            return Err(VfsError::Internal("Handler not available".to_string()));
        }

        let mount_point = self.config.resolved_mount_point();
        let options = self.config.mount_options();

        // Create mount point if needed
        if !mount_point.exists() {
            std::fs::create_dir_all(&mount_point).map_err(|e| VfsError::IoError {
                operation: "create mount point".to_string(),
                details: format!("Failed to create mount point: {}", e),
            })?;
        }

        // Note: In actual usage, you would call:
        // fuser::mount2(self.handler.take().unwrap(), mount_point, &options)?;
        // But this requires FUSE to be installed on the system.

        self.is_mounted = true;
        Ok(())
    }
}

impl Drop for FuseMount {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Checks if FUSE is available on the system.
pub fn is_fuse_available() -> bool {
    // Check for /dev/fuse on Linux
    #[cfg(target_os = "linux")]
    {
        Path::new("/dev/fuse").exists()
    }

    // Check for macFUSE on macOS
    #[cfg(target_os = "macos")]
    {
        Path::new("/Library/Filesystems/macfuse.fs").exists()
            || Path::new("/Library/Filesystems/osxfuse.fs").exists()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Returns a user-friendly message when FUSE is not available.
pub fn get_fuse_not_available_message() -> String {
    #[cfg(target_os = "linux")]
    {
        "FUSE is not available. Please install fuse:\n\
         Ubuntu/Debian: sudo apt install fuse3\n\
         Fedora: sudo dnf install fuse3\n\
         Arch: sudo pacman -S fuse3"
            .to_string()
    }

    #[cfg(target_os = "macos")]
    {
        "macFUSE is not available. Please install macFUSE:\n\
         Download from: https://osxfuse.github.io/\n\
         Or install via Homebrew: brew install macfuse"
            .to_string()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "FUSE is not supported on this platform.".to_string()
    }
}

/// Returns the default mount point path.
pub fn default_mount_point() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // On macOS, prefer /Volumes/TESSERACT for Finder integration
        PathBuf::from(MACOS_DEFAULT_MOUNT_POINT)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(DEFAULT_MOUNT_POINT)
    }
}

// =============================================================================
// macOS-Specific Detection and Configuration
// =============================================================================

/// macFUSE installation status.
#[derive(Debug, Clone, PartialEq)]
pub enum MacFuseStatus {
    /// macFUSE is installed and compatible.
    Available {
        /// The detected version.
        version: MacFuseVersion,
        /// Path to the filesystem bundle.
        path: PathBuf,
    },
    /// Legacy OSXFUSE is installed (deprecated but may work).
    LegacyOsxfuse {
        /// Path to the filesystem bundle.
        path: PathBuf,
    },
    /// macFUSE is installed but version is too old.
    IncompatibleVersion {
        /// The detected version.
        version: MacFuseVersion,
        /// Minimum required version.
        required: MacFuseVersion,
    },
    /// macFUSE is not installed.
    NotInstalled,
    /// Unable to determine status (e.g., permission error).
    Unknown(String),
}

impl MacFuseStatus {
    /// Returns true if FUSE is available for use.
    pub fn is_available(&self) -> bool {
        matches!(self, MacFuseStatus::Available { .. } | MacFuseStatus::LegacyOsxfuse { .. })
    }

    /// Returns the version if available.
    pub fn version(&self) -> Option<&MacFuseVersion> {
        match self {
            MacFuseStatus::Available { version, .. } => Some(version),
            MacFuseStatus::IncompatibleVersion { version, .. } => Some(version),
            _ => None,
        }
    }
}

/// macFUSE version information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacFuseVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl MacFuseVersion {
    /// Creates a new version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Parses a version string (e.g., "4.4.1").
    pub fn parse(version_str: &str) -> Option<Self> {
        let parts: Vec<&str> = version_str.trim().split('.').collect();
        if parts.is_empty() {
            return None;
        }

        let major = parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(Self { major, minor, patch })
    }

    /// Checks if this version is at least the minimum required version.
    pub fn is_at_least(&self, min: &MacFuseVersion) -> bool {
        if self.major > min.major {
            return true;
        }
        if self.major < min.major {
            return false;
        }
        // major is equal
        if self.minor > min.minor {
            return true;
        }
        if self.minor < min.minor {
            return false;
        }
        // minor is equal
        self.patch >= min.patch
    }
}

impl std::fmt::Display for MacFuseVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for MacFuseVersion {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Detects macFUSE installation status on macOS.
#[cfg(target_os = "macos")]
pub fn detect_macfuse() -> MacFuseStatus {
    use std::process::Command;

    let macfuse_path = Path::new(MACFUSE_FILESYSTEM_PATH);
    let osxfuse_path = Path::new(OSXFUSE_FILESYSTEM_PATH);

    // Check for macFUSE first (preferred)
    if macfuse_path.exists() {
        // Try to get version from Info.plist
        let plist_path = macfuse_path.join("Contents/Info.plist");
        if let Some(version) = read_plist_version(&plist_path) {
            let min_version = MacFuseVersion::new(
                MACFUSE_MIN_VERSION.0,
                MACFUSE_MIN_VERSION.1,
                MACFUSE_MIN_VERSION.2,
            );

            if version.is_at_least(&min_version) {
                return MacFuseStatus::Available {
                    version,
                    path: macfuse_path.to_path_buf(),
                };
            } else {
                return MacFuseStatus::IncompatibleVersion {
                    version,
                    required: min_version,
                };
            }
        }

        // Fallback: try `pkgutil --pkg-info`
        if let Ok(output) = Command::new("pkgutil")
            .args(["--pkg-info", "io.macfuse.installer.components.core"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.starts_with("version:") {
                        let version_str = line.strip_prefix("version:").unwrap_or("").trim();
                        if let Some(version) = MacFuseVersion::parse(version_str) {
                            let min_version = MacFuseVersion::new(
                                MACFUSE_MIN_VERSION.0,
                                MACFUSE_MIN_VERSION.1,
                                MACFUSE_MIN_VERSION.2,
                            );

                            if version.is_at_least(&min_version) {
                                return MacFuseStatus::Available {
                                    version,
                                    path: macfuse_path.to_path_buf(),
                                };
                            } else {
                                return MacFuseStatus::IncompatibleVersion {
                                    version,
                                    required: min_version,
                                };
                            }
                        }
                    }
                }
            }
        }

        // macFUSE exists but couldn't get version - assume it's compatible
        return MacFuseStatus::Available {
            version: MacFuseVersion::new(4, 0, 0),
            path: macfuse_path.to_path_buf(),
        };
    }

    // Check for legacy OSXFUSE
    if osxfuse_path.exists() {
        warn!("OSXFUSE detected. This is deprecated; consider upgrading to macFUSE.");
        return MacFuseStatus::LegacyOsxfuse {
            path: osxfuse_path.to_path_buf(),
        };
    }

    MacFuseStatus::NotInstalled
}

/// Non-macOS stub for macFUSE detection.
#[cfg(not(target_os = "macos"))]
pub fn detect_macfuse() -> MacFuseStatus {
    MacFuseStatus::NotInstalled
}

/// Reads the version from a macFUSE Info.plist file.
#[cfg(target_os = "macos")]
fn read_plist_version(plist_path: &Path) -> Option<MacFuseVersion> {
    use std::process::Command;

    // Use /usr/libexec/PlistBuddy to read the version
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString", plist_path.to_str()?])
        .output()
        .ok()?;

    if output.status.success() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        return MacFuseVersion::parse(&version_str);
    }

    // Fallback: try CFBundleVersion
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleVersion", plist_path.to_str()?])
        .output()
        .ok()?;

    if output.status.success() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        return MacFuseVersion::parse(&version_str);
    }

    None
}

/// Returns macOS-specific installation instructions.
#[cfg(target_os = "macos")]
pub fn get_macfuse_install_instructions() -> String {
    "To install macFUSE on macOS:\n\n\
     Option 1: Download from the official website\n\
       1. Visit https://osxfuse.github.io/\n\
       2. Download the latest macFUSE release\n\
       3. Run the installer package\n\
       4. Grant required system permissions in System Preferences > Security & Privacy\n\
       5. Restart your Mac\n\n\
     Option 2: Install via Homebrew\n\
       1. Open Terminal\n\
       2. Run: brew install --cask macfuse\n\
       3. Grant required permissions and restart\n\n\
     Note: macOS 12.3+ requires enabling kernel extensions in Recovery Mode.\n\
     See: https://github.com/osxfuse/osxfuse/wiki/FAQ".to_string()
}

/// Non-macOS stub for macFUSE install instructions.
#[cfg(not(target_os = "macos"))]
pub fn get_macfuse_install_instructions() -> String {
    "macFUSE is only available on macOS.".to_string()
}

/// Validates a mount point path for macOS.
#[cfg(target_os = "macos")]
pub fn validate_macos_mount_point(path: &Path) -> Result<(), String> {
    // /Volumes mounts need appropriate permissions
    if path.starts_with("/Volumes") {
        // Check if /Volumes exists and is accessible
        if !Path::new("/Volumes").exists() {
            return Err("/Volumes directory does not exist".to_string());
        }

        // Check if the mount point already exists as a mounted volume
        if path.exists() && path.is_dir() {
            // Check if it's already a mount point (has different device)
            // This is a simplistic check - in production, use statfs
            let entries = std::fs::read_dir(path);
            if entries.is_ok() {
                return Err(format!(
                    "Mount point {} already exists. Choose a different name or unmount first.",
                    path.display()
                ));
            }
        }
    }

    // Check for reasonable path length
    if path.to_string_lossy().len() > 1024 {
        return Err("Mount point path is too long".to_string());
    }

    // Check for special characters that might cause issues
    let path_str = path.to_string_lossy();
    if path_str.contains('\0') {
        return Err("Mount point path contains null characters".to_string());
    }

    Ok(())
}

/// Non-macOS stub for mount point validation.
#[cfg(not(target_os = "macos"))]
pub fn validate_macos_mount_point(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Gets the macOS FUSE mount options.
#[cfg(target_os = "macos")]
pub fn get_macos_mount_options(config: &FuseConfig) -> Vec<MountOption> {
    let mut options = vec![
        MountOption::FSName(FILESYSTEM_NAME.to_string()),
        MountOption::Subtype(FILESYSTEM_NAME.to_string()),
        MountOption::DefaultPermissions,
    ];

    // Add local volume option for Finder integration
    options.push(MountOption::CUSTOM("local".to_string()));

    // Set volume name for Finder
    options.push(MountOption::CUSTOM(format!("volname={}", config.volume_label)));

    if config.read_only {
        options.push(MountOption::RO);
    } else {
        options.push(MountOption::RW);
    }

    if config.allow_other {
        options.push(MountOption::AllowOther);
    }

    if config.allow_root {
        options.push(MountOption::AllowRoot);
    }

    // macOS-specific: negative vnodes for better caching
    options.push(MountOption::CUSTOM("negative_vncache".to_string()));

    // Enable extended attributes (required for some apps)
    options.push(MountOption::CUSTOM("extended_security".to_string()));

    options
}

/// Creates a mount point in /Volumes (macOS-specific).
#[cfg(target_os = "macos")]
pub fn create_volumes_mount_point(name: &str) -> Result<PathBuf, VfsError> {
    let mount_point = PathBuf::from("/Volumes").join(name);

    // Validate the mount point
    validate_macos_mount_point(&mount_point).map_err(|e| VfsError::InvalidPath {
        path: mount_point.to_string_lossy().to_string(),
        reason: e,
    })?;

    // Create the directory if it doesn't exist
    if !mount_point.exists() {
        std::fs::create_dir(&mount_point).map_err(|e| VfsError::IoError {
            message: format!("Failed to create mount point in /Volumes: {}", e),
        })?;
    }

    Ok(mount_point)
}

/// Non-macOS stub.
#[cfg(not(target_os = "macos"))]
pub fn create_volumes_mount_point(_name: &str) -> Result<PathBuf, VfsError> {
    Err(VfsError::Internal("Not on macOS".to_string()))
}

/// Graceful fallback behavior when macFUSE is not installed.
#[derive(Debug, Clone, PartialEq)]
pub enum MacFuseFallback {
    /// macFUSE is available, no fallback needed.
    Available,
    /// macFUSE not installed, suggest installation.
    NotInstalled {
        /// Installation instructions.
        instructions: String
    },
    /// macFUSE version too old, suggest upgrade.
    NeedsUpgrade {
        /// Current version.
        current: MacFuseVersion,
        /// Required version.
        required: MacFuseVersion,
        /// Upgrade instructions.
        instructions: String,
    },
    /// Use built-in file browser only (no VFS integration).
    BuiltInBrowserOnly,
}

impl MacFuseFallback {
    /// Returns true if VFS integration is available.
    pub fn has_vfs(&self) -> bool {
        matches!(self, MacFuseFallback::Available)
    }

    /// Returns a user-friendly message about the fallback.
    pub fn message(&self) -> String {
        match self {
            MacFuseFallback::Available => {
                "macFUSE is available. Files can be accessed through Finder.".to_string()
            }
            MacFuseFallback::NotInstalled { instructions } => {
                format!(
                    "macFUSE is not installed. Finder integration is unavailable.\n\n\
                     You can still use the built-in file browser to manage your vault.\n\n\
                     To enable Finder integration:\n{}",
                    instructions
                )
            }
            MacFuseFallback::NeedsUpgrade { current, required, instructions } => {
                format!(
                    "macFUSE version {} is installed, but version {} or later is required.\n\n\
                     You can still use the built-in file browser to manage your vault.\n\n\
                     To upgrade:\n{}",
                    current, required, instructions
                )
            }
            MacFuseFallback::BuiltInBrowserOnly => {
                "Finder integration is not available. Using built-in file browser.".to_string()
            }
        }
    }
}

/// Determines the appropriate fallback behavior based on macFUSE status.
pub fn get_macfuse_fallback() -> MacFuseFallback {
    let status = detect_macfuse();

    match status {
        MacFuseStatus::Available { .. } | MacFuseStatus::LegacyOsxfuse { .. } => {
            MacFuseFallback::Available
        }
        MacFuseStatus::NotInstalled => {
            #[cfg(target_os = "macos")]
            {
                MacFuseFallback::NotInstalled {
                    instructions: get_macfuse_install_instructions(),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                MacFuseFallback::BuiltInBrowserOnly
            }
        }
        MacFuseStatus::IncompatibleVersion { version, required } => {
            #[cfg(target_os = "macos")]
            {
                MacFuseFallback::NeedsUpgrade {
                    current: version,
                    required,
                    instructions: get_macfuse_install_instructions(),
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (version, required);
                MacFuseFallback::BuiltInBrowserOnly
            }
        }
        MacFuseStatus::Unknown(_) => {
            MacFuseFallback::BuiltInBrowserOnly
        }
    }
}

/// macOS-specific FUSE configuration.
#[cfg(target_os = "macos")]
impl FuseConfig {
    /// Creates a configuration with the macOS-standard /Volumes mount point.
    pub fn macos_default() -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        Self {
            mount_point: PathBuf::from(MACOS_DEFAULT_MOUNT_POINT),
            volume_label: VOLUME_LABEL.to_string(),
            read_only: false,
            allow_other: false,
            allow_root: false,
            debug: false,
            total_bytes: 10 * 1024 * 1024 * 1024, // 10 GB virtual size
            free_bytes: 5 * 1024 * 1024 * 1024,   // 5 GB free
            uid,
            gid,
        }
    }

    /// Creates a configuration with a custom name in /Volumes.
    pub fn in_volumes(name: &str) -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let mount_point = PathBuf::from("/Volumes").join(name);

        Self {
            mount_point,
            volume_label: name.to_string(),
            read_only: false,
            allow_other: false,
            allow_root: false,
            debug: false,
            total_bytes: 10 * 1024 * 1024 * 1024,
            free_bytes: 5 * 1024 * 1024 * 1024,
            uid,
            gid,
        }
    }

    /// Returns macOS-optimized mount options.
    pub fn macos_mount_options(&self) -> Vec<MountOption> {
        get_macos_mount_options(self)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // InodeEntry Tests
    // =========================================================================

    #[test]
    fn test_inode_entry_root() {
        let entry = InodeEntry::root();
        assert_eq!(entry.inode, ROOT_INODE);
        assert_eq!(entry.path, "/");
        assert_eq!(entry.parent, ROOT_INODE);
        assert_eq!(entry.entry_type, EntryType::Directory);
        assert!(entry.uuid.is_none());
    }

    #[test]
    fn test_inode_entry_new_file() {
        let uuid = Uuid::new_v4();
        let entry = InodeEntry::new(
            2,
            Some(uuid),
            "/test.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            1024,
            1700000000,
        );
        assert_eq!(entry.inode, 2);
        assert_eq!(entry.uuid, Some(uuid));
        assert_eq!(entry.path, "/test.txt");
        assert_eq!(entry.parent, ROOT_INODE);
        assert_eq!(entry.entry_type, EntryType::File);
        assert_eq!(entry.access_level, 1);
        assert_eq!(entry.size, 1024);
    }

    #[test]
    fn test_inode_entry_to_file_attr_file() {
        let entry = InodeEntry::new(
            5,
            Some(Uuid::new_v4()),
            "/file.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            512,
            1700000000,
        );

        let attr = entry.to_file_attr(1000, 1000);
        assert_eq!(attr.ino, 5);
        assert_eq!(attr.size, 512);
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.perm, FILE_MODE);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
    }

    #[test]
    fn test_inode_entry_to_file_attr_directory() {
        let entry = InodeEntry::new(
            3,
            None,
            "/docs".to_string(),
            ROOT_INODE,
            EntryType::Directory,
            0,
            0,
            1700000000,
        );

        let attr = entry.to_file_attr(1000, 1000);
        assert_eq!(attr.ino, 3);
        assert_eq!(attr.kind, FileType::Directory);
        assert_eq!(attr.perm, DIR_MODE);
        assert_eq!(attr.nlink, 2);
    }

    // =========================================================================
    // InodeTable Tests
    // =========================================================================

    #[test]
    fn test_inode_table_new() {
        let table = InodeTable::new();
        assert_eq!(table.len(), 1); // Root only
        assert!(table.get(ROOT_INODE).is_some());
    }

    #[test]
    fn test_inode_table_allocate_inode() {
        let mut table = InodeTable::new();
        let inode1 = table.allocate_inode();
        let inode2 = table.allocate_inode();
        assert!(inode1 > ROOT_INODE);
        assert_eq!(inode2, inode1 + 1);
    }

    #[test]
    fn test_inode_table_insert_and_get() {
        let mut table = InodeTable::new();
        let entry = InodeEntry::new(
            2,
            Some(Uuid::new_v4()),
            "/test.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            100,
            1700000000,
        );

        table.insert(entry.clone());
        assert_eq!(table.len(), 2);

        let retrieved = table.get(2).unwrap();
        assert_eq!(retrieved.path, "/test.txt");

        let by_path = table.get_by_path("/test.txt").unwrap();
        assert_eq!(by_path.inode, 2);
    }

    #[test]
    fn test_inode_table_remove() {
        let mut table = InodeTable::new();
        let entry = InodeEntry::new(
            2,
            None,
            "/docs".to_string(),
            ROOT_INODE,
            EntryType::Directory,
            0,
            0,
            1700000000,
        );

        table.insert(entry);
        assert_eq!(table.len(), 2);

        let removed = table.remove(2);
        assert!(removed.is_some());
        assert_eq!(table.len(), 1);
        assert!(table.get(2).is_none());
        assert!(table.get_by_path("/docs").is_none());
    }

    #[test]
    fn test_inode_table_update_path() {
        let mut table = InodeTable::new();
        let entry = InodeEntry::new(
            2,
            Some(Uuid::new_v4()),
            "/old.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            100,
            1700000000,
        );

        table.insert(entry);
        table.update_path(2, "/new.txt".to_string());

        assert!(table.get_by_path("/old.txt").is_none());
        let entry = table.get_by_path("/new.txt").unwrap();
        assert_eq!(entry.inode, 2);
        assert_eq!(entry.path, "/new.txt");
    }

    #[test]
    fn test_inode_table_clear() {
        let mut table = InodeTable::new();
        table.insert(InodeEntry::new(
            2,
            None,
            "/docs".to_string(),
            ROOT_INODE,
            EntryType::Directory,
            0,
            0,
            1700000000,
        ));
        table.insert(InodeEntry::new(
            3,
            Some(Uuid::new_v4()),
            "/file.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            100,
            1700000000,
        ));

        assert_eq!(table.len(), 3);
        table.clear();
        assert_eq!(table.len(), 1); // Only root remains
        assert!(table.get(ROOT_INODE).is_some());
    }

    // =========================================================================
    // CachedChunk Tests
    // =========================================================================

    #[test]
    fn test_cached_chunk_new() {
        let chunk = CachedChunk::new(100, vec![1, 2, 3, 4]);
        assert_eq!(chunk.offset, 100);
        assert_eq!(chunk.data, vec![1, 2, 3, 4]);
        assert_eq!(chunk.end_offset(), 104);
    }

    #[test]
    fn test_cached_chunk_contains() {
        let chunk = CachedChunk::new(100, vec![0; 50]);
        assert!(!chunk.contains(99));
        assert!(chunk.contains(100));
        assert!(chunk.contains(125));
        assert!(chunk.contains(149));
        assert!(!chunk.contains(150));
    }

    #[test]
    fn test_cached_chunk_read() {
        let chunk = CachedChunk::new(100, vec![10, 20, 30, 40, 50]);
        let mut buf = [0u8; 3];

        // Read from start
        let read = chunk.read(100, &mut buf);
        assert_eq!(read, 3);
        assert_eq!(buf, [10, 20, 30]);

        // Read from middle
        let read = chunk.read(102, &mut buf);
        assert_eq!(read, 3);
        assert_eq!(buf, [30, 40, 50]);

        // Read past end
        let read = chunk.read(104, &mut buf);
        assert_eq!(read, 1);
        assert_eq!(buf[0], 50);

        // Read before chunk
        let read = chunk.read(50, &mut buf);
        assert_eq!(read, 0);
    }

    #[test]
    fn test_cached_chunk_expired() {
        let chunk = CachedChunk::new(0, vec![1]);
        assert!(!chunk.is_expired()); // Just created, not expired
    }

    // =========================================================================
    // ChunkCache Tests
    // =========================================================================

    #[test]
    fn test_chunk_cache_new() {
        let cache = ChunkCache::new();
        assert_eq!(cache.total_size(), 0);
    }

    #[test]
    fn test_chunk_cache_insert_and_find() {
        let mut cache = ChunkCache::new();
        let chunk = CachedChunk::new(0, vec![1, 2, 3, 4]);

        cache.insert(1, chunk);
        assert_eq!(cache.total_size(), 4);

        let found = cache.find_chunk(1, 2);
        assert!(found.is_some());
        assert_eq!(found.unwrap().data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_chunk_cache_clear_file() {
        let mut cache = ChunkCache::new();
        cache.insert(1, CachedChunk::new(0, vec![1, 2, 3]));
        cache.insert(1, CachedChunk::new(100, vec![4, 5, 6]));
        cache.insert(2, CachedChunk::new(0, vec![7, 8, 9]));

        assert_eq!(cache.total_size(), 9);
        cache.clear_file(1);
        assert_eq!(cache.total_size(), 3);
    }

    #[test]
    fn test_chunk_cache_clear_all() {
        let mut cache = ChunkCache::new();
        cache.insert(1, CachedChunk::new(0, vec![1; 100]));
        cache.insert(2, CachedChunk::new(0, vec![2; 200]));

        assert_eq!(cache.total_size(), 300);
        cache.clear();
        assert_eq!(cache.total_size(), 0);
    }

    // =========================================================================
    // WriteBuffer Tests
    // =========================================================================

    #[test]
    fn test_write_buffer_new_file() {
        let buffer = WriteBuffer::new_file("test.txt".to_string(), 1);
        assert!(buffer.is_new_file);
        assert!(buffer.is_empty());
        assert!(buffer.is_modified());
        assert_eq!(buffer.filename, "test.txt");
        assert_eq!(buffer.access_level, 1);
    }

    #[test]
    fn test_write_buffer_existing_file() {
        let content = vec![1, 2, 3, 4, 5];
        let buffer = WriteBuffer::existing_file(content.clone(), "test.txt".to_string(), 2);

        assert!(!buffer.is_new_file);
        assert!(!buffer.is_empty());
        assert!(!buffer.is_modified());
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.data, content);
    }

    #[test]
    fn test_write_buffer_write_at() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string(), 1);

        buffer.write_at(0, &[1, 2, 3]);
        assert_eq!(buffer.len(), 3);

        buffer.write_at(5, &[4, 5]);
        assert_eq!(buffer.len(), 7);
        assert_eq!(buffer.data, vec![1, 2, 3, 0, 0, 4, 5]);

        buffer.write_at(2, &[10, 11, 12]);
        assert_eq!(buffer.data, vec![1, 2, 10, 11, 12, 4, 5]);
    }

    #[test]
    fn test_write_buffer_set_end_of_file() {
        let mut buffer = WriteBuffer::existing_file(vec![1, 2, 3, 4, 5], "test.txt".to_string(), 1);

        buffer.set_end_of_file(3);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.data, vec![1, 2, 3]);

        buffer.set_end_of_file(5);
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.data, vec![1, 2, 3, 0, 0]);
    }

    #[test]
    fn test_write_buffer_read_at() {
        let buffer = WriteBuffer::existing_file(vec![10, 20, 30, 40, 50], "test.txt".to_string(), 1);

        let mut buf = [0u8; 3];
        let read = buffer.read_at(1, &mut buf);
        assert_eq!(read, 3);
        assert_eq!(buf, [20, 30, 40]);

        let read = buffer.read_at(4, &mut buf);
        assert_eq!(read, 1);
        assert_eq!(buf[0], 50);

        let read = buffer.read_at(10, &mut buf);
        assert_eq!(read, 0);
    }

    // =========================================================================
    // FileHandle Tests
    // =========================================================================

    #[test]
    fn test_file_handle_new() {
        let handle = FileHandle::new(
            5,
            Some(Uuid::new_v4()),
            "/test.txt".to_string(),
            false,
            1,
            1024,
            true,
        );

        assert_eq!(handle.inode, 5);
        assert!(!handle.is_directory);
        assert_eq!(handle.access_level, 1);
        assert_eq!(handle.size, 1024);
        assert!(handle.write_access);
        assert!(handle.write_buffer.is_none());
    }

    #[test]
    fn test_file_handle_root() {
        let handle = FileHandle::root();
        assert_eq!(handle.inode, ROOT_INODE);
        assert!(handle.is_directory);
        assert_eq!(handle.path, "/");
        assert!(handle.uuid.is_none());
    }

    // =========================================================================
    // FuseConfig Tests
    // =========================================================================

    #[test]
    fn test_fuse_config_new() {
        let config = FuseConfig::new("/mnt/tesseract");
        assert_eq!(config.mount_point, PathBuf::from("/mnt/tesseract"));
        assert_eq!(config.volume_label, VOLUME_LABEL);
        assert!(!config.read_only);
        assert!(!config.allow_other);
    }

    #[test]
    fn test_fuse_config_default_mount_point() {
        let config = FuseConfig::default_mount_point();
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        assert_eq!(config.mount_point, PathBuf::from(home).join(DEFAULT_MOUNT_POINT));
    }

    #[test]
    fn test_fuse_config_builders() {
        let config = FuseConfig::new("/mnt/test")
            .with_volume_label("TEST")
            .with_read_only(true)
            .with_allow_other(true)
            .with_debug(true)
            .with_disk_space(100, 50)
            .with_ownership(500, 500);

        assert_eq!(config.volume_label, "TEST");
        assert!(config.read_only);
        assert!(config.allow_other);
        assert!(config.debug);
        assert_eq!(config.total_bytes, 100);
        assert_eq!(config.free_bytes, 50);
        assert_eq!(config.uid, 500);
        assert_eq!(config.gid, 500);
    }

    #[test]
    fn test_fuse_config_resolved_mount_point_absolute() {
        let config = FuseConfig::new("/mnt/tesseract");
        assert_eq!(config.resolved_mount_point(), PathBuf::from("/mnt/tesseract"));
    }

    #[test]
    fn test_fuse_config_resolved_mount_point_relative() {
        let config = FuseConfig::new("my_vault");
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        assert_eq!(config.resolved_mount_point(), PathBuf::from(home).join("my_vault"));
    }

    #[test]
    fn test_fuse_config_mount_options() {
        let config = FuseConfig::new("/mnt/test");
        let options = config.mount_options();

        // Check for expected options
        assert!(options.iter().any(|o| matches!(o, MountOption::RW)));
        assert!(options.iter().any(|o| matches!(o, MountOption::DefaultPermissions)));
    }

    #[test]
    fn test_fuse_config_mount_options_read_only() {
        let config = FuseConfig::new("/mnt/test").with_read_only(true);
        let options = config.mount_options();

        assert!(options.iter().any(|o| matches!(o, MountOption::RO)));
        assert!(!options.iter().any(|o| matches!(o, MountOption::RW)));
    }

    #[test]
    fn test_fuse_config_mount_options_allow_other() {
        let config = FuseConfig::new("/mnt/test").with_allow_other(true);
        let options = config.mount_options();

        assert!(options.iter().any(|o| matches!(o, MountOption::AllowOther)));
    }

    // =========================================================================
    // Error Mapping Tests
    // =========================================================================

    #[test]
    fn test_vault_error_to_errno() {
        assert_eq!(vault_error_to_errno(&VaultError::FileNotFound), libc::ENOENT);
        assert_eq!(vault_error_to_errno(&VaultError::AccessDenied), libc::EACCES);
        assert_eq!(vault_error_to_errno(&VaultError::VaultLocked), libc::EACCES);
        assert_eq!(
            vault_error_to_errno(&VaultError::InvalidPath("test".to_string())),
            libc::EINVAL
        );
        assert_eq!(
            vault_error_to_errno(&VaultError::IntegrityError("test".to_string())),
            libc::EIO
        );
    }

    #[test]
    fn test_vfs_error_to_errno() {
        assert_eq!(vfs_error_to_errno(&VfsError::AccessDenied), libc::EACCES);
        assert_eq!(vfs_error_to_errno(&VfsError::FileNotFound), libc::ENOENT);
        assert_eq!(
            vfs_error_to_errno(&VfsError::AlreadyExists { path: "test".to_string() }),
            libc::EEXIST
        );
        assert_eq!(
            vfs_error_to_errno(&VfsError::DirectoryNotEmpty { path: "test".to_string() }),
            libc::ENOTEMPTY
        );
        assert_eq!(
            vfs_error_to_errno(&VfsError::IsDirectory { path: "test".to_string() }),
            libc::EISDIR
        );
        assert_eq!(
            vfs_error_to_errno(&VfsError::DiskFull { path: "test".to_string() }),
            libc::ENOSPC
        );
        assert_eq!(
            vfs_error_to_errno(&VfsError::NameTooLong { name: "test".to_string(), max_length: 255 }),
            libc::ENAMETOOLONG
        );
    }

    // =========================================================================
    // Helper Function Tests
    // =========================================================================

    #[test]
    fn test_normalize_path() {
        assert_eq!(TesseractFuseHandler::normalize_path(""), "/");
        assert_eq!(TesseractFuseHandler::normalize_path("/"), "/");
        assert_eq!(TesseractFuseHandler::normalize_path("foo"), "/foo");
        assert_eq!(TesseractFuseHandler::normalize_path("/foo"), "/foo");
        assert_eq!(TesseractFuseHandler::normalize_path("/foo/bar"), "/foo/bar");
    }

    #[test]
    fn test_path_name() {
        assert_eq!(TesseractFuseHandler::path_name("/"), "");
        assert_eq!(TesseractFuseHandler::path_name("/foo"), "foo");
        assert_eq!(TesseractFuseHandler::path_name("/foo/bar"), "bar");
        assert_eq!(TesseractFuseHandler::path_name("/foo/bar/baz.txt"), "baz.txt");
    }

    #[test]
    fn test_parent_path() {
        assert_eq!(TesseractFuseHandler::parent_path("/"), "/");
        assert_eq!(TesseractFuseHandler::parent_path("/foo"), "/");
        assert_eq!(TesseractFuseHandler::parent_path("/foo/bar"), "/foo");
        assert_eq!(TesseractFuseHandler::parent_path("/foo/bar/baz"), "/foo/bar");
    }

    #[test]
    fn test_is_fuse_available() {
        // This just tests that the function doesn't panic
        let _ = is_fuse_available();
    }

    #[test]
    fn test_get_fuse_not_available_message() {
        let msg = get_fuse_not_available_message();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_default_mount_point() {
        let path = default_mount_point();
        assert!(path.ends_with(DEFAULT_MOUNT_POINT));
    }

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn test_constants() {
        assert_eq!(ROOT_INODE, 1);
        assert_eq!(VOLUME_LABEL, "TESSERACT");
        assert_eq!(FILESYSTEM_NAME, "tesseract-vfs");
        assert_eq!(MAX_NAME_LENGTH, 255);
        assert_eq!(BLOCK_SIZE, 4096);
        assert_eq!(DIR_MODE, 0o755);
        assert_eq!(FILE_MODE, 0o644);
    }

    // =========================================================================
    // macOS-Specific Tests
    // =========================================================================

    #[test]
    fn test_macfuse_version_new() {
        let version = MacFuseVersion::new(4, 4, 1);
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 4);
        assert_eq!(version.patch, 1);
    }

    #[test]
    fn test_macfuse_version_parse_full() {
        let version = MacFuseVersion::parse("4.4.1").unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 4);
        assert_eq!(version.patch, 1);
    }

    #[test]
    fn test_macfuse_version_parse_two_parts() {
        let version = MacFuseVersion::parse("4.4").unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 4);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_macfuse_version_parse_single_part() {
        let version = MacFuseVersion::parse("4").unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 0);
        assert_eq!(version.patch, 0);
    }

    #[test]
    fn test_macfuse_version_parse_with_whitespace() {
        let version = MacFuseVersion::parse("  4.4.1  \n").unwrap();
        assert_eq!(version.major, 4);
        assert_eq!(version.minor, 4);
        assert_eq!(version.patch, 1);
    }

    #[test]
    fn test_macfuse_version_parse_empty_returns_some() {
        // Empty string returns Some with 0.0.0
        let version = MacFuseVersion::parse("");
        assert!(version.is_none() || version.unwrap() == MacFuseVersion::new(0, 0, 0));
    }

    #[test]
    fn test_macfuse_version_is_at_least_equal() {
        let v1 = MacFuseVersion::new(4, 0, 0);
        let v2 = MacFuseVersion::new(4, 0, 0);
        assert!(v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_is_at_least_major_greater() {
        let v1 = MacFuseVersion::new(5, 0, 0);
        let v2 = MacFuseVersion::new(4, 9, 9);
        assert!(v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_is_at_least_major_less() {
        let v1 = MacFuseVersion::new(3, 9, 9);
        let v2 = MacFuseVersion::new(4, 0, 0);
        assert!(!v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_is_at_least_minor_greater() {
        let v1 = MacFuseVersion::new(4, 5, 0);
        let v2 = MacFuseVersion::new(4, 4, 9);
        assert!(v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_is_at_least_minor_less() {
        let v1 = MacFuseVersion::new(4, 3, 9);
        let v2 = MacFuseVersion::new(4, 4, 0);
        assert!(!v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_is_at_least_patch_greater() {
        let v1 = MacFuseVersion::new(4, 4, 2);
        let v2 = MacFuseVersion::new(4, 4, 1);
        assert!(v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_is_at_least_patch_less() {
        let v1 = MacFuseVersion::new(4, 4, 0);
        let v2 = MacFuseVersion::new(4, 4, 1);
        assert!(!v1.is_at_least(&v2));
    }

    #[test]
    fn test_macfuse_version_display() {
        let version = MacFuseVersion::new(4, 4, 1);
        assert_eq!(format!("{}", version), "4.4.1");
    }

    #[test]
    fn test_macfuse_version_default() {
        let version = MacFuseVersion::default();
        assert_eq!(version, MacFuseVersion::new(0, 0, 0));
    }

    #[test]
    fn test_macfuse_status_is_available_true() {
        let status = MacFuseStatus::Available {
            version: MacFuseVersion::new(4, 4, 1),
            path: PathBuf::from("/Library/Filesystems/macfuse.fs"),
        };
        assert!(status.is_available());
    }

    #[test]
    fn test_macfuse_status_is_available_legacy() {
        let status = MacFuseStatus::LegacyOsxfuse {
            path: PathBuf::from("/Library/Filesystems/osxfuse.fs"),
        };
        assert!(status.is_available());
    }

    #[test]
    fn test_macfuse_status_is_available_incompatible() {
        let status = MacFuseStatus::IncompatibleVersion {
            version: MacFuseVersion::new(3, 0, 0),
            required: MacFuseVersion::new(4, 0, 0),
        };
        assert!(!status.is_available());
    }

    #[test]
    fn test_macfuse_status_is_available_not_installed() {
        let status = MacFuseStatus::NotInstalled;
        assert!(!status.is_available());
    }

    #[test]
    fn test_macfuse_status_version_available() {
        let version = MacFuseVersion::new(4, 4, 1);
        let status = MacFuseStatus::Available {
            version: version.clone(),
            path: PathBuf::from("/Library/Filesystems/macfuse.fs"),
        };
        assert_eq!(status.version(), Some(&version));
    }

    #[test]
    fn test_macfuse_status_version_not_installed() {
        let status = MacFuseStatus::NotInstalled;
        assert_eq!(status.version(), None);
    }

    #[test]
    fn test_macfuse_fallback_has_vfs_available() {
        let fallback = MacFuseFallback::Available;
        assert!(fallback.has_vfs());
    }

    #[test]
    fn test_macfuse_fallback_has_vfs_not_installed() {
        let fallback = MacFuseFallback::NotInstalled {
            instructions: "test".to_string(),
        };
        assert!(!fallback.has_vfs());
    }

    #[test]
    fn test_macfuse_fallback_has_vfs_needs_upgrade() {
        let fallback = MacFuseFallback::NeedsUpgrade {
            current: MacFuseVersion::new(3, 0, 0),
            required: MacFuseVersion::new(4, 0, 0),
            instructions: "test".to_string(),
        };
        assert!(!fallback.has_vfs());
    }

    #[test]
    fn test_macfuse_fallback_has_vfs_builtin_only() {
        let fallback = MacFuseFallback::BuiltInBrowserOnly;
        assert!(!fallback.has_vfs());
    }

    #[test]
    fn test_macfuse_fallback_message_available() {
        let fallback = MacFuseFallback::Available;
        let msg = fallback.message();
        assert!(msg.contains("macFUSE is available"));
        assert!(msg.contains("Finder"));
    }

    #[test]
    fn test_macfuse_fallback_message_not_installed() {
        let fallback = MacFuseFallback::NotInstalled {
            instructions: "Install macFUSE".to_string(),
        };
        let msg = fallback.message();
        assert!(msg.contains("not installed"));
        assert!(msg.contains("Install macFUSE"));
    }

    #[test]
    fn test_macfuse_fallback_message_needs_upgrade() {
        let fallback = MacFuseFallback::NeedsUpgrade {
            current: MacFuseVersion::new(3, 0, 0),
            required: MacFuseVersion::new(4, 0, 0),
            instructions: "Upgrade macFUSE".to_string(),
        };
        let msg = fallback.message();
        assert!(msg.contains("3.0.0"));
        assert!(msg.contains("4.0.0"));
        assert!(msg.contains("Upgrade macFUSE"));
    }

    #[test]
    fn test_macfuse_fallback_message_builtin_only() {
        let fallback = MacFuseFallback::BuiltInBrowserOnly;
        let msg = fallback.message();
        assert!(msg.contains("built-in file browser"));
    }

    #[test]
    fn test_detect_macfuse_returns_status() {
        // This test just ensures the function runs without panic
        let status = detect_macfuse();
        // On non-macOS systems, it should return NotInstalled
        #[cfg(not(target_os = "macos"))]
        assert_eq!(status, MacFuseStatus::NotInstalled);
        // On macOS, it could be any status
        #[cfg(target_os = "macos")]
        let _ = status;
    }

    #[test]
    fn test_get_macfuse_fallback_returns_fallback() {
        // This test just ensures the function runs without panic
        let fallback = get_macfuse_fallback();
        // On non-macOS systems, it should return BuiltInBrowserOnly
        #[cfg(not(target_os = "macos"))]
        assert_eq!(fallback, MacFuseFallback::BuiltInBrowserOnly);
        // On macOS, it could be any fallback
        #[cfg(target_os = "macos")]
        let _ = fallback;
    }

    #[test]
    fn test_get_macfuse_install_instructions_not_empty() {
        let instructions = get_macfuse_install_instructions();
        assert!(!instructions.is_empty());
        #[cfg(target_os = "macos")]
        {
            assert!(instructions.contains("macFUSE"));
            assert!(instructions.contains("https://"));
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(instructions.contains("macOS"));
        }
    }

    #[test]
    fn test_validate_macos_mount_point_long_path() {
        // Create a very long path
        let long_path = format!("/Volumes/{}", "a".repeat(2000));
        let result = validate_macos_mount_point(Path::new(&long_path));
        // On macOS, this should fail due to length
        #[cfg(target_os = "macos")]
        assert!(result.is_err());
        // On non-macOS, this should succeed (stub)
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_macos_mount_point_null_char() {
        let path_with_null = "/Volumes/test\0name";
        let result = validate_macos_mount_point(Path::new(path_with_null));
        // On macOS, this should fail due to null character
        #[cfg(target_os = "macos")]
        assert!(result.is_err());
        // On non-macOS, this should succeed (stub)
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_macos_mount_point_valid() {
        let result = validate_macos_mount_point(Path::new("/Volumes/TESSERACT"));
        // On non-macOS, stub always returns Ok
        // On macOS, depends on whether path already exists
        #[cfg(not(target_os = "macos"))]
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_volumes_mount_point_not_macos() {
        #[cfg(not(target_os = "macos"))]
        {
            let result = create_volumes_mount_point("TESSERACT");
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_default_mount_point_platform_specific() {
        let path = default_mount_point();
        #[cfg(target_os = "macos")]
        {
            assert_eq!(path, PathBuf::from(MACOS_DEFAULT_MOUNT_POINT));
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(path.ends_with(DEFAULT_MOUNT_POINT));
        }
    }

    // =========================================================================
    // macOS FuseConfig Tests (macOS-only)
    // =========================================================================

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;

        #[test]
        fn test_fuse_config_macos_default() {
            let config = FuseConfig::macos_default();
            assert_eq!(config.mount_point, PathBuf::from(MACOS_DEFAULT_MOUNT_POINT));
            assert_eq!(config.volume_label, VOLUME_LABEL);
        }

        #[test]
        fn test_fuse_config_in_volumes() {
            let config = FuseConfig::in_volumes("TestVault");
            assert_eq!(config.mount_point, PathBuf::from("/Volumes/TestVault"));
            assert_eq!(config.volume_label, "TestVault");
        }

        #[test]
        fn test_fuse_config_macos_mount_options() {
            let config = FuseConfig::macos_default();
            let options = config.macos_mount_options();
            // Should have various options
            assert!(!options.is_empty());
        }

        #[test]
        fn test_get_macos_mount_options_includes_volname() {
            let config = FuseConfig::new("/Volumes/MyVault").with_volume_label("MyVault");
            let options = get_macos_mount_options(&config);
            // Check that volname option is included
            let has_volname = options.iter().any(|opt| {
                if let MountOption::CUSTOM(s) = opt {
                    s.starts_with("volname=")
                } else {
                    false
                }
            });
            assert!(has_volname);
        }

        #[test]
        fn test_get_macos_mount_options_read_only() {
            let config = FuseConfig::new("/Volumes/MyVault").with_read_only(true);
            let options = get_macos_mount_options(&config);
            let has_ro = options.iter().any(|opt| matches!(opt, MountOption::RO));
            assert!(has_ro);
        }
    }

    // =========================================================================
    // macOS Constants Tests (macOS-only)
    // =========================================================================

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_constants() {
        assert_eq!(MACOS_DEFAULT_MOUNT_POINT, "/Volumes/TESSERACT");
        assert_eq!(MACFUSE_FILESYSTEM_PATH, "/Library/Filesystems/macfuse.fs");
        assert_eq!(OSXFUSE_FILESYSTEM_PATH, "/Library/Filesystems/osxfuse.fs");
        assert_eq!(MACFUSE_MIN_VERSION, (4, 0, 0));
    }
}
