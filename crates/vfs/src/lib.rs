//! TESSERACT Virtual Filesystem Integration
//!
//! Provides transparent encryption/decryption through OS filesystem
//! interfaces (FUSE on Linux/macOS, Dokan on Windows).

#![warn(missing_docs)]
#![warn(clippy::all)]

/// VFS driver detection (Dokan/WinFsp on Windows).
pub mod detection;

/// Mount point selection and management.
pub mod mount_point;

/// FUSE filesystem implementation (Linux/macOS).
#[cfg(unix)]
pub mod fuse;

/// Dokan filesystem implementation (Windows).
#[cfg(windows)]
pub mod dokan;

/// VFS error types.
pub mod error;

/// Common filesystem operations.
pub mod ops;

/// Integration tests for VFS operations.
#[cfg(test)]
mod integration_tests;

pub use detection::{
    detect_vfs_driver, detect_vfs_driver_info, detect_all_vfs_drivers,
    is_vfs_detection_supported, get_no_driver_message, get_driver_install_instructions,
    VfsDriver, VfsDriverInfo, DetectionResult,
};
pub use error::{
    VfsError, ErrorSeverity, NtStatusCode,
    OperationState, OperationContext, OperationType,
    log_operation_start, log_operation_complete, log_operation_failure,
    disk_full, media_removed, io_error, timeout, corrupted_data,
};
pub use mount_point::{
    get_available_drive_letters, is_drive_letter_in_use, validate_drive_letter,
    select_drive_letter, is_mount_point_selection_supported, get_mount_point_help_message,
    DriveLetterInfo, MountPointSelection, MountPointError,
    DEFAULT_DRIVE_LETTER, RESERVED_DRIVE_LETTERS, PREFERRED_DRIVE_ORDER,
};

// Re-export Dokan types on Windows
#[cfg(windows)]
pub use dokan::{
    TesseractDokanHandler, DokanMount, DokanConfig,
    FileHandle, FileInfo, FindData, DiskSpace, VolumeInfo,
    FileSystemFlags, FileAttributes, NtStatus, OpenHandleInfo,
    unix_to_filetime, filetime_to_unix,
    VOLUME_LABEL, FILESYSTEM_NAME, MAX_COMPONENT_LENGTH, VOLUME_SERIAL,
    DEFAULT_UNMOUNT_TIMEOUT_MS,
};

// Re-export FUSE types on Unix (Linux/macOS)
#[cfg(unix)]
pub use fuse::{
    TesseractFuseHandler, FuseMount, FuseConfig,
    FileHandle as FuseFileHandle, InodeEntry, InodeTable,
    CachedChunk, ChunkCache, WriteBuffer,
    is_fuse_available, get_fuse_not_available_message, default_mount_point,
    VOLUME_LABEL as FUSE_VOLUME_LABEL, FILESYSTEM_NAME as FUSE_FILESYSTEM_NAME,
    MAX_NAME_LENGTH, BLOCK_SIZE, ROOT_INODE, ATTR_TTL,
    DIR_MODE, FILE_MODE, DEFAULT_MOUNT_POINT,
    CACHE_CHUNK_SIZE, MAX_CACHED_CHUNKS_PER_FILE, MAX_CACHE_SIZE, CACHE_EXPIRATION_SECS,
    // macOS-specific types and functions
    MacFuseStatus, MacFuseVersion, MacFuseFallback,
    detect_macfuse, get_macfuse_fallback, get_macfuse_install_instructions,
    validate_macos_mount_point, create_volumes_mount_point,
};

// Re-export macOS-specific constants on macOS
#[cfg(target_os = "macos")]
pub use fuse::{
    MACOS_DEFAULT_MOUNT_POINT, MACFUSE_FILESYSTEM_PATH, OSXFUSE_FILESYSTEM_PATH,
    MACFUSE_MIN_VERSION, MACFUSE_MOUNT_HELPER,
    get_macos_mount_options,
};
