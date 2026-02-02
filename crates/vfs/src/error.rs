//! VFS error types.
//!
//! Provides comprehensive error handling for VFS operations with:
//! - Windows-specific NT status code mappings
//! - Logging and diagnostics support
//! - Recovery and corruption protection

use std::path::PathBuf;
use thiserror::Error;
use tracing::{error, warn, debug, instrument};

/// Errors that can occur during VFS operations.
#[derive(Debug, Error)]
pub enum VfsError {
    /// Mount operation failed.
    #[error("Failed to mount filesystem: {0}")]
    MountFailed(String),

    /// Unmount operation failed.
    #[error("Failed to unmount filesystem: {0}")]
    UnmountFailed(String),

    /// Unmount timed out.
    #[error("Unmount timed out after {0} ms (handles still open: {1})")]
    UnmountTimeout(u64, usize),

    /// Force unmount failed.
    #[error("Force unmount failed: {0}")]
    ForceUnmountFailed(String),

    /// Flush failed during unmount.
    #[error("Failed to flush pending writes: {0}")]
    FlushFailed(String),

    /// VFS driver not available.
    #[error("VFS driver not available: {0}")]
    DriverNotAvailable(String),

    /// File operation failed.
    #[error("File operation failed: {0}")]
    OperationFailed(String),

    /// Access denied.
    #[error("Access denied")]
    AccessDenied,

    /// File not found.
    #[error("File not found")]
    FileNotFound,

    /// Handle busy.
    #[error("File handle is busy: {0}")]
    HandleBusy(String),

    /// Core vault error.
    #[error("Vault error: {0}")]
    VaultError(#[from] tesseract_core::VaultError),

    // =========================================================================
    // US-053: Robust VFS Error Handling
    // =========================================================================

    /// Disk is full, cannot write more data.
    #[error("Disk full: cannot write {requested_bytes} bytes (available: {available_bytes})")]
    DiskFull {
        /// Bytes requested to write.
        requested_bytes: u64,
        /// Bytes currently available.
        available_bytes: u64,
    },

    /// Media was removed during operation (USB unplugged).
    #[error("Media removed during {operation}")]
    MediaRemoved {
        /// The operation that was interrupted.
        operation: String,
    },

    /// Device is not ready (USB not inserted, drive not mounted).
    #[error("Device not ready: {reason}")]
    DeviceNotReady {
        /// Reason device is not ready.
        reason: String,
    },

    /// I/O error during read/write operation.
    #[error("I/O error during {operation}: {details}")]
    IoError {
        /// The operation being performed.
        operation: String,
        /// Error details.
        details: String,
    },

    /// Write protected media.
    #[error("Media is write protected")]
    WriteProtected,

    /// File or directory already exists.
    #[error("File or directory already exists: {path}")]
    AlreadyExists {
        /// Path that already exists.
        path: String,
    },

    /// Directory is not empty (cannot delete).
    #[error("Directory is not empty: {path}")]
    DirectoryNotEmpty {
        /// Path to the non-empty directory.
        path: String,
    },

    /// Path is a directory when file was expected.
    #[error("Path is a directory: {path}")]
    IsDirectory {
        /// Path that is a directory.
        path: String,
    },

    /// Path is a file when directory was expected.
    #[error("Path is not a directory: {path}")]
    NotADirectory {
        /// Path that is not a directory.
        path: String,
    },

    /// Invalid file path or name.
    #[error("Invalid path: {path} ({reason})")]
    InvalidPath {
        /// The invalid path.
        path: String,
        /// Reason path is invalid.
        reason: String,
    },

    /// File name too long.
    #[error("File name too long: {name} ({length} > {max_length})")]
    NameTooLong {
        /// The file name.
        name: String,
        /// Actual length.
        length: usize,
        /// Maximum allowed length.
        max_length: usize,
    },

    /// Too many files open.
    #[error("Too many open files (limit: {limit})")]
    TooManyOpenFiles {
        /// Current limit.
        limit: usize,
    },

    /// Sharing violation (file locked by another process).
    #[error("Sharing violation: file is in use")]
    SharingViolation,

    /// Lock violation.
    #[error("Lock violation: byte range is locked")]
    LockViolation,

    /// Operation timed out.
    #[error("Operation timed out after {timeout_ms} ms: {operation}")]
    Timeout {
        /// The operation that timed out.
        operation: String,
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Vault session is locked.
    #[error("Vault session is locked")]
    SessionLocked,

    /// Encryption error.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption error.
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Integrity check failed.
    #[error("Integrity check failed: {0}")]
    IntegrityError(String),

    /// Corrupted data detected.
    #[error("Corrupted data detected: {details}")]
    CorruptedData {
        /// Description of the corruption.
        details: String,
    },

    /// Recovery needed.
    #[error("Recovery needed: {reason}")]
    RecoveryNeeded {
        /// Reason recovery is needed.
        reason: String,
    },

    /// Internal error (unexpected state).
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VfsError {
    /// Check if this error is recoverable (can retry operation).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
            | Self::DeviceNotReady { .. }
            | Self::TooManyOpenFiles { .. }
            | Self::SharingViolation
            | Self::LockViolation
        )
    }

    /// Check if this error indicates data loss may have occurred.
    pub fn may_cause_data_loss(&self) -> bool {
        matches!(
            self,
            Self::MediaRemoved { .. }
            | Self::IoError { .. }
            | Self::CorruptedData { .. }
        )
    }

    /// Check if this error indicates potential corruption.
    pub fn may_indicate_corruption(&self) -> bool {
        matches!(
            self,
            Self::IntegrityError(_)
            | Self::CorruptedData { .. }
            | Self::DecryptionError(_)
        )
    }

    /// Get severity level for logging.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            // Critical - requires immediate attention
            Self::CorruptedData { .. }
            | Self::IntegrityError(_)
            | Self::MediaRemoved { .. }
            | Self::RecoveryNeeded { .. } => ErrorSeverity::Critical,

            // Error - operation failed but no data loss
            Self::DiskFull { .. }
            | Self::WriteProtected
            | Self::IoError { .. }
            | Self::EncryptionError(_)
            | Self::DecryptionError(_)
            | Self::MountFailed(_)
            | Self::UnmountFailed(_)
            | Self::ForceUnmountFailed(_) => ErrorSeverity::Error,

            // Warning - expected failures
            Self::AccessDenied
            | Self::FileNotFound
            | Self::AlreadyExists { .. }
            | Self::DirectoryNotEmpty { .. }
            | Self::IsDirectory { .. }
            | Self::NotADirectory { .. }
            | Self::InvalidPath { .. }
            | Self::NameTooLong { .. }
            | Self::SharingViolation
            | Self::LockViolation
            | Self::SessionLocked => ErrorSeverity::Warning,

            // Info - transient/recoverable
            Self::Timeout { .. }
            | Self::DeviceNotReady { .. }
            | Self::TooManyOpenFiles { .. }
            | Self::UnmountTimeout(_, _)
            | Self::HandleBusy(_)
            | Self::FlushFailed(_) => ErrorSeverity::Info,

            // Debug - internal/generic
            Self::OperationFailed(_)
            | Self::DriverNotAvailable(_)
            | Self::Internal(_)
            | Self::VaultError(_) => ErrorSeverity::Debug,
        }
    }

    /// Log this error with appropriate severity level.
    pub fn log(&self) {
        match self.severity() {
            ErrorSeverity::Critical => error!(error = %self, "Critical VFS error"),
            ErrorSeverity::Error => error!(error = %self, "VFS error"),
            ErrorSeverity::Warning => warn!(error = %self, "VFS warning"),
            ErrorSeverity::Info => debug!(error = %self, "VFS info"),
            ErrorSeverity::Debug => debug!(error = %self, "VFS debug"),
        }
    }

    /// Log error with additional context.
    #[instrument(skip(self))]
    pub fn log_with_context(&self, operation: &str, path: Option<&str>) {
        match self.severity() {
            ErrorSeverity::Critical => {
                error!(
                    error = %self,
                    operation = operation,
                    path = path,
                    recoverable = self.is_recoverable(),
                    may_cause_data_loss = self.may_cause_data_loss(),
                    "Critical VFS error during operation"
                );
            }
            ErrorSeverity::Error => {
                error!(
                    error = %self,
                    operation = operation,
                    path = path,
                    "VFS operation failed"
                );
            }
            ErrorSeverity::Warning => {
                warn!(
                    error = %self,
                    operation = operation,
                    path = path,
                    "VFS operation warning"
                );
            }
            _ => {
                debug!(
                    error = %self,
                    operation = operation,
                    path = path,
                    "VFS operation info"
                );
            }
        }
    }
}

/// Severity level for VFS errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Debug-level information.
    Debug = 0,
    /// Informational, typically transient.
    Info = 1,
    /// Warning, expected failures.
    Warning = 2,
    /// Error, operation failed.
    Error = 3,
    /// Critical, requires immediate attention.
    Critical = 4,
}

impl ErrorSeverity {
    /// Returns the severity name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

// =============================================================================
// Windows NT Status Code Mapping (for Dokan integration)
// =============================================================================

/// Windows NT status codes for VFS operations.
///
/// These are the NTSTATUS values returned by the Dokan driver to applications.
/// Each code maps to a standard Windows error that applications expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatusCode {
    /// Operation completed successfully.
    Success = 0,

    // -------------------------------------------------------------------------
    // Standard file operation errors
    // -------------------------------------------------------------------------

    /// The file or directory was not found.
    ObjectNameNotFound = 0xC0000034_u32 as isize,

    /// Access is denied.
    AccessDenied = 0xC0000022_u32 as isize,

    /// The operation is not implemented.
    NotImplemented = 0xC0000002_u32 as isize,

    /// Invalid parameter.
    InvalidParameter = 0xC000000D_u32 as isize,

    /// File exists when it shouldn't.
    ObjectNameCollision = 0xC0000035_u32 as isize,

    /// End of file reached.
    EndOfFile = 0xC0000011_u32 as isize,

    /// Internal error.
    InternalError = 0xC00000E5_u32 as isize,

    /// Not a directory.
    NotADirectory = 0xC0000103_u32 as isize,

    /// Is a directory (operation not valid on directory).
    FileIsADirectory = 0xC00000BA_u32 as isize,

    // -------------------------------------------------------------------------
    // Disk/Media errors (US-053)
    // -------------------------------------------------------------------------

    /// Disk is full.
    DiskFull = 0xC000007F_u32 as isize,

    /// Media was removed (USB unplugged).
    NoMediaInDevice = 0xC0000013_u32 as isize,

    /// Device is not ready.
    DeviceNotReady = 0xC00000A3_u32 as isize,

    /// Write protected media.
    MediaWriteProtected = 0xC00000A2_u32 as isize,

    /// Data error (CRC or similar).
    DataError = 0xC000003E_u32 as isize,

    /// Device I/O error.
    IoDeviceError = 0xC0000185_u32 as isize,

    // -------------------------------------------------------------------------
    // Sharing and locking errors
    // -------------------------------------------------------------------------

    /// Sharing violation.
    SharingViolation = 0xC0000043_u32 as isize,

    /// Lock violation.
    FileLockConflict = 0xC0000054_u32 as isize,

    // -------------------------------------------------------------------------
    // Directory errors
    // -------------------------------------------------------------------------

    /// Directory is not empty.
    DirectoryNotEmpty = 0xC0000101_u32 as isize,

    // -------------------------------------------------------------------------
    // Resource errors
    // -------------------------------------------------------------------------

    /// Too many files open.
    TooManyOpenFiles = 0xC000011F_u32 as isize,

    /// Insufficient resources.
    InsufficientResources = 0xC000009A_u32 as isize,

    // -------------------------------------------------------------------------
    // Path and name errors
    // -------------------------------------------------------------------------

    /// Object name invalid.
    ObjectNameInvalid = 0xC0000033_u32 as isize,

    /// Object path not found.
    ObjectPathNotFound = 0xC000003A_u32 as isize,

    // -------------------------------------------------------------------------
    // Encryption/Integrity errors
    // -------------------------------------------------------------------------

    /// File corrupt error.
    FileCorruptError = 0xC0000102_u32 as isize,

    /// Encryption failed.
    EncryptionFailed = 0xC000028E_u32 as isize,

    /// Decryption failed.
    DecryptionFailed = 0xC000028F_u32 as isize,

    // -------------------------------------------------------------------------
    // Timeout
    // -------------------------------------------------------------------------

    /// IO timeout.
    IoTimeout = 0xC00000B5_u32 as isize,

    // -------------------------------------------------------------------------
    // Cancelled
    // -------------------------------------------------------------------------

    /// Operation cancelled.
    Cancelled = 0xC0000120_u32 as isize,
}

impl NtStatusCode {
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
}

impl From<&VfsError> for NtStatusCode {
    fn from(err: &VfsError) -> Self {
        match err {
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

            // Mount/Unmount - these are typically not exposed to applications
            VfsError::MountFailed(_) | VfsError::UnmountFailed(_) => Self::InternalError,
            VfsError::ForceUnmountFailed(_) | VfsError::FlushFailed(_) => Self::InternalError,
            VfsError::DriverNotAvailable(_) => Self::DeviceNotReady,

            // Recovery
            VfsError::RecoveryNeeded { .. } => Self::FileCorruptError,

            // Core vault errors - map through VaultError
            VfsError::VaultError(vault_err) => {
                use tesseract_core::VaultError;
                match vault_err {
                    VaultError::FileNotFound(_) => Self::ObjectNameNotFound,
                    VaultError::AccessDenied => Self::AccessDenied,
                    VaultError::VaultLocked => Self::AccessDenied,
                    VaultError::InvalidData(_) => Self::ObjectNameInvalid,
                    VaultError::HeaderIntegrityFailed => Self::FileCorruptError,
                    _ => Self::InternalError,
                }
            }

            // Generic
            VfsError::OperationFailed(_) | VfsError::Internal(_) => Self::InternalError,
        }
    }
}

impl From<VfsError> for NtStatusCode {
    fn from(err: VfsError) -> Self {
        Self::from(&err)
    }
}

// =============================================================================
// Error Recovery and Corruption Protection
// =============================================================================

/// State of a file operation for recovery purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationState {
    /// Operation not started.
    NotStarted,
    /// Operation in progress.
    InProgress,
    /// Operation completed successfully.
    Completed,
    /// Operation failed, can retry.
    Failed,
    /// Operation failed, needs recovery.
    NeedsRecovery,
}

/// Information about a potentially incomplete operation.
#[derive(Debug, Clone)]
pub struct OperationContext {
    /// Unique operation ID.
    pub operation_id: u64,
    /// Type of operation.
    pub operation_type: OperationType,
    /// Current state.
    pub state: OperationState,
    /// Path being operated on (if applicable).
    pub path: Option<PathBuf>,
    /// Temporary file used during operation.
    pub temp_path: Option<PathBuf>,
    /// Timestamp when operation started.
    pub started_at: std::time::Instant,
    /// Last error encountered.
    pub last_error: Option<String>,
}

/// Type of VFS operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Creating a new file.
    CreateFile,
    /// Writing to a file.
    WriteFile,
    /// Deleting a file.
    DeleteFile,
    /// Renaming/moving a file.
    RenameFile,
    /// Updating file attributes.
    SetAttributes,
    /// Flushing file buffers.
    FlushBuffers,
}

impl OperationType {
    /// Get a description of this operation type.
    pub fn description(self) -> &'static str {
        match self {
            Self::CreateFile => "create file",
            Self::WriteFile => "write file",
            Self::DeleteFile => "delete file",
            Self::RenameFile => "rename file",
            Self::SetAttributes => "set attributes",
            Self::FlushBuffers => "flush buffers",
        }
    }
}

impl OperationContext {
    /// Create a new operation context.
    pub fn new(operation_id: u64, operation_type: OperationType) -> Self {
        Self {
            operation_id,
            operation_type,
            state: OperationState::NotStarted,
            path: None,
            temp_path: None,
            started_at: std::time::Instant::now(),
            last_error: None,
        }
    }

    /// Set operation path.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Set temporary path.
    pub fn with_temp_path(mut self, path: PathBuf) -> Self {
        self.temp_path = Some(path);
        self
    }

    /// Mark operation as started.
    pub fn start(&mut self) {
        self.state = OperationState::InProgress;
    }

    /// Mark operation as completed successfully.
    pub fn complete(&mut self) {
        self.state = OperationState::Completed;
    }

    /// Mark operation as failed with error.
    pub fn fail(&mut self, error: &VfsError) {
        self.last_error = Some(error.to_string());
        if error.may_cause_data_loss() {
            self.state = OperationState::NeedsRecovery;
        } else {
            self.state = OperationState::Failed;
        }
    }

    /// Get elapsed time since operation started.
    pub fn elapsed(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Check if operation needs cleanup.
    pub fn needs_cleanup(&self) -> bool {
        matches!(
            self.state,
            OperationState::Failed | OperationState::NeedsRecovery
        ) && self.temp_path.is_some()
    }
}

/// Log and track a VFS operation for debugging and recovery.
#[instrument(skip_all, fields(op_id = %op_id, op_type = %op_type.description()))]
pub fn log_operation_start(op_id: u64, op_type: OperationType, path: Option<&str>) {
    debug!(
        operation_id = op_id,
        operation_type = op_type.description(),
        path = path,
        "Starting VFS operation"
    );
}

/// Log operation completion.
#[instrument(skip_all, fields(op_id = %op_id))]
pub fn log_operation_complete(op_id: u64, duration_ms: u64) {
    debug!(
        operation_id = op_id,
        duration_ms = duration_ms,
        "VFS operation completed"
    );
}

/// Log operation failure.
#[instrument(skip_all, fields(op_id = %op_id))]
pub fn log_operation_failure(op_id: u64, error: &VfsError) {
    error!(
        operation_id = op_id,
        error = %error,
        severity = error.severity().name(),
        recoverable = error.is_recoverable(),
        may_cause_data_loss = error.may_cause_data_loss(),
        "VFS operation failed"
    );
}

// =============================================================================
// Error Helpers
// =============================================================================

/// Create a disk full error.
pub fn disk_full(requested: u64, available: u64) -> VfsError {
    let err = VfsError::DiskFull {
        requested_bytes: requested,
        available_bytes: available,
    };
    err.log();
    err
}

/// Create a media removed error.
pub fn media_removed(operation: &str) -> VfsError {
    let err = VfsError::MediaRemoved {
        operation: operation.to_string(),
    };
    err.log();
    err
}

/// Create an I/O error.
pub fn io_error(operation: &str, details: &str) -> VfsError {
    let err = VfsError::IoError {
        operation: operation.to_string(),
        details: details.to_string(),
    };
    err.log();
    err
}

/// Create a timeout error.
pub fn timeout(operation: &str, timeout_ms: u64) -> VfsError {
    let err = VfsError::Timeout {
        operation: operation.to_string(),
        timeout_ms,
    };
    err.log();
    err
}

/// Create a corrupted data error.
pub fn corrupted_data(details: &str) -> VfsError {
    let err = VfsError::CorruptedData {
        details: details.to_string(),
    };
    err.log();
    err
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // VfsError Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_vfs_error_display() {
        let err = VfsError::DiskFull {
            requested_bytes: 1000,
            available_bytes: 500,
        };
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
    }

    #[test]
    fn test_vfs_error_is_recoverable() {
        assert!(VfsError::Timeout {
            operation: "test".into(),
            timeout_ms: 100
        }
        .is_recoverable());
        assert!(VfsError::DeviceNotReady {
            reason: "test".into()
        }
        .is_recoverable());
        assert!(VfsError::TooManyOpenFiles { limit: 100 }.is_recoverable());
        assert!(VfsError::SharingViolation.is_recoverable());
        assert!(VfsError::LockViolation.is_recoverable());

        assert!(!VfsError::AccessDenied.is_recoverable());
        assert!(!VfsError::FileNotFound.is_recoverable());
        assert!(!VfsError::DiskFull {
            requested_bytes: 100,
            available_bytes: 0
        }
        .is_recoverable());
    }

    #[test]
    fn test_vfs_error_may_cause_data_loss() {
        assert!(VfsError::MediaRemoved {
            operation: "write".into()
        }
        .may_cause_data_loss());
        assert!(VfsError::IoError {
            operation: "write".into(),
            details: "test".into()
        }
        .may_cause_data_loss());
        assert!(VfsError::CorruptedData {
            details: "test".into()
        }
        .may_cause_data_loss());

        assert!(!VfsError::AccessDenied.may_cause_data_loss());
        assert!(!VfsError::FileNotFound.may_cause_data_loss());
    }

    #[test]
    fn test_vfs_error_may_indicate_corruption() {
        assert!(VfsError::IntegrityError("test".into()).may_indicate_corruption());
        assert!(VfsError::CorruptedData {
            details: "test".into()
        }
        .may_indicate_corruption());
        assert!(VfsError::DecryptionError("test".into()).may_indicate_corruption());

        assert!(!VfsError::AccessDenied.may_indicate_corruption());
        assert!(!VfsError::IoError {
            operation: "read".into(),
            details: "test".into()
        }
        .may_indicate_corruption());
    }

    #[test]
    fn test_vfs_error_severity() {
        assert_eq!(
            VfsError::CorruptedData {
                details: "".into()
            }
            .severity(),
            ErrorSeverity::Critical
        );
        assert_eq!(
            VfsError::MediaRemoved {
                operation: "".into()
            }
            .severity(),
            ErrorSeverity::Critical
        );

        assert_eq!(
            VfsError::DiskFull {
                requested_bytes: 0,
                available_bytes: 0
            }
            .severity(),
            ErrorSeverity::Error
        );
        assert_eq!(VfsError::WriteProtected.severity(), ErrorSeverity::Error);

        assert_eq!(VfsError::AccessDenied.severity(), ErrorSeverity::Warning);
        assert_eq!(VfsError::FileNotFound.severity(), ErrorSeverity::Warning);

        assert_eq!(
            VfsError::Timeout {
                operation: "".into(),
                timeout_ms: 0
            }
            .severity(),
            ErrorSeverity::Info
        );
    }

    // -------------------------------------------------------------------------
    // ErrorSeverity Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Critical > ErrorSeverity::Error);
        assert!(ErrorSeverity::Error > ErrorSeverity::Warning);
        assert!(ErrorSeverity::Warning > ErrorSeverity::Info);
        assert!(ErrorSeverity::Info > ErrorSeverity::Debug);
    }

    #[test]
    fn test_error_severity_name() {
        assert_eq!(ErrorSeverity::Critical.name(), "critical");
        assert_eq!(ErrorSeverity::Error.name(), "error");
        assert_eq!(ErrorSeverity::Warning.name(), "warning");
        assert_eq!(ErrorSeverity::Info.name(), "info");
        assert_eq!(ErrorSeverity::Debug.name(), "debug");
    }

    // -------------------------------------------------------------------------
    // NtStatusCode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_ntstatus_success() {
        assert_eq!(NtStatusCode::Success.as_i32(), 0);
        assert!(NtStatusCode::Success.is_success());
        assert!(!NtStatusCode::Success.is_error());
    }

    #[test]
    fn test_ntstatus_errors_are_negative() {
        assert!(NtStatusCode::ObjectNameNotFound.is_error());
        assert!(NtStatusCode::AccessDenied.is_error());
        assert!(NtStatusCode::DiskFull.is_error());
        assert!(NtStatusCode::NoMediaInDevice.is_error());
    }

    #[test]
    fn test_ntstatus_from_vfs_error() {
        assert_eq!(
            NtStatusCode::from(&VfsError::FileNotFound),
            NtStatusCode::ObjectNameNotFound
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::AccessDenied),
            NtStatusCode::AccessDenied
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::DiskFull {
                requested_bytes: 100,
                available_bytes: 0
            }),
            NtStatusCode::DiskFull
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::MediaRemoved {
                operation: "write".into()
            }),
            NtStatusCode::NoMediaInDevice
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::WriteProtected),
            NtStatusCode::MediaWriteProtected
        );
    }

    #[test]
    fn test_ntstatus_directory_errors() {
        assert_eq!(
            NtStatusCode::from(&VfsError::DirectoryNotEmpty {
                path: "/test".into()
            }),
            NtStatusCode::DirectoryNotEmpty
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::IsDirectory {
                path: "/test".into()
            }),
            NtStatusCode::FileIsADirectory
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::NotADirectory {
                path: "/test".into()
            }),
            NtStatusCode::NotADirectory
        );
    }

    #[test]
    fn test_ntstatus_encryption_errors() {
        assert_eq!(
            NtStatusCode::from(&VfsError::EncryptionError("test".into())),
            NtStatusCode::EncryptionFailed
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::DecryptionError("test".into())),
            NtStatusCode::DecryptionFailed
        );
        assert_eq!(
            NtStatusCode::from(&VfsError::IntegrityError("test".into())),
            NtStatusCode::FileCorruptError
        );
    }

    #[test]
    fn test_ntstatus_description() {
        assert_eq!(NtStatusCode::Success.description(), "Success");
        assert_eq!(NtStatusCode::DiskFull.description(), "Disk full");
        assert_eq!(
            NtStatusCode::NoMediaInDevice.description(),
            "No media in device"
        );
    }

    // -------------------------------------------------------------------------
    // OperationContext Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_operation_context_new() {
        let ctx = OperationContext::new(1, OperationType::WriteFile);
        assert_eq!(ctx.operation_id, 1);
        assert_eq!(ctx.operation_type, OperationType::WriteFile);
        assert_eq!(ctx.state, OperationState::NotStarted);
        assert!(ctx.path.is_none());
        assert!(ctx.temp_path.is_none());
    }

    #[test]
    fn test_operation_context_with_paths() {
        let ctx = OperationContext::new(1, OperationType::CreateFile)
            .with_path(PathBuf::from("/test/file"))
            .with_temp_path(PathBuf::from("/test/.tmp"));

        assert_eq!(ctx.path, Some(PathBuf::from("/test/file")));
        assert_eq!(ctx.temp_path, Some(PathBuf::from("/test/.tmp")));
    }

    #[test]
    fn test_operation_context_state_transitions() {
        let mut ctx = OperationContext::new(1, OperationType::WriteFile);
        assert_eq!(ctx.state, OperationState::NotStarted);

        ctx.start();
        assert_eq!(ctx.state, OperationState::InProgress);

        ctx.complete();
        assert_eq!(ctx.state, OperationState::Completed);
    }

    #[test]
    fn test_operation_context_failure_recovery_needed() {
        let mut ctx = OperationContext::new(1, OperationType::WriteFile);
        ctx.start();

        // Non-data-loss error -> Failed state
        ctx.fail(&VfsError::AccessDenied);
        assert_eq!(ctx.state, OperationState::Failed);

        // Data-loss error -> NeedsRecovery state
        let mut ctx2 = OperationContext::new(2, OperationType::WriteFile);
        ctx2.start();
        ctx2.fail(&VfsError::MediaRemoved {
            operation: "write".into(),
        });
        assert_eq!(ctx2.state, OperationState::NeedsRecovery);
    }

    #[test]
    fn test_operation_context_needs_cleanup() {
        let mut ctx = OperationContext::new(1, OperationType::CreateFile)
            .with_temp_path(PathBuf::from("/test/.tmp"));

        ctx.start();
        assert!(!ctx.needs_cleanup());

        ctx.fail(&VfsError::AccessDenied);
        assert!(ctx.needs_cleanup());
    }

    #[test]
    fn test_operation_context_no_cleanup_without_temp() {
        let mut ctx = OperationContext::new(1, OperationType::CreateFile);
        ctx.start();
        ctx.fail(&VfsError::AccessDenied);
        assert!(!ctx.needs_cleanup()); // No temp_path
    }

    // -------------------------------------------------------------------------
    // OperationType Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_operation_type_description() {
        assert_eq!(OperationType::CreateFile.description(), "create file");
        assert_eq!(OperationType::WriteFile.description(), "write file");
        assert_eq!(OperationType::DeleteFile.description(), "delete file");
        assert_eq!(OperationType::RenameFile.description(), "rename file");
        assert_eq!(OperationType::SetAttributes.description(), "set attributes");
        assert_eq!(OperationType::FlushBuffers.description(), "flush buffers");
    }

    // -------------------------------------------------------------------------
    // Helper Function Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_disk_full_helper() {
        let err = disk_full(1000, 500);
        match err {
            VfsError::DiskFull {
                requested_bytes,
                available_bytes,
            } => {
                assert_eq!(requested_bytes, 1000);
                assert_eq!(available_bytes, 500);
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_media_removed_helper() {
        let err = media_removed("write file");
        match err {
            VfsError::MediaRemoved { operation } => {
                assert_eq!(operation, "write file");
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_io_error_helper() {
        let err = io_error("read", "device disconnected");
        match err {
            VfsError::IoError { operation, details } => {
                assert_eq!(operation, "read");
                assert_eq!(details, "device disconnected");
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_timeout_helper() {
        let err = timeout("mount", 5000);
        match err {
            VfsError::Timeout {
                operation,
                timeout_ms,
            } => {
                assert_eq!(operation, "mount");
                assert_eq!(timeout_ms, 5000);
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_corrupted_data_helper() {
        let err = corrupted_data("checksum mismatch");
        match err {
            VfsError::CorruptedData { details } => {
                assert_eq!(details, "checksum mismatch");
            }
            _ => panic!("Wrong error type"),
        }
    }

    // -------------------------------------------------------------------------
    // VaultError Integration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_ntstatus_from_vault_error_via_vfs_error() {
        let vault_err = tesseract_core::VaultError::FileNotFound("test.txt".to_string());
        let vfs_err = VfsError::VaultError(vault_err);
        assert_eq!(
            NtStatusCode::from(&vfs_err),
            NtStatusCode::ObjectNameNotFound
        );
    }

    #[test]
    fn test_ntstatus_from_vault_locked() {
        let vault_err = tesseract_core::VaultError::VaultLocked;
        let vfs_err = VfsError::VaultError(vault_err);
        assert_eq!(NtStatusCode::from(&vfs_err), NtStatusCode::AccessDenied);
    }

    // -------------------------------------------------------------------------
    // Edge Case Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_locked_maps_to_access_denied() {
        assert_eq!(
            NtStatusCode::from(&VfsError::SessionLocked),
            NtStatusCode::AccessDenied
        );
    }

    #[test]
    fn test_handle_busy_maps_to_sharing_violation() {
        assert_eq!(
            NtStatusCode::from(&VfsError::HandleBusy("test".into())),
            NtStatusCode::SharingViolation
        );
    }

    #[test]
    fn test_internal_error_severity_is_debug() {
        assert_eq!(
            VfsError::Internal("test".into()).severity(),
            ErrorSeverity::Debug
        );
    }
}
