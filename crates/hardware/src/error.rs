//! Hardware encryption error types.
//!
//! This module defines error types for all hardware encryption operations
//! including drive detection, container management, and SED operations.

use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during hardware encryption operations.
#[derive(Error, Debug)]
pub enum HardwareError {
    /// I/O error during disk operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Drive not found at the specified path.
    #[error("Drive not found: {path}")]
    DriveNotFound {
        /// Path to the drive that was not found.
        path: PathBuf,
    },

    /// Drive is not removable (fixed disk).
    #[error("Drive is not removable: {path}")]
    NotRemovable {
        /// Path to the non-removable drive.
        path: PathBuf,
    },

    /// Drive is currently mounted and cannot be modified.
    #[error("Drive is mounted: {path}")]
    DriveMounted {
        /// Path to the mounted drive.
        path: PathBuf,
    },

    /// Drive does not have a valid THC header.
    #[error("Invalid THC header: {reason}")]
    InvalidHeader {
        /// Reason the header is invalid.
        reason: String,
    },

    /// THC container version is not supported.
    #[error("Unsupported container version: {version}")]
    UnsupportedVersion {
        /// The unsupported version number.
        version: u8,
    },

    /// Password verification failed.
    #[error("Invalid password")]
    InvalidPassword,

    /// Drive is locked and requires authentication.
    #[error("Drive is locked")]
    DriveLocked,

    /// Container is already unlocked.
    #[error("Container already unlocked")]
    AlreadyUnlocked,

    /// Container is already locked.
    #[error("Container already locked")]
    AlreadyLocked,

    /// Insufficient permissions for the operation.
    #[error("Permission denied: {operation} - {hint}")]
    PermissionDenied {
        /// The operation that was denied.
        operation: String,
        /// Hint on how to resolve (e.g., "Run as administrator").
        hint: String,
    },

    /// Platform is not supported for this operation.
    #[error("Platform not supported: {platform}")]
    PlatformNotSupported {
        /// The unsupported platform name.
        platform: String,
    },

    /// TCG Opal is not supported on this drive.
    #[error("TCG Opal not supported on this drive")]
    OpalNotSupported,

    /// TCG Opal drive is not initialized.
    #[error("Opal drive not initialized - run initial setup first")]
    OpalNotInitialized,

    /// External tool (e.g., sedutil) not found.
    #[error("External tool not found: {tool}")]
    ToolNotFound {
        /// Name of the missing tool.
        tool: String,
    },

    /// Cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] tesseract_crypto::CryptoError),

    /// Header MAC verification failed (tampering detected).
    #[error("Header integrity check failed - possible tampering")]
    IntegrityError,

    /// Drive is busy (files open, etc.).
    #[error("Drive is busy: {reason}")]
    DriveBusy {
        /// Reason the drive is busy.
        reason: String,
    },

    /// Container creation was cancelled by user.
    #[error("Operation cancelled by user")]
    Cancelled,

    /// Operation timed out.
    #[error("Operation timed out after {seconds} seconds")]
    Timeout {
        /// Number of seconds before timeout.
        seconds: u64,
    },

    /// Device was removed during operation.
    #[error("Device was removed during operation")]
    DeviceRemoved,

    /// Drive is currently in use and cannot be ejected.
    #[error("Drive is in use and cannot be ejected: {path}")]
    DriveInUse {
        /// Path to the drive that is in use.
        path: PathBuf,
    },

    /// Platform is not supported for this operation.
    #[error("Operation not supported on this platform: {operation}")]
    UnsupportedPlatform {
        /// The unsupported operation.
        operation: String,
    },

    /// External command failed.
    #[error("Command '{command}' failed: {reason}")]
    CommandFailed {
        /// The command that failed.
        command: String,
        /// Reason for failure.
        reason: String,
    },

    /// Invalid device path format.
    #[error("Invalid device path: {path}")]
    InvalidDevicePath {
        /// The invalid path.
        path: String,
    },

    /// Insufficient disk space.
    #[error("Insufficient disk space: need {needed} bytes, have {available} bytes")]
    InsufficientSpace {
        /// Bytes needed.
        needed: u64,
        /// Bytes available.
        available: u64,
    },

    /// Loop device error (Linux).
    #[error("Loop device error: {0}")]
    LoopDeviceError(String),

    /// dm-crypt error (Linux).
    #[error("dm-crypt error: {0}")]
    DmCryptError(String),

    /// Invalid mount point path.
    #[error("Invalid mount point: {path}")]
    InvalidMountPoint {
        /// The invalid mount point path.
        path: PathBuf,
    },

    /// Generic I/O error with custom message.
    #[error("I/O error: {message}")]
    IoError {
        /// Description of the I/O error.
        message: String,
    },
}

impl HardwareError {
    /// Create a permission denied error with appropriate hint for the platform.
    #[must_use]
    pub fn permission_denied(operation: impl Into<String>) -> Self {
        let hint = if cfg!(windows) {
            "Run as Administrator"
        } else if cfg!(unix) {
            "Run with sudo or as root"
        } else {
            "Ensure you have appropriate permissions"
        };

        Self::PermissionDenied {
            operation: operation.into(),
            hint: hint.to_string(),
        }
    }

    /// Check if this error is recoverable (user can retry).
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::InvalidPassword
                | Self::DriveLocked
                | Self::Cancelled
                | Self::DriveBusy { .. }
                | Self::DriveInUse { .. }
                | Self::Timeout { .. }
        )
    }

    /// Check if this error indicates the drive was removed.
    #[must_use]
    pub fn is_device_removed(&self) -> bool {
        matches!(self, Self::DeviceRemoved | Self::DriveNotFound { .. })
    }
}

/// Result type for hardware operations.
pub type Result<T> = std::result::Result<T, HardwareError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HardwareError::InvalidPassword;
        assert_eq!(err.to_string(), "Invalid password");
    }

    #[test]
    fn test_drive_not_found() {
        let err = HardwareError::DriveNotFound {
            path: PathBuf::from("/dev/sdb"),
        };
        assert!(err.to_string().contains("/dev/sdb"));
    }

    #[test]
    fn test_permission_denied() {
        let err = HardwareError::permission_denied("create container");
        assert!(err.to_string().contains("create container"));
    }

    #[test]
    fn test_is_recoverable() {
        assert!(HardwareError::InvalidPassword.is_recoverable());
        assert!(HardwareError::DriveLocked.is_recoverable());
        assert!(HardwareError::Cancelled.is_recoverable());
        assert!(!HardwareError::IntegrityError.is_recoverable());
        assert!(!HardwareError::OpalNotSupported.is_recoverable());
    }

    #[test]
    fn test_is_device_removed() {
        assert!(HardwareError::DeviceRemoved.is_device_removed());
        assert!(HardwareError::DriveNotFound {
            path: PathBuf::from("/dev/sdb")
        }
        .is_device_removed());
        assert!(!HardwareError::InvalidPassword.is_device_removed());
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let hw_err: HardwareError = io_err.into();
        assert!(matches!(hw_err, HardwareError::Io(_)));
    }

    #[test]
    fn test_invalid_header() {
        let err = HardwareError::InvalidHeader {
            reason: "bad magic".to_string(),
        };
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn test_insufficient_space() {
        let err = HardwareError::InsufficientSpace {
            needed: 1024,
            available: 512,
        };
        assert!(err.to_string().contains("1024"));
        assert!(err.to_string().contains("512"));
    }
}
