//! Platform-specific implementations.
//!
//! This module provides platform-specific implementations for:
//! - Drive detection and enumeration
//! - Container creation, unlock, and lock
//! - Raw disk I/O operations

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

// Re-export platform implementations
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "macos")]
pub use macos::*;

// Fallback for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod unsupported;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub use unsupported::*;

use crate::detect::DriveInfo;
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
use crate::error::HardwareError;
use crate::error::Result;
use std::path::Path;

/// Progress callback type for long operations.
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

/// Platform-specific drive operations trait.
///
/// Each platform must implement this trait for its specific drive
/// management capabilities.
pub trait DriveOperations {
    /// Detect all connected removable drives.
    fn detect_drives(&self) -> Result<Vec<DriveInfo>>;

    /// Create a THC container on the specified device.
    ///
    /// # Warning
    ///
    /// This operation destroys all data on the device.
    fn create_container(
        &self,
        device_path: &Path,
        password: &[u8],
        progress: Option<ProgressCallback>,
    ) -> Result<()>;

    /// Unlock a THC container and mount it.
    ///
    /// Returns the mount point path.
    fn unlock_container(&self, device_path: &Path, password: &[u8]) -> Result<std::path::PathBuf>;

    /// Lock a container and unmount it.
    fn lock_container(&self, mount_point: &Path) -> Result<()>;
}

/// Get the current platform name.
#[must_use]
pub fn platform_name() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Linux";

    #[cfg(target_os = "windows")]
    return "Windows";

    #[cfg(target_os = "macos")]
    return "macOS";

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    return "Unsupported";
}

/// Check if the current platform supports hardware encryption.
#[must_use]
pub fn is_platform_supported() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos"
    ))
}

// Default implementation for unsupported platforms
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod unsupported {
    use super::*;

    /// On unsupported platforms, return empty vec for graceful degradation.
    pub fn detect_drives() -> Result<Vec<DriveInfo>> {
        // Return empty vec instead of error for graceful degradation
        Ok(Vec::new())
    }

    pub fn create_container(
        _device_path: &Path,
        _password: &[u8],
        _progress: Option<ProgressCallback>,
    ) -> Result<()> {
        Err(HardwareError::PlatformNotSupported {
            platform: platform_name().to_string(),
        })
    }

    pub fn unlock_container(
        _device_path: &Path,
        _password: &[u8],
    ) -> Result<std::path::PathBuf> {
        Err(HardwareError::PlatformNotSupported {
            platform: platform_name().to_string(),
        })
    }

    pub fn lock_container(_mount_point: &Path) -> Result<()> {
        Err(HardwareError::PlatformNotSupported {
            platform: platform_name().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_name() {
        let name = platform_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn test_is_platform_supported() {
        // On Linux, Windows, or macOS, this should be true
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        assert!(is_platform_supported());

        // On other platforms, it should be false
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        assert!(!is_platform_supported());
    }
}
