//! TESSERACT Hardware Encryption
//!
//! This crate provides hardware-level encryption support for TESSERACT:
//!
//! - **THC Containers**: TESSERACT Hardware Container format for full-disk
//!   encryption on USB drives using AES-256-XTS.
//!
//! - **TCG Opal SED**: Support for Self-Encrypting Drives that implement
//!   the TCG Opal 2.0 standard.
//!
//! - **Cross-Platform**: Drive detection and container management for
//!   Linux, Windows, and macOS.
//!
//! # Triple-Layer Encryption
//!
//! TESSERACT provides three layers of encryption:
//!
//! 1. **Hardware Layer**: AES-256-XTS full-disk encryption (this crate)
//! 2. **Vault Layer**: AES-256-GCM file encryption (tesseract-core)
//! 3. **Access Levels**: Per-level key hierarchy (1-4 levels)
//!
//! # Key Hierarchy
//!
//! ```text
//! Master Password
//!       |
//!       v
//!   Argon2id KDF
//!       |
//!       +-----> HKDF ("TESSERACT-HARDWARE-KEY") --> Hardware Key (XTS)
//!       |
//!       +-----> HKDF ("TESSERACT-SOFTWARE-KEY") --> Vault Key (GCM)
//! ```
//!
//! # Example
//!
//! ```no_run
//! use tesseract_hardware::{detect_drives, DriveType};
//!
//! // Detect connected USB drives
//! let drives = detect_drives()?;
//!
//! for drive in drives {
//!     println!("Found: {} ({}) - {:?}",
//!         drive.display_name(),
//!         drive.size_display(),
//!         drive.drive_type
//!     );
//!
//!     match drive.drive_type {
//!         DriveType::TesseractContainer => {
//!             println!("  -> TESSERACT container (locked: {})", drive.is_locked);
//!         }
//!         DriveType::Unencrypted => {
//!             println!("  -> Unencrypted, can be initialized");
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok::<(), tesseract_hardware::HardwareError>(())
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

/// Error types for hardware encryption operations.
pub mod error;

/// Drive detection and enumeration.
pub mod detect;

/// THC (TESSERACT Hardware Container) format and operations.
pub mod container;

/// Hardware-specific cryptographic operations.
pub mod crypto;

/// Platform-specific implementations.
pub mod platform;

/// Self-Encrypting Drive (SED) support.
pub mod sed;

// Re-export main types
pub use error::{HardwareError, Result};
pub use detect::{
    detect_drives, eject_drive, is_thc_container, DriveInfo, DriveType,
    find_drive_for_path, check_encrypted_drive_status, is_drive_connected,
};
pub use container::{ThcHeader, CipherSuite, THC_HEADER_SIZE, THC_MAGIC, THC_VERSION};
pub use crypto::{derive_dual_keys, DualKeys, Xts256, KEY_SIZE, XTS_KEY_SIZE};
pub use platform::{is_platform_supported, platform_name, ProgressCallback};
pub use sed::{is_opal_supported, get_opal_status, OpalDrive, OpalStatus};

/// Create a new THC container on the specified device.
///
/// # Warning
///
/// This operation destroys all data on the device.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., `/dev/sdb` on Linux)
/// * `password` - Master password for encryption
/// * `progress` - Optional progress callback
///
/// # Errors
///
/// Returns an error if the device is not found, not removable, or
/// container creation fails.
pub fn create_container(
    device_path: &std::path::Path,
    password: &[u8],
    progress: Option<ProgressCallback>,
) -> Result<()> {
    platform::create_container(device_path, password, progress)
}

/// Unlock a THC container and mount it.
///
/// # Arguments
///
/// * `device_path` - Path to the device with THC container
/// * `password` - Master password for decryption
///
/// # Returns
///
/// The mount point path on success.
///
/// # Errors
///
/// Returns an error if the password is incorrect or the container
/// cannot be mounted.
pub fn unlock_container(
    device_path: &std::path::Path,
    password: &[u8],
) -> Result<std::path::PathBuf> {
    platform::unlock_container(device_path, password)
}

/// Lock a THC container and unmount it.
///
/// # Arguments
///
/// * `mount_point` - Path where the container is mounted
///
/// # Errors
///
/// Returns an error if the container is busy or cannot be unmounted.
pub fn lock_container(mount_point: &std::path::Path) -> Result<()> {
    platform::lock_container(mount_point)
}

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_platform_name() {
        let name = platform_name();
        assert!(!name.is_empty());
        #[cfg(target_os = "linux")]
        assert_eq!(name, "Linux");
        #[cfg(target_os = "windows")]
        assert_eq!(name, "Windows");
        #[cfg(target_os = "macos")]
        assert_eq!(name, "macOS");
    }

    #[test]
    fn test_is_platform_supported() {
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        assert!(is_platform_supported());
    }

    #[test]
    fn test_detect_drives() {
        // Should not panic, returns empty on unsupported/no drives
        let result = detect_drives();
        assert!(result.is_ok());
    }

    #[test]
    fn test_thc_constants() {
        assert_eq!(THC_HEADER_SIZE, 4096);
        assert_eq!(THC_VERSION, 1);
        assert_eq!(THC_MAGIC.len(), 8);
    }

    #[test]
    fn test_key_size_constants() {
        assert_eq!(KEY_SIZE, 32);
        assert_eq!(XTS_KEY_SIZE, 64);
    }
}
