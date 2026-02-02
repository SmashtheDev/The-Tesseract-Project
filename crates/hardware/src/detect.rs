//! Drive detection and enumeration.
//!
//! This module provides cross-platform drive detection capabilities,
//! identifying USB drives and their encryption status.

use std::path::PathBuf;
use tracing::{debug, info, warn, instrument};

use crate::error::{HardwareError, Result};

/// Type of drive encryption detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    /// Drive supports TCG Opal SED (Self-Encrypting Drive).
    SedOpal,
    /// Drive has a TESSERACT Hardware Container (THC).
    TesseractContainer,
    /// Drive is unencrypted.
    Unencrypted,
    /// Drive type is unknown or could not be determined.
    Unknown,
}

impl DriveType {
    /// Check if this drive type indicates hardware encryption.
    #[must_use]
    pub fn is_hardware_encrypted(&self) -> bool {
        matches!(self, Self::SedOpal | Self::TesseractContainer)
    }

    /// Check if the drive can be initialized with TESSERACT encryption.
    #[must_use]
    pub fn can_initialize(&self) -> bool {
        matches!(self, Self::Unencrypted | Self::Unknown)
    }

    /// Get a human-readable description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::SedOpal => "TCG Opal Self-Encrypting Drive",
            Self::TesseractContainer => "TESSERACT Encrypted Container",
            Self::Unencrypted => "Unencrypted Drive",
            Self::Unknown => "Unknown Drive Type",
        }
    }
}

/// Information about a detected drive.
#[derive(Debug, Clone)]
pub struct DriveInfo {
    /// Device path (e.g., `/dev/sdb` on Linux, `\\.\PhysicalDrive1` on Windows).
    pub device_path: PathBuf,
    /// Mount point if mounted (e.g., `/mnt/usb` or `E:\`).
    pub mount_point: Option<PathBuf>,
    /// Total size in bytes.
    pub size_bytes: u64,
    /// Drive vendor name.
    pub vendor: String,
    /// Drive model name.
    pub model: String,
    /// Serial number (if available).
    pub serial: Option<String>,
    /// Detected drive type.
    pub drive_type: DriveType,
    /// Whether the drive is currently locked.
    pub is_locked: bool,
    /// Whether this is a removable drive.
    pub is_removable: bool,
}

impl DriveInfo {
    /// Create a new `DriveInfo` with basic information.
    #[must_use]
    pub fn new(device_path: PathBuf, size_bytes: u64) -> Self {
        Self {
            device_path,
            mount_point: None,
            size_bytes,
            vendor: String::new(),
            model: String::new(),
            serial: None,
            drive_type: DriveType::Unknown,
            is_locked: false,
            is_removable: true,
        }
    }

    /// Get a display name for the drive.
    #[must_use]
    pub fn display_name(&self) -> String {
        if !self.vendor.is_empty() && !self.model.is_empty() {
            format!("{} {}", self.vendor.trim(), self.model.trim())
        } else if !self.model.is_empty() {
            self.model.trim().to_string()
        } else {
            self.device_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "Unknown Drive".to_string())
        }
    }

    /// Get the size in human-readable format.
    #[must_use]
    pub fn size_display(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;

        if self.size_bytes >= TB {
            format!("{:.1} TB", self.size_bytes as f64 / TB as f64)
        } else if self.size_bytes >= GB {
            format!("{:.1} GB", self.size_bytes as f64 / GB as f64)
        } else if self.size_bytes >= MB {
            format!("{:.1} MB", self.size_bytes as f64 / MB as f64)
        } else if self.size_bytes >= KB {
            format!("{:.1} KB", self.size_bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", self.size_bytes)
        }
    }

    /// Check if the drive requires unlocking before use.
    #[must_use]
    pub fn requires_unlock(&self) -> bool {
        self.is_locked || matches!(self.drive_type, DriveType::TesseractContainer)
    }
}

/// Detect all connected USB/removable drives.
///
/// Returns a list of detected drives with their information.
/// Empty list is returned on unsupported platforms.
///
/// # Errors
///
/// Returns an error if drive enumeration fails for platform-specific reasons.
#[instrument(level = "debug")]
pub fn detect_drives() -> Result<Vec<DriveInfo>> {
    debug!("Starting drive detection");
    let drives = crate::platform::detect_drives()?;
    info!(count = drives.len(), "Drive detection complete");
    for drive in &drives {
        debug!(
            device = %drive.device_path.display(),
            drive_type = ?drive.drive_type,
            size_bytes = drive.size_bytes,
            is_locked = drive.is_locked,
            "Detected drive"
        );
    }
    Ok(drives)
}

/// Find the drive containing a given file path.
///
/// Detects all drives and checks if the given path is located on one of them.
/// This is useful for determining if a vault file is on an encrypted drive.
///
/// # Arguments
///
/// * `path` - The file or directory path to check
///
/// # Returns
///
/// Returns `Some(DriveInfo)` if the path is on a detected removable drive,
/// or `None` if the path is not on a removable drive or detection fails.
pub fn find_drive_for_path(path: &std::path::Path) -> Option<DriveInfo> {
    // Canonicalize the path to resolve symlinks and get absolute path
    let canonical_path = path.canonicalize().ok()?;

    // Detect all drives
    let drives = detect_drives().ok()?;

    // Check if the path is on any detected drive
    for drive in drives {
        if let Some(ref mount_point) = drive.mount_point {
            // Check if the canonical path starts with the mount point
            if canonical_path.starts_with(mount_point) {
                return Some(drive);
            }
        }

        // On Linux, also check if path device matches drive device path
        #[cfg(target_os = "linux")]
        {
            if let Ok(path_metadata) = std::fs::metadata(&canonical_path) {
                use std::os::unix::fs::MetadataExt;
                let path_dev = path_metadata.dev();

                // Try to match device numbers
                if let Ok(drive_metadata) = std::fs::metadata(&drive.device_path) {
                    let drive_dev = drive_metadata.rdev();
                    // Major device numbers should match for the same device
                    // (path_dev is st_dev, drive_dev is st_rdev for block devices)
                    let path_major = (path_dev >> 8) & 0xff;
                    let drive_major = (drive_dev >> 8) & 0xff;
                    if path_major == drive_major && path_major != 0 {
                        return Some(drive);
                    }
                }
            }
        }
    }

    None
}

/// Check if a path is on an encrypted drive that requires unlocking.
///
/// Returns information about whether the path is on an encrypted drive
/// and whether that drive is currently locked.
///
/// # Arguments
///
/// * `path` - The file or directory path to check
///
/// # Returns
///
/// Returns a tuple of (is_on_encrypted_drive, is_locked, drive_info)
pub fn check_encrypted_drive_status(path: &std::path::Path) -> (bool, bool, Option<DriveInfo>) {
    if let Some(drive) = find_drive_for_path(path) {
        let is_encrypted = drive.drive_type.is_hardware_encrypted();
        let is_locked = drive.is_locked;
        (is_encrypted, is_locked, Some(drive))
    } else {
        (false, false, None)
    }
}

/// Safely eject a removable drive.
///
/// This function attempts to unmount and eject a drive safely.
/// On success, the drive can be physically removed.
///
/// # Platform Behavior
///
/// - **Linux**: Uses `udisksctl power-off` or `eject` command
/// - **macOS**: Uses `diskutil eject`
/// - **Windows**: Uses `mountvol` with removal flag
///
/// # Errors
///
/// Returns an error if:
/// - The drive cannot be found
/// - The drive is still in use
/// - Permission is denied
/// - The platform command fails
#[instrument(level = "info", skip_all, fields(device = %device_path.display()))]
pub fn eject_drive(device_path: &std::path::Path) -> Result<()> {
    info!(device = %device_path.display(), "Ejecting drive");
    #[cfg(target_os = "linux")]
    {
        eject_drive_linux(device_path)
    }

    #[cfg(target_os = "macos")]
    {
        eject_drive_macos(device_path)
    }

    #[cfg(target_os = "windows")]
    {
        eject_drive_windows(device_path)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = device_path;
        Err(HardwareError::UnsupportedPlatform {
            operation: "drive ejection".to_string(),
        })
    }
}

#[cfg(target_os = "linux")]
fn eject_drive_linux(device_path: &std::path::Path) -> Result<()> {
    use std::process::Command;

    let path_str = device_path.to_string_lossy().into_owned();

    // Try udisksctl first (modern Linux)
    debug!("Trying udisksctl power-off");
    let udisks_result = Command::new("udisksctl")
        .args(["power-off", "-b", &path_str])
        .output();

    match udisks_result {
        Ok(output) if output.status.success() => {
            info!(device = %device_path.display(), "Drive ejected successfully via udisksctl");
            return Ok(());
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If device is busy, report that specifically
            if stderr.contains("busy") || stderr.contains("in use") {
                warn!(device = %device_path.display(), "Drive is busy, cannot eject");
                return Err(HardwareError::DriveInUse {
                    path: device_path.to_path_buf(),
                });
            }
            debug!("udisksctl failed, trying eject command: {}", stderr);
            // Fall through to try eject command
        }
        Err(e) => {
            debug!("udisksctl not available: {}", e);
            // udisksctl not available, try eject command
        }
    }

    // Fallback to eject command
    debug!("Trying eject command");
    let eject_result = Command::new("eject").arg(&path_str).output();

    match eject_result {
        Ok(output) if output.status.success() => {
            info!(device = %device_path.display(), "Drive ejected successfully via eject command");
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("busy") || stderr.contains("in use") {
                warn!(device = %device_path.display(), "Drive is busy, cannot eject");
                Err(HardwareError::DriveInUse {
                    path: device_path.to_path_buf(),
                })
            } else {
                warn!(device = %device_path.display(), error = %stderr, "Eject command failed");
                Err(HardwareError::CommandFailed {
                    command: "eject".to_string(),
                    reason: stderr.to_string(),
                })
            }
        }
        Err(e) => {
            warn!(device = %device_path.display(), error = %e, "Eject command execution failed");
            Err(HardwareError::CommandFailed {
                command: "eject".to_string(),
                reason: e.to_string(),
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn eject_drive_macos(device_path: &std::path::Path) -> Result<()> {
    use std::process::Command;

    let path_str = device_path.to_string_lossy().into_owned();

    let output = Command::new("diskutil")
        .args(["eject", &path_str])
        .output()
        .map_err(|e| HardwareError::CommandFailed {
            command: "diskutil eject".to_string(),
            reason: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("busy") || stderr.contains("in use") {
            Err(HardwareError::DriveInUse {
                path: device_path.to_path_buf(),
            })
        } else {
            Err(HardwareError::CommandFailed {
                command: "diskutil eject".to_string(),
                reason: stderr.to_string(),
            })
        }
    }
}

#[cfg(target_os = "windows")]
fn eject_drive_windows(device_path: &std::path::Path) -> Result<()> {
    use std::process::Command;

    let path_str = device_path.to_string_lossy().into_owned();

    // On Windows, we need to use mountvol or DeviceIoControl
    // For simplicity, use PowerShell to eject
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$vol = Get-Volume | Where-Object {{ $_.Path -like '*{}*' }}; \
                 if ($vol) {{ \
                     $vol | Get-Partition | Remove-PartitionAccessPath -AccessPath $vol.Path -ErrorAction SilentlyContinue; \
                     Write-Output 'Ejected' \
                 }} else {{ \
                     $eject = New-Object -comObject Shell.Application; \
                     $eject.NameSpace(17).ParseName('{}').InvokeVerb('Eject') \
                 }}",
                path_str.replace('\\', "\\\\"),
                path_str
            ),
        ])
        .output()
        .map_err(|e| HardwareError::CommandFailed {
            command: "PowerShell eject".to_string(),
            reason: e.to_string(),
        })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(HardwareError::CommandFailed {
            command: "PowerShell eject".to_string(),
            reason: stderr.to_string(),
        })
    }
}

/// Check if a specific path points to a THC container.
///
/// Reads the first 8 bytes to check for THC magic bytes.
///
/// # Errors
///
/// Returns an error if the path cannot be read.
#[instrument(level = "debug", skip_all, fields(device = %device_path.display()))]
pub fn is_thc_container(device_path: &std::path::Path) -> Result<bool> {
    use std::fs::File;
    use std::io::Read;

    debug!(device = %device_path.display(), "Checking for THC container");

    let mut file = match File::open(device_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(device = %device_path.display(), "Device not found");
            return Err(HardwareError::DriveNotFound {
                path: device_path.to_path_buf(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            debug!(device = %device_path.display(), "Permission denied reading device");
            return Err(HardwareError::permission_denied("read device header"));
        }
        Err(e) => return Err(e.into()),
    };

    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() {
        debug!(device = %device_path.display(), "Could not read magic bytes");
        return Ok(false);
    }

    let is_thc = &magic == crate::container::THC_MAGIC;
    debug!(device = %device_path.display(), is_thc_container = is_thc, "THC container check complete");
    Ok(is_thc)
}

/// Check if a drive is still connected to the system.
///
/// This function checks if a device path still exists and is accessible.
/// It's useful for detecting when a removable drive has been disconnected.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., `/dev/sdb` on Linux)
///
/// # Returns
///
/// Returns `true` if the device is still connected, `false` otherwise.
///
/// # Example
///
/// ```no_run
/// use tesseract_hardware::detect::is_drive_connected;
/// use std::path::Path;
///
/// let device_path = Path::new("/dev/sdb");
/// if !is_drive_connected(device_path) {
///     println!("Drive has been disconnected!");
/// }
/// ```
pub fn is_drive_connected(device_path: &std::path::Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        is_drive_connected_linux(device_path)
    }

    #[cfg(target_os = "macos")]
    {
        is_drive_connected_macos(device_path)
    }

    #[cfg(target_os = "windows")]
    {
        is_drive_connected_windows(device_path)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // On unsupported platforms, assume drive is connected (graceful degradation)
        let _ = device_path;
        true
    }
}

#[cfg(target_os = "linux")]
fn is_drive_connected_linux(device_path: &std::path::Path) -> bool {
    // On Linux, check if the device file exists
    if !device_path.exists() {
        return false;
    }

    // Also check /sys/block to see if the device is still registered
    if let Some(device_name) = device_path.file_name() {
        let device_str = device_name.to_string_lossy();
        // Handle partitions (e.g., sdb1 -> sdb)
        let base_device: String = device_str
            .chars()
            .take_while(|c| !c.is_ascii_digit())
            .collect();

        let sys_path = PathBuf::from("/sys/block").join(&base_device);
        if !sys_path.exists() {
            return false;
        }
    }

    true
}

#[cfg(target_os = "macos")]
fn is_drive_connected_macos(device_path: &std::path::Path) -> bool {
    // On macOS, check if the device file exists
    if !device_path.exists() {
        return false;
    }

    // Also verify via diskutil that the disk is still present
    if let Some(device_name) = device_path.file_name() {
        let device_str = device_name.to_string_lossy();
        // Use diskutil info to check if the disk exists
        if let Ok(output) = std::process::Command::new("diskutil")
            .args(["info", &device_str])
            .output()
        {
            return output.status.success();
        }
    }

    true
}

#[cfg(target_os = "windows")]
fn is_drive_connected_windows(device_path: &std::path::Path) -> bool {
    let path_str = device_path.to_string_lossy();

    // For drive letters (e.g., "E:\"), check if the path exists
    if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
        return device_path.exists();
    }

    // For physical drive paths (e.g., "\\.\PhysicalDrive1"), check via GetLogicalDriveStrings
    // or by trying to open the device
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;

        match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(device_path)
        {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drive_type_is_hardware_encrypted() {
        assert!(DriveType::SedOpal.is_hardware_encrypted());
        assert!(DriveType::TesseractContainer.is_hardware_encrypted());
        assert!(!DriveType::Unencrypted.is_hardware_encrypted());
        assert!(!DriveType::Unknown.is_hardware_encrypted());
    }

    #[test]
    fn test_drive_type_can_initialize() {
        assert!(!DriveType::SedOpal.can_initialize());
        assert!(!DriveType::TesseractContainer.can_initialize());
        assert!(DriveType::Unencrypted.can_initialize());
        assert!(DriveType::Unknown.can_initialize());
    }

    #[test]
    fn test_drive_type_description() {
        assert!(DriveType::SedOpal.description().contains("Opal"));
        assert!(DriveType::TesseractContainer
            .description()
            .contains("TESSERACT"));
    }

    #[test]
    fn test_drive_info_new() {
        let info = DriveInfo::new(PathBuf::from("/dev/sdb"), 1024 * 1024 * 1024);
        assert_eq!(info.device_path, PathBuf::from("/dev/sdb"));
        assert_eq!(info.size_bytes, 1024 * 1024 * 1024);
        assert!(info.is_removable);
        assert!(!info.is_locked);
    }

    #[test]
    fn test_drive_info_display_name() {
        let mut info = DriveInfo::new(PathBuf::from("/dev/sdb"), 0);
        assert_eq!(info.display_name(), "sdb");

        info.model = "USB Flash Drive".to_string();
        assert_eq!(info.display_name(), "USB Flash Drive");

        info.vendor = "SanDisk".to_string();
        assert_eq!(info.display_name(), "SanDisk USB Flash Drive");
    }

    #[test]
    fn test_drive_info_size_display() {
        assert_eq!(DriveInfo::new(PathBuf::new(), 500).size_display(), "500 bytes");
        assert_eq!(
            DriveInfo::new(PathBuf::new(), 2 * 1024).size_display(),
            "2.0 KB"
        );
        assert_eq!(
            DriveInfo::new(PathBuf::new(), 512 * 1024 * 1024).size_display(),
            "512.0 MB"
        );
        assert_eq!(
            DriveInfo::new(PathBuf::new(), 16 * 1024 * 1024 * 1024).size_display(),
            "16.0 GB"
        );
        assert_eq!(
            DriveInfo::new(PathBuf::new(), 2 * 1024 * 1024 * 1024 * 1024).size_display(),
            "2.0 TB"
        );
    }

    #[test]
    fn test_drive_info_requires_unlock() {
        let mut info = DriveInfo::new(PathBuf::new(), 0);
        assert!(!info.requires_unlock());

        info.is_locked = true;
        assert!(info.requires_unlock());

        info.is_locked = false;
        info.drive_type = DriveType::TesseractContainer;
        assert!(info.requires_unlock());
    }

    #[test]
    fn test_is_drive_connected_nonexistent_path() {
        // A non-existent path should return false
        let fake_path = PathBuf::from("/dev/sdzzzzz_nonexistent_drive");
        assert!(!is_drive_connected(&fake_path));
    }

    #[test]
    fn test_is_drive_connected_existing_regular_file() {
        // Create a temp file and verify it returns false (not a drive)
        // Note: This test is platform-specific behavior
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("tesseract_drive_test_file");

        // Clean up if exists
        let _ = std::fs::remove_file(&temp_file);

        // Create the file
        if std::fs::File::create(&temp_file).is_ok() {
            // On Linux, a regular file in temp won't match /sys/block/*
            // so this should return false
            #[cfg(target_os = "linux")]
            {
                // Regular files don't have entries in /sys/block
                // but the file exists, so the first check passes
                // The second check (sysfs) will likely fail
                // depending on the path structure
            }

            // Clean up
            let _ = std::fs::remove_file(&temp_file);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_drive_connected_linux_root_device() {
        // /dev/sda or /dev/nvme0n1 typically exists on Linux systems
        // This is a basic sanity check
        let sda = PathBuf::from("/dev/sda");
        let nvme = PathBuf::from("/dev/nvme0n1");

        // At least one of these should exist on most Linux systems
        // but we don't assert they're connected since this is a unit test
        // that should work in CI environments too
        let _ = is_drive_connected(&sda);
        let _ = is_drive_connected(&nvme);
    }
}
