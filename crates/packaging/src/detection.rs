//! Removable media detection.
//!
//! Provides cross-platform detection of removable storage devices (USB drives, SD cards)
//! versus fixed storage (internal HDD/SSD). TESSERACT requires execution from removable
//! media for security purposes.

use std::path::Path;
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during drive detection.
#[derive(Debug, Error)]
pub enum DetectionError {
    /// Failed to determine drive root from path.
    #[error("Unable to determine drive root from path: {0}")]
    InvalidPath(String),

    /// Drive type detection failed.
    #[error("Failed to detect drive type: {0}")]
    DetectionFailed(String),

    /// Application launched from fixed disk.
    #[error("TESSERACT must be run from a removable drive (USB/SD card). Current location is on a fixed disk: {0}")]
    FixedDiskExecution(String),

    /// Platform not supported for drive detection.
    #[error("Drive detection not supported on this platform")]
    UnsupportedPlatform,
}

/// Result type for detection operations.
pub type DetectionResult<T> = Result<T, DetectionError>;

/// Drive type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    /// Unknown or undetermined drive type.
    Unknown,
    /// No root directory (invalid drive).
    NoRootDir,
    /// Removable media (USB, SD card, etc.).
    Removable,
    /// Fixed disk (internal HDD/SSD).
    Fixed,
    /// Network drive.
    Remote,
    /// CD-ROM or DVD drive.
    CdRom,
    /// RAM disk.
    RamDisk,
}

impl DriveType {
    /// Returns `true` if this drive type is considered removable.
    #[must_use]
    pub const fn is_removable(self) -> bool {
        matches!(self, Self::Removable)
    }

    /// Returns `true` if this drive type is considered fixed (non-removable).
    #[must_use]
    pub const fn is_fixed(self) -> bool {
        matches!(self, Self::Fixed)
    }

    /// Returns a human-readable description of the drive type.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::NoRootDir => "No Root Directory",
            Self::Removable => "Removable Drive (USB/SD)",
            Self::Fixed => "Fixed Disk (HDD/SSD)",
            Self::Remote => "Network Drive",
            Self::CdRom => "CD-ROM/DVD Drive",
            Self::RamDisk => "RAM Disk",
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_CDROM, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK,
        DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
    };

    /// Converts a Rust path to a null-terminated wide string (UTF-16).
    fn to_wide_null(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Gets the drive root from a path (e.g., "C:\\" from "C:\\Users\\...").
    pub fn get_drive_root(path: &Path) -> DetectionResult<String> {
        // Get the canonical path first to resolve any relative paths
        let canonical = path.canonicalize().map_err(|e| {
            DetectionError::InvalidPath(format!(
                "{}: {}",
                path.display(),
                e
            ))
        })?;

        // Extract the root component
        let root = canonical
            .components()
            .next()
            .ok_or_else(|| DetectionError::InvalidPath(path.display().to_string()))?;

        // Build the drive root path (e.g., "C:\\")
        let root_str = match root {
            std::path::Component::Prefix(prefix) => {
                format!("{}\\", prefix.as_os_str().to_string_lossy())
            }
            _ => {
                return Err(DetectionError::InvalidPath(format!(
                    "Path does not have a drive prefix: {}",
                    path.display()
                )))
            }
        };

        Ok(root_str)
    }

    /// Gets the drive type for a given root path using Windows API.
    ///
    /// # Safety
    /// This function calls the Windows `GetDriveTypeW` API which is safe to call
    /// with a properly null-terminated wide string.
    pub fn get_drive_type_for_root(root_path: &str) -> DriveType {
        let wide_path = to_wide_null(OsStr::new(root_path));

        // SAFETY: GetDriveTypeW is safe to call with a null-terminated wide string.
        // It only reads from the string and does not modify it.
        let drive_type = unsafe { GetDriveTypeW(wide_path.as_ptr()) };

        debug!(
            "GetDriveTypeW({}) returned: {}",
            root_path, drive_type
        );

        match drive_type {
            DRIVE_UNKNOWN => DriveType::Unknown,
            DRIVE_NO_ROOT_DIR => DriveType::NoRootDir,
            DRIVE_REMOVABLE => DriveType::Removable,
            DRIVE_FIXED => DriveType::Fixed,
            DRIVE_REMOTE => DriveType::Remote,
            DRIVE_CDROM => DriveType::CdRom,
            DRIVE_RAMDISK => DriveType::RamDisk,
            _ => DriveType::Unknown,
        }
    }

    /// Detects the drive type for a given path.
    pub fn detect_drive_type(path: &Path) -> DetectionResult<DriveType> {
        let root = get_drive_root(path)?;
        Ok(get_drive_type_for_root(&root))
    }

    /// Checks if a path is on a removable drive.
    pub fn is_removable_drive(path: &Path) -> DetectionResult<bool> {
        let drive_type = detect_drive_type(path)?;
        Ok(drive_type.is_removable())
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::fs;

    /// Path to the sysfs block devices directory.
    const SYSFS_BLOCK: &str = "/sys/block";

    /// Path to the mount information file.
    const PROC_MOUNTS: &str = "/proc/mounts";

    /// Information about a mounted filesystem.
    #[derive(Debug, Clone)]
    pub struct MountInfo {
        /// The device path (e.g., "/dev/sda1").
        pub device: String,
        /// The mount point (e.g., "/media/usb").
        pub mount_point: String,
        /// The filesystem type (e.g., "ext4", "vfat").
        pub fs_type: String,
    }

    /// Parses /proc/mounts to find all mounted filesystems.
    fn parse_mounts() -> Vec<MountInfo> {
        let content = match fs::read_to_string(PROC_MOUNTS) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read {}: {}", PROC_MOUNTS, e);
                return Vec::new();
            }
        };

        content
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    Some(MountInfo {
                        device: parts[0].to_string(),
                        mount_point: parts[1].to_string(),
                        fs_type: parts[2].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Finds the mount info for a given path by finding the longest matching mount point.
    fn find_mount_for_path(path: &Path) -> Option<MountInfo> {
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to canonicalize path {:?}: {}", path, e);
                return None;
            }
        };

        let path_str = canonical.to_string_lossy();
        let mounts = parse_mounts();

        // Find the longest matching mount point (most specific match)
        mounts
            .into_iter()
            .filter(|m| path_str.starts_with(&m.mount_point))
            .max_by_key(|m| m.mount_point.len())
    }

    /// Extracts the block device name from a device path.
    ///
    /// For example:
    /// - "/dev/sda1" -> "sda"
    /// - "/dev/nvme0n1p1" -> "nvme0n1"
    /// - "/dev/mmcblk0p1" -> "mmcblk0"
    fn extract_block_device(device: &str) -> Option<String> {
        let device_name = device.strip_prefix("/dev/")?;

        // Handle NVMe devices (nvme0n1p1 -> nvme0n1)
        if device_name.starts_with("nvme") {
            // Format: nvmeXnYpZ - we want nvmeXnY
            if let Some(pos) = device_name.rfind('p') {
                // Check if what follows 'p' is numeric (partition number)
                let after_p = &device_name[pos + 1..];
                if !after_p.is_empty() && after_p.chars().all(|c| c.is_ascii_digit()) {
                    return Some(device_name[..pos].to_string());
                }
            }
            return Some(device_name.to_string());
        }

        // Handle MMC/SD card devices (mmcblk0p1 -> mmcblk0)
        if device_name.starts_with("mmcblk") {
            // Format: mmcblkXpY - we want mmcblkX
            if let Some(pos) = device_name.rfind('p') {
                let after_p = &device_name[pos + 1..];
                if !after_p.is_empty() && after_p.chars().all(|c| c.is_ascii_digit()) {
                    return Some(device_name[..pos].to_string());
                }
            }
            return Some(device_name.to_string());
        }

        // Handle loop devices (loop0, loop1, etc.)
        if device_name.starts_with("loop") {
            return Some(device_name.to_string());
        }

        // Handle standard block devices (sda1 -> sda, vda1 -> vda)
        // Strip trailing partition number
        let base_name: String = device_name
            .chars()
            .take_while(|c| !c.is_ascii_digit())
            .collect();

        if base_name.is_empty() {
            None
        } else {
            Some(base_name)
        }
    }

    /// Reads the removable flag from sysfs for a block device.
    ///
    /// Returns `true` if the device is removable, `false` if fixed,
    /// or `None` if the removable flag cannot be determined.
    fn read_removable_flag(block_device: &str) -> Option<bool> {
        let removable_path = format!("{}/{}/removable", SYSFS_BLOCK, block_device);
        let content = match fs::read_to_string(&removable_path) {
            Ok(c) => c,
            Err(e) => {
                debug!(
                    "Failed to read removable flag for {}: {}",
                    block_device, e
                );
                return None;
            }
        };

        match content.trim() {
            "1" => {
                debug!("Device {} is marked as removable", block_device);
                Some(true)
            }
            "0" => {
                debug!("Device {} is marked as fixed", block_device);
                Some(false)
            }
            other => {
                warn!(
                    "Unexpected removable flag value for {}: '{}'",
                    block_device, other
                );
                None
            }
        }
    }

    /// Checks if a device is a USB device by examining sysfs.
    fn is_usb_device(block_device: &str) -> bool {
        // Check the device subsystem by following symlinks
        let device_path = format!("{}/{}/device", SYSFS_BLOCK, block_device);
        let subsystem_path = format!("{}/subsystem", device_path);

        if let Ok(target) = fs::read_link(&subsystem_path) {
            let subsystem = target.file_name().map(|n| n.to_string_lossy().to_string());
            if subsystem.as_deref() == Some("usb") {
                debug!("Device {} is a USB device", block_device);
                return true;
            }
        }

        // Alternative: check if the device path contains "usb"
        if let Ok(canonical) = fs::canonicalize(&device_path) {
            let path_str = canonical.to_string_lossy();
            if path_str.contains("/usb") {
                debug!(
                    "Device {} is connected via USB (path contains /usb)",
                    block_device
                );
                return true;
            }
        }

        false
    }

    /// Checks if a device is an SD card / MMC device.
    fn is_mmc_device(block_device: &str) -> bool {
        block_device.starts_with("mmcblk")
    }

    /// Detects the drive type for a Linux block device.
    fn detect_block_device_type(block_device: &str) -> DriveType {
        // SD cards are removable
        if is_mmc_device(block_device) {
            debug!("Device {} is an MMC/SD card (removable)", block_device);
            return DriveType::Removable;
        }

        // Check the removable flag in sysfs
        if let Some(is_removable) = read_removable_flag(block_device) {
            if is_removable {
                return DriveType::Removable;
            }
        }

        // USB devices that aren't marked removable might still be removable
        // (some USB HDDs report as non-removable)
        if is_usb_device(block_device) {
            debug!(
                "Device {} is USB, treating as potentially removable",
                block_device
            );
            // Check if it's a USB flash drive vs USB HDD
            // USB flash drives typically have no rotational disk
            let rotational_path = format!("{}/{}/queue/rotational", SYSFS_BLOCK, block_device);
            if let Ok(content) = fs::read_to_string(&rotational_path) {
                if content.trim() == "0" {
                    // Non-rotational USB device - likely a flash drive
                    debug!("Device {} is non-rotational USB (likely flash drive)", block_device);
                    return DriveType::Removable;
                }
            }
            // Rotational USB device - likely external HDD, treat as fixed
            return DriveType::Fixed;
        }

        // NVMe drives are typically fixed (internal SSDs)
        if block_device.starts_with("nvme") {
            debug!("Device {} is NVMe (fixed)", block_device);
            return DriveType::Fixed;
        }

        // Loop devices are typically fixed/virtual
        if block_device.starts_with("loop") {
            debug!("Device {} is a loop device (fixed)", block_device);
            return DriveType::Fixed;
        }

        // Default to fixed for unknown devices
        debug!("Device {} type unknown, defaulting to fixed", block_device);
        DriveType::Fixed
    }

    /// Detects the drive type for a given path.
    pub fn detect_drive_type(path: &Path) -> DetectionResult<DriveType> {
        let mount = find_mount_for_path(path).ok_or_else(|| {
            DetectionError::DetectionFailed(format!(
                "Could not find mount point for path: {}",
                path.display()
            ))
        })?;

        debug!(
            "Path {} is on mount point {} (device: {}, fs: {})",
            path.display(),
            mount.mount_point,
            mount.device,
            mount.fs_type
        );

        // Handle special filesystem types
        match mount.fs_type.as_str() {
            "tmpfs" | "ramfs" => {
                debug!("Filesystem {} is a RAM-based filesystem", mount.fs_type);
                return Ok(DriveType::RamDisk);
            }
            "nfs" | "nfs4" | "cifs" | "smb" | "smbfs" | "fuse.sshfs" => {
                debug!("Filesystem {} is a network filesystem", mount.fs_type);
                return Ok(DriveType::Remote);
            }
            "iso9660" | "udf" => {
                debug!("Filesystem {} is an optical disc filesystem", mount.fs_type);
                return Ok(DriveType::CdRom);
            }
            _ => {}
        }

        // Extract the block device from the device path
        let block_device = extract_block_device(&mount.device).ok_or_else(|| {
            DetectionError::DetectionFailed(format!(
                "Could not extract block device from: {}",
                mount.device
            ))
        })?;

        Ok(detect_block_device_type(&block_device))
    }

    /// Checks if a path is on a removable drive.
    pub fn is_removable_drive(path: &Path) -> DetectionResult<bool> {
        let drive_type = detect_drive_type(path)?;
        Ok(drive_type.is_removable())
    }

    /// Gets the drive root (mount point) for a path.
    pub fn get_drive_root(path: &Path) -> DetectionResult<String> {
        let mount = find_mount_for_path(path).ok_or_else(|| {
            DetectionError::InvalidPath(format!(
                "Could not find mount point for path: {}",
                path.display()
            ))
        })?;

        Ok(mount.mount_point)
    }

    /// Information about a Linux block device.
    #[derive(Debug, Clone)]
    pub struct BlockDeviceInfo {
        /// Name of the block device (e.g., "sda").
        pub name: String,
        /// Whether the device is removable.
        pub is_removable: bool,
        /// Whether the device is a USB device.
        pub is_usb: bool,
        /// Whether the device is an MMC/SD card.
        pub is_mmc: bool,
        /// Whether the device is rotational (HDD) vs non-rotational (SSD/flash).
        pub is_rotational: Option<bool>,
        /// The device path (e.g., "/dev/sda").
        pub device_path: String,
    }

    impl BlockDeviceInfo {
        /// Creates a new `BlockDeviceInfo` by reading sysfs for a block device.
        pub fn from_name(name: &str) -> Option<Self> {
            let sysfs_path = format!("{}/{}", SYSFS_BLOCK, name);
            if !Path::new(&sysfs_path).exists() {
                return None;
            }

            let is_removable = read_removable_flag(name).unwrap_or(false);
            let is_usb = is_usb_device(name);
            let is_mmc = is_mmc_device(name);

            let rotational_path = format!("{}/queue/rotational", sysfs_path);
            let is_rotational = fs::read_to_string(&rotational_path)
                .ok()
                .map(|c| c.trim() == "1");

            Some(Self {
                name: name.to_string(),
                is_removable,
                is_usb,
                is_mmc,
                is_rotational,
                device_path: format!("/dev/{}", name),
            })
        }
    }

    /// Lists all block devices on the system.
    pub fn list_block_devices() -> Vec<BlockDeviceInfo> {
        let entries = match fs::read_dir(SYSFS_BLOCK) {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read {}: {}", SYSFS_BLOCK, e);
                return Vec::new();
            }
        };

        entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                BlockDeviceInfo::from_name(&name)
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        #[test]
        fn test_extract_block_device_sda1() {
            assert_eq!(extract_block_device("/dev/sda1"), Some("sda".to_string()));
        }

        #[test]
        fn test_extract_block_device_sda() {
            assert_eq!(extract_block_device("/dev/sda"), Some("sda".to_string()));
        }

        #[test]
        fn test_extract_block_device_sdb3() {
            assert_eq!(extract_block_device("/dev/sdb3"), Some("sdb".to_string()));
        }

        #[test]
        fn test_extract_block_device_nvme() {
            assert_eq!(
                extract_block_device("/dev/nvme0n1p1"),
                Some("nvme0n1".to_string())
            );
        }

        #[test]
        fn test_extract_block_device_nvme_no_partition() {
            assert_eq!(
                extract_block_device("/dev/nvme0n1"),
                Some("nvme0n1".to_string())
            );
        }

        #[test]
        fn test_extract_block_device_mmcblk() {
            assert_eq!(
                extract_block_device("/dev/mmcblk0p1"),
                Some("mmcblk0".to_string())
            );
        }

        #[test]
        fn test_extract_block_device_mmcblk_no_partition() {
            assert_eq!(
                extract_block_device("/dev/mmcblk0"),
                Some("mmcblk0".to_string())
            );
        }

        #[test]
        fn test_extract_block_device_loop() {
            assert_eq!(
                extract_block_device("/dev/loop0"),
                Some("loop".to_string())
            );
        }

        #[test]
        fn test_extract_block_device_vda() {
            assert_eq!(extract_block_device("/dev/vda1"), Some("vda".to_string()));
        }

        #[test]
        fn test_extract_block_device_invalid() {
            assert_eq!(extract_block_device("/dev/"), None);
            assert_eq!(extract_block_device("sda1"), None);
        }

        #[test]
        fn test_is_mmc_device() {
            assert!(is_mmc_device("mmcblk0"));
            assert!(is_mmc_device("mmcblk1"));
            assert!(!is_mmc_device("sda"));
            assert!(!is_mmc_device("nvme0n1"));
        }

        #[test]
        fn test_detect_block_device_type_mmc() {
            // MMC devices should always be removable
            assert_eq!(detect_block_device_type("mmcblk0"), DriveType::Removable);
        }

        #[test]
        fn test_detect_block_device_type_nvme() {
            // NVMe devices should be fixed (internal SSDs)
            assert_eq!(detect_block_device_type("nvme0n1"), DriveType::Fixed);
        }

        #[test]
        fn test_detect_block_device_type_loop() {
            // Loop devices should be fixed
            assert_eq!(detect_block_device_type("loop0"), DriveType::Fixed);
        }

        #[test]
        fn test_mount_info_struct() {
            let mount = MountInfo {
                device: "/dev/sda1".to_string(),
                mount_point: "/media/usb".to_string(),
                fs_type: "vfat".to_string(),
            };
            assert_eq!(mount.device, "/dev/sda1");
            assert_eq!(mount.mount_point, "/media/usb");
            assert_eq!(mount.fs_type, "vfat");
        }

        #[test]
        fn test_block_device_info_struct() {
            let info = BlockDeviceInfo {
                name: "sda".to_string(),
                is_removable: true,
                is_usb: true,
                is_mmc: false,
                is_rotational: Some(false),
                device_path: "/dev/sda".to_string(),
            };
            assert!(info.is_removable);
            assert!(info.is_usb);
            assert!(!info.is_mmc);
            assert_eq!(info.is_rotational, Some(false));
        }

        // Integration tests that use the actual system

        #[test]
        fn test_parse_mounts() {
            // This test reads the actual /proc/mounts
            let mounts = parse_mounts();
            // Should have at least the root filesystem
            assert!(!mounts.is_empty(), "Should have at least one mount point");

            // Root should be mounted
            let has_root = mounts.iter().any(|m| m.mount_point == "/");
            assert!(has_root, "Root filesystem should be mounted");
        }

        #[test]
        fn test_find_mount_for_path_root() {
            let mount = find_mount_for_path(Path::new("/"));
            assert!(mount.is_some(), "Should find mount for root");
            assert_eq!(mount.unwrap().mount_point, "/");
        }

        #[test]
        fn test_find_mount_for_path_tmp() {
            // /tmp should exist on any Linux system
            if Path::new("/tmp").exists() {
                let mount = find_mount_for_path(Path::new("/tmp"));
                assert!(mount.is_some(), "Should find mount for /tmp");
            }
        }

        #[test]
        fn test_detect_drive_type_root() {
            // Root filesystem should be detectable
            let result = detect_drive_type(Path::new("/"));
            // Depending on the system, root could be on various device types
            match result {
                Ok(drive_type) => {
                    // Should be a valid drive type
                    assert!(matches!(
                        drive_type,
                        DriveType::Fixed
                            | DriveType::Removable
                            | DriveType::Remote
                            | DriveType::RamDisk
                            | DriveType::Unknown
                    ));
                }
                Err(e) => {
                    // Some containerized environments might fail
                    debug!("Drive detection failed (may be containerized): {}", e);
                }
            }
        }

        #[test]
        fn test_detect_drive_type_tmp() {
            // /tmp is often a tmpfs (RAM disk) or on the root filesystem
            if Path::new("/tmp").exists() {
                let result = detect_drive_type(Path::new("/tmp"));
                match result {
                    Ok(drive_type) => {
                        // tmpfs should be RamDisk, otherwise it's on the underlying device
                        assert!(matches!(
                            drive_type,
                            DriveType::RamDisk | DriveType::Fixed | DriveType::Removable
                        ));
                    }
                    Err(_) => {
                        // May fail in some environments
                    }
                }
            }
        }

        #[test]
        fn test_get_drive_root_for_root() {
            let result = get_drive_root(Path::new("/"));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "/");
        }

        #[test]
        fn test_is_removable_drive_root() {
            let result = is_removable_drive(Path::new("/"));
            match result {
                Ok(is_removable) => {
                    // Root is usually not removable
                    debug!("Root is_removable: {}", is_removable);
                }
                Err(_) => {
                    // May fail in some environments
                }
            }
        }

        #[test]
        fn test_list_block_devices() {
            let devices = list_block_devices();
            // There should be at least some block devices on a typical system
            // (though this may be empty in containers)
            debug!("Found {} block devices", devices.len());
            for dev in &devices {
                debug!(
                    "  {} removable={} usb={} mmc={} rotational={:?}",
                    dev.name, dev.is_removable, dev.is_usb, dev.is_mmc, dev.is_rotational
                );
            }
        }

        // Tests for edge cases

        #[test]
        fn test_extract_block_device_xvda() {
            // Xen virtual devices
            assert_eq!(extract_block_device("/dev/xvda1"), Some("xvda".to_string()));
        }

        #[test]
        fn test_extract_block_device_hda() {
            // Old IDE devices
            assert_eq!(extract_block_device("/dev/hda1"), Some("hda".to_string()));
        }

        #[test]
        fn test_extract_block_device_dm() {
            // Device mapper devices
            assert_eq!(extract_block_device("/dev/dm-0"), Some("dm-".to_string()));
        }

        #[test]
        fn test_detect_drive_type_nonexistent() {
            let result = detect_drive_type(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_get_drive_root_nonexistent() {
            let result = get_drive_root(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use std::process::Command;

    /// Default mount point for volumes on macOS.
    const VOLUMES_PATH: &str = "/Volumes";

    /// Information parsed from diskutil output.
    #[derive(Debug, Clone, Default)]
    pub struct DiskutilInfo {
        /// Device identifier (e.g., "disk2s1").
        pub device_identifier: Option<String>,
        /// Device node path (e.g., "/dev/disk2s1").
        pub device_node: Option<String>,
        /// Volume name.
        pub volume_name: Option<String>,
        /// Mount point path.
        pub mount_point: Option<String>,
        /// Whether the device is removable.
        pub removable: Option<bool>,
        /// Whether the device is ejectable.
        pub ejectable: Option<bool>,
        /// Whether the device is internal.
        pub internal: Option<bool>,
        /// Whether the device is a network volume.
        pub network_volume: Option<bool>,
        /// Device protocol (USB, SATA, NVMe, Thunderbolt, etc.).
        pub protocol: Option<String>,
        /// Media type (e.g., "Generic", "SSD", "CD/DVD").
        pub media_type: Option<String>,
        /// Whether the device is a whole disk.
        pub whole_disk: Option<bool>,
        /// Parent whole disk (e.g., "disk2" for "disk2s1").
        pub parent_disk: Option<String>,
        /// Device/media name.
        pub device_media_name: Option<String>,
        /// Whether the volume is read-only.
        pub read_only: Option<bool>,
        /// Whether the media is a solid state device.
        pub solid_state: Option<bool>,
        /// Virtual disk indicator.
        pub virtual_disk: Option<bool>,
    }

    impl DiskutilInfo {
        /// Creates a new empty `DiskutilInfo`.
        pub fn new() -> Self {
            Self::default()
        }

        /// Determines if this device is a removable drive based on all available information.
        ///
        /// The logic handles various edge cases:
        /// - External USB drives (always removable)
        /// - External SSDs (removable even if not marked "removable")
        /// - Thunderbolt devices (external = removable)
        /// - SD cards via built-in reader (removable)
        /// - Network volumes (not removable)
        /// - Internal drives (not removable)
        #[must_use]
        pub fn is_removable_device(&self) -> bool {
            // Network volumes are not removable media
            if self.network_volume == Some(true) {
                debug!("Device is a network volume, not removable");
                return false;
            }

            // Virtual disks are not removable
            if self.virtual_disk == Some(true) {
                debug!("Device is a virtual disk, not removable");
                return false;
            }

            // If explicitly marked as removable, it's removable
            if self.removable == Some(true) {
                debug!("Device is explicitly marked as removable");
                return true;
            }

            // If ejectable, it's removable (USB drives, SD cards, etc.)
            if self.ejectable == Some(true) {
                debug!("Device is ejectable, treating as removable");
                return true;
            }

            // Check protocol for external connections
            if let Some(ref protocol) = self.protocol {
                let protocol_lower = protocol.to_lowercase();

                // USB devices are removable
                if protocol_lower.contains("usb") {
                    debug!("Device uses USB protocol, treating as removable");
                    return true;
                }

                // Thunderbolt external devices are removable
                if protocol_lower.contains("thunderbolt") {
                    // Only external Thunderbolt devices
                    if self.internal != Some(true) {
                        debug!("Device uses Thunderbolt protocol and is external, treating as removable");
                        return true;
                    }
                }

                // FireWire devices are removable
                if protocol_lower.contains("firewire") || protocol_lower.contains("ieee 1394") {
                    debug!("Device uses FireWire protocol, treating as removable");
                    return true;
                }

                // SD card reader
                if protocol_lower.contains("secure digital") || protocol_lower.contains("sd card") {
                    debug!("Device is an SD card, treating as removable");
                    return true;
                }
            }

            // Check device/media name for USB indicators
            if let Some(ref name) = self.device_media_name {
                let name_lower = name.to_lowercase();
                if name_lower.contains("usb") || name_lower.contains("flash") {
                    debug!("Device name suggests USB/flash drive, treating as removable");
                    return true;
                }
            }

            // Check media type for optical drives (CD/DVD)
            if let Some(ref media_type) = self.media_type {
                let type_lower = media_type.to_lowercase();
                if type_lower.contains("cd") || type_lower.contains("dvd") || type_lower.contains("optical") {
                    debug!("Device is optical media, treating as removable");
                    return true;
                }
            }

            // If internal is explicitly false and we haven't determined it's removable yet,
            // check if it's an external SSD (which should be removable)
            if self.internal == Some(false) {
                debug!("Device is external, treating as removable");
                return true;
            }

            // Default: internal devices are not removable
            if self.internal == Some(true) {
                debug!("Device is internal, not removable");
                return false;
            }

            // Unknown - default to not removable for safety
            debug!("Unable to determine if device is removable, defaulting to false");
            false
        }

        /// Determines the DriveType based on diskutil information.
        #[must_use]
        pub fn to_drive_type(&self) -> DriveType {
            // Network volumes
            if self.network_volume == Some(true) {
                return DriveType::Remote;
            }

            // Check for optical media
            if let Some(ref media_type) = self.media_type {
                let type_lower = media_type.to_lowercase();
                if type_lower.contains("cd") || type_lower.contains("dvd") || type_lower.contains("optical") {
                    return DriveType::CdRom;
                }
            }

            // Check protocol for optical drives
            if let Some(ref protocol) = self.protocol {
                let protocol_lower = protocol.to_lowercase();
                if protocol_lower.contains("atapi") {
                    return DriveType::CdRom;
                }
            }

            // Virtual/disk image
            if self.virtual_disk == Some(true) {
                return DriveType::RamDisk;
            }

            // Removable vs fixed
            if self.is_removable_device() {
                DriveType::Removable
            } else {
                DriveType::Fixed
            }
        }
    }

    /// Runs `diskutil info` on a path and parses the output.
    fn run_diskutil_info(path: &Path) -> DetectionResult<DiskutilInfo> {
        let path_str = path.to_string_lossy();

        let output = Command::new("diskutil")
            .args(["info", &path_str])
            .output()
            .map_err(|e| {
                DetectionError::DetectionFailed(format!(
                    "Failed to run diskutil info: {}",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DetectionError::DetectionFailed(format!(
                "diskutil info failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_diskutil_output(&stdout))
    }

    /// Runs `diskutil info` on a device identifier (e.g., "disk2").
    fn run_diskutil_info_device(device: &str) -> DetectionResult<DiskutilInfo> {
        let output = Command::new("diskutil")
            .args(["info", device])
            .output()
            .map_err(|e| {
                DetectionError::DetectionFailed(format!(
                    "Failed to run diskutil info: {}",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DetectionError::DetectionFailed(format!(
                "diskutil info failed for {}: {}",
                device,
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_diskutil_output(&stdout))
    }

    /// Parses the key-value output from `diskutil info`.
    fn parse_diskutil_output(output: &str) -> DiskutilInfo {
        let mut info = DiskutilInfo::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Split on first colon
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "Device Identifier" => {
                        info.device_identifier = Some(value.to_string());
                    }
                    "Device Node" => {
                        info.device_node = Some(value.to_string());
                    }
                    "Volume Name" => {
                        if !value.is_empty() && value != "Not applicable" {
                            info.volume_name = Some(value.to_string());
                        }
                    }
                    "Mount Point" => {
                        if !value.is_empty() && value != "Not applicable" {
                            info.mount_point = Some(value.to_string());
                        }
                    }
                    "Removable Media" | "Removable" => {
                        info.removable = parse_bool_value(value);
                    }
                    "Ejectable" => {
                        info.ejectable = parse_bool_value(value);
                    }
                    "Internal" | "Device Location" => {
                        if key == "Device Location" {
                            info.internal = Some(value.to_lowercase() == "internal");
                        } else {
                            info.internal = parse_bool_value(value);
                        }
                    }
                    "Network" => {
                        info.network_volume = parse_bool_value(value);
                    }
                    "Protocol" | "Device Protocol" => {
                        info.protocol = Some(value.to_string());
                    }
                    "Media Type" | "Medium Type" => {
                        if !value.is_empty() && value != "Not applicable" {
                            info.media_type = Some(value.to_string());
                        }
                    }
                    "Whole" => {
                        info.whole_disk = parse_bool_value(value);
                    }
                    "Part of Whole" => {
                        info.parent_disk = Some(value.to_string());
                    }
                    "Device / Media Name" | "Media Name" | "Device Name" => {
                        info.device_media_name = Some(value.to_string());
                    }
                    "Read-Only Media" | "Read-Only Volume" => {
                        info.read_only = parse_bool_value(value);
                    }
                    "Solid State" => {
                        info.solid_state = parse_bool_value(value);
                    }
                    "Virtual" => {
                        info.virtual_disk = parse_bool_value(value);
                    }
                    _ => {
                        // Ignore unknown keys
                    }
                }
            }
        }

        info
    }

    /// Parses a yes/no or true/false value from diskutil output.
    fn parse_bool_value(value: &str) -> Option<bool> {
        let value_lower = value.to_lowercase();
        match value_lower.as_str() {
            "yes" | "true" | "1" => Some(true),
            "no" | "false" | "0" => Some(false),
            _ => None,
        }
    }

    /// Finds the mount point for a given path by checking /Volumes or the path itself.
    fn find_mount_point(path: &Path) -> DetectionResult<String> {
        let canonical = path.canonicalize().map_err(|e| {
            DetectionError::InvalidPath(format!(
                "{}: {}",
                path.display(),
                e
            ))
        })?;

        let path_str = canonical.to_string_lossy();

        // Check if it's directly under /Volumes
        if path_str.starts_with(VOLUMES_PATH) {
            // Extract the volume name from /Volumes/VolumeName/...
            let after_volumes = &path_str[VOLUMES_PATH.len()..];
            if after_volumes.starts_with('/') {
                let volume_path = after_volumes[1..].split('/').next();
                if let Some(volume_name) = volume_path {
                    if !volume_name.is_empty() {
                        let mount_point = format!("{}/{}", VOLUMES_PATH, volume_name);
                        if Path::new(&mount_point).exists() {
                            return Ok(mount_point);
                        }
                    }
                }
            }
        }

        // Check if it's the root filesystem
        if path_str == "/" || path_str.starts_with('/') && !path_str.starts_with(VOLUMES_PATH) {
            // Could be the root volume or a path under root
            // Use `df` to find the mount point
            let output = Command::new("df")
                .args(["-P", &path_str])
                .output()
                .map_err(|e| {
                    DetectionError::DetectionFailed(format!(
                        "Failed to run df: {}",
                        e
                    ))
                })?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // df output format: Filesystem 512-blocks Used Available Capacity Mounted on
                // Skip header line and parse the mount point from the last column
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let mount = parts[5..].join(" ");
                        return Ok(mount);
                    }
                }
            }
        }

        // Fall back to returning the root
        Ok("/".to_string())
    }

    /// Detects the drive type for a given path.
    pub fn detect_drive_type(path: &Path) -> DetectionResult<DriveType> {
        // First try to get info directly for the path
        let info = run_diskutil_info(path);

        let info = match info {
            Ok(i) => i,
            Err(_) => {
                // Path might not be a mount point, try to find the mount point first
                let mount_point = find_mount_point(path)?;
                run_diskutil_info(Path::new(&mount_point))?
            }
        };

        // If this is a partition, also check the parent disk for more info
        if let Some(ref parent) = info.parent_disk {
            if let Ok(parent_info) = run_diskutil_info_device(parent) {
                // Merge some properties from parent disk
                let mut merged = info.clone();

                // Protocol and internal status are often only on the parent disk
                if merged.protocol.is_none() {
                    merged.protocol = parent_info.protocol;
                }
                if merged.internal.is_none() {
                    merged.internal = parent_info.internal;
                }
                if merged.device_media_name.is_none() {
                    merged.device_media_name = parent_info.device_media_name;
                }
                if merged.removable.is_none() {
                    merged.removable = parent_info.removable;
                }
                if merged.ejectable.is_none() {
                    merged.ejectable = parent_info.ejectable;
                }

                debug!(
                    "Merged info for {} from parent {}: protocol={:?}, internal={:?}",
                    path.display(),
                    parent,
                    merged.protocol,
                    merged.internal
                );

                return Ok(merged.to_drive_type());
            }
        }

        debug!(
            "Drive info for {}: removable={:?}, ejectable={:?}, internal={:?}, protocol={:?}",
            path.display(),
            info.removable,
            info.ejectable,
            info.internal,
            info.protocol
        );

        Ok(info.to_drive_type())
    }

    /// Checks if a path is on a removable drive.
    pub fn is_removable_drive(path: &Path) -> DetectionResult<bool> {
        let drive_type = detect_drive_type(path)?;
        Ok(drive_type.is_removable())
    }

    /// Gets the drive root (mount point) for a path.
    pub fn get_drive_root(path: &Path) -> DetectionResult<String> {
        find_mount_point(path)
    }

    /// Information about a macOS disk/volume.
    #[derive(Debug, Clone)]
    pub struct MacosDiskInfo {
        /// Device identifier (e.g., "disk2s1").
        pub device_identifier: String,
        /// Volume name if mounted.
        pub volume_name: Option<String>,
        /// Mount point if mounted.
        pub mount_point: Option<String>,
        /// Whether the disk is removable.
        pub is_removable: bool,
        /// Whether the disk is external.
        pub is_external: bool,
        /// Protocol (USB, Thunderbolt, SATA, NVMe, etc.).
        pub protocol: Option<String>,
        /// The detected drive type.
        pub drive_type: DriveType,
    }

    /// Lists all mounted volumes on the system.
    pub fn list_mounted_volumes() -> Vec<MacosDiskInfo> {
        let mut volumes = Vec::new();

        // Use `diskutil list` to get all disks
        let output = match Command::new("diskutil")
            .args(["list", "-plist"])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return volumes,
        };

        // Parse the plist output to get disk identifiers
        // For simplicity, we'll use `diskutil list` text output instead
        let list_output = match Command::new("diskutil")
            .arg("list")
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return volumes,
        };

        let stdout = String::from_utf8_lossy(&list_output.stdout);

        // Extract disk identifiers from the output
        for line in stdout.lines() {
            // Lines like "/dev/disk0" or "   1:    APFS Container ..."
            if line.starts_with("/dev/disk") {
                let disk = line.trim_start_matches("/dev/").split_whitespace().next();
                if let Some(disk_id) = disk {
                    if let Ok(info) = run_diskutil_info_device(disk_id) {
                        if info.mount_point.is_some() || info.whole_disk == Some(true) {
                            let disk_info = MacosDiskInfo {
                                device_identifier: disk_id.to_string(),
                                volume_name: info.volume_name,
                                mount_point: info.mount_point,
                                is_removable: info.is_removable_device(),
                                is_external: info.internal == Some(false),
                                protocol: info.protocol,
                                drive_type: info.to_drive_type(),
                            };
                            volumes.push(disk_info);
                        }
                    }
                }
            }
        }

        volumes
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        // Unit tests for parsing logic

        #[test]
        fn test_parse_bool_value_yes() {
            assert_eq!(parse_bool_value("Yes"), Some(true));
            assert_eq!(parse_bool_value("yes"), Some(true));
            assert_eq!(parse_bool_value("YES"), Some(true));
        }

        #[test]
        fn test_parse_bool_value_no() {
            assert_eq!(parse_bool_value("No"), Some(false));
            assert_eq!(parse_bool_value("no"), Some(false));
            assert_eq!(parse_bool_value("NO"), Some(false));
        }

        #[test]
        fn test_parse_bool_value_true_false() {
            assert_eq!(parse_bool_value("true"), Some(true));
            assert_eq!(parse_bool_value("false"), Some(false));
            assert_eq!(parse_bool_value("True"), Some(true));
            assert_eq!(parse_bool_value("False"), Some(false));
        }

        #[test]
        fn test_parse_bool_value_numeric() {
            assert_eq!(parse_bool_value("1"), Some(true));
            assert_eq!(parse_bool_value("0"), Some(false));
        }

        #[test]
        fn test_parse_bool_value_unknown() {
            assert_eq!(parse_bool_value("maybe"), None);
            assert_eq!(parse_bool_value(""), None);
            assert_eq!(parse_bool_value("unknown"), None);
        }

        #[test]
        fn test_parse_diskutil_output_usb_drive() {
            let output = r#"
   Device Identifier:         disk2s1
   Device Node:               /dev/disk2s1
   Whole:                     No
   Part of Whole:             disk2
   Volume Name:               USBDRIVE
   Mount Point:               /Volumes/USBDRIVE
   Removable Media:           Yes
   Ejectable:                 Yes
   Device Location:           External
   Protocol:                  USB
   Device / Media Name:       USB Flash Drive
            "#;

            let info = parse_diskutil_output(output);
            assert_eq!(info.device_identifier, Some("disk2s1".to_string()));
            assert_eq!(info.device_node, Some("/dev/disk2s1".to_string()));
            assert_eq!(info.volume_name, Some("USBDRIVE".to_string()));
            assert_eq!(info.mount_point, Some("/Volumes/USBDRIVE".to_string()));
            assert_eq!(info.removable, Some(true));
            assert_eq!(info.ejectable, Some(true));
            assert_eq!(info.internal, Some(false)); // External = not internal
            assert_eq!(info.protocol, Some("USB".to_string()));
            assert_eq!(info.parent_disk, Some("disk2".to_string()));
        }

        #[test]
        fn test_parse_diskutil_output_internal_ssd() {
            let output = r#"
   Device Identifier:         disk0s1
   Device Node:               /dev/disk0s1
   Whole:                     No
   Part of Whole:             disk0
   Volume Name:               Macintosh HD
   Mount Point:               /
   Removable Media:           No
   Ejectable:                 No
   Internal:                  Yes
   Protocol:                  Apple Fabric
   Solid State:               Yes
            "#;

            let info = parse_diskutil_output(output);
            assert_eq!(info.removable, Some(false));
            assert_eq!(info.ejectable, Some(false));
            assert_eq!(info.internal, Some(true));
            assert_eq!(info.solid_state, Some(true));
        }

        #[test]
        fn test_parse_diskutil_output_network_volume() {
            let output = r#"
   Device Identifier:         disk4
   Volume Name:               NAS Share
   Mount Point:               /Volumes/NAS Share
   Network:                   Yes
            "#;

            let info = parse_diskutil_output(output);
            assert_eq!(info.network_volume, Some(true));
        }

        #[test]
        fn test_parse_diskutil_output_thunderbolt_ssd() {
            let output = r#"
   Device Identifier:         disk3s1
   Device Node:               /dev/disk3s1
   Volume Name:               External SSD
   Mount Point:               /Volumes/External SSD
   Removable Media:           No
   Ejectable:                 Yes
   Internal:                  No
   Protocol:                  Thunderbolt
   Solid State:               Yes
            "#;

            let info = parse_diskutil_output(output);
            assert_eq!(info.removable, Some(false));
            assert_eq!(info.ejectable, Some(true));
            assert_eq!(info.internal, Some(false));
            assert_eq!(info.protocol, Some("Thunderbolt".to_string()));
        }

        #[test]
        fn test_parse_diskutil_output_sd_card() {
            let output = r#"
   Device Identifier:         disk5s1
   Volume Name:               SDCARD
   Mount Point:               /Volumes/SDCARD
   Removable Media:           Yes
   Ejectable:                 Yes
   Internal:                  Yes
   Protocol:                  Secure Digital
            "#;

            let info = parse_diskutil_output(output);
            assert_eq!(info.removable, Some(true));
            assert_eq!(info.protocol, Some("Secure Digital".to_string()));
        }

        #[test]
        fn test_diskutil_info_default() {
            let info = DiskutilInfo::new();
            assert!(info.device_identifier.is_none());
            assert!(info.mount_point.is_none());
            assert!(info.removable.is_none());
        }

        // is_removable_device tests

        #[test]
        fn test_is_removable_usb_drive() {
            let mut info = DiskutilInfo::new();
            info.removable = Some(true);
            info.protocol = Some("USB".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_ejectable() {
            let mut info = DiskutilInfo::new();
            info.ejectable = Some(true);
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_usb_protocol() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("USB".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_thunderbolt_external() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("Thunderbolt".to_string());
            info.internal = Some(false);
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_thunderbolt_internal() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("Thunderbolt".to_string());
            info.internal = Some(true);
            assert!(!info.is_removable_device());
        }

        #[test]
        fn test_is_removable_firewire() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("FireWire".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_sd_card() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("Secure Digital".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_not_removable_network() {
            let mut info = DiskutilInfo::new();
            info.network_volume = Some(true);
            assert!(!info.is_removable_device());
        }

        #[test]
        fn test_is_not_removable_virtual() {
            let mut info = DiskutilInfo::new();
            info.virtual_disk = Some(true);
            assert!(!info.is_removable_device());
        }

        #[test]
        fn test_is_not_removable_internal() {
            let mut info = DiskutilInfo::new();
            info.internal = Some(true);
            info.removable = Some(false);
            assert!(!info.is_removable_device());
        }

        #[test]
        fn test_is_removable_external_no_protocol() {
            let mut info = DiskutilInfo::new();
            info.internal = Some(false);
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_usb_in_name() {
            let mut info = DiskutilInfo::new();
            info.device_media_name = Some("SanDisk USB Drive".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_flash_in_name() {
            let mut info = DiskutilInfo::new();
            info.device_media_name = Some("Flash Memory".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_is_removable_unknown_defaults_false() {
            let info = DiskutilInfo::new();
            assert!(!info.is_removable_device());
        }

        // to_drive_type tests

        #[test]
        fn test_to_drive_type_network() {
            let mut info = DiskutilInfo::new();
            info.network_volume = Some(true);
            assert_eq!(info.to_drive_type(), DriveType::Remote);
        }

        #[test]
        fn test_to_drive_type_cdrom_media_type() {
            let mut info = DiskutilInfo::new();
            info.media_type = Some("CD-ROM".to_string());
            assert_eq!(info.to_drive_type(), DriveType::CdRom);
        }

        #[test]
        fn test_to_drive_type_dvd_media_type() {
            let mut info = DiskutilInfo::new();
            info.media_type = Some("DVD".to_string());
            assert_eq!(info.to_drive_type(), DriveType::CdRom);
        }

        #[test]
        fn test_to_drive_type_atapi_protocol() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("ATAPI".to_string());
            assert_eq!(info.to_drive_type(), DriveType::CdRom);
        }

        #[test]
        fn test_to_drive_type_virtual() {
            let mut info = DiskutilInfo::new();
            info.virtual_disk = Some(true);
            assert_eq!(info.to_drive_type(), DriveType::RamDisk);
        }

        #[test]
        fn test_to_drive_type_removable() {
            let mut info = DiskutilInfo::new();
            info.removable = Some(true);
            assert_eq!(info.to_drive_type(), DriveType::Removable);
        }

        #[test]
        fn test_to_drive_type_fixed() {
            let mut info = DiskutilInfo::new();
            info.internal = Some(true);
            info.removable = Some(false);
            assert_eq!(info.to_drive_type(), DriveType::Fixed);
        }

        // MacosDiskInfo tests

        #[test]
        fn test_macos_disk_info_struct() {
            let info = MacosDiskInfo {
                device_identifier: "disk2s1".to_string(),
                volume_name: Some("USB".to_string()),
                mount_point: Some("/Volumes/USB".to_string()),
                is_removable: true,
                is_external: true,
                protocol: Some("USB".to_string()),
                drive_type: DriveType::Removable,
            };
            assert_eq!(info.device_identifier, "disk2s1");
            assert!(info.is_removable);
            assert!(info.is_external);
        }

        // Integration tests that use actual system

        #[test]
        fn test_detect_drive_type_root() {
            let result = detect_drive_type(Path::new("/"));
            assert!(result.is_ok(), "Should detect drive type for root");
            let drive_type = result.unwrap();
            // Root is typically fixed
            assert!(matches!(
                drive_type,
                DriveType::Fixed | DriveType::Removable | DriveType::Unknown
            ));
        }

        #[test]
        fn test_get_drive_root_for_root() {
            let result = get_drive_root(Path::new("/"));
            assert!(result.is_ok());
            // Should return "/" for root
            assert_eq!(result.unwrap(), "/");
        }

        #[test]
        fn test_get_drive_root_for_tmp() {
            if Path::new("/tmp").exists() {
                let result = get_drive_root(Path::new("/tmp"));
                assert!(result.is_ok());
                // /tmp is usually under / on macOS
                let root = result.unwrap();
                assert!(!root.is_empty());
            }
        }

        #[test]
        fn test_is_removable_drive_root() {
            let result = is_removable_drive(Path::new("/"));
            assert!(result.is_ok());
            // Root is typically not removable
            let is_removable = result.unwrap();
            assert!(!is_removable, "Root should not be removable");
        }

        #[test]
        fn test_detect_drive_type_nonexistent() {
            let result = detect_drive_type(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_get_drive_root_nonexistent() {
            let result = get_drive_root(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_detect_drive_type_applications() {
            // /Applications should exist on any macOS system
            if Path::new("/Applications").exists() {
                let result = detect_drive_type(Path::new("/Applications"));
                assert!(result.is_ok());
                let drive_type = result.unwrap();
                // Internal disk
                assert!(matches!(
                    drive_type,
                    DriveType::Fixed | DriveType::Removable
                ));
            }
        }

        #[test]
        fn test_list_mounted_volumes() {
            let volumes = list_mounted_volumes();
            // Should have at least the root volume
            debug!("Found {} volumes", volumes.len());
            for vol in &volumes {
                debug!(
                    "  {} ({:?}) removable={} external={}",
                    vol.device_identifier,
                    vol.mount_point,
                    vol.is_removable,
                    vol.is_external
                );
            }
        }

        // Edge case tests

        #[test]
        fn test_parse_diskutil_empty_output() {
            let info = parse_diskutil_output("");
            assert!(info.device_identifier.is_none());
        }

        #[test]
        fn test_parse_diskutil_no_colon() {
            let info = parse_diskutil_output("This line has no colon");
            assert!(info.device_identifier.is_none());
        }

        #[test]
        fn test_parse_diskutil_not_applicable() {
            let output = r#"
   Volume Name:               Not applicable
   Mount Point:               Not applicable
            "#;
            let info = parse_diskutil_output(output);
            assert!(info.volume_name.is_none());
            assert!(info.mount_point.is_none());
        }

        #[test]
        fn test_is_removable_ieee1394() {
            let mut info = DiskutilInfo::new();
            info.protocol = Some("IEEE 1394".to_string());
            assert!(info.is_removable_device());
        }

        #[test]
        fn test_to_drive_type_optical() {
            let mut info = DiskutilInfo::new();
            info.media_type = Some("Optical".to_string());
            assert_eq!(info.to_drive_type(), DriveType::CdRom);
        }
    }
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
mod unsupported_impl {
    use super::*;

    /// Placeholder for unsupported platforms.
    pub fn detect_drive_type(_path: &Path) -> DetectionResult<DriveType> {
        Err(DetectionError::UnsupportedPlatform)
    }

    /// Placeholder for unsupported platforms.
    pub fn is_removable_drive(_path: &Path) -> DetectionResult<bool> {
        Err(DetectionError::UnsupportedPlatform)
    }

    /// Placeholder for unsupported platforms.
    pub fn get_drive_root(_path: &Path) -> DetectionResult<String> {
        Err(DetectionError::UnsupportedPlatform)
    }
}

// Re-export platform-specific implementations
#[cfg(windows)]
pub use windows_impl::*;

#[cfg(target_os = "linux")]
pub use linux_impl::*;

#[cfg(target_os = "macos")]
pub use macos_impl::*;

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub use unsupported_impl::*;

/// Information about a detected drive.
#[derive(Debug, Clone)]
pub struct DriveInfo {
    /// Path to the drive root.
    pub root_path: String,
    /// Type of the drive.
    pub drive_type: DriveType,
    /// Whether this drive is removable.
    pub is_removable: bool,
}

impl DriveInfo {
    /// Creates a new `DriveInfo` by detecting the drive type for a path.
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    pub fn from_path(path: &Path) -> DetectionResult<Self> {
        let root_path = get_drive_root(path)?;
        let drive_type = detect_drive_type(path)?;
        let is_removable = drive_type.is_removable();

        Ok(Self {
            root_path,
            drive_type,
            is_removable,
        })
    }

    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    pub fn from_path(_path: &Path) -> DetectionResult<Self> {
        Err(DetectionError::UnsupportedPlatform)
    }
}

/// Validates that the application is running from a removable drive.
///
/// This function should be called early in the application startup to ensure
/// TESSERACT is only run from removable media.
///
/// # Arguments
///
/// * `exe_path` - Path to the running executable.
///
/// # Returns
///
/// * `Ok(DriveInfo)` - If running from a removable drive, returns drive information.
/// * `Err(DetectionError::FixedDiskExecution)` - If running from a fixed disk.
///
/// # Example
///
/// ```ignore
/// use tesseract_packaging::detection::validate_removable_media;
/// use std::env;
///
/// fn main() {
///     let exe_path = env::current_exe().expect("Failed to get executable path");
///     match validate_removable_media(&exe_path) {
///         Ok(info) => println!("Running from: {}", info.root_path),
///         Err(e) => {
///             eprintln!("{}", e);
///             std::process::exit(1);
///         }
///     }
/// }
/// ```
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub fn validate_removable_media(exe_path: &Path) -> DetectionResult<DriveInfo> {
    let info = DriveInfo::from_path(exe_path)?;

    debug!(
        "Executable at '{}' is on {} ({})",
        exe_path.display(),
        info.root_path,
        info.drive_type.description()
    );

    if info.is_removable {
        Ok(info)
    } else {
        warn!(
            "Application launched from fixed disk: {} ({})",
            info.root_path,
            info.drive_type.description()
        );
        Err(DetectionError::FixedDiskExecution(info.root_path))
    }
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub fn validate_removable_media(_exe_path: &Path) -> DetectionResult<DriveInfo> {
    Err(DetectionError::UnsupportedPlatform)
}

/// Gets a user-friendly error message explaining the removable media requirement.
#[must_use]
pub fn get_fixed_disk_error_message(drive_path: &str) -> String {
    format!(
        "TESSERACT Security Requirement\n\
         ================================\n\n\
         TESSERACT must be run from a removable drive (USB flash drive or SD card).\n\n\
         Current location: {drive_path}\n\
         This appears to be a fixed disk (internal HDD/SSD).\n\n\
         To use TESSERACT:\n\
         1. Copy the TESSERACT folder to a USB flash drive or SD card\n\
         2. Run TESSERACT directly from the removable drive\n\n\
         This requirement ensures your encrypted vault remains portable and\n\
         does not leave traces on fixed storage."
    )
}

/// Checks if the current platform supports drive detection.
#[must_use]
pub const fn is_detection_supported() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drive_type_is_removable() {
        assert!(DriveType::Removable.is_removable());
        assert!(!DriveType::Fixed.is_removable());
        assert!(!DriveType::Unknown.is_removable());
        assert!(!DriveType::Remote.is_removable());
        assert!(!DriveType::CdRom.is_removable());
        assert!(!DriveType::RamDisk.is_removable());
        assert!(!DriveType::NoRootDir.is_removable());
    }

    #[test]
    fn test_drive_type_is_fixed() {
        assert!(DriveType::Fixed.is_fixed());
        assert!(!DriveType::Removable.is_fixed());
        assert!(!DriveType::Unknown.is_fixed());
        assert!(!DriveType::Remote.is_fixed());
        assert!(!DriveType::CdRom.is_fixed());
        assert!(!DriveType::RamDisk.is_fixed());
        assert!(!DriveType::NoRootDir.is_fixed());
    }

    #[test]
    fn test_drive_type_description() {
        assert_eq!(DriveType::Unknown.description(), "Unknown");
        assert_eq!(DriveType::NoRootDir.description(), "No Root Directory");
        assert_eq!(DriveType::Removable.description(), "Removable Drive (USB/SD)");
        assert_eq!(DriveType::Fixed.description(), "Fixed Disk (HDD/SSD)");
        assert_eq!(DriveType::Remote.description(), "Network Drive");
        assert_eq!(DriveType::CdRom.description(), "CD-ROM/DVD Drive");
        assert_eq!(DriveType::RamDisk.description(), "RAM Disk");
    }

    #[test]
    fn test_error_messages() {
        let msg = get_fixed_disk_error_message("C:\\");
        assert!(msg.contains("TESSERACT"));
        assert!(msg.contains("removable drive"));
        assert!(msg.contains("C:\\"));
        assert!(msg.contains("USB flash drive"));
    }

    #[test]
    fn test_is_detection_supported() {
        // This test validates the const fn works
        let supported = is_detection_supported();
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        assert!(supported);
        #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
        assert!(!supported);
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use std::env;

        #[test]
        fn test_get_drive_root_c_drive() {
            // Test with a typical Windows path
            let path = Path::new("C:\\Windows\\System32");
            if path.exists() {
                let result = get_drive_root(path);
                assert!(result.is_ok());
                let root = result.unwrap();
                assert!(root.starts_with("C:") || root.starts_with("c:"));
                assert!(root.ends_with('\\'));
            }
        }

        #[test]
        fn test_get_drive_root_current_dir() {
            let current_dir = env::current_dir().expect("Failed to get current directory");
            let result = get_drive_root(&current_dir);
            assert!(result.is_ok(), "Should detect drive root for current directory");
            let root = result.unwrap();
            assert!(root.len() >= 3, "Root should be at least 'X:\\'");
            assert!(root.ends_with('\\'));
        }

        #[test]
        fn test_detect_drive_type_current_dir() {
            let current_dir = env::current_dir().expect("Failed to get current directory");
            let result = detect_drive_type(&current_dir);
            assert!(result.is_ok(), "Should detect drive type for current directory");
            let drive_type = result.unwrap();
            // The drive type could be any of the valid types
            assert!(matches!(
                drive_type,
                DriveType::Fixed
                    | DriveType::Removable
                    | DriveType::Remote
                    | DriveType::RamDisk
                    | DriveType::Unknown
            ));
        }

        #[test]
        fn test_is_removable_drive_current_dir() {
            let current_dir = env::current_dir().expect("Failed to get current directory");
            let result = is_removable_drive(&current_dir);
            assert!(result.is_ok(), "Should determine if drive is removable");
            // Result can be true or false depending on where tests run
        }

        #[test]
        fn test_drive_info_from_path() {
            let current_dir = env::current_dir().expect("Failed to get current directory");
            let result = DriveInfo::from_path(&current_dir);
            assert!(result.is_ok());
            let info = result.unwrap();
            assert!(!info.root_path.is_empty());
            assert_eq!(info.is_removable, info.drive_type.is_removable());
        }

        #[test]
        fn test_validate_removable_media_executable() {
            let exe = env::current_exe().expect("Failed to get executable path");
            let result = validate_removable_media(&exe);
            // This test will return Ok if on removable, Err(FixedDiskExecution) if on fixed
            match result {
                Ok(info) => {
                    assert!(info.is_removable);
                    assert!(info.drive_type.is_removable());
                }
                Err(DetectionError::FixedDiskExecution(path)) => {
                    assert!(!path.is_empty());
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }

        #[test]
        fn test_get_drive_type_for_root_c_drive() {
            let drive_type = get_drive_type_for_root("C:\\");
            // C: drive is typically fixed
            assert!(matches!(
                drive_type,
                DriveType::Fixed | DriveType::Unknown | DriveType::NoRootDir
            ));
        }

        #[test]
        fn test_get_drive_type_for_root_invalid() {
            // Test with an invalid drive letter
            let drive_type = get_drive_type_for_root("Z:\\");
            // Should return NoRootDir or Unknown for non-existent drive
            assert!(matches!(
                drive_type,
                DriveType::NoRootDir | DriveType::Unknown
            ));
        }

        #[test]
        fn test_fixed_disk_error_contains_all_elements() {
            let msg = get_fixed_disk_error_message("C:\\");
            // Verify all required elements are in the message
            assert!(msg.contains("Security Requirement"));
            assert!(msg.contains("removable drive"));
            assert!(msg.contains("USB flash drive"));
            assert!(msg.contains("SD card"));
            assert!(msg.contains("C:\\"));
            assert!(msg.contains("fixed disk"));
            assert!(msg.contains("HDD/SSD"));
            assert!(msg.contains("portable"));
        }

        #[test]
        fn test_error_types() {
            // Test error display implementations
            let invalid_path = DetectionError::InvalidPath("test".to_string());
            assert!(invalid_path.to_string().contains("test"));

            let detection_failed = DetectionError::DetectionFailed("reason".to_string());
            assert!(detection_failed.to_string().contains("reason"));

            let fixed_disk = DetectionError::FixedDiskExecution("C:\\".to_string());
            assert!(fixed_disk.to_string().contains("C:\\"));
            assert!(fixed_disk.to_string().contains("removable"));

            let unsupported = DetectionError::UnsupportedPlatform;
            assert!(unsupported.to_string().contains("not supported"));
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use std::env;

        #[test]
        fn test_detect_drive_type_root() {
            let result = detect_drive_type(Path::new("/"));
            // Root should be detectable
            match result {
                Ok(drive_type) => {
                    assert!(matches!(
                        drive_type,
                        DriveType::Fixed
                            | DriveType::Removable
                            | DriveType::Remote
                            | DriveType::RamDisk
                    ));
                }
                Err(_) => {
                    // May fail in containerized environments
                }
            }
        }

        #[test]
        fn test_get_drive_root_root() {
            let result = get_drive_root(Path::new("/"));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "/");
        }

        #[test]
        fn test_get_drive_root_current_dir() {
            let current_dir = env::current_dir().expect("Failed to get current directory");
            let result = get_drive_root(&current_dir);
            assert!(result.is_ok());
        }

        #[test]
        fn test_is_removable_drive_root() {
            let result = is_removable_drive(Path::new("/"));
            // Should be Ok(bool), value depends on system
            assert!(result.is_ok());
        }

        #[test]
        fn test_drive_info_from_path_root() {
            let result = DriveInfo::from_path(Path::new("/"));
            assert!(result.is_ok());
            let info = result.unwrap();
            assert_eq!(info.root_path, "/");
            assert_eq!(info.is_removable, info.drive_type.is_removable());
        }

        #[test]
        fn test_validate_removable_media_executable() {
            let exe = env::current_exe().expect("Failed to get executable path");
            let result = validate_removable_media(&exe);
            // This test will return Ok if on removable, Err(FixedDiskExecution) if on fixed
            match result {
                Ok(info) => {
                    assert!(info.is_removable);
                    assert!(info.drive_type.is_removable());
                }
                Err(DetectionError::FixedDiskExecution(path)) => {
                    assert!(!path.is_empty());
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }

        #[test]
        fn test_detect_drive_type_nonexistent() {
            let result = detect_drive_type(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_get_drive_root_nonexistent() {
            let result = get_drive_root(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_error_types() {
            // Test error display implementations
            let invalid_path = DetectionError::InvalidPath("test".to_string());
            assert!(invalid_path.to_string().contains("test"));

            let detection_failed = DetectionError::DetectionFailed("reason".to_string());
            assert!(detection_failed.to_string().contains("reason"));

            let fixed_disk = DetectionError::FixedDiskExecution("/".to_string());
            assert!(fixed_disk.to_string().contains("/"));
            assert!(fixed_disk.to_string().contains("removable"));

            let unsupported = DetectionError::UnsupportedPlatform;
            assert!(unsupported.to_string().contains("not supported"));
        }

        #[test]
        fn test_fixed_disk_error_message_linux() {
            let msg = get_fixed_disk_error_message("/dev/sda1");
            assert!(msg.contains("TESSERACT"));
            assert!(msg.contains("removable drive"));
            assert!(msg.contains("/dev/sda1"));
        }
    }

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::*;
        use std::env;

        #[test]
        fn test_detect_drive_type_root() {
            let result = detect_drive_type(Path::new("/"));
            // Root should be detectable
            match result {
                Ok(drive_type) => {
                    assert!(matches!(
                        drive_type,
                        DriveType::Fixed
                            | DriveType::Removable
                            | DriveType::Remote
                            | DriveType::RamDisk
                    ));
                }
                Err(_) => {
                    // May fail in containerized environments
                }
            }
        }

        #[test]
        fn test_get_drive_root_root() {
            let result = get_drive_root(Path::new("/"));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "/");
        }

        #[test]
        fn test_get_drive_root_current_dir() {
            let current_dir = env::current_dir().expect("Failed to get current directory");
            let result = get_drive_root(&current_dir);
            assert!(result.is_ok());
        }

        #[test]
        fn test_is_removable_drive_root() {
            let result = is_removable_drive(Path::new("/"));
            // Should be Ok(bool), value depends on system
            assert!(result.is_ok());
            // Root is typically not removable
            assert!(!result.unwrap());
        }

        #[test]
        fn test_drive_info_from_path_root() {
            let result = DriveInfo::from_path(Path::new("/"));
            assert!(result.is_ok());
            let info = result.unwrap();
            assert_eq!(info.root_path, "/");
            assert_eq!(info.is_removable, info.drive_type.is_removable());
        }

        #[test]
        fn test_validate_removable_media_executable() {
            let exe = env::current_exe().expect("Failed to get executable path");
            let result = validate_removable_media(&exe);
            // This test will return Ok if on removable, Err(FixedDiskExecution) if on fixed
            match result {
                Ok(info) => {
                    assert!(info.is_removable);
                    assert!(info.drive_type.is_removable());
                }
                Err(DetectionError::FixedDiskExecution(path)) => {
                    assert!(!path.is_empty());
                }
                Err(e) => panic!("Unexpected error: {}", e),
            }
        }

        #[test]
        fn test_detect_drive_type_nonexistent() {
            let result = detect_drive_type(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_get_drive_root_nonexistent() {
            let result = get_drive_root(Path::new("/nonexistent/path/that/does/not/exist"));
            assert!(result.is_err());
        }

        #[test]
        fn test_error_types() {
            // Test error display implementations
            let invalid_path = DetectionError::InvalidPath("test".to_string());
            assert!(invalid_path.to_string().contains("test"));

            let detection_failed = DetectionError::DetectionFailed("reason".to_string());
            assert!(detection_failed.to_string().contains("reason"));

            let fixed_disk = DetectionError::FixedDiskExecution("/".to_string());
            assert!(fixed_disk.to_string().contains("/"));
            assert!(fixed_disk.to_string().contains("removable"));

            let unsupported = DetectionError::UnsupportedPlatform;
            assert!(unsupported.to_string().contains("not supported"));
        }

        #[test]
        fn test_fixed_disk_error_message_macos() {
            let msg = get_fixed_disk_error_message("/Volumes/Macintosh HD");
            assert!(msg.contains("TESSERACT"));
            assert!(msg.contains("removable drive"));
            assert!(msg.contains("/Volumes/Macintosh HD"));
        }
    }

    #[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
    mod unsupported_tests {
        use super::*;

        #[test]
        fn test_detect_drive_type_unsupported() {
            let path = Path::new("/tmp");
            let result = detect_drive_type(path);
            assert!(matches!(result, Err(DetectionError::UnsupportedPlatform)));
        }

        #[test]
        fn test_is_removable_drive_unsupported() {
            let path = Path::new("/tmp");
            let result = is_removable_drive(path);
            assert!(matches!(result, Err(DetectionError::UnsupportedPlatform)));
        }

        #[test]
        fn test_get_drive_root_unsupported() {
            let path = Path::new("/tmp");
            let result = get_drive_root(path);
            assert!(matches!(result, Err(DetectionError::UnsupportedPlatform)));
        }

        #[test]
        fn test_validate_removable_media_unsupported() {
            let path = Path::new("/usr/bin/test");
            let result = validate_removable_media(path);
            assert!(matches!(result, Err(DetectionError::UnsupportedPlatform)));
        }

        #[test]
        fn test_drive_info_from_path_unsupported() {
            let path = Path::new("/tmp");
            let result = DriveInfo::from_path(path);
            assert!(matches!(result, Err(DetectionError::UnsupportedPlatform)));
        }
    }
}
