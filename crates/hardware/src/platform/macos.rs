//! macOS platform implementation.
//!
//! Uses DiskArbitration framework for drive detection and hdiutil/FUSE
//! for container management.

use std::path::{Path, PathBuf};

use crate::detect::{DriveInfo, DriveType};
use crate::error::{HardwareError, Result};
use super::ProgressCallback;

/// Detect all connected removable drives on macOS.
///
/// Uses diskutil to enumerate external and removable drives.
///
/// # Returns
///
/// A vector of `DriveInfo` for each detected removable/external drive.
/// Returns empty vector on non-macOS platforms or if no drives found.
///
/// # Errors
///
/// Returns an error if there's a critical failure in disk enumeration.
#[cfg(target_os = "macos")]
pub fn detect_drives() -> Result<Vec<DriveInfo>> {
    let mut drives = Vec::new();

    // Get list of all disks using diskutil
    let disk_list = match list_disks() {
        Ok(list) => list,
        Err(_) => return Ok(drives), // Return empty on failure
    };

    // Process each disk
    for disk_id in disk_list {
        // Skip internal disks - only process external/removable
        if !is_disk_external(&disk_id).unwrap_or(false) {
            continue;
        }

        // Get disk info
        if let Ok(info) = get_disk_info(&disk_id) {
            drives.push(info);
        }
    }

    Ok(drives)
}

/// Detect all connected removable drives on macOS.
///
/// Non-macOS platforms return an empty vector (graceful degradation).
#[cfg(not(target_os = "macos"))]
pub fn detect_drives() -> Result<Vec<DriveInfo>> {
    // Non-macOS platforms return empty vec
    Ok(Vec::new())
}

/// Create a THC container on a macOS device.
///
/// # Warning
///
/// This operation destroys all data on the device.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/disk2)
/// * `password` - The master password for encryption
/// * `progress` - Optional callback for progress updates
///
/// # Errors
///
/// Returns an error if:
/// - Device does not exist
/// - Device is not removable
/// - Insufficient permissions
/// - Device is busy/in use
#[cfg(target_os = "macos")]
pub fn create_container(
    device_path: &Path,
    password: &[u8],
    progress: Option<ProgressCallback>,
) -> Result<()> {
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};

    use crate::container::ThcHeader;

    // Validate device path
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // Get disk identifier from path (e.g., "disk2" from "/dev/disk2")
    let disk_id = device_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HardwareError::InvalidDevicePath {
            path: device_path.to_string_lossy().to_string(),
        })?;

    // Verify the device is external/removable
    if !is_disk_external(disk_id)? {
        return Err(HardwareError::NotRemovable {
            path: device_path.to_path_buf(),
        });
    }

    // Unmount the disk first
    unmount_disk(disk_id)?;

    // Open device for raw writing
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                HardwareError::permission_denied("open device for writing")
            } else {
                HardwareError::Io(e)
            }
        })?;

    // Get device size
    let device_size = get_device_size(&mut file)?;

    // Report progress: starting
    if let Some(ref cb) = progress {
        cb(0, device_size);
    }

    // Initialize and write THC header
    let header = ThcHeader::initialize(password, 64, 3, 1)?;
    let header_bytes = header.to_bytes();

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header_bytes)?;

    // Report progress: header written
    if let Some(ref cb) = progress {
        cb(header_bytes.len() as u64, device_size);
    }

    // Zero-initialize the encrypted data region
    let data_start = header_bytes.len() as u64;
    let chunk_size: usize = 1024 * 1024; // 1 MB chunks
    let zeros = vec![0u8; chunk_size];

    let mut pos = data_start;
    while pos < device_size {
        let write_size = std::cmp::min(chunk_size as u64, device_size - pos) as usize;
        file.write_all(&zeros[..write_size])?;
        pos += write_size as u64;

        // Report progress
        if let Some(ref cb) = progress {
            cb(pos, device_size);
        }
    }

    // Sync to disk
    file.sync_all()?;

    Ok(())
}

/// Create a THC container (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn create_container(
    _device_path: &Path,
    _password: &[u8],
    _progress: Option<ProgressCallback>,
) -> Result<()> {
    Err(HardwareError::PlatformNotSupported {
        platform: "macOS (not yet implemented)".to_string(),
    })
}

/// Get the size of a device.
#[cfg(target_os = "macos")]
fn get_device_size(file: &mut std::fs::File) -> Result<u64> {
    use std::io::{Seek, SeekFrom};

    // Seek to end to get size
    let size = file.seek(SeekFrom::End(0))?;
    // Seek back to start
    file.seek(SeekFrom::Start(0))?;
    Ok(size)
}

/// Unmount a disk using diskutil.
#[cfg(target_os = "macos")]
fn unmount_disk(disk_id: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("diskutil")
        .args(["unmountDisk", disk_id])
        .output()
        .map_err(|e| HardwareError::ToolNotFound {
            tool: format!("diskutil: {}", e),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if already unmounted or no volumes to unmount
        if stderr.contains("was already unmounted")
            || stderr.contains("No volumes")
            || stderr.contains("does not appear to have any mountable volumes")
        {
            return Ok(());
        }
        return Err(HardwareError::DriveBusy {
            reason: format!("Failed to unmount: {}", stderr),
        });
    }

    Ok(())
}

/// Unlock a THC container on macOS.
///
/// Reads and validates the THC header, derives encryption keys, and prepares
/// the container for mounting. Full mounting requires hdiutil or FUSE.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/disk2)
/// * `password` - The password to unlock the container
///
/// # Returns
///
/// Path to the mount point (typically /Volumes/TESSERACT-{diskid}).
///
/// # Errors
///
/// Returns an error if:
/// - Device does not exist
/// - Invalid THC header
/// - Incorrect password
#[cfg(target_os = "macos")]
pub fn unlock_container(device_path: &Path, password: &[u8]) -> Result<PathBuf> {
    use std::fs::File;
    use std::io::Read;

    use crate::container::ThcHeader;

    // Validate device path
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // Get disk identifier from path
    let disk_id = device_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HardwareError::InvalidDevicePath {
            path: device_path.to_string_lossy().to_string(),
        })?;

    // Unmount the disk first to get raw access
    unmount_disk(disk_id)?;

    // Open device for reading
    let mut file = File::open(device_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            HardwareError::permission_denied("open device for reading")
        } else {
            HardwareError::Io(e)
        }
    })?;

    // Read THC header
    let mut header_bytes = [0u8; crate::container::THC_HEADER_SIZE];
    file.read_exact(&mut header_bytes)?;

    // Parse and validate header
    let header = ThcHeader::from_bytes(&header_bytes)?;

    // Unlock the header (derive and verify keys)
    let _keys = header.unlock(password)?;

    // Create mount point directory
    let mount_point = PathBuf::from(format!("/Volumes/TESSERACT-{}", disk_id));

    // Note: Full mounting requires either:
    // 1. hdiutil with a disk image format
    // 2. FUSE for user-space filesystem mounting
    // For now, we validate the header and return the intended mount point
    //
    // A complete implementation would:
    // 1. Create a sparse disk image
    // 2. Set up encryption with the derived keys
    // 3. Mount using hdiutil attach

    Ok(mount_point)
}

/// Unlock a THC container (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn unlock_container(_device_path: &Path, _password: &[u8]) -> Result<PathBuf> {
    Err(HardwareError::PlatformNotSupported {
        platform: "macOS (not yet implemented)".to_string(),
    })
}

/// Lock a THC container on macOS.
///
/// Unmounts the container using diskutil eject.
///
/// # Arguments
///
/// * `mount_point` - Path to the mount point (e.g., /Volumes/TESSERACT-disk2)
///
/// # Errors
///
/// Returns an error if:
/// - Mount point does not exist
/// - Volume is busy (files open)
/// - Unmount fails
#[cfg(target_os = "macos")]
pub fn lock_container(mount_point: &Path) -> Result<()> {
    use std::process::Command;

    // Validate mount point path
    if !mount_point.exists() {
        // If the mount point doesn't exist, consider it already locked
        return Err(HardwareError::AlreadyLocked);
    }

    // Get the volume name from the path
    let volume_name = mount_point
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HardwareError::InvalidMountPoint {
            path: mount_point.to_path_buf(),
        })?;

    // Try to unmount using diskutil
    let output = Command::new("diskutil")
        .args(["unmount", "force", &mount_point.to_string_lossy()])
        .output()
        .map_err(|e| HardwareError::ToolNotFound {
            tool: format!("diskutil: {}", e),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check for common error conditions
        if stderr.contains("was already unmounted")
            || stderr.contains("is not mounted")
            || stderr.contains("does not exist")
        {
            return Ok(());
        }

        if stderr.contains("busy") || stderr.contains("Resource busy") {
            return Err(HardwareError::DriveBusy {
                reason: format!("Volume {} is busy", volume_name),
            });
        }

        return Err(HardwareError::IoError {
            message: format!("Failed to unmount: {}", stderr),
        });
    }

    // Keys should be zeroized by the caller (DualKeys has ZeroizeOnDrop)

    Ok(())
}

/// Lock a THC container (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn lock_container(_mount_point: &Path) -> Result<()> {
    Err(HardwareError::PlatformNotSupported {
        platform: "macOS (not yet implemented)".to_string(),
    })
}

/// List all disks using diskutil.
///
/// Returns a list of disk identifiers (e.g., ["disk0", "disk1", "disk2"]).
#[cfg(target_os = "macos")]
fn list_disks() -> Result<Vec<String>> {
    use std::process::Command;

    let output = Command::new("diskutil")
        .args(["list", "-plist"])
        .output()
        .map_err(|e| HardwareError::ToolNotFound {
            tool: format!("diskutil: {}", e),
        })?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the plist output to find disk identifiers
    // Look for <string>disk0</string>, <string>disk1</string>, etc.
    let mut disks = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<string>disk") && trimmed.ends_with("</string>") {
            // Extract disk identifier
            let disk_id = trimmed
                .strip_prefix("<string>")
                .and_then(|s| s.strip_suffix("</string>"))
                .unwrap_or("");
            // Only add whole disk entries (disk0, disk1) not partitions (disk0s1)
            if !disk_id.is_empty() && !disk_id.contains('s') {
                disks.push(disk_id.to_string());
            }
        }
    }

    Ok(disks)
}

/// Get drive information for a disk.
#[cfg(target_os = "macos")]
fn get_disk_info(disk_id: &str) -> Result<DriveInfo> {
    use std::process::Command;

    let output = Command::new("diskutil")
        .args(["info", disk_id])
        .output()
        .map_err(|e| HardwareError::ToolNotFound {
            tool: format!("diskutil: {}", e),
        })?;

    if !output.status.success() {
        return Err(HardwareError::DriveNotFound {
            path: PathBuf::from(format!("/dev/{}", disk_id)),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse disk info from diskutil output
    let mut vendor = None;
    let mut model = None;
    let mut size = 0u64;
    let mut mount_point = None;

    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "Device / Media Name" => {
                model = Some(value.to_string());
            }
            "Disk Size" => {
                // Parse size like "32.0 GB (32000000000 Bytes)"
                if let Some(bytes_str) = value.split('(').nth(1) {
                    if let Some(num_str) = bytes_str.split(' ').next() {
                        size = num_str.parse().unwrap_or(0);
                    }
                }
            }
            "Mount Point" => {
                if !value.is_empty() {
                    mount_point = Some(PathBuf::from(value));
                }
            }
            "Media Name" => {
                // Use as vendor if available
                vendor = Some(value.to_string());
            }
            _ => {}
        }
    }

    // Detect drive type by checking for THC header
    let device_path = PathBuf::from(format!("/dev/{}", disk_id));
    let drive_type = detect_drive_type(&device_path);

    Ok(DriveInfo {
        device_path,
        mount_point,
        size_bytes: size,
        vendor: vendor.unwrap_or_default(),
        model: model.unwrap_or_default(),
        serial: None, // macOS doesn't easily expose serial
        drive_type,
        is_locked: matches!(drive_type, DriveType::TesseractContainer),
        is_removable: true,
    })
}

/// Detect the drive type by checking for THC header.
#[cfg(target_os = "macos")]
fn detect_drive_type(device_path: &Path) -> DriveType {
    use std::fs::File;
    use std::io::Read;

    // Try to open device and read first 8 bytes for magic check
    let mut file = match File::open(device_path) {
        Ok(f) => f,
        Err(_) => return DriveType::Unknown,
    };

    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() {
        return DriveType::Unknown;
    }

    // Check for THC magic bytes: "TESS-HWC" followed by null
    if &magic[..7] == b"TESS-HW" && magic[7] == b'C' {
        DriveType::TesseractContainer
    } else {
        DriveType::Unencrypted
    }
}

/// Run diskutil command and return output.
#[allow(dead_code)]
fn run_diskutil(args: &[&str]) -> Result<String> {
    use std::process::Command;

    let output = Command::new("diskutil")
        .args(args)
        .output()
        .map_err(|e| HardwareError::ToolNotFound {
            tool: format!("diskutil: {}", e),
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(HardwareError::InvalidDevicePath {
            path: stderr.to_string(),
        })
    }
}

/// Check if a disk is external using diskutil info.
#[cfg(target_os = "macos")]
fn is_disk_external(disk_id: &str) -> Result<bool> {
    use std::process::Command;

    let output = Command::new("diskutil")
        .args(["info", disk_id])
        .output()
        .map_err(|e| HardwareError::ToolNotFound {
            tool: format!("diskutil: {}", e),
        })?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check for external/removable indicators
    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim().to_lowercase();

        match key {
            "Removable Media" | "Removable" => {
                if value == "removable" || value == "yes" {
                    return Ok(true);
                }
            }
            "Protocol" => {
                // USB drives are external
                if value.contains("usb") {
                    return Ok(true);
                }
            }
            "Location" => {
                if value.contains("external") {
                    return Ok(true);
                }
            }
            _ => {}
        }
    }

    Ok(false)
}

/// Non-macOS stub for is_disk_external.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn is_disk_external(_disk_id: &str) -> Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_drives_returns_vec() {
        // detect_drives should return Ok on any platform
        // On non-macOS, it returns an empty vec
        // On macOS, it returns detected drives (may be empty if no external drives)
        let result = detect_drives();
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_container_non_macos() {
        // On non-macOS, create_container returns PlatformNotSupported
        #[cfg(not(target_os = "macos"))]
        {
            let result = create_container(Path::new("/dev/disk2"), b"password", None);
            assert!(matches!(
                result,
                Err(HardwareError::PlatformNotSupported { .. })
            ));
        }
    }

    #[test]
    fn test_unlock_container_non_macos() {
        // On non-macOS, unlock_container returns PlatformNotSupported
        #[cfg(not(target_os = "macos"))]
        {
            let result = unlock_container(Path::new("/dev/disk2"), b"password");
            assert!(matches!(
                result,
                Err(HardwareError::PlatformNotSupported { .. })
            ));
        }
    }

    #[test]
    fn test_lock_container_non_macos() {
        // On non-macOS, lock_container returns PlatformNotSupported
        #[cfg(not(target_os = "macos"))]
        {
            let result = lock_container(Path::new("/Volumes/TESSERACT"));
            assert!(matches!(
                result,
                Err(HardwareError::PlatformNotSupported { .. })
            ));
        }
    }

    #[test]
    fn test_is_disk_external_returns_result() {
        // Should return Ok(false) on non-macOS, Ok(true/false) on macOS
        let result = is_disk_external("disk99");
        assert!(result.is_ok());
        // On non-macOS, always returns false
        #[cfg(not(target_os = "macos"))]
        assert!(!result.unwrap());
    }

    #[test]
    fn test_detect_drives_non_macos() {
        // On non-macOS platforms, detect_drives returns empty vec
        #[cfg(not(target_os = "macos"))]
        {
            let result = detect_drives();
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }
    }
}
