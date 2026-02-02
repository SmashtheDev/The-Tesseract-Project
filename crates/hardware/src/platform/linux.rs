//! Linux platform implementation.
//!
//! Uses /sys/block for drive detection, loop devices and dm-crypt
//! for container management.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn, error, instrument};

use crate::detect::{DriveInfo, DriveType};
use crate::error::{HardwareError, Result};
use super::ProgressCallback;

/// Detect all connected removable drives on Linux.
///
/// Enumerates block devices from /sys/block and filters to removable drives.
/// Reads device info from sysfs (vendor, model, size) and gets mount points
/// from /proc/mounts.
#[instrument(level = "debug")]
pub fn detect_drives() -> Result<Vec<DriveInfo>> {
    debug!("Starting Linux drive detection");
    let mut drives = Vec::new();

    // Get mount points first
    let mount_points = get_mount_points()?;

    // Enumerate /sys/block/
    let sys_block = Path::new("/sys/block");
    if !sys_block.exists() {
        return Ok(drives);
    }

    let entries = match fs::read_dir(sys_block) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(HardwareError::permission_denied("read /sys/block"));
        }
        Err(_) => return Ok(drives), // Graceful degradation
    };

    for entry in entries.flatten() {
        let device_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue, // Skip non-UTF8 device names
        };

        // Skip virtual devices (loop, ram, dm-*)
        if is_virtual_device(&device_name) {
            continue;
        }

        // Check if removable
        if !is_device_removable(&device_name).unwrap_or(false) {
            continue;
        }

        // Get device info
        let device_path = PathBuf::from(format!("/dev/{}", device_name));
        let size_bytes = get_device_size(&device_name).unwrap_or(0);

        if size_bytes == 0 {
            continue; // Skip devices with no size (not present)
        }

        let mut info = DriveInfo::new(device_path.clone(), size_bytes);
        info.vendor = get_device_vendor(&device_name).unwrap_or_default();
        info.model = get_device_model(&device_name).unwrap_or_default();
        info.serial = get_device_serial(&device_name);
        info.is_removable = true;

        // Find mount point for this device or its partitions
        info.mount_point = find_mount_point(&device_name, &mount_points);

        // Check for THC container
        info.drive_type = detect_drive_type(&device_path);

        debug!(
            device = %device_path.display(),
            drive_type = ?info.drive_type,
            size_bytes = info.size_bytes,
            "Found removable drive"
        );
        drives.push(info);
    }

    info!(count = drives.len(), "Linux drive detection complete");
    Ok(drives)
}

/// Check if device name indicates a virtual device.
fn is_virtual_device(device_name: &str) -> bool {
    device_name.starts_with("loop")
        || device_name.starts_with("ram")
        || device_name.starts_with("dm-")
        || device_name.starts_with("sr")      // CD/DVD
        || device_name.starts_with("fd")      // Floppy
        || device_name.starts_with("zram")
        || device_name.starts_with("nbd")     // Network block device
        || device_name.starts_with("md")      // RAID
}

/// Parse /proc/mounts to get all mount points.
/// Returns a map from device path to mount point.
fn get_mount_points() -> Result<HashMap<String, PathBuf>> {
    let mut mounts = HashMap::new();

    let content = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(mounts),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(HardwareError::permission_denied("read /proc/mounts"));
        }
        Err(_) => return Ok(mounts), // Graceful degradation
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let device = parts[0].to_string();
            let mount_point = PathBuf::from(parts[1]);
            mounts.insert(device, mount_point);
        }
    }

    Ok(mounts)
}

/// Find mount point for a device or any of its partitions.
fn find_mount_point(device_name: &str, mounts: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    // Check direct device mount
    let device_path = format!("/dev/{}", device_name);
    if let Some(mp) = mounts.get(&device_path) {
        return Some(mp.clone());
    }

    // Check partition mounts (e.g., sdb1, sdb2, ...)
    for (device, mount_point) in mounts {
        if device.starts_with(&device_path) && device.len() > device_path.len() {
            // Check if remainder is digits (partition number)
            let suffix = &device[device_path.len()..];
            if suffix.chars().all(|c| c.is_ascii_digit()) {
                return Some(mount_point.clone());
            }
        }
    }

    None
}

/// Detect the drive type by checking for THC header.
fn detect_drive_type(device_path: &Path) -> DriveType {
    match crate::detect::is_thc_container(device_path) {
        Ok(true) => DriveType::TesseractContainer,
        Ok(false) => DriveType::Unencrypted,
        Err(_) => DriveType::Unknown, // Can't read - unknown
    }
}

/// Get the serial number from sysfs.
fn get_device_serial(device_name: &str) -> Option<String> {
    let path = format!("/sys/block/{}/device/serial", device_name);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Create a THC container on a Linux device.
///
/// Writes a THC header to the first 4096 bytes of the device and
/// initializes the encrypted data region.
///
/// # Warning
///
/// This operation destroys all data on the device.
///
/// # Arguments
///
/// * `device_path` - Path to the block device (e.g., `/dev/sdb`)
/// * `password` - Master password for encryption
/// * `progress` - Optional callback for progress updates
///
/// # Errors
///
/// Returns an error if:
/// - Device does not exist
/// - Device is not removable
/// - Device is mounted
/// - Insufficient permissions
#[instrument(level = "info", skip(password, progress), fields(device = %device_path.display()))]
pub fn create_container(
    device_path: &Path,
    password: &[u8],
    progress: Option<ProgressCallback>,
) -> Result<()> {
    use crate::container::{ThcHeader, THC_HEADER_SIZE};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    info!(device = %device_path.display(), "Creating THC container");

    // Get device name from path
    let device_name = device_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HardwareError::InvalidDevicePath {
            path: device_path.to_string_lossy().to_string(),
        })?;

    // Verify device exists and is a block device
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // Verify device is removable (skip for loop devices in tests)
    if !device_name.starts_with("loop") {
        if !is_device_removable(device_name)? {
            return Err(HardwareError::NotRemovable {
                path: device_path.to_path_buf(),
            });
        }
    }

    // Verify device is not mounted
    let mount_points = get_mount_points()?;
    if find_mount_point(device_name, &mount_points).is_some() {
        return Err(HardwareError::DriveMounted {
            path: device_path.to_path_buf(),
        });
    }

    // Get device size for progress reporting
    let device_size = get_device_size_from_path(device_path)?;
    if device_size < THC_HEADER_SIZE as u64 {
        return Err(HardwareError::InsufficientSpace {
            needed: THC_HEADER_SIZE as u64,
            available: device_size,
        });
    }

    // Initialize the header with password
    let header = ThcHeader::initialize(password, 64, 3, 4)?;

    // Report progress: starting header write (0%)
    if let Some(ref cb) = progress {
        cb(0, device_size);
    }

    // Open device for writing
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_SYNC) // Sync writes to disk
        .open(device_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                HardwareError::permission_denied("open device for writing")
            } else {
                HardwareError::Io(e)
            }
        })?;

    // Write header
    let header_bytes = header.to_bytes();
    file.write_all(&header_bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            HardwareError::permission_denied("write THC header")
        } else {
            HardwareError::Io(e)
        }
    })?;

    // Report progress: header written
    if let Some(ref cb) = progress {
        cb(THC_HEADER_SIZE as u64, device_size);
    }

    // Initialize data region by writing zeros
    // We'll do this in chunks to report progress
    let chunk_size: usize = 1024 * 1024; // 1 MB chunks
    let zero_chunk = vec![0u8; chunk_size];
    let mut written: u64 = THC_HEADER_SIZE as u64;

    while written < device_size {
        let remaining = device_size - written;
        let to_write = std::cmp::min(remaining, chunk_size as u64) as usize;

        file.write_all(&zero_chunk[..to_write]).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                HardwareError::permission_denied("initialize data region")
            } else {
                HardwareError::Io(e)
            }
        })?;

        written += to_write as u64;

        if let Some(ref cb) = progress {
            cb(written, device_size);
        }
    }

    // Ensure all data is flushed
    file.sync_all()?;

    info!(device = %device_path.display(), "THC container created successfully");
    Ok(())
}

/// Get device size by reading the device directly or from sysfs.
fn get_device_size_from_path(device_path: &Path) -> Result<u64> {
    use std::fs::File;
    use std::io::{Seek, SeekFrom};

    // First try from sysfs
    if let Some(device_name) = device_path.file_name().and_then(|n| n.to_str()) {
        if let Ok(size) = get_device_size(device_name) {
            return Ok(size);
        }
    }

    // Fallback: open and seek to end
    let mut file = File::open(device_path)?;
    let size = file.seek(SeekFrom::End(0))?;
    Ok(size)
}

/// Unlock a THC container on Linux.
///
/// Reads and validates the THC header, derives keys from password,
/// creates a loop device for the container data region, sets up
/// dm-crypt mapping with the derived key, and mounts the filesystem.
///
/// # Arguments
///
/// * `device_path` - Path to the block device (e.g., `/dev/sdb`)
/// * `password` - Master password for decryption
///
/// # Returns
///
/// The mount point path on success.
///
/// # Errors
///
/// Returns an error if:
/// - Device does not exist
/// - THC header is invalid
/// - Password is incorrect
/// - Insufficient permissions
#[instrument(level = "info", skip(password), fields(device = %device_path.display()))]
pub fn unlock_container(device_path: &Path, password: &[u8]) -> Result<PathBuf> {
    use crate::container::{ThcHeader, THC_HEADER_SIZE};
    use std::fs::File;
    use std::io::Read;

    info!(device = %device_path.display(), "Unlocking THC container");

    // Verify device exists
    if !device_path.exists() {
        warn!(device = %device_path.display(), "Device not found");
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // Read THC header
    let mut file = File::open(device_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            HardwareError::permission_denied("open device for reading")
        } else {
            HardwareError::Io(e)
        }
    })?;

    let mut header_bytes = [0u8; THC_HEADER_SIZE];
    file.read_exact(&mut header_bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            HardwareError::InvalidHeader {
                reason: "Device too small for THC header".to_string(),
            }
        } else {
            HardwareError::Io(e)
        }
    })?;

    // Parse and validate header
    let header = ThcHeader::from_bytes(&header_bytes)?;

    // Unlock header with password (verifies password, returns keys)
    let keys = header.unlock(password)?;

    // Generate unique names based on device
    let device_name = device_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("thc");
    let dm_name = format!("tesseract-{}", device_name);
    let mount_point = PathBuf::from(format!("/mnt/tesseract-{}", device_name));

    // Create mount point directory
    std::fs::create_dir_all(&mount_point).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            HardwareError::permission_denied("create mount point")
        } else {
            HardwareError::Io(e)
        }
    })?;

    // Create loop device for data region (offset by header size)
    let loop_device = setup_loop_device(device_path, THC_HEADER_SIZE as u64)?;

    // Set up dm-crypt mapping
    if let Err(e) = setup_dm_crypt(&loop_device, &dm_name, keys.hardware_key()) {
        // Clean up loop device on failure
        let _ = teardown_loop_device(&loop_device);
        return Err(e);
    }

    let dm_device = PathBuf::from(format!("/dev/mapper/{}", dm_name));

    // Mount the decrypted device
    debug!(dm_device = %dm_device.display(), mount_point = %mount_point.display(), "Mounting decrypted device");
    if let Err(e) = mount_filesystem(&dm_device, &mount_point) {
        // Clean up on failure
        error!(error = %e, "Failed to mount filesystem, cleaning up");
        let _ = teardown_dm_crypt(&dm_name);
        let _ = teardown_loop_device(&loop_device);
        return Err(e);
    }

    info!(mount_point = %mount_point.display(), "THC container unlocked and mounted successfully");
    Ok(mount_point)
}

/// Lock a THC container on Linux.
///
/// Unmounts the filesystem, removes dm-crypt mapping, and detaches
/// the loop device.
///
/// # Arguments
///
/// * `mount_point` - The mount point path returned by `unlock_container`
///
/// # Errors
///
/// Returns an error if:
/// - Mount point does not exist
/// - Filesystem is busy
/// - Insufficient permissions
#[instrument(level = "info", skip_all, fields(mount_point = %mount_point.display()))]
pub fn lock_container(mount_point: &Path) -> Result<()> {
    use std::process::Command;

    info!(mount_point = %mount_point.display(), "Locking THC container");

    // Verify mount point exists
    if !mount_point.exists() {
        debug!(mount_point = %mount_point.display(), "Mount point does not exist, already locked");
        return Err(HardwareError::AlreadyLocked);
    }

    // Extract dm_name from mount point
    let mount_name = mount_point
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HardwareError::InvalidDevicePath {
            path: mount_point.to_string_lossy().to_string(),
        })?;

    let dm_name = mount_name.strip_prefix("tesseract-").unwrap_or(mount_name);

    // Unmount filesystem
    let unmount_result = Command::new("umount")
        .arg(mount_point)
        .output();

    match unmount_result {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("busy") || stderr.contains("target is busy") {
                return Err(HardwareError::DriveBusy {
                    reason: "Files are open on the mounted filesystem".to_string(),
                });
            }
            return Err(HardwareError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("umount failed: {}", stderr),
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HardwareError::ToolNotFound {
                tool: "umount".to_string(),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(HardwareError::permission_denied("unmount filesystem"));
        }
        Err(e) => return Err(HardwareError::Io(e)),
        Ok(_) => {}
    }

    // Remove dm-crypt mapping
    let dm_full_name = format!("tesseract-{}", dm_name);
    teardown_dm_crypt(&dm_full_name)?;

    // Find and detach associated loop device
    // The loop device is determined by checking /sys/block/dm-*/slaves
    if let Some(loop_device) = find_loop_device_for_dm(&dm_full_name) {
        teardown_loop_device(&loop_device)?;
    }

    // Remove mount point directory (if empty)
    let _ = std::fs::remove_dir(mount_point);

    info!(mount_point = %mount_point.display(), "THC container locked successfully");
    Ok(())
}

/// Set up a loop device with an offset.
#[instrument(level = "debug", skip_all, fields(device = %device_path.display(), offset))]
fn setup_loop_device(device_path: &Path, offset: u64) -> Result<PathBuf> {
    use std::process::Command;

    debug!(device = %device_path.display(), offset, "Setting up loop device");

    let output = Command::new("losetup")
        .arg("-f")
        .arg("--show")
        .arg("--offset")
        .arg(offset.to_string())
        .arg(device_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let loop_device = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_string();
            debug!(loop_device = %loop_device, "Loop device created");
            Ok(PathBuf::from(loop_device))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(error = %stderr, "losetup failed");
            Err(HardwareError::LoopDeviceError(format!(
                "losetup failed: {}",
                stderr
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            error!("losetup tool not found");
            Err(HardwareError::ToolNotFound {
                tool: "losetup".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            warn!("Permission denied for losetup");
            Err(HardwareError::permission_denied("create loop device"))
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Tear down a loop device.
#[instrument(level = "debug", skip_all, fields(loop_device = %loop_device.display()))]
fn teardown_loop_device(loop_device: &Path) -> Result<()> {
    use std::process::Command;

    debug!(loop_device = %loop_device.display(), "Tearing down loop device");

    let output = Command::new("losetup")
        .arg("-d")
        .arg(loop_device)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            debug!(loop_device = %loop_device.display(), "Loop device detached");
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(loop_device = %loop_device.display(), error = %stderr, "losetup -d failed");
            Err(HardwareError::LoopDeviceError(format!(
                "losetup -d failed: {}",
                stderr
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            error!("losetup tool not found");
            Err(HardwareError::ToolNotFound {
                tool: "losetup".to_string(),
            })
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Set up dm-crypt mapping with AES-XTS.
#[instrument(level = "debug", skip(key), fields(loop_device = %loop_device.display(), dm_name))]
fn setup_dm_crypt(loop_device: &Path, dm_name: &str, key: &[u8; 64]) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    debug!(loop_device = %loop_device.display(), dm_name, "Setting up dm-crypt mapping");

    // Use cryptsetup plainOpen for raw key access
    let mut child = Command::new("cryptsetup")
        .arg("open")
        .arg("--type")
        .arg("plain")
        .arg("--cipher")
        .arg("aes-xts-plain64")
        .arg("--key-size")
        .arg("512") // 64 bytes = 512 bits
        .arg("--key-file")
        .arg("-") // Read key from stdin
        .arg(loop_device)
        .arg(dm_name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                HardwareError::ToolNotFound {
                    tool: "cryptsetup".to_string(),
                }
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                HardwareError::permission_denied("run cryptsetup")
            } else {
                HardwareError::Io(e)
            }
        })?;

    // Write the raw key bytes to stdin
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            HardwareError::DmCryptError("Failed to open stdin for cryptsetup".to_string())
        })?;
        stdin.write_all(key)?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(dm_name, error = %stderr, "cryptsetup open failed");
        return Err(HardwareError::DmCryptError(format!(
            "cryptsetup open failed: {}",
            stderr
        )));
    }

    debug!(dm_name, "dm-crypt mapping created");
    Ok(())
}

/// Tear down dm-crypt mapping.
#[instrument(level = "debug", fields(dm_name))]
fn teardown_dm_crypt(dm_name: &str) -> Result<()> {
    use std::process::Command;

    debug!(dm_name, "Tearing down dm-crypt mapping");

    let output = Command::new("cryptsetup")
        .arg("close")
        .arg(dm_name)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            debug!(dm_name, "dm-crypt mapping removed");
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Not an error if already closed
            if stderr.contains("not found") || stderr.contains("does not exist") {
                debug!(dm_name, "dm-crypt mapping already removed");
                Ok(())
            } else {
                warn!(dm_name, error = %stderr, "cryptsetup close failed");
                Err(HardwareError::DmCryptError(format!(
                    "cryptsetup close failed: {}",
                    stderr
                )))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            error!("cryptsetup tool not found");
            Err(HardwareError::ToolNotFound {
                tool: "cryptsetup".to_string(),
            })
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Mount a filesystem.
#[instrument(level = "debug", skip_all, fields(device = %device.display(), mount_point = %mount_point.display()))]
fn mount_filesystem(device: &Path, mount_point: &Path) -> Result<()> {
    use std::process::Command;

    debug!(device = %device.display(), mount_point = %mount_point.display(), "Mounting filesystem");

    let output = Command::new("mount")
        .arg(device)
        .arg(mount_point)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            debug!(mount_point = %mount_point.display(), "Filesystem mounted");
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(device = %device.display(), error = %stderr, "mount failed");
            Err(HardwareError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mount failed: {}", stderr),
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            error!("mount tool not found");
            Err(HardwareError::ToolNotFound {
                tool: "mount".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            warn!("Permission denied for mount");
            Err(HardwareError::permission_denied("mount filesystem"))
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Find the loop device associated with a dm-crypt mapping.
fn find_loop_device_for_dm(dm_name: &str) -> Option<PathBuf> {
    // Use dmsetup to find the underlying device
    use std::process::Command;

    let output = Command::new("dmsetup")
        .arg("deps")
        .arg("-o")
        .arg("blkdevname")
        .arg(dm_name)
        .output()
        .ok()?;

    if output.status.success() {
        let deps = String::from_utf8_lossy(&output.stdout);
        // Output format: "loop0" or similar
        let device = deps.trim();
        if device.starts_with("loop") {
            return Some(PathBuf::from(format!("/dev/{}", device)));
        }
    }

    None
}

/// Read a block device's removable flag from sysfs.
fn is_device_removable(device_name: &str) -> Result<bool> {
    let path = format!("/sys/block/{}/removable", device_name);
    match fs::read_to_string(&path) {
        Ok(content) => Ok(content.trim() == "1"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Read a block device's size in bytes from sysfs.
fn get_device_size(device_name: &str) -> Result<u64> {
    let path = format!("/sys/block/{}/size", device_name);
    let content = fs::read_to_string(&path)?;
    let sectors: u64 = content
        .trim()
        .parse()
        .map_err(|_| HardwareError::InvalidDevicePath {
            path: device_name.to_string(),
        })?;
    // Each sector is 512 bytes
    Ok(sectors * 512)
}

/// Get the vendor name from sysfs.
fn get_device_vendor(device_name: &str) -> Option<String> {
    let path = format!("/sys/block/{}/device/vendor", device_name);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Get the model name from sysfs.
fn get_device_model(device_name: &str) -> Option<String> {
    let path = format!("/sys/block/{}/device/model", device_name);
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_drives_returns_vec() {
        // detect_drives should always succeed on Linux
        let result = detect_drives();
        assert!(result.is_ok());
        // May or may not find drives depending on hardware
    }

    #[test]
    fn test_detect_drives_filters_virtual() {
        assert!(is_virtual_device("loop0"));
        assert!(is_virtual_device("ram0"));
        assert!(is_virtual_device("dm-0"));
        assert!(is_virtual_device("sr0"));
        assert!(is_virtual_device("zram0"));
        assert!(!is_virtual_device("sda"));
        assert!(!is_virtual_device("nvme0n1"));
    }

    #[test]
    fn test_get_mount_points() {
        // get_mount_points should always succeed
        let result = get_mount_points();
        assert!(result.is_ok());
        let mounts = result.unwrap();
        // Should have at least root mount
        assert!(mounts.values().any(|p| p == Path::new("/")));
    }

    #[test]
    fn test_find_mount_point_direct() {
        let mut mounts = HashMap::new();
        mounts.insert("/dev/sdb".to_string(), PathBuf::from("/mnt/usb"));

        let result = find_mount_point("sdb", &mounts);
        assert_eq!(result, Some(PathBuf::from("/mnt/usb")));
    }

    #[test]
    fn test_find_mount_point_partition() {
        let mut mounts = HashMap::new();
        mounts.insert("/dev/sdb1".to_string(), PathBuf::from("/mnt/usb"));

        let result = find_mount_point("sdb", &mounts);
        assert_eq!(result, Some(PathBuf::from("/mnt/usb")));
    }

    #[test]
    fn test_find_mount_point_none() {
        let mounts = HashMap::new();
        let result = find_mount_point("sdb", &mounts);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_container_device_not_found() {
        let result = create_container(Path::new("/dev/nonexistent_device_12345"), b"password", None);
        assert!(matches!(result, Err(HardwareError::DriveNotFound { .. })));
    }

    #[test]
    fn test_create_container_not_removable() {
        // Trying to create container on sda (system disk) should fail
        let result = create_container(Path::new("/dev/sda"), b"password", None);
        // Either not removable, or permission denied, or drive not found
        assert!(result.is_err());
    }

    #[test]
    fn test_create_container_with_file() {
        // Test with a temp file (simulates loop device behavior)
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("test_container");

        // Create a 1MB test file
        let mut file = std::fs::File::create(&test_file).unwrap();
        file.write_all(&vec![0u8; 1024 * 1024]).unwrap();

        // This should work since the file starts with "test" not from /dev/
        // And our path extraction will fail so it won't be treated as a block device
        let result = create_container(&test_file, b"password", None);

        // Should fail because it's not in /dev/ and path extraction fails
        // or because sysfs doesn't have info for it
        assert!(result.is_err());
    }

    #[test]
    fn test_unlock_container_device_not_found() {
        let result = unlock_container(Path::new("/dev/nonexistent_device_12345"), b"password");
        assert!(matches!(result, Err(HardwareError::DriveNotFound { .. })));
    }

    #[test]
    fn test_unlock_container_regular_file() {
        // Create a temp file - should fail because it's not a valid THC container
        use std::io::Write;
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("test_container");
        let mut file = std::fs::File::create(&test_file).unwrap();
        // Write some garbage data (not a valid THC header)
        file.write_all(&vec![0u8; 8192]).unwrap();

        let result = unlock_container(&test_file, b"password");
        // Should fail with invalid header or some other error
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_container_not_mounted() {
        let result = lock_container(Path::new("/mnt/nonexistent_tesseract_mount"));
        assert!(matches!(result, Err(HardwareError::AlreadyLocked)));
    }

    #[test]
    fn test_lock_container_invalid_path() {
        let result = lock_container(Path::new("/"));
        // Root path is not a tesseract mount point - will try to unmount and fail
        assert!(result.is_err());
    }

    #[test]
    fn test_is_device_removable_nonexistent() {
        let result = is_device_removable("nonexistent_device_12345");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_get_device_size_nonexistent() {
        let result = get_device_size("nonexistent_device_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_device_vendor_nonexistent() {
        let result = get_device_vendor("nonexistent_device_12345");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_device_model_nonexistent() {
        let result = get_device_model("nonexistent_device_12345");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_device_serial_nonexistent() {
        let result = get_device_serial("nonexistent_device_12345");
        assert!(result.is_none());
    }
}
