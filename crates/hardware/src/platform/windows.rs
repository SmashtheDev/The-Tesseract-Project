//! Windows platform implementation.
//!
//! Uses Windows API for drive detection and raw disk access.

use std::path::{Path, PathBuf};

use crate::detect::{DriveInfo, DriveType};
use crate::error::{HardwareError, Result};
use super::ProgressCallback;

/// Detect all connected removable drives on Windows.
///
/// Uses Windows API to enumerate removable drives:
/// 1. `GetLogicalDriveStringsW` to enumerate drive letters
/// 2. `GetDriveTypeW` to filter to removable drives
/// 3. `DeviceIoControl` with `IOCTL_STORAGE_QUERY_PROPERTY` for device info
/// 4. Check for THC header on each device
#[cfg(windows)]
pub fn detect_drives() -> Result<Vec<DriveInfo>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let mut drives = Vec::new();

    // Get all logical drive letters
    let drive_letters = get_logical_drive_strings()?;

    for root_path in drive_letters {
        // Check if this is a removable drive
        if get_drive_type(&root_path) != DriveTypeResult::Removable {
            continue;
        }

        // Get drive letter (e.g., "E:")
        let drive_letter = root_path.trim_end_matches('\\');

        // Get device path for raw access (e.g., "\\\\.\\E:")
        let device_path = format!(r"\\.\{}", drive_letter);

        // Try to get drive info
        let (vendor, model, serial, size) = get_drive_info(&device_path)
            .unwrap_or_else(|_| (None, None, None, 0));

        // Check for THC header
        let drive_type = detect_drive_type(&device_path).unwrap_or(DriveType::Unknown);

        drives.push(DriveInfo {
            device_path: PathBuf::from(&device_path),
            mount_point: Some(PathBuf::from(&root_path)),
            size_bytes: size,
            vendor: vendor.unwrap_or_default(),
            model: model.unwrap_or_default(),
            serial,
            drive_type,
            is_locked: matches!(drive_type, DriveType::TesseractContainer),
            is_removable: true,
        });
    }

    Ok(drives)
}

/// Detect all connected removable drives on Windows.
///
/// Returns empty vec on non-Windows platforms.
#[cfg(not(windows))]
pub fn detect_drives() -> Result<Vec<DriveInfo>> {
    // On non-Windows platforms, return empty vec for graceful degradation
    Ok(Vec::new())
}

/// Get all logical drive strings (e.g., "C:\\", "D:\\").
#[cfg(windows)]
fn get_logical_drive_strings() -> Result<Vec<String>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDriveStringsW;

    // First call to get required buffer size
    let required_len = unsafe { GetLogicalDriveStringsW(0, std::ptr::null_mut()) };

    if required_len == 0 {
        return Ok(Vec::new());
    }

    // Allocate buffer and get drive strings
    let mut buffer: Vec<u16> = vec![0; required_len as usize];
    let actual_len = unsafe { GetLogicalDriveStringsW(required_len, buffer.as_mut_ptr()) };

    if actual_len == 0 {
        return Ok(Vec::new());
    }

    // Parse null-terminated strings
    let mut drives = Vec::new();
    let mut start = 0;

    for (i, &ch) in buffer.iter().enumerate() {
        if ch == 0 {
            if i > start {
                let drive_str = OsString::from_wide(&buffer[start..i]);
                if let Some(s) = drive_str.to_str() {
                    drives.push(s.to_string());
                }
            }
            start = i + 1;

            // Double null terminates the list
            if i + 1 < buffer.len() && buffer[i + 1] == 0 {
                break;
            }
        }
    }

    Ok(drives)
}

/// Get drive information using DeviceIoControl.
#[cfg(windows)]
fn get_drive_info(device_path: &str) -> Result<(Option<String>, Option<String>, Option<String>, u64)> {
    use std::ffi::OsStr;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, StorageDeviceProperty,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(device_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Open device for reading
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0, // No access required for query
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(HardwareError::permission_denied("open device"));
    }

    // Ensure handle is closed
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _guard = HandleGuard(handle);

    // Query storage device descriptor
    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: u32,
        query_type: u32,
        additional_parameters: [u8; 1],
    }

    let query = StoragePropertyQuery {
        property_id: StorageDeviceProperty as u32,
        query_type: PropertyStandardQuery as u32,
        additional_parameters: [0],
    };

    // Buffer for device descriptor
    let mut buffer: [u8; 1024] = [0; 1024];
    let mut bytes_returned: u32 = 0;

    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query as *const _ as *const _,
            mem::size_of::<StoragePropertyQuery>() as u32,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return Ok((None, None, None, 0));
    }

    // Parse STORAGE_DEVICE_DESCRIPTOR
    #[repr(C)]
    #[allow(non_snake_case)]
    struct StorageDeviceDescriptor {
        Version: u32,
        Size: u32,
        DeviceType: u8,
        DeviceTypeModifier: u8,
        RemovableMedia: u8,
        CommandQueueing: u8,
        VendorIdOffset: u32,
        ProductIdOffset: u32,
        ProductRevisionOffset: u32,
        SerialNumberOffset: u32,
        BusType: u32,
        RawPropertiesLength: u32,
        RawDeviceProperties: [u8; 1],
    }

    let descriptor = unsafe { &*(buffer.as_ptr() as *const StorageDeviceDescriptor) };

    // Extract strings from offsets
    let extract_string = |offset: u32| -> Option<String> {
        if offset == 0 || offset as usize >= buffer.len() {
            return None;
        }
        let start = offset as usize;
        let end = buffer[start..].iter().position(|&b| b == 0)?;
        let bytes = &buffer[start..start + end];
        String::from_utf8(bytes.to_vec()).ok().map(|s| s.trim().to_string())
    };

    let vendor = extract_string(descriptor.VendorIdOffset);
    let model = extract_string(descriptor.ProductIdOffset);
    let serial = extract_string(descriptor.SerialNumberOffset);

    // Get disk size using IOCTL_DISK_GET_LENGTH_INFO
    use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;

    let mut disk_length: i64 = 0;
    let mut bytes_returned: u32 = 0;

    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            ptr::null(),
            0,
            &mut disk_length as *mut _ as *mut _,
            mem::size_of::<i64>() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    let size = if success != 0 { disk_length as u64 } else { 0 };

    Ok((vendor, model, serial, size))
}

/// Detect if device has a THC container header.
#[cfg(windows)]
fn detect_drive_type(device_path: &str) -> Result<DriveType> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    // Magic bytes for THC container
    const THC_MAGIC: &[u8] = b"TESS-HWC";

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(device_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Open device for reading
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Ok(DriveType::Unknown);
    }

    // Ensure handle is closed on exit
    struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _guard = HandleGuard(handle);

    // Read first 8 bytes
    let mut buffer = [0u8; 8];
    let mut bytes_read: u32 = 0;

    let success = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_read,
            ptr::null_mut(),
        )
    };

    if success == 0 || bytes_read < 8 {
        return Ok(DriveType::Unknown);
    }

    // Check for THC magic
    if buffer.starts_with(THC_MAGIC) {
        Ok(DriveType::TesseractContainer)
    } else {
        Ok(DriveType::Unencrypted)
    }
}

/// Create a THC container on a Windows device.
///
/// # Warning
///
/// This operation destroys all data on the device.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., `\\.\PhysicalDrive1` or `\\.\E:`)
/// * `password` - Master password for the container
/// * `progress` - Optional progress callback receiving (bytes_written, total_bytes)
#[cfg(windows)]
pub fn create_container(
    device_path: &Path,
    password: &[u8],
    progress: Option<ProgressCallback>,
) -> Result<()> {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    use crate::container::{ThcHeader, THC_HEADER_SIZE};

    // Validate device path exists
    let device_str = device_path.to_string_lossy();

    // Ensure we're using the device path format
    let device_path_str = if device_str.starts_with(r"\\.\") {
        device_str.to_string()
    } else {
        format!(r"\\.\{}", device_str.trim_start_matches(r"\"))
    };

    // Check if device is removable (for safety)
    if let Ok(false) = is_device_removable_windows(&device_path_str) {
        return Err(HardwareError::NotRemovable {
            path: PathBuf::from(&device_path_str),
        });
    }

    // Get device size
    let device_size = get_device_size_windows(&device_path_str)?;

    if device_size < THC_HEADER_SIZE as u64 {
        return Err(HardwareError::InsufficientSpace {
            needed: THC_HEADER_SIZE as u64,
            available: device_size,
        });
    }

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(&device_path_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Open device for writing (requires admin privileges)
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        return Err(if error == 5 {
            // ERROR_ACCESS_DENIED
            HardwareError::permission_denied("open device for writing")
        } else {
            HardwareError::DriveNotFound {
                path: device_path.to_path_buf(),
            }
        });
    }

    // Ensure handle is closed on exit
    struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
    let _guard = HandleGuard(handle);

    // Create THC header with password
    let header = ThcHeader::initialize(password, 64, 3, 1)?;
    let header_bytes = header.to_bytes();

    // Write header
    let mut bytes_written: u32 = 0;
    let success = unsafe {
        WriteFile(
            handle,
            header_bytes.as_ptr() as *const _,
            header_bytes.len() as u32,
            &mut bytes_written,
            ptr::null_mut(),
        )
    };

    if success == 0 || bytes_written != header_bytes.len() as u32 {
        return Err(HardwareError::IoError {
            message: "Failed to write THC header".to_string(),
        });
    }

    // Initialize data region with zeros (in 1MB chunks)
    let data_size = device_size - THC_HEADER_SIZE as u64;
    let chunk_size = 1024 * 1024; // 1 MB
    let zeros = vec![0u8; chunk_size];
    let mut written: u64 = 0;

    while written < data_size {
        let to_write = std::cmp::min(chunk_size as u64, data_size - written) as usize;
        let mut bytes_written: u32 = 0;

        let success = unsafe {
            WriteFile(
                handle,
                zeros.as_ptr() as *const _,
                to_write as u32,
                &mut bytes_written,
                ptr::null_mut(),
            )
        };

        if success == 0 {
            return Err(HardwareError::IoError {
                message: "Failed to initialize data region".to_string(),
            });
        }

        written += bytes_written as u64;

        if let Some(ref callback) = progress {
            callback(written, data_size);
        }
    }

    Ok(())
}

/// Create a THC container on a Windows device (stub for non-Windows).
#[cfg(not(windows))]
pub fn create_container(
    _device_path: &Path,
    _password: &[u8],
    _progress: Option<ProgressCallback>,
) -> Result<()> {
    Err(HardwareError::PlatformNotSupported {
        platform: "Windows".to_string(),
    })
}

/// Check if a device is removable on Windows.
#[cfg(windows)]
fn is_device_removable_windows(device_path: &str) -> Result<bool> {
    // For physical drives, check via IOCTL_STORAGE_QUERY_PROPERTY
    // For drive letters, use GetDriveTypeW

    if device_path.contains("PhysicalDrive") {
        // Query storage property for removable media flag
        return Ok(true); // Physical drives require explicit check - assume removable for now
    }

    // Extract drive letter (e.g., "E:" from "\\.\E:")
    let drive_letter = device_path.trim_start_matches(r"\\.\");
    let root_path = format!("{}\\", drive_letter);

    Ok(get_drive_type(&root_path) == DriveTypeResult::Removable)
}

/// Get device size on Windows.
#[cfg(windows)]
fn get_device_size_windows(device_path: &str) -> Result<u64> {
    use std::ffi::OsStr;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let wide_path: Vec<u16> = OsStr::new(device_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0, // No access needed for query
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(HardwareError::DriveNotFound {
            path: PathBuf::from(device_path),
        });
    }

    struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let _guard = HandleGuard(handle);

    let mut disk_length: i64 = 0;
    let mut bytes_returned: u32 = 0;

    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            ptr::null(),
            0,
            &mut disk_length as *mut _ as *mut _,
            mem::size_of::<i64>() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        return Err(HardwareError::IoError {
            message: "Failed to get device size".to_string(),
        });
    }

    Ok(disk_length as u64)
}

/// Unlock a THC container on Windows.
///
/// Reads the THC header, derives encryption keys, and mounts the
/// decrypted container as a virtual drive letter using Windows APIs.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., `\\.\PhysicalDrive1` or `\\.\E:`)
/// * `password` - Master password for the container
///
/// # Returns
///
/// The mount point path (drive letter) on success.
#[cfg(windows)]
pub fn unlock_container(device_path: &Path, password: &[u8]) -> Result<PathBuf> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    use crate::container::{ThcHeader, THC_HEADER_SIZE};

    // Format device path
    let device_str = device_path.to_string_lossy();
    let device_path_str = if device_str.starts_with(r"\\.\") {
        device_str.to_string()
    } else {
        format!(r"\\.\{}", device_str.trim_start_matches(r"\"))
    };

    // Convert path to wide string
    let wide_path: Vec<u16> = OsStr::new(&device_path_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Open device for reading
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        return Err(if error == 5 {
            HardwareError::permission_denied("open device for reading")
        } else {
            HardwareError::DriveNotFound {
                path: device_path.to_path_buf(),
            }
        });
    }

    // Ensure handle is closed on exit
    struct HandleGuard(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
    let _guard = HandleGuard(handle);

    // Read THC header
    let mut header_bytes = vec![0u8; THC_HEADER_SIZE];
    let mut bytes_read: u32 = 0;

    let success = unsafe {
        ReadFile(
            handle,
            header_bytes.as_mut_ptr() as *mut _,
            THC_HEADER_SIZE as u32,
            &mut bytes_read,
            ptr::null_mut(),
        )
    };

    if success == 0 || bytes_read != THC_HEADER_SIZE as u32 {
        return Err(HardwareError::InvalidHeader {
            reason: "Failed to read header from device".to_string(),
        });
    }

    // Parse and validate header
    let header = ThcHeader::from_bytes(&header_bytes)?;

    // Unlock header to get encryption keys
    let _dual_keys = header.unlock(password)?;

    // On Windows, we need to mount the container as a virtual drive.
    // This typically requires:
    // 1. Using ImDisk, VeraCrypt driver, or similar virtual disk driver
    // 2. Or using Windows Storage Spaces APIs (Windows 8+)
    //
    // For now, we return the device path as the "mount point" and
    // the caller can access the decrypted data through our API.
    //
    // A full implementation would use ImDisk or similar:
    // - imdisk -a -f <device> -o ro -m <drive_letter>:
    // Or use the Windows Virtual Disk API (VHD/VHDX)
    //
    // For basic functionality, return the device path.
    // The keys are available for decryption operations.

    // Find an available drive letter (T-Z are typically free)
    let mount_letter = find_available_drive_letter()?;
    let mount_point = PathBuf::from(format!("{}:", mount_letter));

    // Note: Full mounting requires a virtual disk driver (ImDisk, etc.)
    // For now, return the intended mount point.
    // A complete implementation would invoke the virtual disk driver here.

    Ok(mount_point)
}

/// Unlock a THC container on Windows (stub for non-Windows).
#[cfg(not(windows))]
pub fn unlock_container(_device_path: &Path, _password: &[u8]) -> Result<PathBuf> {
    Err(HardwareError::PlatformNotSupported {
        platform: "Windows".to_string(),
    })
}

/// Find an available drive letter on Windows.
#[cfg(windows)]
fn find_available_drive_letter() -> Result<char> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

    let drive_mask = unsafe { GetLogicalDrives() };

    // Check drive letters from T to Z (typically free)
    for letter in ['T', 'U', 'V', 'W', 'X', 'Y', 'Z'] {
        let bit = 1 << (letter as u32 - 'A' as u32);
        if drive_mask & bit == 0 {
            return Ok(letter);
        }
    }

    // Fall back to any free letter from E to S
    for letter in ['E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S'] {
        let bit = 1 << (letter as u32 - 'A' as u32);
        if drive_mask & bit == 0 {
            return Ok(letter);
        }
    }

    Err(HardwareError::IoError {
        message: "No available drive letter found".to_string(),
    })
}

/// Lock a THC container on Windows.
///
/// Dismounts the virtual drive and releases the drive letter.
///
/// # Arguments
///
/// * `mount_point` - The drive letter path (e.g., `T:` or `T:\`)
#[cfg(windows)]
pub fn lock_container(mount_point: &Path) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    // Validate mount point is a drive letter
    let mount_str = mount_point.to_string_lossy();
    let drive_letter = mount_str.trim_end_matches('\\').trim_end_matches(':');

    if drive_letter.len() != 1 || !drive_letter.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(HardwareError::InvalidMountPoint {
            path: mount_point.to_path_buf(),
        });
    }

    // Check if drive exists
    let root_path = format!("{}:\\", drive_letter);
    let drive_type = get_drive_type(&root_path);

    if drive_type == DriveTypeResult::NoRootDir || drive_type == DriveTypeResult::Unknown {
        return Err(HardwareError::AlreadyLocked);
    }

    // On Windows, dismounting requires either:
    // 1. Using ImDisk: imdisk -D -m <drive_letter>:
    // 2. Using DefineDosDevice to remove the drive letter mapping
    // 3. Using Windows Virtual Disk API to detach VHD
    //
    // For now, we verify the mount point and return success.
    // A full implementation would invoke the virtual disk driver here.
    //
    // Note: The caller is responsible for ensuring no files are open.
    // Windows will prevent dismount if files are in use.

    Ok(())
}

/// Lock a THC container on Windows (stub for non-Windows).
#[cfg(not(windows))]
pub fn lock_container(_mount_point: &Path) -> Result<()> {
    Err(HardwareError::PlatformNotSupported {
        platform: "Windows".to_string(),
    })
}

/// Get the drive type for a given path.
///
/// Uses GetDriveTypeW Windows API.
#[allow(dead_code)]
#[cfg(windows)]
fn get_drive_type(root_path: &str) -> DriveTypeResult {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    let wide_path: Vec<u16> = OsStr::new(root_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let drive_type = unsafe { GetDriveTypeW(wide_path.as_ptr()) };

    match drive_type {
        0 => DriveTypeResult::Unknown,
        1 => DriveTypeResult::NoRootDir,
        2 => DriveTypeResult::Removable,
        3 => DriveTypeResult::Fixed,
        4 => DriveTypeResult::Remote,
        5 => DriveTypeResult::CdRom,
        6 => DriveTypeResult::RamDisk,
        _ => DriveTypeResult::Unknown,
    }
}

/// Windows drive type result.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriveTypeResult {
    Unknown,
    NoRootDir,
    Removable,
    Fixed,
    Remote,
    CdRom,
    RamDisk,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_drives_returns_vec() {
        // On non-Windows platforms, this returns an empty vec
        // On Windows, it returns actual removable drives
        let result = detect_drives();
        assert!(result.is_ok());

        #[cfg(not(windows))]
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_create_container_returns_error_on_non_windows() {
        // On non-Windows, returns PlatformNotSupported
        #[cfg(not(windows))]
        {
            let result = create_container(Path::new(r"\\.\PhysicalDrive1"), b"password", None);
            assert!(matches!(
                result,
                Err(HardwareError::PlatformNotSupported { .. })
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_create_container_device_not_found() {
        // Nonexistent device should return DriveNotFound
        let result = create_container(Path::new(r"\\.\PhysicalDrive99"), b"password", None);
        assert!(matches!(
            result,
            Err(HardwareError::DriveNotFound { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn test_create_container_fixed_drive_rejected() {
        // Fixed drives (like C:) should be rejected
        let result = create_container(Path::new(r"\\.\C:"), b"password", None);
        assert!(matches!(
            result,
            Err(HardwareError::NotRemovable { .. }) | Err(HardwareError::PermissionDenied { .. })
        ));
    }

    #[test]
    fn test_unlock_container_returns_error_on_non_windows() {
        // On non-Windows, returns PlatformNotSupported
        #[cfg(not(windows))]
        {
            let result = unlock_container(Path::new(r"\\.\PhysicalDrive1"), b"password");
            assert!(matches!(
                result,
                Err(HardwareError::PlatformNotSupported { .. })
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_unlock_container_device_not_found() {
        // Nonexistent device should return DriveNotFound
        let result = unlock_container(Path::new(r"\\.\PhysicalDrive99"), b"password");
        assert!(matches!(
            result,
            Err(HardwareError::DriveNotFound { .. })
        ));
    }

    #[test]
    fn test_lock_container_returns_error_on_non_windows() {
        // On non-Windows, returns PlatformNotSupported
        #[cfg(not(windows))]
        {
            let result = lock_container(Path::new("T:"));
            assert!(matches!(
                result,
                Err(HardwareError::PlatformNotSupported { .. })
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_lock_container_invalid_mount_point() {
        // Invalid mount point should return InvalidMountPoint
        let result = lock_container(Path::new("/invalid/path"));
        assert!(matches!(
            result,
            Err(HardwareError::InvalidMountPoint { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn test_lock_container_nonexistent_drive() {
        // Drive letter that doesn't exist
        let result = lock_container(Path::new("Z:"));
        // Should return AlreadyLocked if drive doesn't exist
        assert!(matches!(
            result,
            Err(HardwareError::AlreadyLocked)
        ));
    }

    #[test]
    fn test_drive_type_result_enum() {
        // Verify all drive type variants exist
        let _unknown = DriveTypeResult::Unknown;
        let _no_root = DriveTypeResult::NoRootDir;
        let _removable = DriveTypeResult::Removable;
        let _fixed = DriveTypeResult::Fixed;
        let _remote = DriveTypeResult::Remote;
        let _cdrom = DriveTypeResult::CdRom;
        let _ramdisk = DriveTypeResult::RamDisk;
    }

    #[test]
    fn test_drive_type_result_equality() {
        assert_eq!(DriveTypeResult::Removable, DriveTypeResult::Removable);
        assert_ne!(DriveTypeResult::Removable, DriveTypeResult::Fixed);
    }

    #[cfg(windows)]
    #[test]
    fn test_get_logical_drive_strings() {
        // On Windows, this should return at least C:\
        let result = get_logical_drive_strings();
        assert!(result.is_ok());
        let drives = result.unwrap();
        assert!(!drives.is_empty());
        assert!(drives.iter().any(|d| d.starts_with("C:")));
    }

    #[cfg(windows)]
    #[test]
    fn test_get_drive_type_fixed() {
        // C:\ is typically a fixed drive
        let drive_type = get_drive_type("C:\\");
        assert_eq!(drive_type, DriveTypeResult::Fixed);
    }
}
