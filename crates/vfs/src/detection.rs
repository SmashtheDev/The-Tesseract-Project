//! VFS Driver Detection Module.
//!
//! Detects installed VFS drivers (Dokan and WinFsp) on Windows systems.
//! Provides version compatibility checking and graceful fallback when
//! no suitable driver is installed.

use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Supported VFS drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsDriver {
    /// Dokan filesystem driver (Windows).
    Dokan,
    /// WinFsp filesystem driver (Windows).
    WinFsp,
}

impl VfsDriver {
    /// Returns the display name of the driver.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dokan => "Dokan",
            Self::WinFsp => "WinFsp",
        }
    }

    /// Returns a description of the driver.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Dokan => "Dokan user-mode filesystem driver for Windows",
            Self::WinFsp => "Windows File System Proxy (WinFsp) driver",
        }
    }

    /// Returns the minimum compatible version.
    #[must_use]
    pub const fn minimum_version(self) -> (u32, u32) {
        match self {
            Self::Dokan => (2, 0),
            Self::WinFsp => (2, 0),
        }
    }
}

/// Information about a detected VFS driver installation.
#[derive(Debug, Clone)]
pub struct VfsDriverInfo {
    /// The driver type.
    pub driver: VfsDriver,
    /// Installation path.
    pub install_path: Option<PathBuf>,
    /// Detected version (major, minor, patch).
    pub version: Option<(u32, u32, u32)>,
    /// Whether the version is compatible with TESSERACT requirements.
    pub is_compatible: bool,
    /// DLL path for the driver.
    pub dll_path: Option<PathBuf>,
}

impl VfsDriverInfo {
    /// Creates a new `VfsDriverInfo`.
    #[must_use]
    pub fn new(driver: VfsDriver) -> Self {
        Self {
            driver,
            install_path: None,
            version: None,
            is_compatible: false,
            dll_path: None,
        }
    }

    /// Returns the version as a display string.
    #[must_use]
    pub fn version_string(&self) -> String {
        match self.version {
            Some((major, minor, patch)) => format!("{major}.{minor}.{patch}"),
            None => "unknown".to_string(),
        }
    }

    /// Returns whether this driver meets minimum version requirements.
    #[must_use]
    pub fn meets_minimum_version(&self) -> bool {
        if let Some((major, minor, _)) = self.version {
            let (min_major, min_minor) = self.driver.minimum_version();
            major > min_major || (major == min_major && minor >= min_minor)
        } else {
            false
        }
    }
}

/// Detection result containing all discovered drivers.
#[derive(Debug, Default)]
pub struct DetectionResult {
    /// Dokan driver info (if detected).
    pub dokan: Option<VfsDriverInfo>,
    /// WinFsp driver info (if detected).
    pub winfsp: Option<VfsDriverInfo>,
}

impl DetectionResult {
    /// Returns the preferred compatible driver, if any.
    ///
    /// Prefers Dokan if both are installed and compatible.
    #[must_use]
    pub fn preferred_driver(&self) -> Option<&VfsDriverInfo> {
        // Prefer Dokan over WinFsp if both available and compatible
        if let Some(dokan) = &self.dokan {
            if dokan.is_compatible {
                return Some(dokan);
            }
        }
        if let Some(winfsp) = &self.winfsp {
            if winfsp.is_compatible {
                return Some(winfsp);
            }
        }
        None
    }

    /// Returns any available driver info (compatible or not).
    #[must_use]
    pub fn any_driver(&self) -> Option<&VfsDriverInfo> {
        self.dokan.as_ref().or(self.winfsp.as_ref())
    }

    /// Returns `true` if no drivers were detected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dokan.is_none() && self.winfsp.is_none()
    }

    /// Returns `true` if at least one compatible driver is available.
    #[must_use]
    pub fn has_compatible_driver(&self) -> bool {
        self.preferred_driver().is_some()
    }
}

// ============================================================================
// Windows-specific implementation
// ============================================================================

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        REG_SZ,
    };

    /// Dokan registry paths and installation locations.
    const DOKAN_REGISTRY_KEY: &str = r"SOFTWARE\Dokan\Dokan Library";
    const DOKAN_REGISTRY_KEY_WOW64: &str = r"SOFTWARE\WOW6432Node\Dokan\Dokan Library";
    const DOKAN_INSTALL_PATHS: &[&str] = &[
        r"C:\Program Files\Dokan\Dokan Library",
        r"C:\Program Files (x86)\Dokan\Dokan Library",
    ];
    const DOKAN_DLL_NAME: &str = "dokan2.dll";

    /// WinFsp registry paths and installation locations.
    const WINFSP_REGISTRY_KEY: &str = r"SOFTWARE\WinFsp";
    const WINFSP_REGISTRY_KEY_WOW64: &str = r"SOFTWARE\WOW6432Node\WinFsp";
    const WINFSP_INSTALL_PATHS: &[&str] = &[
        r"C:\Program Files\WinFsp",
        r"C:\Program Files (x86)\WinFsp",
    ];
    const WINFSP_DLL_NAME: &str = "winfsp-x64.dll";

    /// Converts a Rust string to a null-terminated wide string (UTF-16).
    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Converts a wide string buffer to a Rust String.
    fn from_wide_buffer(buffer: &[u16]) -> String {
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        OsString::from_wide(&buffer[..len])
            .to_string_lossy()
            .into_owned()
    }

    /// Reads a string value from Windows Registry.
    ///
    /// # Safety
    /// Uses Windows Registry API which is safe when called with valid parameters.
    fn read_registry_string(base_key: HKEY, subkey: &str, value_name: &str) -> Option<String> {
        let subkey_wide = to_wide_null(subkey);
        let value_wide = to_wide_null(value_name);
        let mut key_handle: HKEY = std::ptr::null_mut();
        let mut data_type: u32 = 0;
        let mut buffer: [u16; 512] = [0; 512];
        let mut buffer_size: u32 = (buffer.len() * 2) as u32;

        unsafe {
            // Open the registry key
            let result = RegOpenKeyExW(
                base_key,
                subkey_wide.as_ptr(),
                0,
                KEY_READ,
                &mut key_handle,
            );

            if result != ERROR_SUCCESS {
                debug!("Failed to open registry key: {} (error {})", subkey, result);
                return None;
            }

            // Query the value
            let result = RegQueryValueExW(
                key_handle,
                value_wide.as_ptr(),
                std::ptr::null_mut(),
                &mut data_type,
                buffer.as_mut_ptr().cast(),
                &mut buffer_size,
            );

            let _ = RegCloseKey(key_handle);

            if result != ERROR_SUCCESS {
                debug!(
                    "Failed to read registry value: {}\\{} (error {})",
                    subkey, value_name, result
                );
                return None;
            }

            if data_type != REG_SZ {
                debug!(
                    "Registry value is not a string: {}\\{} (type {})",
                    subkey, value_name, data_type
                );
                return None;
            }

            Some(from_wide_buffer(&buffer))
        }
    }

    /// Parses a version string into (major, minor, patch).
    fn parse_version(version_str: &str) -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = version_str.split('.').collect();
        if parts.is_empty() {
            return None;
        }

        let major = parts.first()?.parse().ok()?;
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some((major, minor, patch))
    }

    /// Checks if a DLL file exists at the given path.
    fn find_dll(base_path: &Path, dll_name: &str) -> Option<PathBuf> {
        // Check in bin directory
        let bin_path = base_path.join("bin").join(dll_name);
        if bin_path.exists() {
            return Some(bin_path);
        }

        // Check in x64 directory
        let x64_path = base_path.join("x64").join(dll_name);
        if x64_path.exists() {
            return Some(x64_path);
        }

        // Check in root
        let root_path = base_path.join(dll_name);
        if root_path.exists() {
            return Some(root_path);
        }

        None
    }

    /// Detects Dokan installation.
    pub fn detect_dokan() -> Option<VfsDriverInfo> {
        let mut info = VfsDriverInfo::new(VfsDriver::Dokan);

        // Try to read from registry
        let registry_keys = [DOKAN_REGISTRY_KEY, DOKAN_REGISTRY_KEY_WOW64];

        for reg_key in &registry_keys {
            // Try to get install path from registry
            if let Some(install_path) = read_registry_string(HKEY_LOCAL_MACHINE, reg_key, "InstallDir") {
                let path = PathBuf::from(&install_path);
                if path.exists() {
                    info.install_path = Some(path.clone());
                    debug!("Found Dokan install path from registry: {}", install_path);

                    // Try to find the DLL
                    if let Some(dll) = find_dll(&path, DOKAN_DLL_NAME) {
                        info.dll_path = Some(dll);
                    }
                }
            }

            // Try to get version from registry
            if let Some(version_str) = read_registry_string(HKEY_LOCAL_MACHINE, reg_key, "Version") {
                if let Some(version) = parse_version(&version_str) {
                    info.version = Some(version);
                    debug!("Found Dokan version from registry: {}", version_str);
                    break;
                }
            }
        }

        // If not found in registry, check common installation paths
        if info.install_path.is_none() {
            for path_str in DOKAN_INSTALL_PATHS {
                let path = Path::new(path_str);
                if path.exists() {
                    info.install_path = Some(path.to_path_buf());
                    debug!("Found Dokan install path at: {}", path_str);

                    // Try to find the DLL
                    if let Some(dll) = find_dll(path, DOKAN_DLL_NAME) {
                        info.dll_path = Some(dll);
                    }

                    // Try to detect version from DLL or version file
                    let version_file = path.join("version.txt");
                    if version_file.exists() {
                        if let Ok(content) = std::fs::read_to_string(&version_file) {
                            if let Some(version) = parse_version(content.trim()) {
                                info.version = Some(version);
                            }
                        }
                    }
                    break;
                }
            }
        }

        // Check if we found anything
        if info.install_path.is_some() || info.dll_path.is_some() {
            info.is_compatible = info.meets_minimum_version();
            debug!(
                "Dokan detection result: path={:?}, version={:?}, compatible={}",
                info.install_path, info.version, info.is_compatible
            );
            Some(info)
        } else {
            debug!("Dokan not detected");
            None
        }
    }

    /// Detects WinFsp installation.
    pub fn detect_winfsp() -> Option<VfsDriverInfo> {
        let mut info = VfsDriverInfo::new(VfsDriver::WinFsp);

        // Try to read from registry
        let registry_keys = [WINFSP_REGISTRY_KEY, WINFSP_REGISTRY_KEY_WOW64];

        for reg_key in &registry_keys {
            // Try to get install path from registry
            if let Some(install_path) = read_registry_string(HKEY_LOCAL_MACHINE, reg_key, "InstallDir") {
                let path = PathBuf::from(&install_path);
                if path.exists() {
                    info.install_path = Some(path.clone());
                    debug!("Found WinFsp install path from registry: {}", install_path);

                    // Try to find the DLL
                    if let Some(dll) = find_dll(&path, WINFSP_DLL_NAME) {
                        info.dll_path = Some(dll);
                    }
                }
            }

            // Try to get version from registry
            if let Some(version_str) = read_registry_string(HKEY_LOCAL_MACHINE, reg_key, "Version") {
                if let Some(version) = parse_version(&version_str) {
                    info.version = Some(version);
                    debug!("Found WinFsp version from registry: {}", version_str);
                    break;
                }
            }
        }

        // If not found in registry, check common installation paths
        if info.install_path.is_none() {
            for path_str in WINFSP_INSTALL_PATHS {
                let path = Path::new(path_str);
                if path.exists() {
                    info.install_path = Some(path.to_path_buf());
                    debug!("Found WinFsp install path at: {}", path_str);

                    // Try to find the DLL
                    if let Some(dll) = find_dll(path, WINFSP_DLL_NAME) {
                        info.dll_path = Some(dll);
                    }

                    break;
                }
            }
        }

        // Check if we found anything
        if info.install_path.is_some() || info.dll_path.is_some() {
            info.is_compatible = info.meets_minimum_version();
            debug!(
                "WinFsp detection result: path={:?}, version={:?}, compatible={}",
                info.install_path, info.version, info.is_compatible
            );
            Some(info)
        } else {
            debug!("WinFsp not detected");
            None
        }
    }

    /// Performs full VFS driver detection.
    pub fn detect_all_drivers() -> DetectionResult {
        info!("Scanning for VFS drivers...");

        let dokan = detect_dokan();
        let winfsp = detect_winfsp();

        let result = DetectionResult { dokan, winfsp };

        if result.is_empty() {
            info!("No VFS drivers detected");
        } else {
            if let Some(dokan) = &result.dokan {
                info!(
                    "Dokan {} detected (compatible: {})",
                    dokan.version_string(),
                    dokan.is_compatible
                );
            }
            if let Some(winfsp) = &result.winfsp {
                info!(
                    "WinFsp {} detected (compatible: {})",
                    winfsp.version_string(),
                    winfsp.is_compatible
                );
            }
        }

        result
    }
}

// ============================================================================
// Non-Windows stub implementation
// ============================================================================

#[cfg(not(windows))]
mod non_windows_impl {
    use super::*;

    /// Stub for Dokan detection on non-Windows platforms.
    pub fn detect_dokan() -> Option<VfsDriverInfo> {
        debug!("Dokan detection not supported on this platform");
        None
    }

    /// Stub for WinFsp detection on non-Windows platforms.
    pub fn detect_winfsp() -> Option<VfsDriverInfo> {
        debug!("WinFsp detection not supported on this platform");
        None
    }

    /// Stub for full driver detection on non-Windows platforms.
    pub fn detect_all_drivers() -> DetectionResult {
        debug!("VFS driver detection not supported on this platform");
        DetectionResult::default()
    }
}

// ============================================================================
// Public API
// ============================================================================

#[cfg(windows)]
pub use windows_impl::*;

#[cfg(not(windows))]
pub use non_windows_impl::*;

/// Detects the best available VFS driver.
///
/// Returns `Some(VfsDriver)` if a compatible driver is found, `None` otherwise.
///
/// # Example
///
/// ```ignore
/// use tesseract_vfs::detection::detect_vfs_driver;
///
/// if let Some(driver) = detect_vfs_driver() {
///     println!("Using {} for filesystem integration", driver.name());
/// } else {
///     println!("No VFS driver available, falling back to built-in file browser");
/// }
/// ```
#[must_use]
pub fn detect_vfs_driver() -> Option<VfsDriver> {
    let result = detect_all_drivers();
    result.preferred_driver().map(|info| info.driver)
}

/// Returns detailed information about the best available VFS driver.
///
/// Similar to [`detect_vfs_driver`] but returns full driver information
/// including version and installation path.
#[must_use]
pub fn detect_vfs_driver_info() -> Option<VfsDriverInfo> {
    let result = detect_all_drivers();
    result.preferred_driver().cloned()
}

/// Returns detection results for all drivers (compatible or not).
///
/// Useful for diagnostic purposes or displaying available options to users.
#[must_use]
pub fn detect_all_vfs_drivers() -> DetectionResult {
    detect_all_drivers()
}

/// Checks if VFS driver detection is supported on this platform.
#[must_use]
pub const fn is_vfs_detection_supported() -> bool {
    cfg!(windows)
}

/// Gets a user-friendly message when no VFS driver is available.
#[must_use]
pub fn get_no_driver_message() -> String {
    format!(
        "No compatible Virtual Filesystem (VFS) driver detected.\n\n\
         To enable transparent file manager integration, please install one of:\n\n\
         • Dokan Library 2.x\n\
           Download: https://dokan-dev.github.io/\n\n\
         • WinFsp 2.x\n\
           Download: https://winfsp.dev/\n\n\
         Without a VFS driver, you can still use the built-in file browser\n\
         to manage your encrypted files."
    )
}

/// Gets installation instructions for a specific driver.
#[must_use]
pub fn get_driver_install_instructions(driver: VfsDriver) -> String {
    match driver {
        VfsDriver::Dokan => {
            "Dokan Library Installation\n\
             ===========================\n\n\
             1. Download Dokan Library 2.x from: https://dokan-dev.github.io/\n\
             2. Run the installer as Administrator\n\
             3. Restart your computer after installation\n\
             4. Restart TESSERACT to enable VFS integration"
                .to_string()
        }
        VfsDriver::WinFsp => {
            "WinFsp Installation\n\
             ====================\n\n\
             1. Download WinFsp 2.x from: https://winfsp.dev/\n\
             2. Run the installer as Administrator\n\
             3. Restart your computer after installation\n\
             4. Restart TESSERACT to enable VFS integration"
                .to_string()
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // VfsDriver enum tests
    // ========================================================================

    #[test]
    fn test_vfs_driver_name() {
        assert_eq!(VfsDriver::Dokan.name(), "Dokan");
        assert_eq!(VfsDriver::WinFsp.name(), "WinFsp");
    }

    #[test]
    fn test_vfs_driver_description() {
        let dokan_desc = VfsDriver::Dokan.description();
        assert!(dokan_desc.contains("Dokan"));
        assert!(dokan_desc.contains("Windows"));

        let winfsp_desc = VfsDriver::WinFsp.description();
        assert!(winfsp_desc.contains("WinFsp"));
    }

    #[test]
    fn test_vfs_driver_minimum_version() {
        assert_eq!(VfsDriver::Dokan.minimum_version(), (2, 0));
        assert_eq!(VfsDriver::WinFsp.minimum_version(), (2, 0));
    }

    #[test]
    fn test_vfs_driver_equality() {
        assert_eq!(VfsDriver::Dokan, VfsDriver::Dokan);
        assert_eq!(VfsDriver::WinFsp, VfsDriver::WinFsp);
        assert_ne!(VfsDriver::Dokan, VfsDriver::WinFsp);
    }

    #[test]
    fn test_vfs_driver_copy() {
        let driver = VfsDriver::Dokan;
        let copied = driver;
        assert_eq!(driver, copied);
    }

    // ========================================================================
    // VfsDriverInfo tests
    // ========================================================================

    #[test]
    fn test_vfs_driver_info_new() {
        let info = VfsDriverInfo::new(VfsDriver::Dokan);
        assert_eq!(info.driver, VfsDriver::Dokan);
        assert!(info.install_path.is_none());
        assert!(info.version.is_none());
        assert!(!info.is_compatible);
        assert!(info.dll_path.is_none());
    }

    #[test]
    fn test_vfs_driver_info_version_string() {
        let mut info = VfsDriverInfo::new(VfsDriver::Dokan);
        assert_eq!(info.version_string(), "unknown");

        info.version = Some((2, 1, 0));
        assert_eq!(info.version_string(), "2.1.0");

        info.version = Some((1, 0, 5));
        assert_eq!(info.version_string(), "1.0.5");
    }

    #[test]
    fn test_vfs_driver_info_meets_minimum_version() {
        let mut info = VfsDriverInfo::new(VfsDriver::Dokan);

        // No version - should not meet minimum
        assert!(!info.meets_minimum_version());

        // Version 1.x - below minimum 2.0
        info.version = Some((1, 9, 9));
        assert!(!info.meets_minimum_version());

        // Version 2.0.0 - exactly at minimum
        info.version = Some((2, 0, 0));
        assert!(info.meets_minimum_version());

        // Version 2.1.0 - above minimum
        info.version = Some((2, 1, 0));
        assert!(info.meets_minimum_version());

        // Version 3.0.0 - major version above minimum
        info.version = Some((3, 0, 0));
        assert!(info.meets_minimum_version());
    }

    #[test]
    fn test_vfs_driver_info_winfsp_meets_minimum() {
        let mut info = VfsDriverInfo::new(VfsDriver::WinFsp);

        info.version = Some((1, 12, 0));
        assert!(!info.meets_minimum_version());

        info.version = Some((2, 0, 0));
        assert!(info.meets_minimum_version());
    }

    // ========================================================================
    // DetectionResult tests
    // ========================================================================

    #[test]
    fn test_detection_result_default() {
        let result = DetectionResult::default();
        assert!(result.dokan.is_none());
        assert!(result.winfsp.is_none());
        assert!(result.is_empty());
        assert!(!result.has_compatible_driver());
    }

    #[test]
    fn test_detection_result_is_empty() {
        let mut result = DetectionResult::default();
        assert!(result.is_empty());

        result.dokan = Some(VfsDriverInfo::new(VfsDriver::Dokan));
        assert!(!result.is_empty());
    }

    #[test]
    fn test_detection_result_preferred_driver_none() {
        let result = DetectionResult::default();
        assert!(result.preferred_driver().is_none());
    }

    #[test]
    fn test_detection_result_preferred_driver_dokan_only() {
        let mut dokan_info = VfsDriverInfo::new(VfsDriver::Dokan);
        dokan_info.version = Some((2, 1, 0));
        dokan_info.is_compatible = true;

        let result = DetectionResult {
            dokan: Some(dokan_info),
            winfsp: None,
        };

        let preferred = result.preferred_driver();
        assert!(preferred.is_some());
        assert_eq!(preferred.unwrap().driver, VfsDriver::Dokan);
    }

    #[test]
    fn test_detection_result_preferred_driver_winfsp_only() {
        let mut winfsp_info = VfsDriverInfo::new(VfsDriver::WinFsp);
        winfsp_info.version = Some((2, 0, 0));
        winfsp_info.is_compatible = true;

        let result = DetectionResult {
            dokan: None,
            winfsp: Some(winfsp_info),
        };

        let preferred = result.preferred_driver();
        assert!(preferred.is_some());
        assert_eq!(preferred.unwrap().driver, VfsDriver::WinFsp);
    }

    #[test]
    fn test_detection_result_preferred_driver_both_compatible() {
        let mut dokan_info = VfsDriverInfo::new(VfsDriver::Dokan);
        dokan_info.version = Some((2, 1, 0));
        dokan_info.is_compatible = true;

        let mut winfsp_info = VfsDriverInfo::new(VfsDriver::WinFsp);
        winfsp_info.version = Some((2, 0, 0));
        winfsp_info.is_compatible = true;

        let result = DetectionResult {
            dokan: Some(dokan_info),
            winfsp: Some(winfsp_info),
        };

        // Dokan should be preferred
        let preferred = result.preferred_driver();
        assert!(preferred.is_some());
        assert_eq!(preferred.unwrap().driver, VfsDriver::Dokan);
    }

    #[test]
    fn test_detection_result_preferred_driver_dokan_incompatible() {
        let mut dokan_info = VfsDriverInfo::new(VfsDriver::Dokan);
        dokan_info.version = Some((1, 5, 0)); // Old version
        dokan_info.is_compatible = false;

        let mut winfsp_info = VfsDriverInfo::new(VfsDriver::WinFsp);
        winfsp_info.version = Some((2, 0, 0));
        winfsp_info.is_compatible = true;

        let result = DetectionResult {
            dokan: Some(dokan_info),
            winfsp: Some(winfsp_info),
        };

        // WinFsp should be preferred since Dokan is incompatible
        let preferred = result.preferred_driver();
        assert!(preferred.is_some());
        assert_eq!(preferred.unwrap().driver, VfsDriver::WinFsp);
    }

    #[test]
    fn test_detection_result_any_driver() {
        let result = DetectionResult::default();
        assert!(result.any_driver().is_none());

        let dokan_info = VfsDriverInfo::new(VfsDriver::Dokan);
        let result = DetectionResult {
            dokan: Some(dokan_info),
            winfsp: None,
        };
        assert!(result.any_driver().is_some());
    }

    #[test]
    fn test_detection_result_has_compatible_driver() {
        let result = DetectionResult::default();
        assert!(!result.has_compatible_driver());

        let mut dokan_info = VfsDriverInfo::new(VfsDriver::Dokan);
        dokan_info.is_compatible = true;

        let result = DetectionResult {
            dokan: Some(dokan_info),
            winfsp: None,
        };
        assert!(result.has_compatible_driver());
    }

    // ========================================================================
    // Public API tests
    // ========================================================================

    #[test]
    fn test_is_vfs_detection_supported() {
        let supported = is_vfs_detection_supported();
        #[cfg(windows)]
        assert!(supported);
        #[cfg(not(windows))]
        assert!(!supported);
    }

    #[test]
    fn test_get_no_driver_message() {
        let msg = get_no_driver_message();
        assert!(msg.contains("VFS"));
        assert!(msg.contains("Dokan"));
        assert!(msg.contains("WinFsp"));
        assert!(msg.contains("download") || msg.contains("Download"));
    }

    #[test]
    fn test_get_driver_install_instructions_dokan() {
        let instructions = get_driver_install_instructions(VfsDriver::Dokan);
        assert!(instructions.contains("Dokan"));
        assert!(instructions.contains("download") || instructions.contains("Download"));
        assert!(instructions.contains("Administrator"));
    }

    #[test]
    fn test_get_driver_install_instructions_winfsp() {
        let instructions = get_driver_install_instructions(VfsDriver::WinFsp);
        assert!(instructions.contains("WinFsp"));
        assert!(instructions.contains("download") || instructions.contains("Download"));
        assert!(instructions.contains("Administrator"));
    }

    #[test]
    fn test_detect_vfs_driver_returns_none_on_non_windows() {
        #[cfg(not(windows))]
        {
            let driver = detect_vfs_driver();
            assert!(driver.is_none());
        }
    }

    #[test]
    fn test_detect_vfs_driver_info_returns_none_on_non_windows() {
        #[cfg(not(windows))]
        {
            let info = detect_vfs_driver_info();
            assert!(info.is_none());
        }
    }

    #[test]
    fn test_detect_all_vfs_drivers_empty_on_non_windows() {
        #[cfg(not(windows))]
        {
            let result = detect_all_vfs_drivers();
            assert!(result.is_empty());
        }
    }

    // ========================================================================
    // Windows-specific tests
    // ========================================================================

    #[cfg(windows)]
    mod windows_tests {
        use super::*;

        #[test]
        fn test_detect_dokan_returns_valid_info_or_none() {
            // This test runs on actual Windows systems
            // It may or may not find Dokan depending on installation
            let info = detect_dokan();
            if let Some(info) = info {
                assert_eq!(info.driver, VfsDriver::Dokan);
                // If detected, should have at least install_path or dll_path
                assert!(info.install_path.is_some() || info.dll_path.is_some());
            }
        }

        #[test]
        fn test_detect_winfsp_returns_valid_info_or_none() {
            // This test runs on actual Windows systems
            // It may or may not find WinFsp depending on installation
            let info = detect_winfsp();
            if let Some(info) = info {
                assert_eq!(info.driver, VfsDriver::WinFsp);
                // If detected, should have at least install_path or dll_path
                assert!(info.install_path.is_some() || info.dll_path.is_some());
            }
        }

        #[test]
        fn test_detect_all_drivers_returns_detection_result() {
            let result = detect_all_drivers();
            // Result should be a valid DetectionResult regardless of installed drivers
            // Just verify the structure is correct
            let _ = result.preferred_driver();
            let _ = result.any_driver();
            let _ = result.is_empty();
            let _ = result.has_compatible_driver();
        }

        #[test]
        fn test_parse_version() {
            use super::super::windows_impl::parse_version;

            assert_eq!(parse_version("2.1.0"), Some((2, 1, 0)));
            assert_eq!(parse_version("1.0"), Some((1, 0, 0)));
            assert_eq!(parse_version("3"), Some((3, 0, 0)));
            assert_eq!(parse_version("2.0.5.1234"), Some((2, 0, 5)));
            assert!(parse_version("").is_none());
            assert!(parse_version("invalid").is_none());
        }

        #[test]
        fn test_to_wide_null() {
            use super::super::windows_impl::to_wide_null;

            let wide = to_wide_null("test");
            assert_eq!(wide.len(), 5); // "test" + null terminator
            assert_eq!(wide[4], 0);
        }
    }
}
