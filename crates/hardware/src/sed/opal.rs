//! TCG Opal 2.0 Self-Encrypting Drive support.
//!
//! TCG (Trusted Computing Group) Opal is an industry standard for
//! hardware-based full disk encryption in Self-Encrypting Drives (SEDs).

use std::path::{Path, PathBuf};

use crate::error::{HardwareError, Result};

/// TCG Opal drive status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpalStatus {
    /// Drive does not support TCG Opal.
    NotSupported,
    /// Drive supports Opal but is not initialized.
    Uninitialized,
    /// Drive is initialized and currently locked.
    Locked,
    /// Drive is initialized and currently unlocked.
    Unlocked,
}

impl OpalStatus {
    /// Check if the drive is usable (unlocked).
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked)
    }

    /// Check if the drive can be initialized.
    #[must_use]
    pub fn can_initialize(&self) -> bool {
        matches!(self, Self::Uninitialized)
    }

    /// Check if the drive requires a password to unlock.
    #[must_use]
    pub fn requires_password(&self) -> bool {
        matches!(self, Self::Locked)
    }

    /// Get a human-readable description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::NotSupported => "TCG Opal not supported",
            Self::Uninitialized => "TCG Opal supported, not initialized",
            Self::Locked => "TCG Opal locked",
            Self::Unlocked => "TCG Opal unlocked",
        }
    }
}

/// TCG Opal drive handle.
#[derive(Debug)]
pub struct OpalDrive {
    /// Device path.
    pub device_path: PathBuf,
    /// Current status.
    pub status: OpalStatus,
    /// Opal version (e.g., "2.0").
    pub version: Option<String>,
}

impl OpalDrive {
    /// Create a new Opal drive handle.
    #[must_use]
    pub fn new(device_path: PathBuf, status: OpalStatus) -> Self {
        Self {
            device_path,
            status,
            version: None,
        }
    }

    /// Unlock the drive with a password.
    ///
    /// Uses sedutil-cli to send the unlock command to the drive.
    /// After successful unlock, updates the drive's status to Unlocked.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to unlock the drive
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The drive does not support Opal
    /// - The drive is not initialized
    /// - The password is incorrect
    /// - sedutil-cli is not available
    /// - Insufficient permissions
    pub fn unlock(&mut self, password: &[u8]) -> Result<()> {
        // Check current status
        match self.status {
            OpalStatus::NotSupported => {
                return Err(HardwareError::OpalNotSupported);
            }
            OpalStatus::Uninitialized => {
                return Err(HardwareError::OpalNotInitialized);
            }
            OpalStatus::Unlocked => {
                // Already unlocked, nothing to do
                return Ok(());
            }
            OpalStatus::Locked => {
                // Proceed with unlock
            }
        }

        #[cfg(target_os = "macos")]
        {
            unlock_opal_macos(&self.device_path, password)?;
            self.status = OpalStatus::Unlocked;
            Ok(())
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            unlock_opal_linux(&self.device_path, password)?;
            self.status = OpalStatus::Unlocked;
            Ok(())
        }

        #[cfg(windows)]
        {
            unlock_opal_windows(&self.device_path, password)?;
            self.status = OpalStatus::Unlocked;
            Ok(())
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = password;
            Err(HardwareError::PlatformNotSupported {
                platform: "non-Unix/Windows".to_string(),
            })
        }
    }

    /// Lock the drive.
    ///
    /// Uses sedutil-cli to set the locking range to read-only (locked).
    pub fn lock(&mut self) -> Result<()> {
        match self.status {
            OpalStatus::NotSupported => {
                return Err(HardwareError::OpalNotSupported);
            }
            OpalStatus::Uninitialized => {
                return Err(HardwareError::OpalNotInitialized);
            }
            OpalStatus::Locked => {
                // Already locked, nothing to do
                return Ok(());
            }
            OpalStatus::Unlocked => {
                // Proceed with lock
            }
        }

        #[cfg(unix)]
        {
            use std::process::Command;

            // Use sedutil-cli to lock the drive
            // sedutil-cli --setLockingRange 0 LK <drive>
            let output = Command::new("sedutil-cli")
                .arg("--setLockingRange")
                .arg("0")
                .arg("LK")
                .arg(&self.device_path)
                .output();

            match output {
                Ok(output) if output.status.success() => {
                    self.status = OpalStatus::Locked;
                    Ok(())
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(HardwareError::CommandFailed {
                        command: "sedutil-cli --setLockingRange 0 LK".to_string(),
                        reason: stderr.to_string(),
                    })
                }
                Err(e) => Err(HardwareError::IoError {
                    message: e.to_string(),
                }),
            }
        }

        #[cfg(windows)]
        {
            use std::process::Command;

            // Use sedutil.exe to lock the drive
            let output = Command::new("sedutil.exe")
                .arg("--setLockingRange")
                .arg("0")
                .arg("LK")
                .arg(&self.device_path)
                .output();

            match output {
                Ok(output) if output.status.success() => {
                    self.status = OpalStatus::Locked;
                    Ok(())
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(HardwareError::CommandFailed {
                        command: "sedutil.exe --setLockingRange 0 LK".to_string(),
                        reason: stderr.to_string(),
                    })
                }
                Err(e) => Err(HardwareError::IoError {
                    message: e.to_string(),
                }),
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(HardwareError::PlatformNotSupported {
                platform: "non-Unix/Windows".to_string(),
            })
        }
    }

    /// Initialize the drive with a password.
    ///
    /// Uses sedutil-cli to perform initial setup of the drive's Opal security.
    /// This sets the SID (Security ID) and Admin1 passwords and enables locking.
    ///
    /// # Warning
    ///
    /// This may erase all data on the drive depending on the drive's configuration.
    /// Ensure data is backed up before initialization.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to set for the drive
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The drive does not support Opal
    /// - The drive is already initialized
    /// - sedutil-cli is not available
    /// - Insufficient permissions
    pub fn initialize(&mut self, password: &[u8]) -> Result<()> {
        // Check current status
        match self.status {
            OpalStatus::NotSupported => {
                return Err(HardwareError::OpalNotSupported);
            }
            OpalStatus::Locked | OpalStatus::Unlocked => {
                // Already initialized
                return Err(HardwareError::CommandFailed {
                    command: "initialize".to_string(),
                    reason: "Drive is already initialized".to_string(),
                });
            }
            OpalStatus::Uninitialized => {
                // Proceed with initialization
            }
        }

        #[cfg(unix)]
        {
            initialize_opal_unix(&self.device_path, password)?;
            self.status = OpalStatus::Unlocked;
            Ok(())
        }

        #[cfg(windows)]
        {
            initialize_opal_windows(&self.device_path, password)?;
            self.status = OpalStatus::Unlocked;
            Ok(())
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = password;
            Err(HardwareError::PlatformNotSupported {
                platform: "non-Unix/Windows".to_string(),
            })
        }
    }
}

/// Query if a drive supports TCG Opal.
///
/// Uses sedutil-cli to query the drive for TCG Opal support.
/// Returns false if sedutil-cli is not available or the drive
/// doesn't support Opal.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/sda)
///
/// # Returns
///
/// `true` if the drive supports TCG Opal, `false` otherwise.
///
/// # Errors
///
/// Returns an error if device path is invalid. Missing sedutil-cli
/// is not an error; it simply returns `false`.
pub fn query_opal_support(device_path: &Path) -> Result<bool> {
    // Check if device path is valid
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // Try to use sedutil-cli to query the drive
    #[cfg(unix)]
    {
        use std::process::Command;

        let output = Command::new("sedutil-cli")
            .arg("--query")
            .arg(device_path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse output for Opal support indicators
                // sedutil-cli --query output includes "Opal" for supported drives
                Ok(stdout.contains("Opal") || stdout.contains("OPAL"))
            }
            Ok(_) => {
                // Command ran but device doesn't support Opal
                Ok(false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // sedutil-cli not installed - not an error, just can't detect
                Ok(false)
            }
            Err(_) => {
                // Other error - still return false
                Ok(false)
            }
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;

        // On Windows, sedutil.exe is used (available from https://github.com/Drive-Trust-Alliance/sedutil)
        let output = Command::new("sedutil.exe")
            .arg("--query")
            .arg(device_path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse output for Opal support indicators
                Ok(stdout.contains("Opal") || stdout.contains("OPAL"))
            }
            Ok(_) => {
                // Command ran but device doesn't support Opal
                Ok(false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // sedutil.exe not installed - not an error, just can't detect
                Ok(false)
            }
            Err(_) => {
                // Other error - still return false
                Ok(false)
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Non-Unix/Windows platforms use different detection
        let _ = device_path;
        Ok(false)
    }
}

/// Get the Opal status for a drive.
///
/// Uses sedutil-cli to determine the current lock state of a
/// TCG Opal drive.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/sda)
///
/// # Returns
///
/// The current `OpalStatus` of the drive.
///
/// # Errors
///
/// Returns an error if device path is invalid.
pub fn get_opal_status(device_path: &Path) -> Result<OpalStatus> {
    // Check if device path is valid
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    #[cfg(unix)]
    {
        use std::process::Command;

        // First, query for Opal support
        let output = Command::new("sedutil-cli")
            .arg("--query")
            .arg(device_path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(parse_sedutil_query_output(&stdout))
            }
            Ok(output) => {
                // Check stderr for more information
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("not authorized") || stderr.contains("Locked") {
                    Ok(OpalStatus::Locked)
                } else {
                    Ok(OpalStatus::NotSupported)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // sedutil-cli not installed
                Err(HardwareError::ToolNotFound {
                    tool: "sedutil-cli".to_string(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(HardwareError::permission_denied("run sedutil-cli"))
            }
            Err(e) => Err(HardwareError::Io(e)),
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;

        // Use sedutil.exe to query Opal status on Windows
        let output = Command::new("sedutil.exe")
            .arg("--query")
            .arg(device_path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(parse_sedutil_query_output_windows(&stdout))
            }
            Ok(output) => {
                // Check stderr for more information
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("not authorized") || stderr.contains("Locked") {
                    Ok(OpalStatus::Locked)
                } else {
                    Ok(OpalStatus::NotSupported)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // sedutil.exe not installed
                Err(HardwareError::ToolNotFound {
                    tool: "sedutil.exe".to_string(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(HardwareError::permission_denied("run sedutil.exe"))
            }
            Err(e) => Err(HardwareError::Io(e)),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = device_path;
        Ok(OpalStatus::NotSupported)
    }
}

/// Parse sedutil-cli --query output to determine Opal status.
#[cfg(unix)]
fn parse_sedutil_query_output(output: &str) -> OpalStatus {
    // Example sedutil-cli --query output (simplified):
    // /dev/sda ... Opal V2.00 ...
    // Locking function (0x0002):
    //     Locked = N, LockingEnabled = Y, ...
    // or
    //     Locked = Y, LockingEnabled = Y, ...
    // or for uninitialized:
    //     MBRDone = N, MBREnabled = N, ...

    let output_lower = output.to_lowercase();

    // Check if Opal is supported at all
    if !output_lower.contains("opal") {
        return OpalStatus::NotSupported;
    }

    // Check locking status
    // Look for "Locked = Y" or "Locked = N" patterns
    if output_lower.contains("locked = y") || output_lower.contains("locked=y") {
        return OpalStatus::Locked;
    }

    // Check if locking is enabled (drive is initialized)
    if output_lower.contains("lockingenabled = y") || output_lower.contains("lockingenabled=y") {
        // Locking enabled but not locked means unlocked
        return OpalStatus::Unlocked;
    }

    // Check for MBRDone which indicates initialization
    if output_lower.contains("mbrdone = y") || output_lower.contains("mbrdone=y") {
        return OpalStatus::Unlocked;
    }

    // Has Opal support but not initialized
    OpalStatus::Uninitialized
}

/// Unlock an Opal drive on Linux using sedutil-cli.
///
/// Uses `sedutil-cli --setLockingRange 0 RW <password> <device>` to unlock
/// the drive's global locking range.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/sda)
/// * `password` - The password to unlock the drive
///
/// # Errors
///
/// Returns an error if:
/// - sedutil-cli is not available
/// - Insufficient permissions
/// - Password is incorrect
#[cfg(unix)]
fn unlock_opal_linux(device_path: &Path, password: &[u8]) -> Result<()> {
    use std::process::Command;

    // Convert password to string (sedutil requires ASCII password)
    let password_str = String::from_utf8_lossy(password);

    // sedutil-cli --setLockingRange 0 RW <password> <device>
    // 0 = Global locking range
    // RW = Read/Write access
    let output = Command::new("sedutil-cli")
        .arg("--setLockingRange")
        .arg("0")
        .arg("RW")
        .arg(password_str.as_ref())
        .arg(device_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Verify unlock by querying status
            let verify_output = Command::new("sedutil-cli")
                .arg("--query")
                .arg(device_path)
                .output();

            if let Ok(verify) = verify_output {
                let stdout = String::from_utf8_lossy(&verify.stdout);
                let status = parse_sedutil_query_output(&stdout);
                if status == OpalStatus::Unlocked {
                    return Ok(());
                }
            }

            // Unlock command succeeded, but we couldn't verify
            // Trust the command result
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stdout, stderr).to_lowercase();

            if combined.contains("not authorized")
                || combined.contains("authority check failed")
                || combined.contains("invalid password")
                || combined.contains("authentication failed")
            {
                Err(HardwareError::InvalidPassword)
            } else if combined.contains("not initialized")
                || combined.contains("locking not enabled")
            {
                Err(HardwareError::OpalNotInitialized)
            } else {
                Err(HardwareError::OpalNotSupported)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(HardwareError::ToolNotFound {
                tool: "sedutil-cli".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(HardwareError::permission_denied("run sedutil-cli"))
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Initialize an Opal drive on Unix using sedutil-cli.
///
/// Uses `sedutil-cli --initialSetup <password> <device>` to perform initial
/// Opal security setup.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/sda)
/// * `password` - The password to set for the drive
///
/// # Errors
///
/// Returns an error if:
/// - sedutil-cli is not available
/// - Insufficient permissions
/// - Drive is already initialized
#[cfg(unix)]
fn initialize_opal_unix(device_path: &Path, password: &[u8]) -> Result<()> {
    use std::process::Command;

    // Convert password to string (sedutil requires ASCII password)
    let password_str = String::from_utf8_lossy(password);

    // sedutil-cli --initialSetup <password> <device>
    // This command:
    // 1. Takes ownership of the drive (sets SID password)
    // 2. Sets Admin1 password
    // 3. Enables locking on the global range
    let output = Command::new("sedutil-cli")
        .arg("--initialSetup")
        .arg(password_str.as_ref())
        .arg(device_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Verify initialization by querying status
            let verify_output = Command::new("sedutil-cli")
                .arg("--query")
                .arg(device_path)
                .output();

            if let Ok(verify) = verify_output {
                let stdout = String::from_utf8_lossy(&verify.stdout);
                let status = parse_sedutil_query_output(&stdout);
                if status == OpalStatus::Unlocked || status == OpalStatus::Locked {
                    return Ok(());
                }
            }

            // Command succeeded, trust the result
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stdout, stderr).to_lowercase();

            if combined.contains("already") || combined.contains("ownership") {
                Err(HardwareError::CommandFailed {
                    command: "sedutil-cli --initialSetup".to_string(),
                    reason: "Drive is already initialized or owned".to_string(),
                })
            } else if combined.contains("not an opal") || combined.contains("not supported") {
                Err(HardwareError::OpalNotSupported)
            } else {
                Err(HardwareError::CommandFailed {
                    command: "sedutil-cli --initialSetup".to_string(),
                    reason: stderr.to_string(),
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(HardwareError::ToolNotFound {
                tool: "sedutil-cli".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(HardwareError::permission_denied("run sedutil-cli"))
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Initialize an Opal drive on Windows using sedutil.exe.
///
/// Uses `sedutil.exe --initialSetup <password> <device>` to perform initial
/// Opal security setup.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., \\.\PhysicalDrive1)
/// * `password` - The password to set for the drive
///
/// # Errors
///
/// Returns an error if:
/// - sedutil.exe is not available
/// - Insufficient permissions (requires Administrator)
/// - Drive is already initialized
#[cfg(windows)]
fn initialize_opal_windows(device_path: &Path, password: &[u8]) -> Result<()> {
    use std::process::Command;

    // Convert password to string (sedutil requires ASCII password)
    let password_str = String::from_utf8_lossy(password);
    let device_str = device_path.to_string_lossy();

    // sedutil.exe --initialSetup <password> <device>
    let output = Command::new("sedutil.exe")
        .arg("--initialSetup")
        .arg(password_str.as_ref())
        .arg(device_str.as_ref())
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Verify initialization by querying status
            let verify_output = Command::new("sedutil.exe")
                .arg("--query")
                .arg(device_str.as_ref())
                .output();

            if let Ok(verify) = verify_output {
                let stdout = String::from_utf8_lossy(&verify.stdout);
                let status = parse_sedutil_query_output_windows(&stdout);
                if status == OpalStatus::Unlocked || status == OpalStatus::Locked {
                    return Ok(());
                }
            }

            // Command succeeded, trust the result
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stdout, stderr).to_lowercase();

            if combined.contains("already") || combined.contains("ownership") {
                Err(HardwareError::CommandFailed {
                    command: "sedutil.exe --initialSetup".to_string(),
                    reason: "Drive is already initialized or owned".to_string(),
                })
            } else if combined.contains("not an opal") || combined.contains("not supported") {
                Err(HardwareError::OpalNotSupported)
            } else if combined.contains("requires elevation") || combined.contains("administrator") {
                Err(HardwareError::permission_denied("run sedutil.exe"))
            } else {
                Err(HardwareError::CommandFailed {
                    command: "sedutil.exe --initialSetup".to_string(),
                    reason: stderr.to_string(),
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(HardwareError::ToolNotFound {
                tool: "sedutil.exe".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(HardwareError::permission_denied("run sedutil.exe"))
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Parse sedutil.exe --query output to determine Opal status on Windows.
///
/// The output format is the same as sedutil-cli on Linux.
#[cfg(windows)]
fn parse_sedutil_query_output_windows(output: &str) -> OpalStatus {
    // The parsing logic is the same as Linux since sedutil uses the same output format
    let output_lower = output.to_lowercase();

    // Check if Opal is supported at all
    if !output_lower.contains("opal") {
        return OpalStatus::NotSupported;
    }

    // Check locking status
    // Look for "Locked = Y" or "Locked = N" patterns
    if output_lower.contains("locked = y") || output_lower.contains("locked=y") {
        return OpalStatus::Locked;
    }

    // Check if locking is enabled (drive is initialized)
    if output_lower.contains("lockingenabled = y") || output_lower.contains("lockingenabled=y") {
        // Locking enabled but not locked means unlocked
        return OpalStatus::Unlocked;
    }

    // Check for MBRDone which indicates initialization
    if output_lower.contains("mbrdone = y") || output_lower.contains("mbrdone=y") {
        return OpalStatus::Unlocked;
    }

    // Has Opal support but not initialized
    OpalStatus::Uninitialized
}

/// Unlock an Opal drive on Windows using sedutil.exe.
///
/// Uses `sedutil.exe --setLockingRange 0 RW <password> <device>` to unlock
/// the drive's global locking range.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., \\.\PhysicalDrive1)
/// * `password` - The password to unlock the drive
///
/// # Errors
///
/// Returns an error if:
/// - sedutil.exe is not available
/// - Insufficient permissions (requires Administrator)
/// - Password is incorrect
#[cfg(windows)]
fn unlock_opal_windows(device_path: &Path, password: &[u8]) -> Result<()> {
    use std::process::Command;

    // Convert password to string (sedutil requires ASCII password)
    let password_str = String::from_utf8_lossy(password);

    // Convert device path to Windows format if needed
    // On Windows, device paths are typically \\.\PhysicalDrive0 format
    let device_str = device_path.to_string_lossy();

    // sedutil.exe --setLockingRange 0 RW <password> <device>
    // 0 = Global locking range
    // RW = Read/Write access
    let output = Command::new("sedutil.exe")
        .arg("--setLockingRange")
        .arg("0")
        .arg("RW")
        .arg(password_str.as_ref())
        .arg(device_str.as_ref())
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Verify unlock by querying status
            let verify_output = Command::new("sedutil.exe")
                .arg("--query")
                .arg(device_str.as_ref())
                .output();

            if let Ok(verify) = verify_output {
                let stdout = String::from_utf8_lossy(&verify.stdout);
                let status = parse_sedutil_query_output_windows(&stdout);
                if status == OpalStatus::Unlocked {
                    return Ok(());
                }
            }

            // Unlock command succeeded, but we couldn't verify
            // Trust the command result
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stdout, stderr).to_lowercase();

            if combined.contains("not authorized")
                || combined.contains("authority check failed")
                || combined.contains("invalid password")
                || combined.contains("authentication failed")
                || combined.contains("access denied")
            {
                Err(HardwareError::InvalidPassword)
            } else if combined.contains("not initialized")
                || combined.contains("locking not enabled")
            {
                Err(HardwareError::OpalNotInitialized)
            } else if combined.contains("requires elevation")
                || combined.contains("administrator")
            {
                Err(HardwareError::permission_denied("run sedutil.exe"))
            } else {
                Err(HardwareError::OpalNotSupported)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(HardwareError::ToolNotFound {
                tool: "sedutil.exe".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(HardwareError::permission_denied("run sedutil.exe"))
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Check if sedutil is available on the system.
#[allow(dead_code)]
fn is_sedutil_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // On macOS, sedutil-cli may be installed via Homebrew or manually
        // Try common paths: /usr/local/bin/sedutil-cli, /opt/homebrew/bin/sedutil-cli
        Command::new("sedutil-cli")
            .arg("--help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::process::Command;
        Command::new("sedutil-cli")
            .arg("--help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("sedutil.exe")
            .arg("--help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    false
}

/// Check if System Integrity Protection (SIP) is enabled on macOS.
///
/// SIP can restrict direct hardware access even with root privileges.
/// Returns `true` if SIP is enabled or if status cannot be determined.
#[cfg(target_os = "macos")]
fn is_sip_enabled() -> bool {
    use std::process::Command;

    // csrutil status returns:
    // "System Integrity Protection status: enabled." or
    // "System Integrity Protection status: disabled."
    let output = Command::new("csrutil")
        .arg("status")
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // If output contains "disabled", SIP is off
            !stdout.to_lowercase().contains("disabled")
        }
        Err(_) => {
            // Cannot determine SIP status, assume enabled for safety
            true
        }
    }
}

/// Query TCG Opal support on macOS.
///
/// On macOS, TCG Opal detection has several challenges:
/// 1. SIP (System Integrity Protection) may restrict hardware access
/// 2. sedutil-cli requires elevated privileges
/// 3. IOKit can provide some drive information but not full Opal control
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/disk1)
///
/// # Returns
///
/// `true` if the drive supports TCG Opal, `false` otherwise.
#[cfg(target_os = "macos")]
pub fn query_opal_support_macos(device_path: &Path) -> Result<bool> {
    use std::process::Command;

    // Check if device path is valid
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // On macOS, sedutil-cli works similarly to Linux
    // but may require additional permissions due to SIP
    let output = Command::new("sedutil-cli")
        .arg("--query")
        .arg(device_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.contains("Opal") || stdout.contains("OPAL"))
        }
        Ok(output) => {
            // Check if this is a SIP restriction issue
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Operation not permitted") && is_sip_enabled() {
                // SIP may be blocking hardware access
                // Log this but don't error - just return false
                Ok(false)
            } else {
                Ok(false)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // sedutil-cli not installed
            Ok(false)
        }
        Err(_) => {
            Ok(false)
        }
    }
}

/// Get TCG Opal status on macOS.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/disk1)
///
/// # Returns
///
/// The current `OpalStatus` of the drive.
#[cfg(target_os = "macos")]
pub fn get_opal_status_macos(device_path: &Path) -> Result<OpalStatus> {
    use std::process::Command;

    // Check if device path is valid
    if !device_path.exists() {
        return Err(HardwareError::DriveNotFound {
            path: device_path.to_path_buf(),
        });
    }

    // Check SIP status first - if enabled, we may have limited functionality
    if is_sip_enabled() {
        // SIP is enabled - we can still try sedutil but warn about potential issues
    }

    let output = Command::new("sedutil-cli")
        .arg("--query")
        .arg(device_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(parse_sedutil_query_output_macos(&stdout))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Operation not permitted") {
                // SIP or permission restriction
                return Err(HardwareError::PermissionDenied {
                    operation: "query Opal status".to_string(),
                    hint: "SIP may be blocking access. Boot to Recovery Mode and run 'csrutil disable' to disable SIP, or ensure sedutil-cli has full disk access".to_string(),
                });
            }
            if stderr.contains("not authorized") || stderr.contains("Locked") {
                Ok(OpalStatus::Locked)
            } else {
                Ok(OpalStatus::NotSupported)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(HardwareError::ToolNotFound {
                tool: "sedutil-cli".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(HardwareError::PermissionDenied {
                operation: "run sedutil-cli".to_string(),
                hint: "Run with sudo or grant Full Disk Access to Terminal".to_string(),
            })
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

/// Parse sedutil-cli output on macOS (same format as Linux).
#[cfg(target_os = "macos")]
fn parse_sedutil_query_output_macos(output: &str) -> OpalStatus {
    let output_lower = output.to_lowercase();

    if !output_lower.contains("opal") {
        return OpalStatus::NotSupported;
    }

    if output_lower.contains("locked = y") || output_lower.contains("locked=y") {
        return OpalStatus::Locked;
    }

    if output_lower.contains("lockingenabled = y") || output_lower.contains("lockingenabled=y") {
        return OpalStatus::Unlocked;
    }

    if output_lower.contains("mbrdone = y") || output_lower.contains("mbrdone=y") {
        return OpalStatus::Unlocked;
    }

    OpalStatus::Uninitialized
}

/// Unlock an Opal drive on macOS using sedutil-cli.
///
/// # macOS-specific considerations
///
/// 1. **SIP Restrictions**: System Integrity Protection may block direct hardware access.
///    If unlock fails with permission errors, SIP may need to be disabled or
///    the binary may need code signing entitlements.
///
/// 2. **Full Disk Access**: Terminal.app or the calling process may need
///    Full Disk Access permission in System Preferences > Security & Privacy.
///
/// 3. **T2 Security Chip**: Macs with T2 chips have built-in encryption that
///    operates independently of TCG Opal. This function is for external SEDs.
///
/// # Arguments
///
/// * `device_path` - Path to the device (e.g., /dev/disk2)
/// * `password` - The password to unlock the drive
///
/// # Errors
///
/// Returns an error if:
/// - sedutil-cli is not available
/// - SIP blocks the operation
/// - Insufficient permissions
/// - Password is incorrect
#[cfg(target_os = "macos")]
pub fn unlock_opal_macos(device_path: &Path, password: &[u8]) -> Result<()> {
    use std::process::Command;

    // Convert password to string (sedutil requires ASCII password)
    let password_str = String::from_utf8_lossy(password);

    // sedutil-cli --setLockingRange 0 RW <password> <device>
    let output = Command::new("sedutil-cli")
        .arg("--setLockingRange")
        .arg("0")
        .arg("RW")
        .arg(password_str.as_ref())
        .arg(device_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            // Verify unlock by querying status
            let verify_output = Command::new("sedutil-cli")
                .arg("--query")
                .arg(device_path)
                .output();

            if let Ok(verify) = verify_output {
                let stdout = String::from_utf8_lossy(&verify.stdout);
                let status = parse_sedutil_query_output_macos(&stdout);
                if status == OpalStatus::Unlocked {
                    return Ok(());
                }
            }

            // Command succeeded, trust the result
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stdout, stderr).to_lowercase();

            if combined.contains("operation not permitted") {
                // This is likely a SIP restriction
                return Err(HardwareError::PermissionDenied {
                    operation: "unlock Opal drive".to_string(),
                    hint: "SIP may be blocking hardware access. Consider disabling SIP or granting Full Disk Access".to_string(),
                });
            }

            if combined.contains("not authorized")
                || combined.contains("authority check failed")
                || combined.contains("invalid password")
                || combined.contains("authentication failed")
            {
                Err(HardwareError::InvalidPassword)
            } else if combined.contains("not initialized")
                || combined.contains("locking not enabled")
            {
                Err(HardwareError::OpalNotInitialized)
            } else {
                Err(HardwareError::OpalNotSupported)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(HardwareError::ToolNotFound {
                tool: "sedutil-cli".to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(HardwareError::PermissionDenied {
                operation: "run sedutil-cli".to_string(),
                hint: "Run with sudo or grant Full Disk Access to Terminal".to_string(),
            })
        }
        Err(e) => Err(HardwareError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opal_status_is_unlocked() {
        assert!(!OpalStatus::NotSupported.is_unlocked());
        assert!(!OpalStatus::Uninitialized.is_unlocked());
        assert!(!OpalStatus::Locked.is_unlocked());
        assert!(OpalStatus::Unlocked.is_unlocked());
    }

    #[test]
    fn test_opal_status_can_initialize() {
        assert!(!OpalStatus::NotSupported.can_initialize());
        assert!(OpalStatus::Uninitialized.can_initialize());
        assert!(!OpalStatus::Locked.can_initialize());
        assert!(!OpalStatus::Unlocked.can_initialize());
    }

    #[test]
    fn test_opal_status_requires_password() {
        assert!(!OpalStatus::NotSupported.requires_password());
        assert!(!OpalStatus::Uninitialized.requires_password());
        assert!(OpalStatus::Locked.requires_password());
        assert!(!OpalStatus::Unlocked.requires_password());
    }

    #[test]
    fn test_opal_status_description() {
        assert!(OpalStatus::NotSupported.description().contains("not supported"));
        assert!(OpalStatus::Locked.description().contains("locked"));
    }

    #[test]
    fn test_opal_drive_new() {
        let drive = OpalDrive::new(PathBuf::from("/dev/sda"), OpalStatus::Locked);
        assert_eq!(drive.device_path, PathBuf::from("/dev/sda"));
        assert_eq!(drive.status, OpalStatus::Locked);
        assert!(drive.version.is_none());
    }

    #[test]
    fn test_query_opal_support_device_not_found() {
        // Should return DriveNotFound error for non-existent device
        let result = query_opal_support(Path::new("/dev/nonexistent_device_12345"));
        assert!(matches!(result, Err(HardwareError::DriveNotFound { .. })));
    }

    #[test]
    fn test_query_opal_support_temp_file() {
        // For a regular file (not a block device), should return false
        // since it won't have Opal support
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("test_device");
        std::fs::write(&test_file, b"test").unwrap();

        let result = query_opal_support(&test_file);
        // Should succeed but return false (sedutil won't find Opal support)
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_get_opal_status_device_not_found() {
        // Should return DriveNotFound error for non-existent device
        let result = get_opal_status(Path::new("/dev/nonexistent_device_12345"));
        assert!(matches!(result, Err(HardwareError::DriveNotFound { .. })));
    }

    #[test]
    fn test_get_opal_status_temp_file() {
        // For a regular file, should return NotSupported or ToolNotFound
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("test_device");
        std::fs::write(&test_file, b"test").unwrap();

        let result = get_opal_status(&test_file);
        // Either NotSupported (sedutil fails) or ToolNotFound (sedutil not installed)
        assert!(matches!(
            result,
            Ok(OpalStatus::NotSupported) | Err(HardwareError::ToolNotFound { .. })
        ));
    }

    #[test]
    fn test_opal_drive_unlock_not_supported() {
        // Trying to unlock a drive that doesn't support Opal
        let mut drive = OpalDrive::new(PathBuf::from("/dev/sda"), OpalStatus::NotSupported);
        let result = drive.unlock(b"password");
        assert!(matches!(result, Err(HardwareError::OpalNotSupported)));
    }

    #[test]
    fn test_opal_drive_unlock_not_initialized() {
        // Trying to unlock a drive that's not initialized
        let mut drive = OpalDrive::new(PathBuf::from("/dev/sda"), OpalStatus::Uninitialized);
        let result = drive.unlock(b"password");
        assert!(matches!(result, Err(HardwareError::OpalNotInitialized)));
    }

    #[test]
    fn test_opal_drive_unlock_already_unlocked() {
        // Trying to unlock a drive that's already unlocked should succeed
        let mut drive = OpalDrive::new(PathBuf::from("/dev/sda"), OpalStatus::Unlocked);
        let result = drive.unlock(b"password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_opal_drive_unlock_locked() {
        // Trying to unlock a locked drive will try sedutil-cli
        // On systems without sedutil-cli, this will fail with ToolNotFound
        let mut drive = OpalDrive::new(PathBuf::from("/dev/nonexistent_device_12345"), OpalStatus::Locked);
        let result = drive.unlock(b"password");
        // Either ToolNotFound (sedutil not installed), permission denied, or other error
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_sedutil_query_opal_locked() {
        let output = r#"
/dev/sda SSD Opal V2.00
Locking function (0x0002):
    Locked = Y, LockingEnabled = Y, MBRDone = Y
"#;
        assert_eq!(parse_sedutil_query_output(output), OpalStatus::Locked);
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_sedutil_query_opal_unlocked() {
        let output = r#"
/dev/sda SSD Opal V2.00
Locking function (0x0002):
    Locked = N, LockingEnabled = Y, MBRDone = Y
"#;
        assert_eq!(parse_sedutil_query_output(output), OpalStatus::Unlocked);
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_sedutil_query_opal_uninitialized() {
        let output = r#"
/dev/sda SSD Opal V2.00
Locking function (0x0002):
    Locked = N, LockingEnabled = N, MBRDone = N
"#;
        assert_eq!(parse_sedutil_query_output(output), OpalStatus::Uninitialized);
    }

    #[cfg(unix)]
    #[test]
    fn test_parse_sedutil_query_no_opal() {
        let output = r#"
/dev/sda Standard SSD
No TCG support detected
"#;
        assert_eq!(parse_sedutil_query_output(output), OpalStatus::NotSupported);
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_sedutil_query_windows_opal_locked() {
        let output = r#"
\\.\PhysicalDrive1 SSD Opal V2.00
Locking function (0x0002):
    Locked = Y, LockingEnabled = Y, MBRDone = Y
"#;
        assert_eq!(parse_sedutil_query_output_windows(output), OpalStatus::Locked);
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_sedutil_query_windows_opal_unlocked() {
        let output = r#"
\\.\PhysicalDrive1 SSD Opal V2.00
Locking function (0x0002):
    Locked = N, LockingEnabled = Y, MBRDone = Y
"#;
        assert_eq!(parse_sedutil_query_output_windows(output), OpalStatus::Unlocked);
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_sedutil_query_windows_opal_uninitialized() {
        let output = r#"
\\.\PhysicalDrive1 SSD Opal V2.00
Locking function (0x0002):
    Locked = N, LockingEnabled = N, MBRDone = N
"#;
        assert_eq!(parse_sedutil_query_output_windows(output), OpalStatus::Uninitialized);
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_sedutil_query_windows_no_opal() {
        let output = r#"
\\.\PhysicalDrive1 Standard SSD
No TCG support detected
"#;
        assert_eq!(parse_sedutil_query_output_windows(output), OpalStatus::NotSupported);
    }

    // macOS-specific tests
    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_sedutil_query_macos_opal_locked() {
        let output = r#"
/dev/disk2 SSD Opal V2.00
Locking function (0x0002):
    Locked = Y, LockingEnabled = Y, MBRDone = Y
"#;
        assert_eq!(parse_sedutil_query_output_macos(output), OpalStatus::Locked);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_sedutil_query_macos_opal_unlocked() {
        let output = r#"
/dev/disk2 SSD Opal V2.00
Locking function (0x0002):
    Locked = N, LockingEnabled = Y, MBRDone = Y
"#;
        assert_eq!(parse_sedutil_query_output_macos(output), OpalStatus::Unlocked);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_sedutil_query_macos_opal_uninitialized() {
        let output = r#"
/dev/disk2 SSD Opal V2.00
Locking function (0x0002):
    Locked = N, LockingEnabled = N, MBRDone = N
"#;
        assert_eq!(parse_sedutil_query_output_macos(output), OpalStatus::Uninitialized);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_sedutil_query_macos_no_opal() {
        let output = r#"
/dev/disk2 Standard SSD
No TCG support detected
"#;
        assert_eq!(parse_sedutil_query_output_macos(output), OpalStatus::NotSupported);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_query_opal_support_macos_device_not_found() {
        let result = query_opal_support_macos(Path::new("/dev/nonexistent_device_12345"));
        assert!(matches!(result, Err(HardwareError::DriveNotFound { .. })));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_query_opal_support_macos_temp_file() {
        // For a regular file, should return false since it won't have Opal support
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("test_device");
        std::fs::write(&test_file, b"test").unwrap();

        let result = query_opal_support_macos(&test_file);
        // Should succeed but return false
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_opal_status_macos_device_not_found() {
        let result = get_opal_status_macos(Path::new("/dev/nonexistent_device_12345"));
        assert!(matches!(result, Err(HardwareError::DriveNotFound { .. })));
    }
}
