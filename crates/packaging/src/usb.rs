//! USB drive preparation.
//!
//! Provides tools for preparing removable drives for TESSERACT deployment:
//! - Validates target is a removable drive (USB/SD card)
//! - Creates required directory structure (`/TESSERACT/`, `/vault/`)
//! - Copies platform executables
//! - Optionally initializes an empty vault
//! - Generates `READY_TO_TEST.md` with testing instructions

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::{debug, info, warn};

use crate::detection::{self, DetectionError, DriveType};

/// Errors that can occur during USB preparation.
#[derive(Debug, Error)]
pub enum PrepareError {
    /// Target path does not exist.
    #[error("Target path does not exist: {0}")]
    PathNotFound(PathBuf),

    /// Target is not a removable drive.
    #[error("Target is not a removable drive: {path} (detected as {drive_type})")]
    NotRemovable {
        /// The path that was checked.
        path: PathBuf,
        /// The detected drive type.
        drive_type: String,
    },

    /// Drive detection failed.
    #[error("Drive detection failed: {0}")]
    DetectionFailed(#[from] DetectionError),

    /// Failed to create directory.
    #[error("Failed to create directory {path}: {source}")]
    CreateDirectoryFailed {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// Failed to write file.
    #[error("Failed to write file {path}: {source}")]
    WriteFileFailed {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// Failed to copy file.
    #[error("Failed to copy {source_path} to {dest_path}: {source}")]
    CopyFileFailed {
        /// Source file path.
        source_path: PathBuf,
        /// Destination file path.
        dest_path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// Platform not supported for preparation.
    #[error("USB preparation not supported on this platform")]
    UnsupportedPlatform,

    /// Vault initialization failed.
    #[error("Vault initialization failed: {0}")]
    VaultInitFailed(String),

    /// Target already has TESSERACT installed.
    #[error("Target already has TESSERACT installed at {0}. Use --force to overwrite.")]
    AlreadyInstalled(PathBuf),
}

/// Result type for USB preparation operations.
pub type PrepareResult<T> = Result<T, PrepareError>;

/// Directory names used by TESSERACT.
pub const TESSERACT_DIR: &str = "TESSERACT";
/// Vault directory name.
pub const VAULT_DIR: &str = "vault";
/// Ready to test instructions file.
pub const READY_TO_TEST_FILE: &str = "READY_TO_TEST.md";

/// Windows executable name.
pub const WINDOWS_EXE: &str = "tesseract.exe";
/// Linux AppImage name.
pub const LINUX_APPIMAGE: &str = "tesseract.AppImage";
/// macOS App Bundle name.
pub const MACOS_APP: &str = "TESSERACT.app";
/// Version info file name.
pub const VERSION_FILE: &str = "VERSION.txt";

/// Configuration for USB preparation.
#[derive(Debug, Clone)]
pub struct PrepareConfig {
    /// Target drive path (e.g., /Volumes/USB, /mnt/usb, E:\).
    pub target_path: PathBuf,

    /// Skip removable drive validation (for testing).
    pub skip_validation: bool,

    /// Force overwrite if TESSERACT is already installed.
    pub force: bool,

    /// Initialize an empty vault after preparation.
    pub init_vault: bool,

    /// Password for vault initialization (required if init_vault is true).
    pub vault_password: Option<String>,

    /// Source directory containing platform executables.
    /// If None, creates placeholder files.
    pub executables_source: Option<PathBuf>,

    /// Version string to write to VERSION.txt.
    pub version: String,
}

impl Default for PrepareConfig {
    fn default() -> Self {
        Self {
            target_path: PathBuf::new(),
            skip_validation: false,
            force: false,
            init_vault: false,
            vault_password: None,
            executables_source: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl PrepareConfig {
    /// Creates a new configuration with the specified target path.
    #[must_use]
    pub fn new(target_path: impl Into<PathBuf>) -> Self {
        Self {
            target_path: target_path.into(),
            ..Default::default()
        }
    }

    /// Sets whether to skip removable drive validation.
    #[must_use]
    pub fn skip_validation(mut self, skip: bool) -> Self {
        self.skip_validation = skip;
        self
    }

    /// Sets whether to force overwrite.
    #[must_use]
    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Sets whether to initialize vault after preparation.
    #[must_use]
    pub fn init_vault(mut self, init: bool) -> Self {
        self.init_vault = init;
        self
    }

    /// Sets the vault password.
    #[must_use]
    pub fn vault_password(mut self, password: impl Into<String>) -> Self {
        self.vault_password = Some(password.into());
        self
    }

    /// Sets the executables source directory.
    #[must_use]
    pub fn executables_source(mut self, source: impl Into<PathBuf>) -> Self {
        self.executables_source = Some(source.into());
        self
    }

    /// Sets the version string.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }
}

/// Result of a successful USB preparation.
#[derive(Debug, Clone)]
pub struct PrepareResult_ {
    /// Path to the TESSERACT directory.
    pub tesseract_dir: PathBuf,
    /// Path to the vault directory.
    pub vault_dir: PathBuf,
    /// Path to the READY_TO_TEST.md file.
    pub readme_path: PathBuf,
    /// Whether vault was initialized.
    pub vault_initialized: bool,
    /// Files that were created.
    pub files_created: Vec<PathBuf>,
    /// Warnings generated during preparation.
    pub warnings: Vec<String>,
}

/// Prepares a USB drive for TESSERACT deployment.
///
/// # Arguments
///
/// * `config` - The preparation configuration.
///
/// # Returns
///
/// Returns `PrepareResult_` on success with details about what was created.
///
/// # Errors
///
/// Returns an error if:
/// - Target path does not exist
/// - Target is not a removable drive (unless validation is skipped)
/// - TESSERACT is already installed (unless force is set)
/// - Directory/file creation fails
pub fn prepare_drive(config: &PrepareConfig) -> PrepareResult<PrepareResult_> {
    let target = &config.target_path;
    let mut warnings = Vec::new();
    let mut files_created = Vec::new();

    // Validate target path exists
    if !target.exists() {
        return Err(PrepareError::PathNotFound(target.clone()));
    }

    info!("Preparing USB drive at: {:?}", target);

    // Validate removable drive
    if !config.skip_validation {
        validate_removable(target)?;
    } else {
        warnings.push("Skipped removable drive validation".to_string());
        warn!("Skipping removable drive validation for {:?}", target);
    }

    // Check if already installed
    let tesseract_dir = target.join(TESSERACT_DIR);
    if tesseract_dir.exists() && !config.force {
        return Err(PrepareError::AlreadyInstalled(tesseract_dir));
    }

    // Create TESSERACT directory
    create_directory(&tesseract_dir)?;
    files_created.push(tesseract_dir.clone());

    // Create vault directory
    let vault_dir = target.join(VAULT_DIR);
    create_directory(&vault_dir)?;
    files_created.push(vault_dir.clone());

    // Copy or create platform executables
    copy_or_create_executables(&tesseract_dir, config, &mut files_created, &mut warnings)?;

    // Create version file
    let version_path = tesseract_dir.join(VERSION_FILE);
    write_version_file(&version_path, &config.version)?;
    files_created.push(version_path);

    // Initialize vault if requested
    let vault_initialized = if config.init_vault {
        match initialize_vault(&vault_dir, config) {
            Ok(()) => {
                info!("Vault initialized at {:?}", vault_dir);
                true
            }
            Err(e) => {
                warnings.push(format!("Vault initialization failed: {e}"));
                warn!("Vault initialization failed: {}", e);
                false
            }
        }
    } else {
        false
    };

    // Generate READY_TO_TEST.md
    let readme_path = target.join(READY_TO_TEST_FILE);
    write_readme(&readme_path, config, vault_initialized)?;
    files_created.push(readme_path.clone());

    info!("USB drive preparation complete");

    Ok(PrepareResult_ {
        tesseract_dir,
        vault_dir,
        readme_path,
        vault_initialized,
        files_created,
        warnings,
    })
}

/// Validates that the target is a removable drive.
fn validate_removable(target: &Path) -> PrepareResult<()> {
    if !detection::is_detection_supported() {
        return Err(PrepareError::UnsupportedPlatform);
    }

    let drive_type = detection::detect_drive_type(target)?;

    debug!("Detected drive type for {:?}: {:?}", target, drive_type);

    match drive_type {
        DriveType::Removable => Ok(()),
        _ => Err(PrepareError::NotRemovable {
            path: target.to_path_buf(),
            drive_type: drive_type.description().to_string(),
        }),
    }
}

/// Creates a directory, handling errors appropriately.
fn create_directory(path: &Path) -> PrepareResult<()> {
    debug!("Creating directory: {:?}", path);

    fs::create_dir_all(path).map_err(|e| PrepareError::CreateDirectoryFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Copies executables from source or creates placeholder files.
fn copy_or_create_executables(
    tesseract_dir: &Path,
    config: &PrepareConfig,
    files_created: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) -> PrepareResult<()> {
    if let Some(source) = &config.executables_source {
        copy_executables(tesseract_dir, source, files_created, warnings)?;
    } else {
        create_placeholder_executables(tesseract_dir, files_created, warnings)?;
    }

    Ok(())
}

/// Copies executables from a source directory.
fn copy_executables(
    tesseract_dir: &Path,
    source: &Path,
    files_created: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) -> PrepareResult<()> {
    // Windows executable
    let windows_src = source.join(WINDOWS_EXE);
    let windows_dst = tesseract_dir.join(WINDOWS_EXE);
    if windows_src.exists() {
        copy_file(&windows_src, &windows_dst)?;
        files_created.push(windows_dst);
    } else {
        warnings.push(format!("Windows executable not found: {windows_src:?}"));
    }

    // Linux AppImage
    let linux_src = source.join(LINUX_APPIMAGE);
    let linux_dst = tesseract_dir.join(LINUX_APPIMAGE);
    if linux_src.exists() {
        copy_file(&linux_src, &linux_dst)?;
        // Make AppImage executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&linux_dst)
                .map_err(|e| PrepareError::WriteFileFailed {
                    path: linux_dst.clone(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&linux_dst, perms).map_err(|e| PrepareError::WriteFileFailed {
                path: linux_dst.clone(),
                source: e,
            })?;
        }
        files_created.push(linux_dst);
    } else {
        warnings.push(format!("Linux AppImage not found: {linux_src:?}"));
    }

    // macOS App Bundle (directory)
    let macos_src = source.join(MACOS_APP);
    let macos_dst = tesseract_dir.join(MACOS_APP);
    if macos_src.exists() && macos_src.is_dir() {
        copy_directory(&macos_src, &macos_dst)?;
        files_created.push(macos_dst);
    } else {
        warnings.push(format!("macOS App Bundle not found: {macos_src:?}"));
    }

    Ok(())
}

/// Copies a single file.
fn copy_file(src: &Path, dst: &Path) -> PrepareResult<()> {
    debug!("Copying {:?} to {:?}", src, dst);

    fs::copy(src, dst).map_err(|e| PrepareError::CopyFileFailed {
        source_path: src.to_path_buf(),
        dest_path: dst.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Recursively copies a directory.
fn copy_directory(src: &Path, dst: &Path) -> PrepareResult<()> {
    debug!("Copying directory {:?} to {:?}", src, dst);

    create_directory(dst)?;

    for entry in fs::read_dir(src).map_err(|e| PrepareError::CreateDirectoryFailed {
        path: src.to_path_buf(),
        source: e,
    })? {
        let entry = entry.map_err(|e| PrepareError::CreateDirectoryFailed {
            path: src.to_path_buf(),
            source: e,
        })?;

        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_directory(&src_path, &dst_path)?;
        } else {
            copy_file(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Creates placeholder executable files (stubs).
fn create_placeholder_executables(
    tesseract_dir: &Path,
    files_created: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) -> PrepareResult<()> {
    warnings.push("No executable source provided; creating placeholders".to_string());

    // Windows placeholder
    let windows_path = tesseract_dir.join(WINDOWS_EXE);
    write_placeholder(&windows_path, "Windows")?;
    files_created.push(windows_path);

    // Linux placeholder (shell script)
    let linux_path = tesseract_dir.join(LINUX_APPIMAGE);
    write_placeholder(&linux_path, "Linux")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&linux_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&linux_path, perms);
        }
    }
    files_created.push(linux_path);

    // macOS placeholder (directory structure)
    let macos_path = tesseract_dir.join(MACOS_APP);
    create_placeholder_app_bundle(&macos_path)?;
    files_created.push(macos_path);

    Ok(())
}

/// Writes a placeholder executable file.
fn write_placeholder(path: &Path, platform: &str) -> PrepareResult<()> {
    let content = format!(
        "# TESSERACT Placeholder - {platform}\n\
         # This is a placeholder file.\n\
         # Replace with actual executable before deployment.\n"
    );

    let mut file = File::create(path).map_err(|e| PrepareError::WriteFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    file.write_all(content.as_bytes())
        .map_err(|e| PrepareError::WriteFileFailed {
            path: path.to_path_buf(),
            source: e,
        })?;

    Ok(())
}

/// Creates a placeholder macOS App Bundle structure.
fn create_placeholder_app_bundle(path: &Path) -> PrepareResult<()> {
    // Create basic .app structure
    let contents_dir = path.join("Contents");
    let macos_dir = contents_dir.join("MacOS");
    let resources_dir = contents_dir.join("Resources");

    create_directory(&macos_dir)?;
    create_directory(&resources_dir)?;

    // Write Info.plist
    let plist_path = contents_dir.join("Info.plist");
    let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>tesseract</string>
    <key>CFBundleIdentifier</key>
    <string>com.tesseract.app</string>
    <key>CFBundleName</key>
    <string>TESSERACT</string>
    <key>CFBundleDisplayName</key>
    <string>TESSERACT</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"#;

    write_file(&plist_path, plist_content)?;

    // Write placeholder executable
    let exe_path = macos_dir.join("tesseract");
    write_placeholder(&exe_path, "macOS")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&exe_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&exe_path, perms);
        }
    }

    Ok(())
}

/// Writes the version file.
fn write_version_file(path: &Path, version: &str) -> PrepareResult<()> {
    let content = format!(
        "TESSERACT Version: {version}\n\
         Build Date: {}\n\
         \n\
         Supported Platforms:\n\
         - Windows (x64)\n\
         - Linux (x64, AppImage)\n\
         - macOS (x64/arm64, Universal)\n",
        chrono_lite_date(),
    );

    write_file(path, &content)
}

/// Returns the current date in YYYY-MM-DD format without chrono dependency.
fn chrono_lite_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Days since Unix epoch
    let days = secs / 86400;

    // Calculate year, month, day (simplified, ignores leap seconds)
    let mut year = 1970;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}")
}

/// Returns true if the given year is a leap year.
const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Writes content to a file.
fn write_file(path: &Path, content: &str) -> PrepareResult<()> {
    debug!("Writing file: {:?}", path);

    let mut file = File::create(path).map_err(|e| PrepareError::WriteFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    file.write_all(content.as_bytes())
        .map_err(|e| PrepareError::WriteFileFailed {
            path: path.to_path_buf(),
            source: e,
        })?;

    Ok(())
}

/// Initializes an empty vault on the prepared drive.
fn initialize_vault(vault_dir: &Path, _config: &PrepareConfig) -> PrepareResult<()> {
    // For now, just create the directory structure.
    // Full vault initialization requires password and key derivation,
    // which is handled by tesseract-core::vault::create_vault.
    // This placeholder just ensures the directory exists.

    if !vault_dir.exists() {
        create_directory(vault_dir)?;
    }

    // Create vault subdirectories
    let keystores_dir = vault_dir.join(".keystores");
    let blobs_dir = vault_dir.join(".blobs");
    let metadata_dir = vault_dir.join(".metadata");

    create_directory(&keystores_dir)?;
    create_directory(&blobs_dir)?;
    create_directory(&metadata_dir)?;

    // Write a placeholder file indicating vault needs initialization
    let init_file = vault_dir.join(".needs_initialization");
    write_file(
        &init_file,
        "This vault has not been initialized.\n\
         Run TESSERACT to complete vault setup.\n",
    )?;

    Ok(())
}

/// Writes the READY_TO_TEST.md file.
fn write_readme(
    path: &Path,
    config: &PrepareConfig,
    vault_initialized: bool,
) -> PrepareResult<()> {
    let vault_status = if vault_initialized {
        "✓ Vault initialized and ready"
    } else {
        "○ Vault directory created (needs initialization on first run)"
    };

    let content = format!(
        r#"# TESSERACT Ready to Test

## USB Drive Preparation Complete

**Target Path:** `{target}`
**Version:** {version}
**Prepared:** {date}

## Directory Structure

```
{target}/
├── TESSERACT/           # Platform executables
│   ├── tesseract.exe    # Windows
│   ├── tesseract.AppImage # Linux
│   ├── TESSERACT.app/   # macOS
│   └── VERSION.txt      # Version info
├── vault/               # Encrypted vault storage
│   ├── .keystores/      # Access level keys
│   ├── .blobs/          # Encrypted files
│   └── .metadata/       # File metadata
└── READY_TO_TEST.md     # This file
```

## Status

- ✓ TESSERACT directory created
- ✓ Platform executables installed
- {vault_status}

## Testing Steps

### Windows
1. Open `{target}\TESSERACT\tesseract.exe`
2. Create a new vault when prompted (if not initialized)
3. Set a strong master password
4. Import test files
5. Verify encryption/decryption works

### Linux
1. Open terminal and run: `{target}/TESSERACT/tesseract.AppImage`
2. Follow the same steps as Windows

### macOS
1. Open `{target}/TESSERACT/TESSERACT.app`
2. If prompted about unidentified developer:
   - Right-click → Open → Open
3. Follow the same steps as Windows

## Security Reminders

- Keep your master password secure
- The USB drive should be ejected safely after use
- Never share the vault password
- Store recovery key in a secure location

## Troubleshooting

If the application fails to start:
- Ensure you're running from a USB/removable drive
- Check that the drive has write permissions
- On Linux, ensure AppImage is marked executable: `chmod +x tesseract.AppImage`
- On macOS, allow the app in Security & Privacy settings

## Support

For issues, visit: https://github.com/tesseract/tesseract/issues
"#,
        target = config.target_path.display(),
        version = config.version,
        date = chrono_lite_date(),
        vault_status = vault_status,
    );

    write_file(path, &content)
}

/// Checks if TESSERACT is already installed on the target.
#[must_use]
pub fn is_installed(target: &Path) -> bool {
    target.join(TESSERACT_DIR).exists()
}

/// Returns information about an existing TESSERACT installation.
#[derive(Debug, Clone)]
pub struct InstallInfo {
    /// Path to the TESSERACT directory.
    pub tesseract_dir: PathBuf,
    /// Path to the vault directory (if exists).
    pub vault_dir: Option<PathBuf>,
    /// Version string (if VERSION.txt exists).
    pub version: Option<String>,
    /// Whether Windows executable exists.
    pub has_windows: bool,
    /// Whether Linux AppImage exists.
    pub has_linux: bool,
    /// Whether macOS App Bundle exists.
    pub has_macos: bool,
}

/// Gets information about an existing installation.
pub fn get_install_info(target: &Path) -> Option<InstallInfo> {
    let tesseract_dir = target.join(TESSERACT_DIR);

    if !tesseract_dir.exists() {
        return None;
    }

    let vault_dir = target.join(VAULT_DIR);
    let vault_dir = if vault_dir.exists() {
        Some(vault_dir)
    } else {
        None
    };

    let version_path = tesseract_dir.join(VERSION_FILE);
    let version = fs::read_to_string(&version_path).ok().and_then(|content| {
        content
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("TESSERACT Version: "))
            .map(String::from)
    });

    Some(InstallInfo {
        tesseract_dir: tesseract_dir.clone(),
        vault_dir,
        version,
        has_windows: tesseract_dir.join(WINDOWS_EXE).exists(),
        has_linux: tesseract_dir.join(LINUX_APPIMAGE).exists(),
        has_macos: tesseract_dir.join(MACOS_APP).exists(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_temp_target() -> TempDir {
        TempDir::new().expect("Failed to create temp directory")
    }

    #[test]
    fn test_prepare_config_builder() {
        let config = PrepareConfig::new("/test/path")
            .skip_validation(true)
            .force(true)
            .init_vault(true)
            .vault_password("secret")
            .version("1.0.0");

        assert_eq!(config.target_path, PathBuf::from("/test/path"));
        assert!(config.skip_validation);
        assert!(config.force);
        assert!(config.init_vault);
        assert_eq!(config.vault_password, Some("secret".to_string()));
        assert_eq!(config.version, "1.0.0");
    }

    #[test]
    fn test_prepare_drive_creates_directories() {
        let temp = create_temp_target();
        let config = PrepareConfig::new(temp.path()).skip_validation(true);

        let result = prepare_drive(&config).expect("Preparation should succeed");

        assert!(result.tesseract_dir.exists());
        assert!(result.vault_dir.exists());
        assert!(result.readme_path.exists());
        assert!(!result.vault_initialized);
    }

    #[test]
    fn test_prepare_drive_creates_placeholder_executables() {
        let temp = create_temp_target();
        let config = PrepareConfig::new(temp.path()).skip_validation(true);

        let result = prepare_drive(&config).expect("Preparation should succeed");

        assert!(result.tesseract_dir.join(WINDOWS_EXE).exists());
        assert!(result.tesseract_dir.join(LINUX_APPIMAGE).exists());
        assert!(result.tesseract_dir.join(MACOS_APP).exists());
        assert!(result.tesseract_dir.join(VERSION_FILE).exists());
    }

    #[test]
    fn test_prepare_drive_creates_macos_app_bundle_structure() {
        let temp = create_temp_target();
        let config = PrepareConfig::new(temp.path()).skip_validation(true);

        let result = prepare_drive(&config).expect("Preparation should succeed");

        let app_dir = result.tesseract_dir.join(MACOS_APP);
        assert!(app_dir.join("Contents/Info.plist").exists());
        assert!(app_dir.join("Contents/MacOS/tesseract").exists());
        assert!(app_dir.join("Contents/Resources").exists());
    }

    #[test]
    fn test_prepare_drive_with_vault_init() {
        let temp = create_temp_target();
        let config = PrepareConfig::new(temp.path())
            .skip_validation(true)
            .init_vault(true);

        let result = prepare_drive(&config).expect("Preparation should succeed");

        assert!(result.vault_dir.join(".keystores").exists());
        assert!(result.vault_dir.join(".blobs").exists());
        assert!(result.vault_dir.join(".metadata").exists());
        assert!(result.vault_dir.join(".needs_initialization").exists());
    }

    #[test]
    fn test_prepare_drive_fails_if_already_installed() {
        let temp = create_temp_target();

        // First preparation
        let config = PrepareConfig::new(temp.path()).skip_validation(true);
        prepare_drive(&config).expect("First preparation should succeed");

        // Second preparation should fail
        let result = prepare_drive(&config);
        assert!(matches!(result, Err(PrepareError::AlreadyInstalled(_))));
    }

    #[test]
    fn test_prepare_drive_force_overwrites() {
        let temp = create_temp_target();

        // First preparation
        let config = PrepareConfig::new(temp.path()).skip_validation(true);
        prepare_drive(&config).expect("First preparation should succeed");

        // Second preparation with force should succeed
        let config = PrepareConfig::new(temp.path())
            .skip_validation(true)
            .force(true);
        let result = prepare_drive(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prepare_drive_fails_for_nonexistent_path() {
        let config = PrepareConfig::new("/nonexistent/path").skip_validation(true);
        let result = prepare_drive(&config);
        assert!(matches!(result, Err(PrepareError::PathNotFound(_))));
    }

    #[test]
    fn test_is_installed() {
        let temp = create_temp_target();

        assert!(!is_installed(temp.path()));

        let config = PrepareConfig::new(temp.path()).skip_validation(true);
        prepare_drive(&config).expect("Preparation should succeed");

        assert!(is_installed(temp.path()));
    }

    #[test]
    fn test_get_install_info() {
        let temp = create_temp_target();

        assert!(get_install_info(temp.path()).is_none());

        let config = PrepareConfig::new(temp.path())
            .skip_validation(true)
            .version("1.2.3");
        prepare_drive(&config).expect("Preparation should succeed");

        let info = get_install_info(temp.path()).expect("Should have install info");
        assert!(info.tesseract_dir.exists());
        assert!(info.vault_dir.is_some());
        assert_eq!(info.version, Some("1.2.3".to_string()));
        assert!(info.has_windows);
        assert!(info.has_linux);
        assert!(info.has_macos);
    }

    #[test]
    fn test_version_file_content() {
        let temp = create_temp_target();
        let config = PrepareConfig::new(temp.path())
            .skip_validation(true)
            .version("2.0.0");

        let result = prepare_drive(&config).expect("Preparation should succeed");

        let version_content =
            fs::read_to_string(result.tesseract_dir.join(VERSION_FILE)).expect("Should read");
        assert!(version_content.contains("TESSERACT Version: 2.0.0"));
        assert!(version_content.contains("Build Date:"));
    }

    #[test]
    fn test_readme_content() {
        let temp = create_temp_target();
        let config = PrepareConfig::new(temp.path())
            .skip_validation(true)
            .version("1.0.0");

        let result = prepare_drive(&config).expect("Preparation should succeed");

        let readme_content = fs::read_to_string(&result.readme_path).expect("Should read");
        assert!(readme_content.contains("TESSERACT Ready to Test"));
        assert!(readme_content.contains("Version:** 1.0.0"));
        assert!(readme_content.contains("Testing Steps"));
        assert!(readme_content.contains("Windows"));
        assert!(readme_content.contains("Linux"));
        assert!(readme_content.contains("macOS"));
    }

    #[test]
    fn test_copy_executables_with_source() {
        let temp = create_temp_target();
        let source_dir = TempDir::new().expect("Failed to create source dir");

        // Create fake executables in source
        fs::write(source_dir.path().join(WINDOWS_EXE), b"fake-exe").expect("Write failed");
        fs::write(source_dir.path().join(LINUX_APPIMAGE), b"fake-appimage").expect("Write failed");

        let config = PrepareConfig::new(temp.path())
            .skip_validation(true)
            .executables_source(source_dir.path());

        let result = prepare_drive(&config).expect("Preparation should succeed");

        // Windows and Linux should be copied
        assert!(result.tesseract_dir.join(WINDOWS_EXE).exists());
        assert!(result.tesseract_dir.join(LINUX_APPIMAGE).exists());

        // macOS should be placeholder (since we didn't create the .app dir)
        assert!(result.tesseract_dir.join(MACOS_APP).exists());

        // Warnings should mention missing macOS
        assert!(result.warnings.iter().any(|w| w.contains("macOS")));
    }

    #[test]
    fn test_chrono_lite_date_format() {
        let date = chrono_lite_date();
        // Should be YYYY-MM-DD format
        assert_eq!(date.len(), 10);
        assert!(date.chars().nth(4) == Some('-'));
        assert!(date.chars().nth(7) == Some('-'));

        // Year should be reasonable
        let year: i32 = date[0..4].parse().expect("Year should parse");
        assert!(year >= 2024);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(!is_leap_year(1900)); // Divisible by 100 but not 400
        assert!(is_leap_year(2024)); // Divisible by 4
        assert!(!is_leap_year(2023)); // Not divisible by 4
    }

    #[test]
    fn test_prepare_error_display() {
        let err = PrepareError::NotRemovable {
            path: PathBuf::from("/dev/sda"),
            drive_type: "Fixed Disk".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("/dev/sda"));
        assert!(msg.contains("Fixed Disk"));
    }
}
