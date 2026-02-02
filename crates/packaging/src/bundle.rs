//! Multi-platform executable bundling.
//!
//! Provides tools for bundling TESSERACT executables for all supported platforms
//! (Windows, Linux, macOS) into a single USB directory structure.
//!
//! # Directory Structure
//!
//! After bundling, the target directory will contain:
//! ```text
//! /TESSERACT/
//! ├── tesseract.exe      # Windows (x64)
//! ├── tesseract.AppImage # Linux (x64)
//! ├── TESSERACT.app/     # macOS (x64/arm64 Universal)
//! └── VERSION.txt        # Version info
//! ```
//!
//! # Size Limits
//!
//! The total bundle size must not exceed 100MB to ensure reasonable
//! USB drive usage and download times.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;
use tracing::{debug, info, warn};

/// Maximum allowed bundle size (100 MB).
pub const MAX_BUNDLE_SIZE_BYTES: u64 = 100 * 1024 * 1024;

/// Target directory name for executables.
pub const TESSERACT_DIR: &str = "TESSERACT";

/// Windows executable name.
pub const WINDOWS_EXE: &str = "tesseract.exe";

/// Linux AppImage name.
pub const LINUX_APPIMAGE: &str = "tesseract.AppImage";

/// macOS App Bundle name.
pub const MACOS_APP: &str = "TESSERACT.app";

/// Version info file name.
pub const VERSION_FILE: &str = "VERSION.txt";

/// Errors that can occur during bundling.
#[derive(Debug, Error)]
pub enum BundleError {
    /// Source executable not found.
    #[error("Source executable not found: {0}")]
    ExecutableNotFound(PathBuf),

    /// Bundle would exceed size limit.
    #[error("Bundle size ({size_mb:.2} MB) exceeds limit ({limit_mb:.2} MB)")]
    SizeLimitExceeded {
        /// Actual size in megabytes.
        size_mb: f64,
        /// Limit in megabytes.
        limit_mb: f64,
    },

    /// Failed to create directory.
    #[error("Failed to create directory {path}: {source}")]
    CreateDirectoryFailed {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// Failed to copy file.
    #[error("Failed to copy {source_path} to {dest_path}: {source}")]
    CopyFileFailed {
        /// Source file path.
        source_path: PathBuf,
        /// Destination file path.
        dest_path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// Failed to write file.
    #[error("Failed to write file {path}: {source}")]
    WriteFileFailed {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// Failed to read file.
    #[error("Failed to read file {path}: {source}")]
    ReadFileFailed {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// No executables provided.
    #[error("No executables provided for bundling")]
    NoExecutables,

    /// Target directory already exists.
    #[error("Target directory already exists: {0}. Use force to overwrite.")]
    AlreadyExists(PathBuf),

    /// Invalid executable (empty or too small).
    #[error("Executable appears invalid (size: {size} bytes, minimum: {minimum})")]
    InvalidExecutable {
        /// Actual size in bytes.
        size: u64,
        /// Minimum required size.
        minimum: u64,
    },
}

/// Result type for bundle operations.
pub type BundleResult<T> = Result<T, BundleError>;

/// Platform-specific executable source.
#[derive(Debug, Clone)]
pub enum ExecutableSource {
    /// Path to the executable file.
    File(PathBuf),
    /// Raw bytes of the executable.
    Bytes(Vec<u8>),
    /// Skip this platform (create placeholder).
    Placeholder,
}

impl ExecutableSource {
    /// Creates a source from a file path.
    #[must_use]
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    /// Creates a source from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }

    /// Creates a placeholder source.
    #[must_use]
    pub fn placeholder() -> Self {
        Self::Placeholder
    }

    /// Returns true if this is a placeholder.
    #[must_use]
    pub fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder)
    }

    /// Returns the size of the executable in bytes.
    ///
    /// Returns 0 for placeholders.
    pub fn size(&self) -> io::Result<u64> {
        match self {
            Self::File(path) => fs::metadata(path).map(|m| m.len()),
            Self::Bytes(bytes) => Ok(bytes.len() as u64),
            Self::Placeholder => Ok(0),
        }
    }
}

/// Information about a single platform's executable.
#[derive(Debug, Clone)]
pub struct PlatformExecutable {
    /// Platform name (Windows, Linux, macOS).
    pub platform: String,
    /// Target filename (e.g., "tesseract.exe").
    pub filename: String,
    /// Size in bytes.
    pub size: u64,
    /// Whether this is a placeholder.
    pub is_placeholder: bool,
    /// Whether this is a directory (like .app bundle).
    pub is_directory: bool,
}

impl PlatformExecutable {
    /// Creates a new platform executable info.
    #[must_use]
    pub fn new(platform: impl Into<String>, filename: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            filename: filename.into(),
            size: 0,
            is_placeholder: false,
            is_directory: false,
        }
    }

    /// Sets the size.
    #[must_use]
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Sets as placeholder.
    #[must_use]
    pub fn as_placeholder(mut self) -> Self {
        self.is_placeholder = true;
        self
    }

    /// Sets as directory.
    #[must_use]
    pub fn as_directory(mut self) -> Self {
        self.is_directory = true;
        self
    }

    /// Returns size in megabytes.
    #[must_use]
    pub fn size_mb(&self) -> f64 {
        self.size as f64 / (1024.0 * 1024.0)
    }
}

/// Configuration for bundle creation.
#[derive(Debug, Clone)]
pub struct BundleConfig {
    /// Target directory for the bundle.
    pub target_dir: PathBuf,

    /// Windows executable source.
    pub windows: Option<ExecutableSource>,

    /// Linux AppImage source.
    pub linux: Option<ExecutableSource>,

    /// macOS App Bundle source (directory).
    pub macos: Option<ExecutableSource>,

    /// Version string.
    pub version: String,

    /// Build date (YYYY-MM-DD format).
    pub build_date: String,

    /// Maximum bundle size in bytes.
    pub max_size: u64,

    /// Force overwrite if target exists.
    pub force: bool,

    /// Additional files to include.
    pub additional_files: Vec<(PathBuf, String)>,
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self {
            target_dir: PathBuf::new(),
            windows: None,
            linux: None,
            macos: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_date: current_date(),
            max_size: MAX_BUNDLE_SIZE_BYTES,
            force: false,
            additional_files: Vec::new(),
        }
    }
}

impl BundleConfig {
    /// Creates a new configuration with the target directory.
    #[must_use]
    pub fn new(target_dir: impl Into<PathBuf>) -> Self {
        Self {
            target_dir: target_dir.into(),
            ..Default::default()
        }
    }

    /// Sets the Windows executable source.
    #[must_use]
    pub fn windows(mut self, source: ExecutableSource) -> Self {
        self.windows = Some(source);
        self
    }

    /// Sets the Windows executable from a file path.
    #[must_use]
    pub fn windows_from_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.windows = Some(ExecutableSource::File(path.into()));
        self
    }

    /// Sets the Linux AppImage source.
    #[must_use]
    pub fn linux(mut self, source: ExecutableSource) -> Self {
        self.linux = Some(source);
        self
    }

    /// Sets the Linux AppImage from a file path.
    #[must_use]
    pub fn linux_from_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.linux = Some(ExecutableSource::File(path.into()));
        self
    }

    /// Sets the macOS App Bundle source.
    #[must_use]
    pub fn macos(mut self, source: ExecutableSource) -> Self {
        self.macos = Some(source);
        self
    }

    /// Sets the macOS App Bundle from a directory path.
    #[must_use]
    pub fn macos_from_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.macos = Some(ExecutableSource::File(path.into()));
        self
    }

    /// Sets the version string.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Sets the build date.
    #[must_use]
    pub fn build_date(mut self, date: impl Into<String>) -> Self {
        self.build_date = date.into();
        self
    }

    /// Sets the maximum bundle size.
    #[must_use]
    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = size;
        self
    }

    /// Sets whether to force overwrite.
    #[must_use]
    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Adds an additional file to include in the bundle.
    #[must_use]
    pub fn add_file(mut self, source: impl Into<PathBuf>, dest_name: impl Into<String>) -> Self {
        self.additional_files.push((source.into(), dest_name.into()));
        self
    }

    /// Returns true if any executables are configured.
    #[must_use]
    pub fn has_executables(&self) -> bool {
        self.windows.is_some() || self.linux.is_some() || self.macos.is_some()
    }

    /// Returns true if all executables are placeholders.
    #[must_use]
    pub fn all_placeholders(&self) -> bool {
        let windows_placeholder = self.windows.as_ref().map_or(true, |s| s.is_placeholder());
        let linux_placeholder = self.linux.as_ref().map_or(true, |s| s.is_placeholder());
        let macos_placeholder = self.macos.as_ref().map_or(true, |s| s.is_placeholder());
        windows_placeholder && linux_placeholder && macos_placeholder
    }
}

/// Result of a successful bundle operation.
#[derive(Debug, Clone)]
pub struct BundleResult_ {
    /// Path to the created bundle directory.
    pub bundle_dir: PathBuf,

    /// Information about each platform executable.
    pub executables: Vec<PlatformExecutable>,

    /// Path to the VERSION.txt file.
    pub version_file: PathBuf,

    /// Total bundle size in bytes.
    pub total_size: u64,

    /// Warnings generated during bundling.
    pub warnings: Vec<String>,
}

impl BundleResult_ {
    /// Returns the total size in megabytes.
    #[must_use]
    pub fn total_size_mb(&self) -> f64 {
        self.total_size as f64 / (1024.0 * 1024.0)
    }

    /// Returns true if the bundle is under the size limit.
    #[must_use]
    pub fn is_within_limit(&self, limit: u64) -> bool {
        self.total_size <= limit
    }

    /// Returns the number of real (non-placeholder) executables.
    #[must_use]
    pub fn real_executable_count(&self) -> usize {
        self.executables.iter().filter(|e| !e.is_placeholder).count()
    }

    /// Returns true if all platforms have real executables.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.executables.len() == 3 && self.real_executable_count() == 3
    }
}

/// Creates a multi-platform executable bundle.
///
/// # Arguments
///
/// * `config` - The bundle configuration.
///
/// # Returns
///
/// Returns `BundleResult_` on success with details about what was created.
///
/// # Errors
///
/// Returns an error if:
/// - No executables are configured
/// - Target directory exists and force is not set
/// - Bundle would exceed size limit
/// - File operations fail
pub fn create_bundle(config: &BundleConfig) -> BundleResult<BundleResult_> {
    if !config.has_executables() {
        return Err(BundleError::NoExecutables);
    }

    let bundle_dir = config.target_dir.join(TESSERACT_DIR);

    // Check if already exists
    if bundle_dir.exists() && !config.force {
        return Err(BundleError::AlreadyExists(bundle_dir));
    }

    // Calculate total size before creating
    let estimated_size = estimate_bundle_size(config)?;
    let limit_mb = config.max_size as f64 / (1024.0 * 1024.0);
    if estimated_size > config.max_size {
        return Err(BundleError::SizeLimitExceeded {
            size_mb: estimated_size as f64 / (1024.0 * 1024.0),
            limit_mb,
        });
    }

    info!("Creating bundle at {:?}", bundle_dir);

    // Create bundle directory
    if bundle_dir.exists() {
        fs::remove_dir_all(&bundle_dir).map_err(|e| BundleError::CreateDirectoryFailed {
            path: bundle_dir.clone(),
            source: e,
        })?;
    }
    fs::create_dir_all(&bundle_dir).map_err(|e| BundleError::CreateDirectoryFailed {
        path: bundle_dir.clone(),
        source: e,
    })?;

    let mut executables = Vec::new();
    let mut warnings = Vec::new();
    let mut total_size: u64 = 0;

    // Copy Windows executable
    if let Some(source) = &config.windows {
        let dest_path = bundle_dir.join(WINDOWS_EXE);
        match copy_executable(source, &dest_path, "Windows") {
            Ok(size) => {
                executables.push(
                    PlatformExecutable::new("Windows", WINDOWS_EXE)
                        .with_size(size)
                );
                total_size += size;
            }
            Err(e) if source.is_placeholder() => {
                create_placeholder_file(&dest_path, "Windows")?;
                executables.push(
                    PlatformExecutable::new("Windows", WINDOWS_EXE)
                        .as_placeholder()
                );
                warnings.push("Windows executable is a placeholder".to_string());
            }
            Err(e) => {
                warnings.push(format!("Failed to copy Windows executable: {e}"));
                create_placeholder_file(&dest_path, "Windows")?;
                executables.push(
                    PlatformExecutable::new("Windows", WINDOWS_EXE)
                        .as_placeholder()
                );
            }
        }
    } else {
        let dest_path = bundle_dir.join(WINDOWS_EXE);
        create_placeholder_file(&dest_path, "Windows")?;
        executables.push(
            PlatformExecutable::new("Windows", WINDOWS_EXE)
                .as_placeholder()
        );
        warnings.push("Windows executable not provided, using placeholder".to_string());
    }

    // Copy Linux AppImage
    if let Some(source) = &config.linux {
        let dest_path = bundle_dir.join(LINUX_APPIMAGE);
        match copy_executable(source, &dest_path, "Linux") {
            Ok(size) => {
                set_executable(&dest_path);
                executables.push(
                    PlatformExecutable::new("Linux", LINUX_APPIMAGE)
                        .with_size(size)
                );
                total_size += size;
            }
            Err(_) if source.is_placeholder() => {
                create_placeholder_file(&dest_path, "Linux")?;
                set_executable(&dest_path);
                executables.push(
                    PlatformExecutable::new("Linux", LINUX_APPIMAGE)
                        .as_placeholder()
                );
                warnings.push("Linux AppImage is a placeholder".to_string());
            }
            Err(e) => {
                warnings.push(format!("Failed to copy Linux AppImage: {e}"));
                create_placeholder_file(&dest_path, "Linux")?;
                set_executable(&dest_path);
                executables.push(
                    PlatformExecutable::new("Linux", LINUX_APPIMAGE)
                        .as_placeholder()
                );
            }
        }
    } else {
        let dest_path = bundle_dir.join(LINUX_APPIMAGE);
        create_placeholder_file(&dest_path, "Linux")?;
        set_executable(&dest_path);
        executables.push(
            PlatformExecutable::new("Linux", LINUX_APPIMAGE)
                .as_placeholder()
        );
        warnings.push("Linux AppImage not provided, using placeholder".to_string());
    }

    // Copy macOS App Bundle
    if let Some(source) = &config.macos {
        let dest_path = bundle_dir.join(MACOS_APP);
        match copy_app_bundle(source, &dest_path) {
            Ok(size) => {
                executables.push(
                    PlatformExecutable::new("macOS", MACOS_APP)
                        .with_size(size)
                        .as_directory()
                );
                total_size += size;
            }
            Err(_) if source.is_placeholder() => {
                create_placeholder_app_bundle(&dest_path)?;
                executables.push(
                    PlatformExecutable::new("macOS", MACOS_APP)
                        .as_placeholder()
                        .as_directory()
                );
                warnings.push("macOS App Bundle is a placeholder".to_string());
            }
            Err(e) => {
                warnings.push(format!("Failed to copy macOS App Bundle: {e}"));
                create_placeholder_app_bundle(&dest_path)?;
                executables.push(
                    PlatformExecutable::new("macOS", MACOS_APP)
                        .as_placeholder()
                        .as_directory()
                );
            }
        }
    } else {
        let dest_path = bundle_dir.join(MACOS_APP);
        create_placeholder_app_bundle(&dest_path)?;
        executables.push(
            PlatformExecutable::new("macOS", MACOS_APP)
                .as_placeholder()
                .as_directory()
        );
        warnings.push("macOS App Bundle not provided, using placeholder".to_string());
    }

    // Create version file
    let version_file = bundle_dir.join(VERSION_FILE);
    write_version_file(&version_file, config, &executables)?;
    total_size += fs::metadata(&version_file).map(|m| m.len()).unwrap_or(0);

    // Copy additional files
    for (source, dest_name) in &config.additional_files {
        let dest_path = bundle_dir.join(dest_name);
        if source.exists() {
            fs::copy(source, &dest_path).map_err(|e| BundleError::CopyFileFailed {
                source_path: source.clone(),
                dest_path: dest_path.clone(),
                source: e,
            })?;
            total_size += fs::metadata(&dest_path).map(|m| m.len()).unwrap_or(0);
        } else {
            warnings.push(format!("Additional file not found: {source:?}"));
        }
    }

    info!(
        "Bundle created: {:.2} MB across {} executables",
        total_size as f64 / (1024.0 * 1024.0),
        executables.len()
    );

    Ok(BundleResult_ {
        bundle_dir,
        executables,
        version_file,
        total_size,
        warnings,
    })
}

/// Estimates the total bundle size without creating files.
fn estimate_bundle_size(config: &BundleConfig) -> BundleResult<u64> {
    let mut total: u64 = 0;

    if let Some(source) = &config.windows {
        total += source.size().unwrap_or(0);
    }

    if let Some(source) = &config.linux {
        total += source.size().unwrap_or(0);
    }

    if let Some(source) = &config.macos {
        if let ExecutableSource::File(path) = source {
            total += dir_size(path).unwrap_or(0);
        } else {
            total += source.size().unwrap_or(0);
        }
    }

    // Add estimate for VERSION.txt (~1KB)
    total += 1024;

    // Add additional files
    for (source, _) in &config.additional_files {
        if source.exists() {
            total += fs::metadata(source).map(|m| m.len()).unwrap_or(0);
        }
    }

    Ok(total)
}

/// Copies an executable from source to destination.
fn copy_executable(source: &ExecutableSource, dest: &Path, platform: &str) -> BundleResult<u64> {
    match source {
        ExecutableSource::File(path) => {
            if !path.exists() {
                return Err(BundleError::ExecutableNotFound(path.clone()));
            }
            debug!("Copying {} executable from {:?}", platform, path);
            fs::copy(path, dest).map_err(|e| BundleError::CopyFileFailed {
                source_path: path.clone(),
                dest_path: dest.to_path_buf(),
                source: e,
            })
        }
        ExecutableSource::Bytes(bytes) => {
            debug!("Writing {} executable from bytes ({} bytes)", platform, bytes.len());
            let mut file = File::create(dest).map_err(|e| BundleError::WriteFileFailed {
                path: dest.to_path_buf(),
                source: e,
            })?;
            file.write_all(bytes).map_err(|e| BundleError::WriteFileFailed {
                path: dest.to_path_buf(),
                source: e,
            })?;
            Ok(bytes.len() as u64)
        }
        ExecutableSource::Placeholder => {
            Err(BundleError::ExecutableNotFound(dest.to_path_buf()))
        }
    }
}

/// Copies a macOS App Bundle (directory) from source to destination.
fn copy_app_bundle(source: &ExecutableSource, dest: &Path) -> BundleResult<u64> {
    match source {
        ExecutableSource::File(path) => {
            if !path.exists() || !path.is_dir() {
                return Err(BundleError::ExecutableNotFound(path.clone()));
            }
            debug!("Copying macOS App Bundle from {:?}", path);
            copy_directory_recursive(path, dest)?;
            Ok(dir_size(dest).unwrap_or(0))
        }
        ExecutableSource::Bytes(_) => {
            // Can't create app bundle from bytes
            Err(BundleError::ExecutableNotFound(dest.to_path_buf()))
        }
        ExecutableSource::Placeholder => {
            Err(BundleError::ExecutableNotFound(dest.to_path_buf()))
        }
    }
}

/// Recursively copies a directory.
fn copy_directory_recursive(src: &Path, dst: &Path) -> BundleResult<()> {
    fs::create_dir_all(dst).map_err(|e| BundleError::CreateDirectoryFailed {
        path: dst.to_path_buf(),
        source: e,
    })?;

    for entry in fs::read_dir(src).map_err(|e| BundleError::ReadFileFailed {
        path: src.to_path_buf(),
        source: e,
    })? {
        let entry = entry.map_err(|e| BundleError::ReadFileFailed {
            path: src.to_path_buf(),
            source: e,
        })?;

        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_directory_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path).map_err(|e| BundleError::CopyFileFailed {
                source_path: src_path,
                dest_path: dst_path,
                source: e,
            })?;
        }
    }

    Ok(())
}

/// Calculates the total size of a directory.
fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total: u64 = 0;

    if path.is_file() {
        return fs::metadata(path).map(|m| m.len());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            total += dir_size(&path)?;
        } else {
            total += entry.metadata()?.len();
        }
    }

    Ok(total)
}

/// Creates a placeholder executable file.
fn create_placeholder_file(path: &Path, platform: &str) -> BundleResult<()> {
    let content = format!(
        "#!/bin/sh\n\
         # TESSERACT Placeholder - {platform}\n\
         # This is a placeholder file.\n\
         # Replace with actual executable before deployment.\n\
         echo \"Error: {platform} executable not available.\"\n\
         echo \"Please download the full bundle from the TESSERACT website.\"\n\
         exit 1\n"
    );

    let mut file = File::create(path).map_err(|e| BundleError::WriteFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    file.write_all(content.as_bytes()).map_err(|e| BundleError::WriteFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Creates a placeholder macOS App Bundle structure.
fn create_placeholder_app_bundle(path: &Path) -> BundleResult<()> {
    // Create basic .app structure
    let contents_dir = path.join("Contents");
    let macos_dir = contents_dir.join("MacOS");
    let resources_dir = contents_dir.join("Resources");

    fs::create_dir_all(&macos_dir).map_err(|e| BundleError::CreateDirectoryFailed {
        path: macos_dir.clone(),
        source: e,
    })?;

    fs::create_dir_all(&resources_dir).map_err(|e| BundleError::CreateDirectoryFailed {
        path: resources_dir.clone(),
        source: e,
    })?;

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
    <string>PLACEHOLDER</string>
    <key>CFBundleShortVersionString</key>
    <string>PLACEHOLDER</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NOTE</key>
    <string>This is a placeholder bundle. Replace with actual application.</string>
</dict>
</plist>
"#;

    let mut plist_file = File::create(&plist_path).map_err(|e| BundleError::WriteFileFailed {
        path: plist_path.clone(),
        source: e,
    })?;
    plist_file.write_all(plist_content.as_bytes()).map_err(|e| BundleError::WriteFileFailed {
        path: plist_path,
        source: e,
    })?;

    // Write placeholder executable
    let exe_path = macos_dir.join("tesseract");
    create_placeholder_file(&exe_path, "macOS")?;
    set_executable(&exe_path);

    Ok(())
}

/// Sets executable permission on Unix systems.
fn set_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path; // Silence unused warning
    }
}

/// Writes the VERSION.txt file.
fn write_version_file(
    path: &Path,
    config: &BundleConfig,
    executables: &[PlatformExecutable],
) -> BundleResult<()> {
    let mut content = format!(
        "TESSERACT Version: {}\n\
         Build Date: {}\n\
         \n\
         Platform Executables:\n",
        config.version, config.build_date,
    );

    for exe in executables {
        let status = if exe.is_placeholder {
            "PLACEHOLDER"
        } else {
            &format!("{:.2} MB", exe.size_mb())
        };
        content.push_str(&format!("  - {} ({}): {}\n", exe.platform, exe.filename, status));
    }

    content.push_str(&format!(
        "\n\
         Supported Platforms:\n\
         - Windows (x64)\n\
         - Linux (x64, AppImage)\n\
         - macOS (x64/arm64, Universal)\n\
         \n\
         Total Bundle Size: {:.2} MB\n\
         Size Limit: {:.2} MB\n",
        executables.iter().map(|e| e.size).sum::<u64>() as f64 / (1024.0 * 1024.0),
        config.max_size as f64 / (1024.0 * 1024.0),
    ));

    let mut file = File::create(path).map_err(|e| BundleError::WriteFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    file.write_all(content.as_bytes()).map_err(|e| BundleError::WriteFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Returns the current date in YYYY-MM-DD format.
fn current_date() -> String {
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

/// Validates that executables are valid (not empty, minimum size).
pub fn validate_executable(path: &Path, minimum_size: u64) -> BundleResult<()> {
    let metadata = fs::metadata(path).map_err(|e| BundleError::ReadFileFailed {
        path: path.to_path_buf(),
        source: e,
    })?;

    if metadata.len() < minimum_size {
        return Err(BundleError::InvalidExecutable {
            size: metadata.len(),
            minimum: minimum_size,
        });
    }

    Ok(())
}

/// Returns bundle size summary information.
#[derive(Debug, Clone)]
pub struct BundleSizeSummary {
    /// Windows executable size.
    pub windows_size: u64,
    /// Linux AppImage size.
    pub linux_size: u64,
    /// macOS App Bundle size.
    pub macos_size: u64,
    /// Other files size.
    pub other_size: u64,
    /// Total size.
    pub total_size: u64,
    /// Size limit.
    pub limit: u64,
}

impl BundleSizeSummary {
    /// Returns true if the bundle is within the size limit.
    #[must_use]
    pub fn is_within_limit(&self) -> bool {
        self.total_size <= self.limit
    }

    /// Returns the percentage of limit used.
    #[must_use]
    pub fn usage_percentage(&self) -> f64 {
        if self.limit == 0 {
            return 0.0;
        }
        (self.total_size as f64 / self.limit as f64) * 100.0
    }

    /// Returns the remaining space.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        if self.total_size >= self.limit {
            0
        } else {
            self.limit - self.total_size
        }
    }
}

/// Analyzes an existing bundle and returns size information.
pub fn analyze_bundle(bundle_dir: &Path) -> BundleResult<BundleSizeSummary> {
    if !bundle_dir.exists() {
        return Err(BundleError::ExecutableNotFound(bundle_dir.to_path_buf()));
    }

    let tesseract_dir = if bundle_dir.file_name().map_or(false, |n| n == TESSERACT_DIR) {
        bundle_dir.to_path_buf()
    } else {
        bundle_dir.join(TESSERACT_DIR)
    };

    let windows_path = tesseract_dir.join(WINDOWS_EXE);
    let linux_path = tesseract_dir.join(LINUX_APPIMAGE);
    let macos_path = tesseract_dir.join(MACOS_APP);

    let windows_size = fs::metadata(&windows_path).map(|m| m.len()).unwrap_or(0);
    let linux_size = fs::metadata(&linux_path).map(|m| m.len()).unwrap_or(0);
    let macos_size = dir_size(&macos_path).unwrap_or(0);

    let total_dir_size = dir_size(&tesseract_dir).unwrap_or(0);
    let other_size = total_dir_size.saturating_sub(windows_size + linux_size + macos_size);

    Ok(BundleSizeSummary {
        windows_size,
        linux_size,
        macos_size,
        other_size,
        total_size: total_dir_size,
        limit: MAX_BUNDLE_SIZE_BYTES,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_temp_dir() -> TempDir {
        TempDir::new().expect("Failed to create temp directory")
    }

    // === ExecutableSource tests ===

    #[test]
    fn test_executable_source_from_path() {
        let source = ExecutableSource::from_path("/test/path");
        assert!(matches!(source, ExecutableSource::File(_)));
        assert!(!source.is_placeholder());
    }

    #[test]
    fn test_executable_source_from_bytes() {
        let source = ExecutableSource::from_bytes(vec![1, 2, 3, 4]);
        assert!(matches!(source, ExecutableSource::Bytes(_)));
        assert!(!source.is_placeholder());
    }

    #[test]
    fn test_executable_source_placeholder() {
        let source = ExecutableSource::placeholder();
        assert!(source.is_placeholder());
        assert_eq!(source.size().unwrap(), 0);
    }

    #[test]
    fn test_executable_source_bytes_size() {
        let source = ExecutableSource::from_bytes(vec![0; 100]);
        assert_eq!(source.size().unwrap(), 100);
    }

    // === PlatformExecutable tests ===

    #[test]
    fn test_platform_executable_new() {
        let exe = PlatformExecutable::new("Windows", "tesseract.exe");
        assert_eq!(exe.platform, "Windows");
        assert_eq!(exe.filename, "tesseract.exe");
        assert_eq!(exe.size, 0);
        assert!(!exe.is_placeholder);
        assert!(!exe.is_directory);
    }

    #[test]
    fn test_platform_executable_with_size() {
        let exe = PlatformExecutable::new("Linux", "test.AppImage")
            .with_size(1024 * 1024);
        assert_eq!(exe.size, 1024 * 1024);
        assert!((exe.size_mb() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_platform_executable_as_placeholder() {
        let exe = PlatformExecutable::new("macOS", "TESSERACT.app")
            .as_placeholder();
        assert!(exe.is_placeholder);
    }

    #[test]
    fn test_platform_executable_as_directory() {
        let exe = PlatformExecutable::new("macOS", "TESSERACT.app")
            .as_directory();
        assert!(exe.is_directory);
    }

    // === BundleConfig tests ===

    #[test]
    fn test_bundle_config_default() {
        let config = BundleConfig::default();
        assert!(config.target_dir.as_os_str().is_empty());
        assert!(config.windows.is_none());
        assert!(config.linux.is_none());
        assert!(config.macos.is_none());
        assert_eq!(config.max_size, MAX_BUNDLE_SIZE_BYTES);
        assert!(!config.force);
    }

    #[test]
    fn test_bundle_config_new() {
        let config = BundleConfig::new("/test/path");
        assert_eq!(config.target_dir, PathBuf::from("/test/path"));
    }

    #[test]
    fn test_bundle_config_builder_chain() {
        let config = BundleConfig::new("/test")
            .windows(ExecutableSource::placeholder())
            .linux(ExecutableSource::placeholder())
            .macos(ExecutableSource::placeholder())
            .version("1.0.0")
            .build_date("2026-01-24")
            .max_size(50 * 1024 * 1024)
            .force(true);

        assert!(config.windows.is_some());
        assert!(config.linux.is_some());
        assert!(config.macos.is_some());
        assert_eq!(config.version, "1.0.0");
        assert_eq!(config.build_date, "2026-01-24");
        assert_eq!(config.max_size, 50 * 1024 * 1024);
        assert!(config.force);
    }

    #[test]
    fn test_bundle_config_has_executables() {
        let config = BundleConfig::default();
        assert!(!config.has_executables());

        let config = BundleConfig::default()
            .windows(ExecutableSource::placeholder());
        assert!(config.has_executables());
    }

    #[test]
    fn test_bundle_config_all_placeholders() {
        let config = BundleConfig::default()
            .windows(ExecutableSource::placeholder())
            .linux(ExecutableSource::placeholder())
            .macos(ExecutableSource::placeholder());
        assert!(config.all_placeholders());

        let config = BundleConfig::default()
            .windows(ExecutableSource::from_bytes(vec![1, 2, 3]));
        assert!(!config.all_placeholders());
    }

    #[test]
    fn test_bundle_config_add_file() {
        let config = BundleConfig::new("/test")
            .add_file("/path/to/readme.md", "README.md")
            .add_file("/path/to/license", "LICENSE");
        assert_eq!(config.additional_files.len(), 2);
    }

    // === BundleResult_ tests ===

    #[test]
    fn test_bundle_result_total_size_mb() {
        let result = BundleResult_ {
            bundle_dir: PathBuf::from("/test"),
            executables: vec![],
            version_file: PathBuf::from("/test/VERSION.txt"),
            total_size: 10 * 1024 * 1024,
            warnings: vec![],
        };
        assert!((result.total_size_mb() - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_bundle_result_is_within_limit() {
        let result = BundleResult_ {
            bundle_dir: PathBuf::from("/test"),
            executables: vec![],
            version_file: PathBuf::from("/test/VERSION.txt"),
            total_size: 50 * 1024 * 1024,
            warnings: vec![],
        };
        assert!(result.is_within_limit(100 * 1024 * 1024));
        assert!(!result.is_within_limit(40 * 1024 * 1024));
    }

    #[test]
    fn test_bundle_result_real_executable_count() {
        let result = BundleResult_ {
            bundle_dir: PathBuf::from("/test"),
            executables: vec![
                PlatformExecutable::new("Windows", "test.exe").with_size(1000),
                PlatformExecutable::new("Linux", "test.AppImage").as_placeholder(),
                PlatformExecutable::new("macOS", "test.app").with_size(2000),
            ],
            version_file: PathBuf::from("/test/VERSION.txt"),
            total_size: 3000,
            warnings: vec![],
        };
        assert_eq!(result.real_executable_count(), 2);
    }

    #[test]
    fn test_bundle_result_is_complete() {
        let result = BundleResult_ {
            bundle_dir: PathBuf::from("/test"),
            executables: vec![
                PlatformExecutable::new("Windows", "test.exe").with_size(1000),
                PlatformExecutable::new("Linux", "test.AppImage").with_size(2000),
                PlatformExecutable::new("macOS", "test.app").with_size(3000),
            ],
            version_file: PathBuf::from("/test/VERSION.txt"),
            total_size: 6000,
            warnings: vec![],
        };
        assert!(result.is_complete());

        let incomplete = BundleResult_ {
            bundle_dir: PathBuf::from("/test"),
            executables: vec![
                PlatformExecutable::new("Windows", "test.exe").with_size(1000),
                PlatformExecutable::new("Linux", "test.AppImage").as_placeholder(),
            ],
            version_file: PathBuf::from("/test/VERSION.txt"),
            total_size: 1000,
            warnings: vec![],
        };
        assert!(!incomplete.is_complete());
    }

    // === BundleSizeSummary tests ===

    #[test]
    fn test_bundle_size_summary_is_within_limit() {
        let summary = BundleSizeSummary {
            windows_size: 10 * 1024 * 1024,
            linux_size: 20 * 1024 * 1024,
            macos_size: 30 * 1024 * 1024,
            other_size: 1024,
            total_size: 60 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        assert!(summary.is_within_limit());
    }

    #[test]
    fn test_bundle_size_summary_usage_percentage() {
        let summary = BundleSizeSummary {
            windows_size: 0,
            linux_size: 0,
            macos_size: 0,
            other_size: 0,
            total_size: 50 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        assert!((summary.usage_percentage() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_bundle_size_summary_remaining() {
        let summary = BundleSizeSummary {
            windows_size: 0,
            linux_size: 0,
            macos_size: 0,
            other_size: 0,
            total_size: 40 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        assert_eq!(summary.remaining(), 60 * 1024 * 1024);
    }

    #[test]
    fn test_bundle_size_summary_remaining_at_limit() {
        let summary = BundleSizeSummary {
            windows_size: 0,
            linux_size: 0,
            macos_size: 0,
            other_size: 0,
            total_size: 120 * 1024 * 1024,
            limit: 100 * 1024 * 1024,
        };
        assert_eq!(summary.remaining(), 0);
    }

    // === create_bundle tests ===

    #[test]
    fn test_create_bundle_no_executables() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path());
        let result = create_bundle(&config);
        assert!(matches!(result, Err(BundleError::NoExecutables)));
    }

    #[test]
    fn test_create_bundle_with_placeholders() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder())
            .linux(ExecutableSource::placeholder())
            .macos(ExecutableSource::placeholder())
            .version("1.0.0");

        let result = create_bundle(&config).expect("Bundle should succeed");

        assert!(result.bundle_dir.exists());
        assert!(result.version_file.exists());
        assert_eq!(result.executables.len(), 3);
        assert!(result.executables.iter().all(|e| e.is_placeholder));
        assert_eq!(result.warnings.len(), 3); // 3 placeholder warnings
    }

    #[test]
    fn test_create_bundle_creates_directory_structure() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder())
            .version("2.0.0");

        let result = create_bundle(&config).expect("Bundle should succeed");

        assert!(result.bundle_dir.join(WINDOWS_EXE).exists());
        assert!(result.bundle_dir.join(LINUX_APPIMAGE).exists());
        assert!(result.bundle_dir.join(MACOS_APP).exists());
        assert!(result.bundle_dir.join(VERSION_FILE).exists());
    }

    #[test]
    fn test_create_bundle_macos_app_structure() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .macos(ExecutableSource::placeholder());

        let result = create_bundle(&config).expect("Bundle should succeed");

        let app_dir = result.bundle_dir.join(MACOS_APP);
        assert!(app_dir.join("Contents/Info.plist").exists());
        assert!(app_dir.join("Contents/MacOS/tesseract").exists());
        assert!(app_dir.join("Contents/Resources").exists());
    }

    #[test]
    fn test_create_bundle_already_exists() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder());

        // First bundle
        create_bundle(&config).expect("First bundle should succeed");

        // Second bundle should fail
        let result = create_bundle(&config);
        assert!(matches!(result, Err(BundleError::AlreadyExists(_))));
    }

    #[test]
    fn test_create_bundle_force_overwrite() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder())
            .version("1.0.0");

        create_bundle(&config).expect("First bundle should succeed");

        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder())
            .version("2.0.0")
            .force(true);

        let result = create_bundle(&config).expect("Force bundle should succeed");

        let version_content = fs::read_to_string(&result.version_file).unwrap();
        assert!(version_content.contains("2.0.0"));
    }

    #[test]
    fn test_create_bundle_with_bytes() {
        let temp = create_temp_dir();
        let fake_exe = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::from_bytes(fake_exe.clone()));

        let result = create_bundle(&config).expect("Bundle should succeed");

        let windows_exe = result.bundle_dir.join(WINDOWS_EXE);
        let content = fs::read(&windows_exe).unwrap();
        assert_eq!(content, fake_exe);
    }

    #[test]
    fn test_create_bundle_with_real_file() {
        let temp = create_temp_dir();
        let source_dir = create_temp_dir();

        // Create a fake executable
        let fake_exe_path = source_dir.path().join("tesseract.exe");
        fs::write(&fake_exe_path, b"FAKE_EXE_CONTENT").unwrap();

        let config = BundleConfig::new(temp.path())
            .windows_from_path(&fake_exe_path);

        let result = create_bundle(&config).expect("Bundle should succeed");

        let windows_exe = result.bundle_dir.join(WINDOWS_EXE);
        let content = fs::read_to_string(&windows_exe).unwrap();
        assert_eq!(content, "FAKE_EXE_CONTENT");
        assert!(!result.executables[0].is_placeholder);
    }

    #[test]
    fn test_create_bundle_size_limit_exceeded() {
        let temp = create_temp_dir();
        // Create a 150MB fake executable
        let large_data = vec![0u8; 150 * 1024 * 1024];
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::from_bytes(large_data))
            .max_size(100 * 1024 * 1024);

        let result = create_bundle(&config);
        assert!(matches!(result, Err(BundleError::SizeLimitExceeded { .. })));
    }

    #[test]
    fn test_create_bundle_version_file_content() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder())
            .version("3.2.1")
            .build_date("2026-01-24");

        let result = create_bundle(&config).expect("Bundle should succeed");

        let version_content = fs::read_to_string(&result.version_file).unwrap();
        assert!(version_content.contains("TESSERACT Version: 3.2.1"));
        assert!(version_content.contains("Build Date: 2026-01-24"));
        assert!(version_content.contains("Windows"));
        assert!(version_content.contains("Linux"));
        assert!(version_content.contains("macOS"));
        assert!(version_content.contains("Size Limit:"));
    }

    #[test]
    fn test_create_bundle_with_additional_files() {
        let temp = create_temp_dir();
        let source_dir = create_temp_dir();

        let readme_path = source_dir.path().join("README.md");
        fs::write(&readme_path, "# TESSERACT\n").unwrap();

        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::placeholder())
            .add_file(&readme_path, "README.md");

        let result = create_bundle(&config).expect("Bundle should succeed");

        assert!(result.bundle_dir.join("README.md").exists());
        let readme_content = fs::read_to_string(result.bundle_dir.join("README.md")).unwrap();
        assert_eq!(readme_content, "# TESSERACT\n");
    }

    // === Helper function tests ===

    #[test]
    fn test_current_date_format() {
        let date = current_date();
        // Should be YYYY-MM-DD format
        assert_eq!(date.len(), 10);
        assert_eq!(date.chars().nth(4), Some('-'));
        assert_eq!(date.chars().nth(7), Some('-'));

        let year: i32 = date[0..4].parse().unwrap();
        assert!(year >= 2024);
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(!is_leap_year(1900)); // Divisible by 100 but not 400
        assert!(is_leap_year(2024)); // Divisible by 4
        assert!(!is_leap_year(2023)); // Not divisible by 4
        assert!(is_leap_year(2028));
    }

    #[test]
    fn test_dir_size() {
        let temp = create_temp_dir();
        fs::write(temp.path().join("file1.txt"), "Hello").unwrap();
        fs::write(temp.path().join("file2.txt"), "World!").unwrap();

        let size = dir_size(temp.path()).unwrap();
        assert!(size >= 11); // "Hello" + "World!" = 11 bytes minimum
    }

    #[test]
    fn test_dir_size_nested() {
        let temp = create_temp_dir();
        let subdir = temp.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(temp.path().join("root.txt"), "root").unwrap();
        fs::write(subdir.join("nested.txt"), "nested").unwrap();

        let size = dir_size(temp.path()).unwrap();
        assert!(size >= 10); // "root" + "nested" = 10 bytes minimum
    }

    #[test]
    fn test_validate_executable() {
        let temp = create_temp_dir();
        let exe_path = temp.path().join("test.exe");
        fs::write(&exe_path, b"This is at least 100 bytes of content for our test executable file that should pass validation").unwrap();

        let result = validate_executable(&exe_path, 50);
        assert!(result.is_ok());

        let result = validate_executable(&exe_path, 1000);
        assert!(matches!(result, Err(BundleError::InvalidExecutable { .. })));
    }

    #[test]
    fn test_analyze_bundle() {
        let temp = create_temp_dir();
        let config = BundleConfig::new(temp.path())
            .windows(ExecutableSource::from_bytes(vec![0; 1024]))
            .linux(ExecutableSource::from_bytes(vec![0; 2048]))
            .macos(ExecutableSource::placeholder());

        create_bundle(&config).expect("Bundle should succeed");

        let summary = analyze_bundle(temp.path()).expect("Analysis should succeed");
        assert!(summary.windows_size >= 1024);
        assert!(summary.linux_size >= 2048);
        assert!(summary.is_within_limit());
    }

    #[test]
    fn test_analyze_bundle_nonexistent() {
        let result = analyze_bundle(Path::new("/nonexistent/path"));
        assert!(matches!(result, Err(BundleError::ExecutableNotFound(_))));
    }

    // === Error tests ===

    #[test]
    fn test_bundle_error_display() {
        let err = BundleError::SizeLimitExceeded {
            size_mb: 120.5,
            limit_mb: 100.0,
        };
        let msg = err.to_string();
        assert!(msg.contains("120.50"));
        assert!(msg.contains("100.00"));
    }

    #[test]
    fn test_bundle_error_executable_not_found() {
        let err = BundleError::ExecutableNotFound(PathBuf::from("/path/to/missing"));
        assert!(err.to_string().contains("/path/to/missing"));
    }

    #[test]
    fn test_bundle_error_already_exists() {
        let err = BundleError::AlreadyExists(PathBuf::from("/path/to/bundle"));
        assert!(err.to_string().contains("/path/to/bundle"));
        assert!(err.to_string().contains("force"));
    }

    // === Constants tests ===

    #[test]
    fn test_max_bundle_size() {
        assert_eq!(MAX_BUNDLE_SIZE_BYTES, 100 * 1024 * 1024);
    }

    #[test]
    fn test_executable_names() {
        assert_eq!(WINDOWS_EXE, "tesseract.exe");
        assert_eq!(LINUX_APPIMAGE, "tesseract.AppImage");
        assert_eq!(MACOS_APP, "TESSERACT.app");
        assert_eq!(VERSION_FILE, "VERSION.txt");
        assert_eq!(TESSERACT_DIR, "TESSERACT");
    }
}
