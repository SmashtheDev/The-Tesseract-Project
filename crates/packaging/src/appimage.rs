//! Linux AppImage packaging utilities.
//!
//! This module provides functionality for creating AppImage packages for Linux.
//! AppImage is a portable application format that bundles the application and
//! its dependencies into a single executable file.
//!
//! # AppImage Structure
//!
//! An AppImage contains:
//! - `AppRun` - Entry point script
//! - `*.desktop` - Desktop file for integration
//! - `*.png` / `*.svg` - Application icon
//! - `usr/bin/` - Application binary
//! - `usr/lib/` - Bundled libraries (if any)
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_packaging::appimage::{AppImageBuilder, AppImageConfig};
//!
//! let config = AppImageConfig::default();
//! let builder = AppImageBuilder::new(config);
//! builder.build("target/release/tesseract", "dist/tesseract.AppImage")?;
//! ```

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during AppImage creation.
#[derive(Debug, Error)]
pub enum AppImageError {
    /// I/O error during file operations.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Binary not found at specified path.
    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    /// AppImage tools not installed.
    #[error("AppImage tools not installed: {message}")]
    ToolsNotInstalled {
        /// Description of missing tools.
        message: String,
    },

    /// Build failed with error message.
    #[error("Build failed: {0}")]
    BuildFailed(String),

    /// Icon generation failed.
    #[error("Icon generation failed: {0}")]
    IconError(String),

    /// Output file too large.
    #[error("AppImage size {size_mb:.1} MB exceeds limit of {limit_mb} MB")]
    SizeLimitExceeded {
        /// Actual size in MB.
        size_mb: f64,
        /// Size limit in MB.
        limit_mb: u64,
    },

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Result type for AppImage operations.
pub type Result<T> = std::result::Result<T, AppImageError>;

/// AppImage version to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppImageVersion {
    /// AppImage Type 1 (legacy).
    Type1,
    /// AppImage Type 2 (current standard, default).
    #[default]
    Type2,
}

impl AppImageVersion {
    /// Returns the version string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AppImageVersion::Type1 => "1",
            AppImageVersion::Type2 => "2",
        }
    }
}

/// Application category for desktop integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppCategory {
    /// Security applications.
    #[default]
    Security,
    /// Utility applications.
    Utility,
    /// System applications.
    System,
    /// Office applications.
    Office,
}

impl AppCategory {
    /// Returns the freedesktop.org category string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AppCategory::Security => "Security",
            AppCategory::Utility => "Utility",
            AppCategory::System => "System",
            AppCategory::Office => "Office",
        }
    }
}

/// Configuration for AppImage building.
#[derive(Debug, Clone)]
pub struct AppImageConfig {
    /// Application name.
    pub app_name: String,
    /// Application display name.
    pub display_name: String,
    /// Application version.
    pub version: String,
    /// Brief description.
    pub comment: String,
    /// Application category.
    pub category: AppCategory,
    /// Keywords for search.
    pub keywords: Vec<String>,
    /// MIME types the application handles.
    pub mime_types: Vec<String>,
    /// AppImage version type.
    pub appimage_version: AppImageVersion,
    /// Maximum file size in MB (0 = no limit).
    pub size_limit_mb: u64,
    /// Strip debug symbols from binary.
    pub strip_binary: bool,
    /// Compress with high ratio (slower build).
    pub high_compression: bool,
    /// Include fuse3 fallback for older systems.
    pub fuse3_fallback: bool,
    /// Path to custom AppRun script (None = generate default).
    pub custom_apprun: Option<PathBuf>,
    /// Additional environment variables for AppRun.
    pub env_vars: Vec<(String, String)>,
}

impl Default for AppImageConfig {
    fn default() -> Self {
        Self {
            app_name: "tesseract".to_string(),
            display_name: "TESSERACT".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            comment: "Secure removable storage encryption".to_string(),
            category: AppCategory::Security,
            keywords: vec![
                "encryption".to_string(),
                "security".to_string(),
                "vault".to_string(),
                "cryptography".to_string(),
                "usb".to_string(),
            ],
            mime_types: Vec::new(),
            appimage_version: AppImageVersion::Type2,
            size_limit_mb: 30,
            strip_binary: true,
            high_compression: true,
            fuse3_fallback: true,
            custom_apprun: None,
            env_vars: Vec::new(),
        }
    }
}

impl AppImageConfig {
    /// Creates a new configuration with the given app name.
    #[must_use]
    pub fn new(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_string(),
            display_name: app_name.to_uppercase(),
            ..Default::default()
        }
    }

    /// Sets the application version.
    #[must_use]
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_display_name(mut self, name: &str) -> Self {
        self.display_name = name.to_string();
        self
    }

    /// Sets the application comment/description.
    #[must_use]
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = comment.to_string();
        self
    }

    /// Sets the application category.
    #[must_use]
    pub fn with_category(mut self, category: AppCategory) -> Self {
        self.category = category;
        self
    }

    /// Sets the size limit in MB (0 for no limit).
    #[must_use]
    pub fn with_size_limit_mb(mut self, limit: u64) -> Self {
        self.size_limit_mb = limit;
        self
    }

    /// Enables or disables binary stripping.
    #[must_use]
    pub fn with_strip_binary(mut self, strip: bool) -> Self {
        self.strip_binary = strip;
        self
    }

    /// Enables or disables high compression.
    #[must_use]
    pub fn with_high_compression(mut self, enable: bool) -> Self {
        self.high_compression = enable;
        self
    }

    /// Adds keywords for desktop search.
    #[must_use]
    pub fn with_keywords(mut self, keywords: Vec<String>) -> Self {
        self.keywords = keywords;
        self
    }

    /// Adds an environment variable for AppRun.
    #[must_use]
    pub fn with_env_var(mut self, key: &str, value: &str) -> Self {
        self.env_vars.push((key.to_string(), value.to_string()));
        self
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.app_name.is_empty() {
            return Err(AppImageError::InvalidConfig(
                "app_name cannot be empty".to_string(),
            ));
        }
        if self.app_name.contains('/') || self.app_name.contains('\\') {
            return Err(AppImageError::InvalidConfig(
                "app_name cannot contain path separators".to_string(),
            ));
        }
        Ok(())
    }
}

/// Result of AppImage build operation.
#[derive(Debug)]
pub struct BuildResult {
    /// Path to the created AppImage.
    pub appimage_path: PathBuf,
    /// Size of the AppImage in bytes.
    pub size_bytes: u64,
    /// Size of the AppImage in MB.
    pub size_mb: f64,
    /// Whether the binary was stripped.
    pub stripped: bool,
    /// Compression used.
    pub compression: String,
}

impl BuildResult {
    /// Checks if the size is within a specified limit.
    #[must_use]
    pub fn is_within_limit(&self, limit_mb: u64) -> bool {
        if limit_mb == 0 {
            return true;
        }
        self.size_bytes <= limit_mb * 1024 * 1024
    }
}

/// Builder for creating Linux AppImage packages.
#[derive(Debug)]
pub struct AppImageBuilder {
    config: AppImageConfig,
    work_dir: Option<PathBuf>,
}

impl AppImageBuilder {
    /// Creates a new builder with the given configuration.
    #[must_use]
    pub fn new(config: AppImageConfig) -> Self {
        Self {
            config,
            work_dir: None,
        }
    }

    /// Creates a new builder with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(AppImageConfig::default())
    }

    /// Sets a custom work directory.
    #[must_use]
    pub fn with_work_dir(mut self, dir: PathBuf) -> Self {
        self.work_dir = Some(dir);
        self
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &AppImageConfig {
        &self.config
    }

    /// Builds an AppImage from the specified binary.
    ///
    /// # Arguments
    ///
    /// * `binary_path` - Path to the compiled binary (e.g., `target/release/tesseract`)
    /// * `output_path` - Path for the output AppImage file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The binary doesn't exist
    /// - AppImage tools are not installed
    /// - Build process fails
    /// - Output size exceeds limit
    pub fn build<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        binary_path: P,
        output_path: Q,
    ) -> Result<BuildResult> {
        let binary_path = binary_path.as_ref();
        let output_path = output_path.as_ref();

        self.config.validate()?;

        // Verify binary exists
        if !binary_path.exists() {
            return Err(AppImageError::BinaryNotFound(binary_path.to_path_buf()));
        }

        info!("Building AppImage for {}", self.config.app_name);
        debug!("Binary: {:?}", binary_path);
        debug!("Output: {:?}", output_path);

        // Create work directory
        let work_dir = self.create_work_dir()?;
        let appdir = work_dir.join(format!("{}.AppDir", self.config.app_name));
        fs::create_dir_all(&appdir)?;

        // Create AppDir structure
        self.create_appdir_structure(&appdir)?;

        // Copy and optionally strip binary
        let stripped = self.copy_binary(binary_path, &appdir)?;

        // Generate desktop file
        self.generate_desktop_file(&appdir)?;

        // Generate icon
        self.generate_icon(&appdir)?;

        // Generate AppRun
        self.generate_apprun(&appdir)?;

        // Create AppImage using appimagetool
        let compression = self.create_appimage(&appdir, output_path)?;

        // Get file size
        let size_bytes = fs::metadata(output_path)?.len();
        let size_mb = size_bytes as f64 / (1024.0 * 1024.0);

        // Check size limit
        if self.config.size_limit_mb > 0 && size_bytes > self.config.size_limit_mb * 1024 * 1024 {
            return Err(AppImageError::SizeLimitExceeded {
                size_mb,
                limit_mb: self.config.size_limit_mb,
            });
        }

        info!("AppImage created: {:.1} MB", size_mb);

        // Cleanup work directory
        if self.work_dir.is_none() {
            fs::remove_dir_all(&work_dir).ok();
        }

        Ok(BuildResult {
            appimage_path: output_path.to_path_buf(),
            size_bytes,
            size_mb,
            stripped,
            compression,
        })
    }

    /// Creates the work directory.
    fn create_work_dir(&self) -> Result<PathBuf> {
        let dir = if let Some(ref work_dir) = self.work_dir {
            work_dir.clone()
        } else {
            std::env::temp_dir().join(format!("tesseract-appimage-{}", std::process::id()))
        };
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Creates the AppDir structure.
    fn create_appdir_structure(&self, appdir: &Path) -> Result<()> {
        fs::create_dir_all(appdir.join("usr/bin"))?;
        fs::create_dir_all(appdir.join("usr/lib"))?;
        fs::create_dir_all(appdir.join("usr/share/applications"))?;
        fs::create_dir_all(appdir.join("usr/share/icons/hicolor/256x256/apps"))?;
        fs::create_dir_all(appdir.join("usr/share/icons/hicolor/128x128/apps"))?;
        fs::create_dir_all(appdir.join("usr/share/icons/hicolor/64x64/apps"))?;
        fs::create_dir_all(appdir.join("usr/share/icons/hicolor/48x48/apps"))?;
        fs::create_dir_all(appdir.join("usr/share/icons/hicolor/32x32/apps"))?;
        fs::create_dir_all(appdir.join("usr/share/metainfo"))?;
        Ok(())
    }

    /// Copies and optionally strips the binary.
    fn copy_binary(&self, binary_path: &Path, appdir: &Path) -> Result<bool> {
        let dest = appdir.join("usr/bin").join(&self.config.app_name);
        fs::copy(binary_path, &dest)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dest, perms)?;
        }

        // Strip binary if requested
        let stripped = if self.config.strip_binary {
            self.strip_binary(&dest)?
        } else {
            false
        };

        Ok(stripped)
    }

    /// Strips debug symbols from the binary.
    fn strip_binary(&self, binary_path: &Path) -> Result<bool> {
        debug!("Stripping binary: {:?}", binary_path);
        let output = Command::new("strip")
            .arg("--strip-all")
            .arg(binary_path)
            .output();

        match output {
            Ok(result) if result.status.success() => {
                info!("Binary stripped successfully");
                Ok(true)
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                warn!("Strip command failed: {}", stderr);
                Ok(false)
            }
            Err(e) => {
                warn!("Strip command not found: {}", e);
                Ok(false)
            }
        }
    }

    /// Generates the .desktop file.
    fn generate_desktop_file(&self, appdir: &Path) -> Result<()> {
        let desktop_content = self.create_desktop_content();

        // Write to root of AppDir (required by AppImage spec)
        let root_desktop = appdir.join(format!("{}.desktop", self.config.app_name));
        fs::write(&root_desktop, &desktop_content)?;

        // Also write to usr/share/applications
        let share_desktop = appdir
            .join("usr/share/applications")
            .join(format!("{}.desktop", self.config.app_name));
        fs::write(&share_desktop, &desktop_content)?;

        debug!("Desktop file generated");
        Ok(())
    }

    /// Creates the desktop file content.
    fn create_desktop_content(&self) -> String {
        let mut content = format!(
            r#"[Desktop Entry]
Type=Application
Name={display_name}
GenericName=Encrypted Storage
Comment={comment}
Exec={app_name}
Icon={app_name}
Terminal=false
Categories={category};
StartupNotify=true
StartupWMClass={app_name}
"#,
            display_name = self.config.display_name,
            comment = self.config.comment,
            app_name = self.config.app_name,
            category = self.config.category.as_str(),
        );

        // Add keywords
        if !self.config.keywords.is_empty() {
            content.push_str(&format!("Keywords={}\n", self.config.keywords.join(";")));
        }

        // Add MIME types
        if !self.config.mime_types.is_empty() {
            content.push_str(&format!("MimeType={}\n", self.config.mime_types.join(";")));
        }

        content
    }

    /// Generates the application icon.
    fn generate_icon(&self, appdir: &Path) -> Result<()> {
        // Generate icons at multiple sizes
        let sizes = [256, 128, 64, 48, 32];

        for size in sizes {
            let icon_data = self.generate_icon_png(size);
            let icon_path = appdir
                .join(format!("usr/share/icons/hicolor/{}x{}/apps", size, size))
                .join(format!("{}.png", self.config.app_name));
            fs::write(&icon_path, &icon_data)?;
        }

        // Create symlink at root of AppDir (required by AppImage spec)
        let root_icon = appdir.join(format!("{}.png", self.config.app_name));
        let largest_icon = appdir
            .join("usr/share/icons/hicolor/256x256/apps")
            .join(format!("{}.png", self.config.app_name));

        // Copy instead of symlink for portability
        fs::copy(&largest_icon, &root_icon)?;

        // Also create .DirIcon symlink (required by some AppImage tools)
        let dir_icon = appdir.join(".DirIcon");
        fs::copy(&largest_icon, &dir_icon)?;

        debug!("Icons generated");
        Ok(())
    }

    /// Generates a PNG icon at the specified size.
    ///
    /// Creates a simple geometric icon representing a secure vault/tesseract.
    /// This is a minimal PNG implementation for portability.
    fn generate_icon_png(&self, size: u32) -> Vec<u8> {
        // Generate RGBA pixel data
        let rgba = self.generate_icon_rgba(size);

        // Encode as PNG
        encode_png(&rgba, size, size)
    }

    /// Generates RGBA pixel data for the icon.
    fn generate_icon_rgba(&self, size: u32) -> Vec<u8> {
        let mut pixels = vec![0u8; (size * size * 4) as usize];
        let center = size as f32 / 2.0;
        let scale = size as f32 / 64.0; // Scale relative to 64px base

        for y in 0..size {
            for x in 0..size {
                let idx = ((y * size + x) * 4) as usize;

                // Calculate distance from center
                let dx = x as f32 - center;
                let dy = y as f32 - center;
                let dist = (dx * dx + dy * dy).sqrt();

                // Outer circle (vault body)
                let outer_radius = 28.0 * scale;
                let inner_radius = 20.0 * scale;
                let keyhole_radius = 6.0 * scale;

                // Anti-aliased outer circle
                let outer_edge = outer_radius - dist;
                let inner_edge = dist - inner_radius;

                // Dark blue vault color
                let vault_color = [0x2E, 0x4A, 0x6B, 0xFF];
                // Light accent
                let accent_color = [0x64, 0x95, 0xC8, 0xFF];
                // Keyhole color
                let keyhole_color = [0x1A, 0x2E, 0x4A, 0xFF];

                if outer_edge >= 0.0 && outer_edge < 1.0 {
                    // Anti-aliased outer edge
                    let alpha = (outer_edge * 255.0) as u8;
                    pixels[idx] = vault_color[0];
                    pixels[idx + 1] = vault_color[1];
                    pixels[idx + 2] = vault_color[2];
                    pixels[idx + 3] = alpha;
                } else if dist <= outer_radius {
                    if dist <= keyhole_radius && dy > -(4.0 * scale) {
                        // Keyhole center
                        pixels[idx..idx + 4].copy_from_slice(&keyhole_color);
                    } else if inner_edge >= 0.0 && inner_edge < 2.0 * scale {
                        // Inner ring accent
                        pixels[idx..idx + 4].copy_from_slice(&accent_color);
                    } else {
                        // Vault body
                        pixels[idx..idx + 4].copy_from_slice(&vault_color);
                    }
                } else {
                    // Transparent
                    pixels[idx] = 0;
                    pixels[idx + 1] = 0;
                    pixels[idx + 2] = 0;
                    pixels[idx + 3] = 0;
                }
            }
        }

        pixels
    }

    /// Generates the AppRun script.
    fn generate_apprun(&self, appdir: &Path) -> Result<()> {
        let apprun_path = appdir.join("AppRun");

        let content = if let Some(ref custom_path) = self.config.custom_apprun {
            fs::read_to_string(custom_path)?
        } else {
            self.create_apprun_content()
        };

        fs::write(&apprun_path, &content)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&apprun_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&apprun_path, perms)?;
        }

        debug!("AppRun generated");
        Ok(())
    }

    /// Creates the AppRun script content.
    fn create_apprun_content(&self) -> String {
        let mut content = String::from(
            r#"#!/bin/bash
# TESSERACT AppImage entry point

# Get the directory where this AppImage is mounted
APPDIR="$(dirname "$(readlink -f "$0")")"

# Set up library path for bundled dependencies
export LD_LIBRARY_PATH="${APPDIR}/usr/lib:${LD_LIBRARY_PATH}"

# Set XDG paths for portable operation
export XDG_DATA_DIRS="${APPDIR}/usr/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"

"#,
        );

        // Add custom environment variables
        for (key, value) in &self.config.env_vars {
            content.push_str(&format!("export {}=\"{}\"\n", key, value));
        }

        // FUSE3 fallback for older systems
        if self.config.fuse3_fallback {
            content.push_str(
                r#"
# FUSE3 fallback: Try fuse3 first, fall back to fuse2 if not available
if ! command -v fusermount3 &> /dev/null && command -v fusermount &> /dev/null; then
    export APPIMAGE_EXTRACT_AND_RUN=1
fi

"#,
            );
        }

        // Launch the application
        content.push_str(&format!(
            r#"# Launch the application
exec "${{APPDIR}}/usr/bin/{}" "$@"
"#,
            self.config.app_name
        ));

        content
    }

    /// Creates the AppImage using appimagetool.
    fn create_appimage(&self, appdir: &Path, output_path: &Path) -> Result<String> {
        // Ensure output directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Check for appimagetool
        let tool = self.find_appimagetool()?;
        debug!("Using appimagetool: {:?}", tool);

        let mut cmd = Command::new(&tool);
        cmd.arg(appdir);
        cmd.arg(output_path);

        // Set architecture
        cmd.env("ARCH", std::env::consts::ARCH);

        // High compression if requested
        let compression = if self.config.high_compression {
            cmd.env("APPIMAGE_COMP", "gzip");
            "gzip (high)".to_string()
        } else {
            "default".to_string()
        };

        info!("Creating AppImage...");
        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AppImageError::BuildFailed(stderr.to_string()));
        }

        Ok(compression)
    }

    /// Finds appimagetool in the system.
    fn find_appimagetool(&self) -> Result<PathBuf> {
        // Check common locations
        let candidates = [
            PathBuf::from("appimagetool"),
            PathBuf::from("/usr/bin/appimagetool"),
            PathBuf::from("/usr/local/bin/appimagetool"),
            dirs::home_dir()
                .map(|h| h.join(".local/bin/appimagetool"))
                .unwrap_or_default(),
            dirs::home_dir()
                .map(|h| h.join("bin/appimagetool"))
                .unwrap_or_default(),
            PathBuf::from("appimagetool-x86_64.AppImage"),
        ];

        for candidate in &candidates {
            if candidate.as_os_str().is_empty() {
                continue;
            }

            // Check if it's in PATH
            if candidate.to_string_lossy() == "appimagetool" {
                if Command::new("which")
                    .arg("appimagetool")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
                {
                    return Ok(candidate.clone());
                }
                continue;
            }

            if candidate.exists() {
                return Ok(candidate.clone());
            }
        }

        Err(AppImageError::ToolsNotInstalled {
            message: "appimagetool not found. Install from https://github.com/AppImage/appimagetool".to_string(),
        })
    }

    /// Generates AppStream metainfo file for software centers.
    pub fn generate_metainfo(&self, appdir: &Path) -> Result<()> {
        let content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>{app_name}.desktop</id>
  <name>{display_name}</name>
  <summary>{comment}</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <description>
    <p>
      TESSERACT is a production-grade removable storage encryption application
      providing AES-256-GCM encryption, Argon2id key derivation, and multi-level
      access control for classified data protection.
    </p>
    <p>
      Features include:
    </p>
    <ul>
      <li>AES-256-GCM authenticated encryption with hardware acceleration</li>
      <li>Argon2id key derivation for password-based encryption</li>
      <li>Four-tier key hierarchy for defense in depth</li>
      <li>Multi-level access control for compartmentalized security</li>
      <li>Virtual filesystem integration (FUSE on Linux)</li>
      <li>Portable GUI requiring no installation</li>
    </ul>
  </description>
  <categories>
    <category>{category}</category>
    <category>Utility</category>
  </categories>
  <url type="homepage">https://github.com/tesseract/tesseract</url>
  <provides>
    <binary>{app_name}</binary>
  </provides>
  <releases>
    <release version="{version}" date="{date}" />
  </releases>
  <content_rating type="oars-1.1" />
</component>
"#,
            app_name = self.config.app_name,
            display_name = self.config.display_name,
            comment = self.config.comment,
            category = self.config.category.as_str(),
            version = self.config.version,
            date = chrono_date(),
        );

        let metainfo_path = appdir
            .join("usr/share/metainfo")
            .join(format!("{}.appdata.xml", self.config.app_name));
        fs::write(&metainfo_path, content)?;

        debug!("AppStream metainfo generated");
        Ok(())
    }
}

/// Checks if AppImage tools are installed.
#[must_use]
pub fn is_appimage_supported() -> bool {
    Command::new("which")
        .arg("appimagetool")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns instructions for installing AppImage tools.
#[must_use]
pub fn get_install_instructions() -> String {
    r#"AppImage tools are required for building AppImage packages.

Installation options:

1. Download appimagetool directly:
   wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
   chmod +x appimagetool-x86_64.AppImage
   sudo mv appimagetool-x86_64.AppImage /usr/local/bin/appimagetool

2. On Ubuntu/Debian:
   sudo apt install appstream

3. On Fedora:
   sudo dnf install appstream

For more information, visit: https://github.com/AppImage/appimagetool
"#
    .to_string()
}

/// Returns the current date in YYYY-MM-DD format.
fn chrono_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let years = 1970 + days / 365;
    let day_of_year = days % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!("{:04}-{:02}-{:02}", years, month.min(12), day.min(31))
}

/// Minimal PNG encoder for icon generation.
///
/// This is a simple implementation to avoid external dependencies.
fn encode_png(rgba: &[u8], width: u32, height: u32) -> Vec<u8> {
    use std::io::Cursor;

    let mut output = Vec::new();

    // PNG signature
    output.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR chunk
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&width.to_be_bytes());
    ihdr_data.extend_from_slice(&height.to_be_bytes());
    ihdr_data.push(8); // bit depth
    ihdr_data.push(6); // color type (RGBA)
    ihdr_data.push(0); // compression method
    ihdr_data.push(0); // filter method
    ihdr_data.push(0); // interlace method
    write_chunk(&mut output, b"IHDR", &ihdr_data);

    // IDAT chunk (image data)
    let mut raw_data = Vec::new();
    for y in 0..height {
        raw_data.push(0); // Filter type: None
        let row_start = (y * width * 4) as usize;
        let row_end = row_start + (width * 4) as usize;
        raw_data.extend_from_slice(&rgba[row_start..row_end]);
    }

    // Compress with deflate
    let compressed = deflate_compress(&raw_data);
    write_chunk(&mut output, b"IDAT", &compressed);

    // IEND chunk
    write_chunk(&mut output, b"IEND", &[]);

    output
}

/// Writes a PNG chunk.
fn write_chunk(output: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let len = data.len() as u32;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(chunk_type);
    output.extend_from_slice(data);

    // Calculate CRC
    let mut crc_data = Vec::with_capacity(chunk_type.len() + data.len());
    crc_data.extend_from_slice(chunk_type);
    crc_data.extend_from_slice(data);
    let crc = crc32(&crc_data);
    output.extend_from_slice(&crc.to_be_bytes());
}

/// CRC-32 calculation for PNG.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        let index = ((crc ^ (*byte as u32)) & 0xFF) as usize;
        crc = CRC_TABLE[index] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// CRC-32 lookup table.
static CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if c & 1 != 0 {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Minimal deflate compression (store only, no actual compression).
///
/// For proper compression, a real deflate library should be used.
/// This minimal implementation creates valid but uncompressed deflate streams.
fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    // Zlib header
    output.push(0x78); // CMF (deflate, 32K window)
    output.push(0x01); // FLG (no dict, fastest)

    // Split into blocks of max 65535 bytes
    let mut remaining = data;
    while !remaining.is_empty() {
        let chunk_size = remaining.len().min(65535);
        let is_final = chunk_size == remaining.len();

        // Block header
        output.push(if is_final { 0x01 } else { 0x00 }); // BFINAL + BTYPE=00 (stored)
        let len = chunk_size as u16;
        output.extend_from_slice(&len.to_le_bytes());
        output.extend_from_slice(&(!len).to_le_bytes()); // NLEN

        // Data
        output.extend_from_slice(&remaining[..chunk_size]);
        remaining = &remaining[chunk_size..];
    }

    // Adler-32 checksum
    let adler = adler32(data);
    output.extend_from_slice(&adler.to_be_bytes());

    output
}

/// Adler-32 checksum for deflate.
fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in data {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ============================================================================
// Build Script Generation
// ============================================================================

/// Generates a build script for creating AppImages.
///
/// This creates a standalone shell script that can be run to build the AppImage.
#[must_use]
pub fn generate_build_script(config: &AppImageConfig) -> String {
    format!(
        r#"#!/bin/bash
# TESSERACT AppImage Build Script
# Generated by tesseract-packaging
#
# This script builds a portable Linux AppImage package.
#
# Requirements:
# - Rust toolchain (cargo)
# - appimagetool (https://github.com/AppImage/appimagetool)
# - strip (binutils)
#
# Usage:
#   ./build-appimage.sh [--release|--debug]

set -e

# Configuration
APP_NAME="{app_name}"
DISPLAY_NAME="{display_name}"
VERSION="{version}"
COMMENT="{comment}"
CATEGORY="{category}"

# Parse arguments
BUILD_TYPE="${{1:---release}}"
if [[ "$BUILD_TYPE" != "--release" && "$BUILD_TYPE" != "--debug" ]]; then
    echo "Usage: $0 [--release|--debug]"
    exit 1
fi

# Determine build directory
if [[ "$BUILD_TYPE" == "--release" ]]; then
    BUILD_DIR="target/release"
    CARGO_FLAGS="--release"
else
    BUILD_DIR="target/debug"
    CARGO_FLAGS=""
fi

echo "Building TESSERACT AppImage..."
echo "Build type: $BUILD_TYPE"
echo "Version: $VERSION"

# Build the binary
echo "Step 1: Building binary..."
cargo build $CARGO_FLAGS --bin tesseract

# Check binary exists
BINARY="$BUILD_DIR/tesseract"
if [[ ! -f "$BINARY" ]]; then
    echo "Error: Binary not found at $BINARY"
    exit 1
fi

# Create AppDir structure
echo "Step 2: Creating AppDir..."
APPDIR="$BUILD_DIR/$APP_NAME.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/64x64/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/48x48/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/32x32/apps"
mkdir -p "$APPDIR/usr/share/metainfo"

# Copy and strip binary
echo "Step 3: Copying and stripping binary..."
cp "$BINARY" "$APPDIR/usr/bin/$APP_NAME"
chmod +x "$APPDIR/usr/bin/$APP_NAME"

if [[ "$BUILD_TYPE" == "--release" ]]; then
    strip --strip-all "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null || echo "Warning: strip failed"
fi

# Generate desktop file
echo "Step 4: Generating desktop file..."
cat > "$APPDIR/$APP_NAME.desktop" << EOF
[Desktop Entry]
Type=Application
Name=$DISPLAY_NAME
GenericName=Encrypted Storage
Comment=$COMMENT
Exec=$APP_NAME
Icon=$APP_NAME
Terminal=false
Categories=$CATEGORY;
StartupNotify=true
StartupWMClass=$APP_NAME
Keywords=encryption;security;vault;cryptography;usb;
EOF

cp "$APPDIR/$APP_NAME.desktop" "$APPDIR/usr/share/applications/"

# Generate icon (using the built-in icon generator or placeholder)
echo "Step 5: Generating icons..."
# If we have a proper icon, use it; otherwise create a placeholder
if command -v convert &> /dev/null; then
    # Create vault icon with ImageMagick if available
    for size in 256 128 64 48 32; do
        convert -size ${{size}}x${{size}} xc:none \
            -fill '#2E4A6B' -draw "circle $((size/2)),$((size/2)) $((size/2)),$((size/8))" \
            -fill '#6495C8' -draw "circle $((size/2)),$((size/2)) $((size/2)),$((size*3/8))" \
            -fill '#1A2E4A' -draw "circle $((size/2)),$((size/2+size/8)) $((size/2)),$((size/2+size/4))" \
            "$APPDIR/usr/share/icons/hicolor/${{size}}x${{size}}/apps/$APP_NAME.png" 2>/dev/null || \
            echo "Creating placeholder ${{size}}x${{size}} icon"
    done
else
    # Create minimal placeholder PNG files
    echo "Warning: ImageMagick not found, using placeholder icons"
    for size in 256 128 64 48 32; do
        # Minimal valid PNG (1x1 transparent)
        printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82' > \
            "$APPDIR/usr/share/icons/hicolor/${{size}}x${{size}}/apps/$APP_NAME.png"
    done
fi

# Copy main icon to AppDir root
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png" "$APPDIR/$APP_NAME.png"
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png" "$APPDIR/.DirIcon"

# Generate AppRun
echo "Step 6: Generating AppRun..."
cat > "$APPDIR/AppRun" << 'APPRUN_EOF'
#!/bin/bash
APPDIR="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="${{APPDIR}}/usr/lib:${{LD_LIBRARY_PATH}}"
export XDG_DATA_DIRS="${{APPDIR}}/usr/share:${{XDG_DATA_DIRS:-/usr/local/share:/usr/share}}"
if ! command -v fusermount3 &> /dev/null && command -v fusermount &> /dev/null; then
    export APPIMAGE_EXTRACT_AND_RUN=1
fi
exec "${{APPDIR}}/usr/bin/{app_name}" "$@"
APPRUN_EOF
chmod +x "$APPDIR/AppRun"

# Generate AppStream metainfo
echo "Step 7: Generating AppStream metainfo..."
cat > "$APPDIR/usr/share/metainfo/$APP_NAME.appdata.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>$APP_NAME.desktop</id>
  <name>$DISPLAY_NAME</name>
  <summary>$COMMENT</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <description>
    <p>TESSERACT is a production-grade removable storage encryption application.</p>
  </description>
  <url type="homepage">https://github.com/tesseract/tesseract</url>
  <provides><binary>$APP_NAME</binary></provides>
  <releases><release version="$VERSION" date="$(date +%Y-%m-%d)" /></releases>
</component>
EOF

# Build AppImage
echo "Step 8: Creating AppImage..."
OUTPUT="$BUILD_DIR/$APP_NAME-$VERSION-x86_64.AppImage"

if command -v appimagetool &> /dev/null; then
    ARCH=x86_64 appimagetool "$APPDIR" "$OUTPUT"
elif [[ -x "appimagetool-x86_64.AppImage" ]]; then
    ARCH=x86_64 ./appimagetool-x86_64.AppImage "$APPDIR" "$OUTPUT"
else
    echo "Error: appimagetool not found!"
    echo ""
    echo "Install with:"
    echo "  wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    echo "  chmod +x appimagetool-x86_64.AppImage"
    echo "  sudo mv appimagetool-x86_64.AppImage /usr/local/bin/appimagetool"
    exit 1
fi

# Check result
if [[ -f "$OUTPUT" ]]; then
    SIZE=$(du -h "$OUTPUT" | cut -f1)
    SIZE_BYTES=$(stat -f%z "$OUTPUT" 2>/dev/null || stat -c%s "$OUTPUT" 2>/dev/null)
    SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

    echo ""
    echo "=========================================="
    echo "AppImage created successfully!"
    echo "=========================================="
    echo "Output: $OUTPUT"
    echo "Size: $SIZE ($SIZE_MB MB)"

    # Size limit check
    if [[ $SIZE_MB -gt {size_limit} ]]; then
        echo ""
        echo "WARNING: AppImage size ($SIZE_MB MB) exceeds {size_limit} MB limit!"
        echo "Consider:"
        echo "  - Using --release build"
        echo "  - Enabling LTO in Cargo.toml"
        echo "  - Removing unused dependencies"
    fi

    echo ""
    echo "Test with:"
    echo "  chmod +x $OUTPUT"
    echo "  ./$OUTPUT"
else
    echo "Error: AppImage creation failed!"
    exit 1
fi
"#,
        app_name = config.app_name,
        display_name = config.display_name,
        version = config.version,
        comment = config.comment,
        category = config.category.as_str(),
        size_limit = config.size_limit_mb,
    )
}

/// Writes the build script to a file.
pub fn write_build_script<P: AsRef<Path>>(config: &AppImageConfig, path: P) -> Result<()> {
    let script = generate_build_script(config);
    let path = path.as_ref();

    fs::write(path, &script)?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // --- AppImageVersion tests ---

    #[test]
    fn test_appimage_version_default() {
        let version = AppImageVersion::default();
        assert_eq!(version, AppImageVersion::Type2);
    }

    #[test]
    fn test_appimage_version_as_str() {
        assert_eq!(AppImageVersion::Type1.as_str(), "1");
        assert_eq!(AppImageVersion::Type2.as_str(), "2");
    }

    // --- AppCategory tests ---

    #[test]
    fn test_app_category_default() {
        let category = AppCategory::default();
        assert_eq!(category, AppCategory::Security);
    }

    #[test]
    fn test_app_category_as_str() {
        assert_eq!(AppCategory::Security.as_str(), "Security");
        assert_eq!(AppCategory::Utility.as_str(), "Utility");
        assert_eq!(AppCategory::System.as_str(), "System");
        assert_eq!(AppCategory::Office.as_str(), "Office");
    }

    // --- AppImageConfig tests ---

    #[test]
    fn test_config_default() {
        let config = AppImageConfig::default();
        assert_eq!(config.app_name, "tesseract");
        assert_eq!(config.display_name, "TESSERACT");
        assert_eq!(config.category, AppCategory::Security);
        assert_eq!(config.size_limit_mb, 30);
        assert!(config.strip_binary);
        assert!(config.high_compression);
    }

    #[test]
    fn test_config_new() {
        let config = AppImageConfig::new("myapp");
        assert_eq!(config.app_name, "myapp");
        assert_eq!(config.display_name, "MYAPP");
    }

    #[test]
    fn test_config_builder() {
        let config = AppImageConfig::new("testapp")
            .with_version("1.2.3")
            .with_display_name("Test App")
            .with_comment("A test application")
            .with_category(AppCategory::Utility)
            .with_size_limit_mb(50)
            .with_strip_binary(false)
            .with_high_compression(false)
            .with_keywords(vec!["test".to_string()])
            .with_env_var("TEST_VAR", "test_value");

        assert_eq!(config.app_name, "testapp");
        assert_eq!(config.version, "1.2.3");
        assert_eq!(config.display_name, "Test App");
        assert_eq!(config.comment, "A test application");
        assert_eq!(config.category, AppCategory::Utility);
        assert_eq!(config.size_limit_mb, 50);
        assert!(!config.strip_binary);
        assert!(!config.high_compression);
        assert_eq!(config.keywords, vec!["test".to_string()]);
        assert_eq!(config.env_vars, vec![("TEST_VAR".to_string(), "test_value".to_string())]);
    }

    #[test]
    fn test_config_validate_empty_name() {
        let config = AppImageConfig {
            app_name: String::new(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppImageError::InvalidConfig(_)));
    }

    #[test]
    fn test_config_validate_path_separator() {
        let config = AppImageConfig {
            app_name: "my/app".to_string(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());

        let config = AppImageConfig {
            app_name: "my\\app".to_string(),
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_valid() {
        let config = AppImageConfig::default();
        assert!(config.validate().is_ok());
    }

    // --- BuildResult tests ---

    #[test]
    fn test_build_result_is_within_limit() {
        let result = BuildResult {
            appimage_path: PathBuf::from("test.AppImage"),
            size_bytes: 20 * 1024 * 1024,
            size_mb: 20.0,
            stripped: true,
            compression: "gzip".to_string(),
        };

        assert!(result.is_within_limit(30));
        assert!(result.is_within_limit(20));
        assert!(!result.is_within_limit(19));
        assert!(result.is_within_limit(0)); // No limit
    }

    // --- AppImageBuilder tests ---

    #[test]
    fn test_builder_new() {
        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        assert_eq!(builder.config().app_name, "tesseract");
    }

    #[test]
    fn test_builder_default_config() {
        let builder = AppImageBuilder::default_config();
        assert_eq!(builder.config().app_name, "tesseract");
    }

    #[test]
    fn test_builder_with_work_dir() {
        let builder = AppImageBuilder::default_config()
            .with_work_dir(PathBuf::from("/tmp/test"));
        assert_eq!(builder.work_dir, Some(PathBuf::from("/tmp/test")));
    }

    #[test]
    fn test_builder_binary_not_found() {
        let builder = AppImageBuilder::default_config();
        let result = builder.build("/nonexistent/path", "/tmp/out.AppImage");
        assert!(matches!(result.unwrap_err(), AppImageError::BinaryNotFound(_)));
    }

    // --- Desktop file generation ---

    #[test]
    fn test_desktop_content() {
        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        let content = builder.create_desktop_content();

        assert!(content.contains("[Desktop Entry]"));
        assert!(content.contains("Type=Application"));
        assert!(content.contains("Name=TESSERACT"));
        assert!(content.contains("Exec=tesseract"));
        assert!(content.contains("Icon=tesseract"));
        assert!(content.contains("Terminal=false"));
        assert!(content.contains("Categories=Security;"));
        assert!(content.contains("Keywords=encryption;"));
    }

    #[test]
    fn test_desktop_content_custom() {
        let config = AppImageConfig::new("myapp")
            .with_display_name("My Application")
            .with_comment("A custom app")
            .with_category(AppCategory::Office)
            .with_keywords(vec!["custom".to_string(), "app".to_string()]);
        let builder = AppImageBuilder::new(config);
        let content = builder.create_desktop_content();

        assert!(content.contains("Name=My Application"));
        assert!(content.contains("Comment=A custom app"));
        assert!(content.contains("Categories=Office;"));
        assert!(content.contains("Keywords=custom;app"));
    }

    // --- AppRun generation ---

    #[test]
    fn test_apprun_content() {
        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        let content = builder.create_apprun_content();

        assert!(content.starts_with("#!/bin/bash"));
        assert!(content.contains("APPDIR="));
        assert!(content.contains("LD_LIBRARY_PATH"));
        assert!(content.contains("XDG_DATA_DIRS"));
        assert!(content.contains("exec \"${APPDIR}/usr/bin/tesseract\""));
    }

    #[test]
    fn test_apprun_content_with_env_vars() {
        let config = AppImageConfig::default()
            .with_env_var("MY_VAR", "my_value")
            .with_env_var("OTHER_VAR", "other");
        let builder = AppImageBuilder::new(config);
        let content = builder.create_apprun_content();

        assert!(content.contains("export MY_VAR=\"my_value\""));
        assert!(content.contains("export OTHER_VAR=\"other\""));
    }

    #[test]
    fn test_apprun_fuse3_fallback() {
        let mut config = AppImageConfig::default();
        config.fuse3_fallback = true;
        let builder = AppImageBuilder::new(config);
        let content = builder.create_apprun_content();

        assert!(content.contains("fusermount3"));
        assert!(content.contains("APPIMAGE_EXTRACT_AND_RUN"));
    }

    // --- Icon generation ---

    #[test]
    fn test_icon_rgba_size() {
        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);

        for size in [32, 48, 64, 128, 256] {
            let rgba = builder.generate_icon_rgba(size);
            assert_eq!(rgba.len(), (size * size * 4) as usize);
        }
    }

    #[test]
    fn test_icon_png_is_valid() {
        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        let png = builder.generate_icon_png(64);

        // Check PNG signature
        assert_eq!(&png[0..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        // Check for IHDR chunk
        assert_eq!(&png[12..16], b"IHDR");

        // Check for IEND chunk at end
        let iend_marker = b"IEND";
        let iend_pos = png.windows(4).rposition(|w| w == iend_marker);
        assert!(iend_pos.is_some());
    }

    // --- CRC32 tests ---

    #[test]
    fn test_crc32() {
        // Test vector from PNG specification
        let data = b"123456789";
        let crc = crc32(data);
        assert_eq!(crc, 0xCBF43926);
    }

    // --- Adler32 tests ---

    #[test]
    fn test_adler32() {
        // Test vector
        let data = b"Wikipedia";
        let checksum = adler32(data);
        assert_eq!(checksum, 0x11E60398);
    }

    // --- Deflate tests ---

    #[test]
    fn test_deflate_compress() {
        let data = b"Hello, World!";
        let compressed = deflate_compress(data);

        // Check zlib header
        assert_eq!(compressed[0], 0x78);

        // Should be larger than input (store mode adds overhead)
        assert!(compressed.len() > data.len());

        // Last 4 bytes should be adler32
        let adler_bytes = &compressed[compressed.len() - 4..];
        let stored_adler = u32::from_be_bytes([
            adler_bytes[0],
            adler_bytes[1],
            adler_bytes[2],
            adler_bytes[3],
        ]);
        assert_eq!(stored_adler, adler32(data));
    }

    // --- Build script generation ---

    #[test]
    fn test_generate_build_script() {
        let config = AppImageConfig::default();
        let script = generate_build_script(&config);

        assert!(script.starts_with("#!/bin/bash"));
        assert!(script.contains("APP_NAME=\"tesseract\""));
        assert!(script.contains("DISPLAY_NAME=\"TESSERACT\""));
        assert!(script.contains("cargo build"));
        assert!(script.contains("appimagetool"));
        assert!(script.contains("strip --strip-all"));
    }

    #[test]
    fn test_write_build_script() {
        let dir = tempdir().unwrap();
        let script_path = dir.path().join("build-appimage.sh");

        let config = AppImageConfig::default();
        write_build_script(&config, &script_path).unwrap();

        assert!(script_path.exists());

        let content = fs::read_to_string(&script_path).unwrap();
        assert!(content.starts_with("#!/bin/bash"));

        // Check permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&script_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o755);
        }
    }

    // --- Utility function tests ---

    #[test]
    fn test_is_appimage_supported() {
        // Just check it doesn't panic
        let _ = is_appimage_supported();
    }

    #[test]
    fn test_get_install_instructions() {
        let instructions = get_install_instructions();
        assert!(instructions.contains("appimagetool"));
        assert!(instructions.contains("https://github.com/AppImage/appimagetool"));
    }

    #[test]
    fn test_chrono_date() {
        let date = chrono_date();
        // Should be YYYY-MM-DD format
        assert_eq!(date.len(), 10);
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
    }

    // --- AppDir structure tests ---

    #[test]
    fn test_create_appdir_structure() {
        let dir = tempdir().unwrap();
        let appdir = dir.path().join("test.AppDir");

        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        builder.create_appdir_structure(&appdir).unwrap();

        assert!(appdir.join("usr/bin").exists());
        assert!(appdir.join("usr/lib").exists());
        assert!(appdir.join("usr/share/applications").exists());
        assert!(appdir.join("usr/share/icons/hicolor/256x256/apps").exists());
        assert!(appdir.join("usr/share/icons/hicolor/64x64/apps").exists());
        assert!(appdir.join("usr/share/metainfo").exists());
    }

    // --- Error tests ---

    #[test]
    fn test_appimage_error_display() {
        let err = AppImageError::BinaryNotFound(PathBuf::from("/test/path"));
        assert!(err.to_string().contains("/test/path"));

        let err = AppImageError::SizeLimitExceeded {
            size_mb: 35.5,
            limit_mb: 30,
        };
        assert!(err.to_string().contains("35.5"));
        assert!(err.to_string().contains("30"));

        let err = AppImageError::ToolsNotInstalled {
            message: "not found".to_string(),
        };
        assert!(err.to_string().contains("not found"));
    }

    // --- Integration-style tests ---

    #[test]
    fn test_full_desktop_file_generation() {
        let dir = tempdir().unwrap();
        let appdir = dir.path().join("test.AppDir");
        fs::create_dir_all(&appdir).unwrap();
        fs::create_dir_all(appdir.join("usr/share/applications")).unwrap();

        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        builder.generate_desktop_file(&appdir).unwrap();

        // Check root desktop file
        let root_desktop = appdir.join("tesseract.desktop");
        assert!(root_desktop.exists());
        let content = fs::read_to_string(&root_desktop).unwrap();
        assert!(content.contains("[Desktop Entry]"));

        // Check share desktop file
        let share_desktop = appdir.join("usr/share/applications/tesseract.desktop");
        assert!(share_desktop.exists());
    }

    #[test]
    fn test_full_apprun_generation() {
        let dir = tempdir().unwrap();
        let appdir = dir.path();

        let config = AppImageConfig::default();
        let builder = AppImageBuilder::new(config);
        builder.generate_apprun(appdir).unwrap();

        let apprun = appdir.join("AppRun");
        assert!(apprun.exists());

        let content = fs::read_to_string(&apprun).unwrap();
        assert!(content.starts_with("#!/bin/bash"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&apprun).unwrap().permissions();
            assert_eq!(perms.mode() & 0o111, 0o111); // Executable
        }
    }

    #[test]
    fn test_metainfo_generation() {
        let dir = tempdir().unwrap();
        let appdir = dir.path();
        fs::create_dir_all(appdir.join("usr/share/metainfo")).unwrap();

        let config = AppImageConfig::new("testapp")
            .with_version("1.0.0")
            .with_display_name("Test Application");
        let builder = AppImageBuilder::new(config);
        builder.generate_metainfo(appdir).unwrap();

        let metainfo = appdir.join("usr/share/metainfo/testapp.appdata.xml");
        assert!(metainfo.exists());

        let content = fs::read_to_string(&metainfo).unwrap();
        assert!(content.contains("<id>testapp.desktop</id>"));
        assert!(content.contains("<name>Test Application</name>"));
        assert!(content.contains("version=\"1.0.0\""));
        assert!(content.contains("<binary>testapp</binary>"));
    }
}
