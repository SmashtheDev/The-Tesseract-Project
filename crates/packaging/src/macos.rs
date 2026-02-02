//! macOS App Bundle packaging utilities.
//!
//! This module provides functionality for creating macOS .app bundles for TESSERACT.
//! App bundles are the standard packaging format for macOS applications, providing
//! Finder integration, code signing, and notarization support.
//!
//! # App Bundle Structure
//!
//! A macOS app bundle contains:
//! ```text
//! TESSERACT.app/
//! ├── Contents/
//! │   ├── Info.plist          # Application metadata
//! │   ├── PkgInfo             # Package type identifier
//! │   ├── MacOS/
//! │   │   └── tesseract       # Main executable
//! │   ├── Resources/
//! │   │   ├── AppIcon.icns    # Application icon
//! │   │   └── en.lproj/       # Localized resources (optional)
//! │   ├── Frameworks/         # Bundled frameworks (if any)
//! │   └── _CodeSignature/     # Code signing data (when signed)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use tesseract_packaging::macos::{AppBundleBuilder, AppBundleConfig};
//!
//! let config = AppBundleConfig::default();
//! let builder = AppBundleBuilder::new(config);
//! builder.build("target/release/tesseract", "dist/TESSERACT.app")?;
//! ```

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur during app bundle creation.
#[derive(Debug, Error)]
pub enum AppBundleError {
    /// I/O error during file operations.
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Binary not found at specified path.
    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    /// Invalid bundle identifier.
    #[error("Invalid bundle identifier: {0}")]
    InvalidBundleIdentifier(String),

    /// Icon generation failed.
    #[error("Icon generation failed: {0}")]
    IconError(String),

    /// Code signing failed.
    #[error("Code signing failed: {0}")]
    CodeSigningError(String),

    /// Notarization failed.
    #[error("Notarization failed: {0}")]
    NotarizationError(String),

    /// Build failed with error message.
    #[error("Build failed: {0}")]
    BuildFailed(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Platform not supported.
    #[error("macOS app bundle creation is only supported on macOS")]
    UnsupportedPlatform,
}

/// Result type for app bundle operations.
pub type Result<T> = std::result::Result<T, AppBundleError>;

/// macOS deployment target version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacOSVersion {
    /// Major version (e.g., 12 for Monterey).
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl MacOSVersion {
    /// Creates a new version.
    #[must_use]
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// macOS 12 Monterey (minimum supported).
    pub const MONTEREY: MacOSVersion = MacOSVersion { major: 12, minor: 0, patch: 0 };

    /// macOS 13 Ventura.
    pub const VENTURA: MacOSVersion = MacOSVersion { major: 13, minor: 0, patch: 0 };

    /// macOS 14 Sonoma.
    pub const SONOMA: MacOSVersion = MacOSVersion { major: 14, minor: 0, patch: 0 };

    /// Returns the version string.
    #[must_use]
    pub fn as_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Returns the short version string (major.minor).
    #[must_use]
    pub fn as_short_string(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

impl Default for MacOSVersion {
    fn default() -> Self {
        Self::MONTEREY
    }
}

/// Application category for macOS App Store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppCategory {
    /// Security applications (default for TESSERACT).
    #[default]
    Security,
    /// Business applications.
    Business,
    /// Developer tools.
    DeveloperTools,
    /// Productivity applications.
    Productivity,
    /// Utilities.
    Utilities,
}

impl AppCategory {
    /// Returns the LSApplicationCategoryType value.
    #[must_use]
    pub fn as_category_type(&self) -> &'static str {
        match self {
            AppCategory::Security => "public.app-category.security",
            AppCategory::Business => "public.app-category.business",
            AppCategory::DeveloperTools => "public.app-category.developer-tools",
            AppCategory::Productivity => "public.app-category.productivity",
            AppCategory::Utilities => "public.app-category.utilities",
        }
    }

    /// Returns a human-readable category name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AppCategory::Security => "Security",
            AppCategory::Business => "Business",
            AppCategory::DeveloperTools => "Developer Tools",
            AppCategory::Productivity => "Productivity",
            AppCategory::Utilities => "Utilities",
        }
    }
}

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// Apple Silicon (arm64).
    Arm64,
    /// Intel (x86_64).
    X86_64,
    /// Universal binary (both architectures).
    Universal,
}

impl Architecture {
    /// Returns the architecture string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::Arm64 => "arm64",
            Architecture::X86_64 => "x86_64",
            Architecture::Universal => "universal",
        }
    }

    /// Returns architectures as array for LSArchitecturePriority.
    #[must_use]
    pub fn as_array(&self) -> Vec<&'static str> {
        match self {
            Architecture::Arm64 => vec!["arm64"],
            Architecture::X86_64 => vec!["x86_64"],
            Architecture::Universal => vec!["arm64", "x86_64"],
        }
    }
}

impl Default for Architecture {
    fn default() -> Self {
        // Default to arm64 for modern Macs
        Architecture::Arm64
    }
}

/// Code signing identity configuration.
#[derive(Debug, Clone)]
pub struct CodeSigningConfig {
    /// Developer ID or certificate identity (e.g., "Developer ID Application: Company Name (TEAM_ID)").
    /// If None, code signing will be skipped.
    pub identity: Option<String>,

    /// Enable hardened runtime (required for notarization).
    pub hardened_runtime: bool,

    /// Entitlements file path (optional).
    pub entitlements: Option<PathBuf>,

    /// Sign nested code (frameworks, dylibs).
    pub deep: bool,

    /// Force re-sign even if already signed.
    pub force: bool,

    /// Timestamp server URL (default: Apple's timestamp server).
    pub timestamp: bool,

    /// Additional options for codesign.
    pub options: Vec<String>,
}

impl Default for CodeSigningConfig {
    fn default() -> Self {
        Self {
            identity: None,
            hardened_runtime: true,
            entitlements: None,
            deep: true,
            force: false,
            timestamp: true,
            options: Vec::new(),
        }
    }
}

impl CodeSigningConfig {
    /// Creates a new code signing config with the given identity.
    pub fn with_identity(identity: impl Into<String>) -> Self {
        Self {
            identity: Some(identity.into()),
            ..Default::default()
        }
    }

    /// Checks if code signing is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.identity.is_some()
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        if let Some(ref entitlements) = self.entitlements {
            if !entitlements.exists() {
                return Err(AppBundleError::InvalidConfig(format!(
                    "Entitlements file not found: {}",
                    entitlements.display()
                )));
            }
        }
        Ok(())
    }
}

/// Notarization configuration.
#[derive(Debug, Clone)]
pub struct NotarizationConfig {
    /// Apple ID for notarization.
    pub apple_id: Option<String>,

    /// Team ID (10-character string).
    pub team_id: Option<String>,

    /// App-specific password (stored in keychain recommended).
    /// Use `@keychain:AC_PASSWORD` format for keychain storage.
    pub password: Option<String>,

    /// Wait for notarization to complete.
    pub wait: bool,

    /// Timeout in seconds for waiting.
    pub timeout_seconds: u64,
}

impl Default for NotarizationConfig {
    fn default() -> Self {
        Self {
            apple_id: None,
            team_id: None,
            password: None,
            wait: true,
            timeout_seconds: 3600, // 1 hour
        }
    }
}

impl NotarizationConfig {
    /// Checks if notarization is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.apple_id.is_some() && self.team_id.is_some() && self.password.is_some()
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.is_enabled() {
            if let Some(ref team_id) = self.team_id {
                if team_id.len() != 10 {
                    return Err(AppBundleError::InvalidConfig(format!(
                        "Team ID must be 10 characters, got: {}",
                        team_id.len()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Configuration for app bundle building.
#[derive(Debug, Clone)]
pub struct AppBundleConfig {
    /// Application name (used for binary name).
    pub app_name: String,

    /// Display name shown in Finder.
    pub display_name: String,

    /// Bundle identifier (e.g., "io.tesseract.app").
    pub bundle_identifier: String,

    /// Application version (CFBundleShortVersionString).
    pub version: String,

    /// Build number (CFBundleVersion).
    pub build: String,

    /// Copyright notice.
    pub copyright: String,

    /// Brief description.
    pub description: String,

    /// Application category.
    pub category: AppCategory,

    /// Minimum macOS version.
    pub minimum_macos_version: MacOSVersion,

    /// Target architecture.
    pub architecture: Architecture,

    /// Enable Retina display support.
    pub high_resolution: bool,

    /// Allow background execution.
    pub background_only: bool,

    /// Support opening files (file associations).
    pub supports_files: bool,

    /// Document types the application handles.
    pub document_types: Vec<DocumentType>,

    /// URL schemes the application handles.
    pub url_schemes: Vec<String>,

    /// Code signing configuration.
    pub code_signing: CodeSigningConfig,

    /// Notarization configuration.
    pub notarization: NotarizationConfig,

    /// Strip debug symbols from binary.
    pub strip_binary: bool,

    /// Create DMG installer.
    pub create_dmg: bool,

    /// Working directory for build (temporary).
    pub work_dir: Option<PathBuf>,
}

/// Document type for file associations.
#[derive(Debug, Clone)]
pub struct DocumentType {
    /// Document type name.
    pub name: String,
    /// File extensions (without dot).
    pub extensions: Vec<String>,
    /// MIME types.
    pub mime_types: Vec<String>,
    /// UTI (Uniform Type Identifier).
    pub uti: Option<String>,
    /// Role (Editor, Viewer, Shell, None).
    pub role: DocumentRole,
    /// Icon file name (in Resources).
    pub icon_file: Option<String>,
}

/// Document role for file associations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DocumentRole {
    /// Application can edit the document.
    #[default]
    Editor,
    /// Application can only view the document.
    Viewer,
    /// Application provides a shell for the document.
    Shell,
    /// No specific role.
    None,
}

impl DocumentRole {
    /// Returns the role string for Info.plist.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            DocumentRole::Editor => "Editor",
            DocumentRole::Viewer => "Viewer",
            DocumentRole::Shell => "Shell",
            DocumentRole::None => "None",
        }
    }
}

impl Default for AppBundleConfig {
    fn default() -> Self {
        Self {
            app_name: "tesseract".to_string(),
            display_name: "TESSERACT".to_string(),
            bundle_identifier: "io.tesseract.encryption".to_string(),
            version: "1.0.0".to_string(),
            build: "1".to_string(),
            copyright: format!("Copyright © {} TESSERACT Project. All rights reserved.",
                chrono_year()),
            description: "Secure removable storage encryption".to_string(),
            category: AppCategory::Security,
            minimum_macos_version: MacOSVersion::MONTEREY,
            architecture: Architecture::default(),
            high_resolution: true,
            background_only: false,
            supports_files: true,
            document_types: vec![
                DocumentType {
                    name: "TESSERACT Vault".to_string(),
                    extensions: vec!["vault".to_string()],
                    mime_types: vec!["application/x-tesseract-vault".to_string()],
                    uti: Some("io.tesseract.vault".to_string()),
                    role: DocumentRole::Editor,
                    icon_file: Some("VaultIcon.icns".to_string()),
                },
            ],
            url_schemes: vec!["tesseract".to_string()],
            code_signing: CodeSigningConfig::default(),
            notarization: NotarizationConfig::default(),
            strip_binary: true,
            create_dmg: false,
            work_dir: None,
        }
    }
}

impl AppBundleConfig {
    /// Creates a new config with the given bundle identifier.
    pub fn new(bundle_identifier: impl Into<String>) -> Self {
        Self {
            bundle_identifier: bundle_identifier.into(),
            ..Default::default()
        }
    }

    /// Builder method to set app name.
    #[must_use]
    pub fn with_app_name(mut self, name: impl Into<String>) -> Self {
        self.app_name = name.into();
        self
    }

    /// Builder method to set display name.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Builder method to set version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Builder method to set build number.
    #[must_use]
    pub fn with_build(mut self, build: impl Into<String>) -> Self {
        self.build = build.into();
        self
    }

    /// Builder method to set minimum macOS version.
    #[must_use]
    pub fn with_minimum_version(mut self, version: MacOSVersion) -> Self {
        self.minimum_macos_version = version;
        self
    }

    /// Builder method to set architecture.
    #[must_use]
    pub fn with_architecture(mut self, arch: Architecture) -> Self {
        self.architecture = arch;
        self
    }

    /// Builder method to enable code signing.
    #[must_use]
    pub fn with_code_signing(mut self, config: CodeSigningConfig) -> Self {
        self.code_signing = config;
        self
    }

    /// Builder method to enable notarization.
    #[must_use]
    pub fn with_notarization(mut self, config: NotarizationConfig) -> Self {
        self.notarization = config;
        self
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate bundle identifier format
        if !is_valid_bundle_identifier(&self.bundle_identifier) {
            return Err(AppBundleError::InvalidBundleIdentifier(
                self.bundle_identifier.clone(),
            ));
        }

        // Validate version format
        if self.version.is_empty() {
            return Err(AppBundleError::InvalidConfig(
                "Version cannot be empty".to_string(),
            ));
        }

        // Validate code signing config
        self.code_signing.validate()?;

        // Validate notarization config
        self.notarization.validate()?;

        Ok(())
    }
}

/// Validates a bundle identifier.
fn is_valid_bundle_identifier(identifier: &str) -> bool {
    if identifier.is_empty() || identifier.len() > 255 {
        return false;
    }

    // Must have at least two parts (e.g., "com.example")
    let parts: Vec<&str> = identifier.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    // Each part must be valid
    for part in parts {
        if part.is_empty() {
            return false;
        }
        // Must start with a letter
        if !part.chars().next().map_or(false, |c| c.is_ascii_alphabetic()) {
            return false;
        }
        // Only alphanumeric, hyphen, and underscore allowed
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return false;
        }
    }

    true
}

/// Returns the current year as string for copyright.
fn chrono_year() -> String {
    // Use a fixed year for determinism in builds, or get from system
    "2026".to_string()
}

/// Result of building an app bundle.
#[derive(Debug, Clone)]
pub struct BuildResult {
    /// Path to the created app bundle.
    pub bundle_path: PathBuf,

    /// Bundle size in bytes.
    pub size_bytes: u64,

    /// Bundle size in MB.
    pub size_mb: f64,

    /// Whether the binary was stripped.
    pub stripped: bool,

    /// Whether the bundle was code signed.
    pub code_signed: bool,

    /// Whether the bundle was notarized.
    pub notarized: bool,

    /// Path to DMG if created.
    pub dmg_path: Option<PathBuf>,
}

/// Builder for creating macOS app bundles.
pub struct AppBundleBuilder {
    config: AppBundleConfig,
    work_dir: Option<PathBuf>,
}

impl AppBundleBuilder {
    /// Creates a new builder with the given configuration.
    pub fn new(config: AppBundleConfig) -> Self {
        Self {
            config,
            work_dir: None,
        }
    }

    /// Creates a builder with default configuration.
    pub fn default_config() -> Self {
        Self::new(AppBundleConfig::default())
    }

    /// Sets a custom work directory.
    pub fn with_work_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(dir.into());
        self
    }

    /// Builds the app bundle from the given binary.
    pub fn build(
        &self,
        binary_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
    ) -> Result<BuildResult> {
        let binary_path = binary_path.as_ref();
        let output_path = output_path.as_ref();

        // Validate config
        self.config.validate()?;

        // Validate binary exists
        if !binary_path.exists() {
            return Err(AppBundleError::BinaryNotFound(binary_path.to_path_buf()));
        }

        info!("Building app bundle: {}", output_path.display());
        debug!("Source binary: {}", binary_path.display());

        // Create app bundle structure
        self.create_bundle_structure(output_path)?;

        // Copy and optionally strip binary
        let stripped = self.copy_binary(binary_path, output_path)?;

        // Generate Info.plist
        self.generate_info_plist(output_path)?;

        // Generate PkgInfo
        self.generate_pkginfo(output_path)?;

        // Generate icon
        self.generate_icon(output_path)?;

        // Code sign if configured
        let code_signed = if self.config.code_signing.is_enabled() {
            self.code_sign(output_path)?;
            true
        } else {
            debug!("Code signing skipped (no identity configured)");
            false
        };

        // Notarize if configured
        let notarized = if self.config.notarization.is_enabled() && code_signed {
            self.notarize(output_path)?;
            true
        } else {
            debug!("Notarization skipped");
            false
        };

        // Create DMG if configured
        let dmg_path = if self.config.create_dmg {
            Some(self.create_dmg(output_path)?)
        } else {
            None
        };

        // Calculate size
        let size_bytes = calculate_directory_size(output_path)?;
        let size_mb = size_bytes as f64 / (1024.0 * 1024.0);

        info!(
            "App bundle created: {} ({:.1} MB)",
            output_path.display(),
            size_mb
        );

        Ok(BuildResult {
            bundle_path: output_path.to_path_buf(),
            size_bytes,
            size_mb,
            stripped,
            code_signed,
            notarized,
            dmg_path,
        })
    }

    /// Creates the app bundle directory structure.
    fn create_bundle_structure(&self, bundle_path: &Path) -> Result<()> {
        debug!("Creating bundle structure: {}", bundle_path.display());

        // Remove existing bundle if present
        if bundle_path.exists() {
            fs::remove_dir_all(bundle_path)?;
        }

        // Create directories
        let contents = bundle_path.join("Contents");
        fs::create_dir_all(contents.join("MacOS"))?;
        fs::create_dir_all(contents.join("Resources"))?;

        // Create Frameworks directory (even if empty, for consistency)
        fs::create_dir_all(contents.join("Frameworks"))?;

        Ok(())
    }

    /// Copies and optionally strips the binary.
    fn copy_binary(&self, source: &Path, bundle_path: &Path) -> Result<bool> {
        let dest = bundle_path
            .join("Contents")
            .join("MacOS")
            .join(&self.config.app_name);

        debug!("Copying binary to: {}", dest.display());
        fs::copy(source, &dest)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dest)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&dest, perms)?;
        }

        // Strip if configured
        let stripped = if self.config.strip_binary {
            self.strip_binary(&dest)?
        } else {
            false
        };

        Ok(stripped)
    }

    /// Strips debug symbols from binary.
    fn strip_binary(&self, binary: &Path) -> Result<bool> {
        debug!("Stripping binary: {}", binary.display());

        let result = Command::new("strip")
            .arg("-x")
            .arg(binary)
            .output();

        match result {
            Ok(output) if output.status.success() => {
                debug!("Binary stripped successfully");
                Ok(true)
            }
            Ok(output) => {
                warn!(
                    "Strip failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(false)
            }
            Err(e) => {
                warn!("Strip command not available: {}", e);
                Ok(false)
            }
        }
    }

    /// Generates the Info.plist file.
    fn generate_info_plist(&self, bundle_path: &Path) -> Result<()> {
        let plist_path = bundle_path.join("Contents").join("Info.plist");
        debug!("Generating Info.plist: {}", plist_path.display());

        let plist = generate_info_plist(&self.config);

        let mut file = File::create(&plist_path)?;
        file.write_all(plist.as_bytes())?;

        Ok(())
    }

    /// Generates the PkgInfo file.
    fn generate_pkginfo(&self, bundle_path: &Path) -> Result<()> {
        let pkginfo_path = bundle_path.join("Contents").join("PkgInfo");
        debug!("Generating PkgInfo: {}", pkginfo_path.display());

        // Standard macOS application package type
        let mut file = File::create(&pkginfo_path)?;
        file.write_all(b"APPL????")?;

        Ok(())
    }

    /// Generates the application icon.
    fn generate_icon(&self, bundle_path: &Path) -> Result<()> {
        let icon_path = bundle_path
            .join("Contents")
            .join("Resources")
            .join("AppIcon.icns");
        debug!("Generating icon: {}", icon_path.display());

        // Generate the icon data
        let icns_data = generate_icns_icon()?;

        let mut file = File::create(&icon_path)?;
        file.write_all(&icns_data)?;

        Ok(())
    }

    /// Signs the app bundle with the configured identity.
    fn code_sign(&self, bundle_path: &Path) -> Result<()> {
        let identity = self.config.code_signing.identity.as_ref()
            .ok_or_else(|| AppBundleError::CodeSigningError("No identity configured".to_string()))?;

        info!("Code signing with identity: {}", identity);

        let mut cmd = Command::new("codesign");

        cmd.arg("--sign").arg(identity);

        if self.config.code_signing.deep {
            cmd.arg("--deep");
        }

        if self.config.code_signing.force {
            cmd.arg("--force");
        }

        if self.config.code_signing.hardened_runtime {
            cmd.arg("--options").arg("runtime");
        }

        if self.config.code_signing.timestamp {
            cmd.arg("--timestamp");
        }

        if let Some(ref entitlements) = self.config.code_signing.entitlements {
            cmd.arg("--entitlements").arg(entitlements);
        }

        for option in &self.config.code_signing.options {
            cmd.arg(option);
        }

        cmd.arg(bundle_path);

        let output = cmd.output()?;

        if output.status.success() {
            info!("Code signing successful");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(AppBundleError::CodeSigningError(stderr.to_string()))
        }
    }

    /// Submits the app bundle for notarization.
    fn notarize(&self, bundle_path: &Path) -> Result<()> {
        let apple_id = self.config.notarization.apple_id.as_ref()
            .ok_or_else(|| AppBundleError::NotarizationError("No Apple ID configured".to_string()))?;
        let team_id = self.config.notarization.team_id.as_ref()
            .ok_or_else(|| AppBundleError::NotarizationError("No Team ID configured".to_string()))?;
        let password = self.config.notarization.password.as_ref()
            .ok_or_else(|| AppBundleError::NotarizationError("No password configured".to_string()))?;

        info!("Submitting for notarization...");

        // Create ZIP for submission
        let zip_path = bundle_path.with_extension("zip");
        let zip_result = Command::new("ditto")
            .arg("-c")
            .arg("-k")
            .arg("--keepParent")
            .arg(bundle_path)
            .arg(&zip_path)
            .output()?;

        if !zip_result.status.success() {
            return Err(AppBundleError::NotarizationError(
                "Failed to create ZIP for notarization".to_string(),
            ));
        }

        // Submit to notary service
        let mut cmd = Command::new("xcrun");
        cmd.arg("notarytool")
            .arg("submit")
            .arg(&zip_path)
            .arg("--apple-id").arg(apple_id)
            .arg("--team-id").arg(team_id)
            .arg("--password").arg(password);

        if self.config.notarization.wait {
            cmd.arg("--wait");
            cmd.arg("--timeout").arg(self.config.notarization.timeout_seconds.to_string());
        }

        let output = cmd.output()?;

        // Clean up ZIP
        let _ = fs::remove_file(&zip_path);

        if output.status.success() {
            // Staple the ticket
            let staple_result = Command::new("xcrun")
                .arg("stapler")
                .arg("staple")
                .arg(bundle_path)
                .output()?;

            if !staple_result.status.success() {
                warn!("Stapling failed (notarization may still be valid)");
            }

            info!("Notarization successful");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(AppBundleError::NotarizationError(stderr.to_string()))
        }
    }

    /// Creates a DMG installer.
    fn create_dmg(&self, bundle_path: &Path) -> Result<PathBuf> {
        let dmg_path = bundle_path.with_extension("dmg");
        info!("Creating DMG: {}", dmg_path.display());

        let volume_name = &self.config.display_name;
        let temp_dmg = bundle_path.with_extension("temp.dmg");

        // Create DMG
        let result = Command::new("hdiutil")
            .arg("create")
            .arg("-volname").arg(volume_name)
            .arg("-srcfolder").arg(bundle_path)
            .arg("-ov")
            .arg("-format").arg("UDBZ")
            .arg(&dmg_path)
            .output()?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(AppBundleError::BuildFailed(format!(
                "DMG creation failed: {}",
                stderr
            )));
        }

        let _ = fs::remove_file(&temp_dmg);

        Ok(dmg_path)
    }
}

/// Generates the Info.plist content.
pub fn generate_info_plist(config: &AppBundleConfig) -> String {
    let mut plist = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
"#);

    // Basic info
    add_plist_string(&mut plist, "CFBundleName", &config.display_name);
    add_plist_string(&mut plist, "CFBundleDisplayName", &config.display_name);
    add_plist_string(&mut plist, "CFBundleIdentifier", &config.bundle_identifier);
    add_plist_string(&mut plist, "CFBundleVersion", &config.build);
    add_plist_string(&mut plist, "CFBundleShortVersionString", &config.version);
    add_plist_string(&mut plist, "CFBundleExecutable", &config.app_name);
    add_plist_string(&mut plist, "CFBundlePackageType", "APPL");
    add_plist_string(&mut plist, "CFBundleSignature", "????");
    add_plist_string(&mut plist, "CFBundleIconFile", "AppIcon");

    // Copyright and description
    add_plist_string(&mut plist, "NSHumanReadableCopyright", &config.copyright);
    add_plist_string(&mut plist, "CFBundleGetInfoString", &config.description);

    // Category
    add_plist_string(&mut plist, "LSApplicationCategoryType", config.category.as_category_type());

    // Minimum macOS version
    add_plist_string(&mut plist, "LSMinimumSystemVersion", &config.minimum_macos_version.as_string());

    // Architecture priority
    plist.push_str("\t<key>LSArchitecturePriority</key>\n\t<array>\n");
    for arch in config.architecture.as_array() {
        plist.push_str(&format!("\t\t<string>{}</string>\n", arch));
    }
    plist.push_str("\t</array>\n");

    // High resolution
    if config.high_resolution {
        add_plist_bool(&mut plist, "NSHighResolutionCapable", true);
    }

    // Background only
    if config.background_only {
        add_plist_bool(&mut plist, "LSBackgroundOnly", true);
    }

    // Principal class (for GUI apps)
    add_plist_string(&mut plist, "NSPrincipalClass", "NSApplication");

    // Supports Secure Coding
    add_plist_bool(&mut plist, "NSSupportsAutomaticTermination", true);
    add_plist_bool(&mut plist, "NSSupportsSuddenTermination", false);

    // Document types
    if !config.document_types.is_empty() {
        plist.push_str("\t<key>CFBundleDocumentTypes</key>\n\t<array>\n");
        for doc_type in &config.document_types {
            plist.push_str("\t\t<dict>\n");
            add_plist_string_indented(&mut plist, "CFBundleTypeName", &doc_type.name, 3);
            add_plist_string_indented(&mut plist, "CFBundleTypeRole", doc_type.role.as_str(), 3);

            if !doc_type.extensions.is_empty() {
                add_plist_array(&mut plist, "CFBundleTypeExtensions", &doc_type.extensions, 3);
            }

            if !doc_type.mime_types.is_empty() {
                add_plist_array(&mut plist, "CFBundleTypeMIMETypes", &doc_type.mime_types, 3);
            }

            if let Some(ref uti) = doc_type.uti {
                add_plist_array(&mut plist, "LSItemContentTypes", &[uti.clone()], 3);
            }

            if let Some(ref icon) = doc_type.icon_file {
                add_plist_string_indented(&mut plist, "CFBundleTypeIconFile", icon, 3);
            }

            plist.push_str("\t\t</dict>\n");
        }
        plist.push_str("\t</array>\n");
    }

    // URL schemes
    if !config.url_schemes.is_empty() {
        plist.push_str("\t<key>CFBundleURLTypes</key>\n\t<array>\n");
        plist.push_str("\t\t<dict>\n");
        add_plist_string_indented(&mut plist, "CFBundleURLName", &config.bundle_identifier, 3);
        add_plist_array(&mut plist, "CFBundleURLSchemes", &config.url_schemes, 3);
        plist.push_str("\t\t</dict>\n");
        plist.push_str("\t</array>\n");
    }

    plist.push_str("</dict>\n</plist>\n");

    plist
}

/// Adds a string key-value pair to plist.
fn add_plist_string(plist: &mut String, key: &str, value: &str) {
    plist.push_str(&format!("\t<key>{}</key>\n\t<string>{}</string>\n",
        escape_xml(key), escape_xml(value)));
}

/// Adds a string key-value pair to plist with custom indentation.
fn add_plist_string_indented(plist: &mut String, key: &str, value: &str, indent: usize) {
    let tabs: String = "\t".repeat(indent);
    plist.push_str(&format!("{}<key>{}</key>\n{}<string>{}</string>\n",
        tabs, escape_xml(key), tabs, escape_xml(value)));
}

/// Adds a boolean key-value pair to plist.
fn add_plist_bool(plist: &mut String, key: &str, value: bool) {
    let bool_str = if value { "<true/>" } else { "<false/>" };
    plist.push_str(&format!("\t<key>{}</key>\n\t{}\n", escape_xml(key), bool_str));
}

/// Adds an array of strings to plist.
fn add_plist_array(plist: &mut String, key: &str, values: &[String], indent: usize) {
    let tabs: String = "\t".repeat(indent);
    plist.push_str(&format!("{}<key>{}</key>\n{}<array>\n", tabs, escape_xml(key), tabs));
    for value in values {
        plist.push_str(&format!("{}\t<string>{}</string>\n", tabs, escape_xml(value)));
    }
    plist.push_str(&format!("{}</array>\n", tabs));
}

/// Escapes XML special characters.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Calculates the total size of a directory.
fn calculate_directory_size(path: &Path) -> io::Result<u64> {
    let mut total = 0;

    if path.is_file() {
        return Ok(fs::metadata(path)?.len());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            total += calculate_directory_size(&path)?;
        } else {
            total += fs::metadata(&path)?.len();
        }
    }

    Ok(total)
}

/// Generates an ICNS icon file.
///
/// The ICNS format contains multiple icon sizes for different display contexts.
/// This generates a minimal ICNS with the essential sizes.
pub fn generate_icns_icon() -> Result<Vec<u8>> {
    // ICNS file structure:
    // - Header: 'icns' (4 bytes) + file size (4 bytes)
    // - Icon entries: type (4 bytes) + size (4 bytes) + data
    //
    // Common icon types:
    // - ic07: 128x128 PNG (10.7+)
    // - ic08: 256x256 PNG (10.5+)
    // - ic09: 512x512 PNG (10.5+)
    // - ic10: 1024x1024 PNG (10.7+ for retina)
    // - ic11: 16x16@2x (32x32) PNG (10.8+)
    // - ic12: 32x32@2x (64x64) PNG (10.8+)
    // - ic13: 128x128@2x (256x256) PNG (10.8+)
    // - ic14: 256x256@2x (512x512) PNG (10.8+)

    let mut icns_data = Vec::new();

    // We'll generate icons at different sizes
    let icon_entries = vec![
        (b"ic07", 128),  // 128x128
        (b"ic08", 256),  // 256x256
        (b"ic09", 512),  // 512x512
    ];

    let mut entries_data = Vec::new();

    for (icon_type, size) in icon_entries {
        let png_data = generate_icon_png(size)?;

        // Entry: type (4) + size (4) + data
        let entry_size = 8 + png_data.len() as u32;

        entries_data.extend_from_slice(icon_type);
        entries_data.extend_from_slice(&entry_size.to_be_bytes());
        entries_data.extend_from_slice(&png_data);
    }

    // ICNS header
    let total_size = 8 + entries_data.len() as u32;
    icns_data.extend_from_slice(b"icns");
    icns_data.extend_from_slice(&total_size.to_be_bytes());
    icns_data.extend_from_slice(&entries_data);

    Ok(icns_data)
}

/// Generates a PNG icon at the specified size.
fn generate_icon_png(size: u32) -> Result<Vec<u8>> {
    // Generate RGBA pixel data
    let rgba = generate_icon_rgba(size);

    // Encode as PNG
    let png_data = encode_png(&rgba, size, size)
        .map_err(|e| AppBundleError::IconError(e))?;

    Ok(png_data)
}

/// Generates RGBA pixel data for the icon.
///
/// Creates a vault/lock icon design similar to the AppImage version.
fn generate_icon_rgba(size: u32) -> Vec<u8> {
    let size = size as usize;
    let mut pixels = vec![0u8; size * size * 4];

    let center_x = size as f32 / 2.0;
    let center_y = size as f32 / 2.0;
    let radius = size as f32 * 0.4;

    // Background color (dark blue/purple gradient)
    let bg_color: [u8; 4] = [45, 55, 72, 255]; // #2D3748
    let accent_color: [u8; 4] = [99, 102, 241, 255]; // #6366F1 (indigo)
    let highlight_color: [u8; 4] = [167, 139, 250, 255]; // #A78BFA (purple)

    for y in 0..size {
        for x in 0..size {
            let idx = (y * size + x) * 4;
            let fx = x as f32;
            let fy = y as f32;

            // Distance from center
            let dx = fx - center_x;
            let dy = fy - center_y;
            let dist = (dx * dx + dy * dy).sqrt();

            // Circular background
            if dist <= radius * 1.1 {
                // Gradient based on distance
                let t = dist / (radius * 1.1);
                let t = t.clamp(0.0, 1.0);

                // Inner circle
                if dist <= radius {
                    // Draw vault door pattern
                    let inner_radius = radius * 0.7;

                    if dist <= inner_radius {
                        // Inner vault area
                        let shade = ((1.0 - t * 0.3) * 255.0) as u8;
                        pixels[idx] = ((bg_color[0] as f32 * 0.8) as u8).min(shade);
                        pixels[idx + 1] = ((bg_color[1] as f32 * 0.8) as u8).min(shade);
                        pixels[idx + 2] = ((bg_color[2] as f32 * 0.8) as u8).min(shade);
                        pixels[idx + 3] = 255;

                        // Lock keyhole
                        let keyhole_size = radius * 0.25;
                        let keyhole_y = center_y - radius * 0.1;

                        // Circle part of keyhole
                        let keyhole_dist = ((fx - center_x).powi(2) + (fy - keyhole_y).powi(2)).sqrt();
                        if keyhole_dist <= keyhole_size * 0.4 {
                            pixels[idx] = accent_color[0];
                            pixels[idx + 1] = accent_color[1];
                            pixels[idx + 2] = accent_color[2];
                            pixels[idx + 3] = 255;
                        }

                        // Rectangle part of keyhole
                        let rect_half_w = keyhole_size * 0.2;
                        let rect_top = keyhole_y;
                        let rect_bottom = keyhole_y + keyhole_size * 0.6;

                        if fx >= center_x - rect_half_w
                            && fx <= center_x + rect_half_w
                            && fy >= rect_top
                            && fy <= rect_bottom
                        {
                            pixels[idx] = accent_color[0];
                            pixels[idx + 1] = accent_color[1];
                            pixels[idx + 2] = accent_color[2];
                            pixels[idx + 3] = 255;
                        }
                    } else {
                        // Outer ring
                        pixels[idx] = accent_color[0];
                        pixels[idx + 1] = accent_color[1];
                        pixels[idx + 2] = accent_color[2];
                        pixels[idx + 3] = 255;
                    }
                } else {
                    // Outer glow
                    let alpha = ((1.0 - (dist - radius) / (radius * 0.1)) * 128.0) as u8;
                    pixels[idx] = highlight_color[0];
                    pixels[idx + 1] = highlight_color[1];
                    pixels[idx + 2] = highlight_color[2];
                    pixels[idx + 3] = alpha;
                }
            }
        }
    }

    pixels
}

/// Encodes RGBA pixels as PNG.
///
/// Minimal PNG encoder without external dependencies.
fn encode_png(rgba: &[u8], width: u32, height: u32) -> std::result::Result<Vec<u8>, String> {
    let mut png = Vec::new();

    // PNG signature
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR chunk
    let mut ihdr_data = Vec::new();
    ihdr_data.extend_from_slice(&width.to_be_bytes());
    ihdr_data.extend_from_slice(&height.to_be_bytes());
    ihdr_data.push(8); // Bit depth
    ihdr_data.push(6); // Color type (RGBA)
    ihdr_data.push(0); // Compression
    ihdr_data.push(0); // Filter
    ihdr_data.push(0); // Interlace

    write_chunk(&mut png, b"IHDR", &ihdr_data);

    // IDAT chunk (image data)
    // Prepare raw data with filter bytes
    let mut raw_data = Vec::new();
    let row_bytes = width as usize * 4;
    for y in 0..height as usize {
        raw_data.push(0); // No filter
        let start = y * row_bytes;
        let end = start + row_bytes;
        raw_data.extend_from_slice(&rgba[start..end]);
    }

    // Compress with zlib
    let compressed = deflate_compress(&raw_data);
    write_chunk(&mut png, b"IDAT", &compressed);

    // IEND chunk
    write_chunk(&mut png, b"IEND", &[]);

    Ok(png)
}

/// Writes a PNG chunk.
fn write_chunk(png: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let length = data.len() as u32;
    png.extend_from_slice(&length.to_be_bytes());
    png.extend_from_slice(chunk_type);
    png.extend_from_slice(data);

    // CRC32 of type + data
    let mut crc_data = Vec::new();
    crc_data.extend_from_slice(chunk_type);
    crc_data.extend_from_slice(data);
    let crc = crc32(&crc_data);
    png.extend_from_slice(&crc.to_be_bytes());
}

/// Minimal zlib/deflate compression (store mode).
fn deflate_compress(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // Zlib header
    result.push(0x78); // CMF (compression method = deflate, window = 32K)
    result.push(0x01); // FLG (no dict, fastest compression)

    // Deflate blocks
    const BLOCK_SIZE: usize = 65535;
    let mut offset = 0;

    while offset < data.len() {
        let remaining = data.len() - offset;
        let block_len = remaining.min(BLOCK_SIZE);
        let is_final = offset + block_len >= data.len();

        // Block header
        result.push(if is_final { 0x01 } else { 0x00 }); // BFINAL + BTYPE=00 (stored)

        let len = block_len as u16;
        let nlen = !len;
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&nlen.to_le_bytes());

        // Block data
        result.extend_from_slice(&data[offset..offset + block_len]);
        offset += block_len;
    }

    // Adler32 checksum
    let checksum = adler32(data);
    result.extend_from_slice(&checksum.to_be_bytes());

    result
}

/// Computes CRC32 checksum.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;

    for &byte in data {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }

    !crc
}

/// Computes Adler32 checksum.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }

    (b << 16) | a
}

/// CRC32 lookup table.
const CRC32_TABLE: [u32; 256] = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7a47, 0x4d6a7683, 0x3a6b3671,
    0xa3621fe7, 0xd4652be9, 0x4e6f3680, 0x394067af, 0xa0d909e7, 0xd7dea28f,
    0x4a64b9e7, 0x3d63c97f, 0xa46ad3cb, 0xd36dc55d, 0x4464a5fe, 0x33631668,
    0xac6a09d2, 0xdb6d3944, 0x4b6e7bf5, 0x3c697bf3, 0xa5601249, 0xd2672adf,
    0x4dc52d7c, 0x3ac23cea, 0xa3c0c450, 0xd4c7f4c6, 0x43621057, 0x347120c1,
    0xad78507b, 0xda7f50ed, 0x446d194e, 0x336a19d8, 0xaa632462, 0xdd6434f4,
    0x4a69254d, 0x3d6f35db, 0xa4660661, 0xd3613af7, 0x4e6e4954, 0x396e49c2,
    0xa0678a78, 0xd7608aee, 0x49042b5f, 0x3e03cbc9, 0xa70c9a73, 0xd00b8ae5,
    0x4f050f46, 0x380232d0, 0xa10b536a, 0xd60ca3fc, 0x40105e6d, 0x37174efb,
    0xae1e7e41, 0xd91936d7, 0x4e1c9674, 0x391186e2, 0xa01ce958, 0xd71bf9ce,
    0x4b6ffc5f, 0x3c68fcc9, 0xa5610a73, 0xd2660ae5, 0x4c221346, 0x3b2563d0,
    0xa22c746a, 0xd52b74fc, 0x4c26856d, 0x3b21b5fb, 0xa228a441, 0xd52f94d7,
    0x4b6b9774, 0x3c6ca7e2, 0xa565f658, 0xd262c6ce, 0x4c07675f, 0x3b0057c9,
    0xa2090673, 0xd50e36e5, 0x4d02d646, 0x3a05e6d0, 0xa30cf76a, 0xd40bc7fc,
    0x4e04f86d, 0x3903c8fb, 0xa00ad941, 0xd70de9d7, 0x4b09e874, 0x3c0ed8e2,
    0xa507c958, 0xd200f9ce, 0x4a0df85f, 0x3d0ac8c9, 0xa403d973, 0xd304e9e5,
    0x4c0ff846, 0x3b08c8d0, 0xa201d96a, 0xd506e9fc, 0x440bf86d, 0x330cc8fb,
    0xaa05d941, 0xdd02e9d7, 0x4f06f874, 0x3801c8e2, 0xa108d958, 0xd60fe9ce,
    0x480bf85f, 0x3f0cc8c9, 0xa605d973, 0xd102e9e5, 0x470ff846, 0x3008c8d0,
    0xa901d96a, 0xde06e9fc, 0x400bf86d, 0x370cc8fb, 0xae05d941, 0xd902e9d7,
    0x4706f874, 0x3001c8e2, 0xa908d958, 0xde0fe9ce, 0x420bf85f, 0x350cc8c9,
    0xac05d973, 0xdb02e9e5, 0x450ff846, 0x3208c8d0, 0xab01d96a, 0xdc06e9fc,
    0x460bf86d, 0x310cc8fb, 0xa805d941, 0xdf02e9d7, 0x4106f874, 0x3601c8e2,
    0xaf08d958, 0xd80fe9ce, 0x440bf85f, 0x330cc8c9, 0xaa05d973, 0xdd02e9e5,
    0x430ff846, 0x3408c8d0, 0xad01d96a, 0xda06e9fc,
];

/// Checks if macOS app bundle creation is supported on this platform.
#[must_use]
pub fn is_macos_supported() -> bool {
    cfg!(target_os = "macos")
}

/// Returns instructions for code signing setup.
#[must_use]
pub fn get_code_signing_instructions() -> String {
    r#"macOS Code Signing Setup:

1. Apple Developer Account:
   - Enroll at https://developer.apple.com
   - Annual fee: $99/year

2. Create Certificates:
   - Open Keychain Access
   - Keychain Access > Certificate Assistant > Request a Certificate from a Certificate Authority
   - Save to disk
   - Upload at https://developer.apple.com/account/resources/certificates
   - Download and install the certificate

3. Create Developer ID Application certificate:
   - Select "Developer ID Application" certificate type
   - This is required for distribution outside the App Store

4. Find your signing identity:
   security find-identity -v -p codesigning

5. Use with AppBundleConfig:
   let config = AppBundleConfig::default()
       .with_code_signing(CodeSigningConfig::with_identity(
           "Developer ID Application: Your Name (TEAM_ID)"
       ));
"#.to_string()
}

/// Returns instructions for notarization setup.
#[must_use]
pub fn get_notarization_instructions() -> String {
    r#"macOS Notarization Setup:

1. Prerequisites:
   - Apple Developer Account
   - Developer ID Application certificate installed
   - Xcode Command Line Tools: xcode-select --install

2. Create App-Specific Password:
   - Go to https://appleid.apple.com
   - Sign in > Security > App-Specific Passwords
   - Generate a password for "notarytool"
   - Store in keychain:
     xcrun notarytool store-credentials "AC_PASSWORD" \
       --apple-id "your@email.com" \
       --team-id "TEAMID1234" \
       --password "xxxx-xxxx-xxxx-xxxx"

3. Find your Team ID:
   - Go to https://developer.apple.com/account
   - Membership > Team ID (10 characters)

4. Use with AppBundleConfig:
   let config = AppBundleConfig::default()
       .with_code_signing(CodeSigningConfig::with_identity("Developer ID Application: ..."))
       .with_notarization(NotarizationConfig {
           apple_id: Some("your@email.com".into()),
           team_id: Some("TEAMID1234".into()),
           password: Some("@keychain:AC_PASSWORD".into()),
           ..Default::default()
       });
"#.to_string()
}

/// Generates a build script for macOS app bundles.
pub fn generate_build_script(config: &AppBundleConfig) -> String {
    let mut script = String::from("#!/bin/bash\n");
    script.push_str("# TESSERACT macOS App Bundle Build Script\n");
    script.push_str("# Generated by tesseract-packaging\n\n");

    script.push_str("set -e\n\n");

    script.push_str("# Configuration\n");
    script.push_str(&format!("APP_NAME=\"{}\"\n", config.app_name));
    script.push_str(&format!("DISPLAY_NAME=\"{}\"\n", config.display_name));
    script.push_str(&format!("VERSION=\"{}\"\n", config.version));
    script.push_str(&format!("BUNDLE_ID=\"{}\"\n", config.bundle_identifier));
    script.push_str("BUILD_DIR=\"target/release\"\n");
    script.push_str("DIST_DIR=\"dist\"\n\n");

    script.push_str("# Build release binary\n");
    script.push_str("echo \"Building release binary...\"\n");

    match config.architecture {
        Architecture::Arm64 => {
            script.push_str("cargo build --release --target aarch64-apple-darwin\n");
            script.push_str("BINARY=\"target/aarch64-apple-darwin/release/$APP_NAME\"\n");
        }
        Architecture::X86_64 => {
            script.push_str("cargo build --release --target x86_64-apple-darwin\n");
            script.push_str("BINARY=\"target/x86_64-apple-darwin/release/$APP_NAME\"\n");
        }
        Architecture::Universal => {
            script.push_str("cargo build --release --target aarch64-apple-darwin\n");
            script.push_str("cargo build --release --target x86_64-apple-darwin\n");
            script.push_str("echo \"Creating universal binary...\"\n");
            script.push_str("lipo -create \\\n");
            script.push_str("  \"target/aarch64-apple-darwin/release/$APP_NAME\" \\\n");
            script.push_str("  \"target/x86_64-apple-darwin/release/$APP_NAME\" \\\n");
            script.push_str("  -output \"$BUILD_DIR/$APP_NAME-universal\"\n");
            script.push_str("BINARY=\"$BUILD_DIR/$APP_NAME-universal\"\n");
        }
    }
    script.push('\n');

    script.push_str("# Create app bundle structure\n");
    script.push_str("BUNDLE=\"$DIST_DIR/$DISPLAY_NAME.app\"\n");
    script.push_str("rm -rf \"$BUNDLE\"\n");
    script.push_str("mkdir -p \"$BUNDLE/Contents/MacOS\"\n");
    script.push_str("mkdir -p \"$BUNDLE/Contents/Resources\"\n");
    script.push_str("mkdir -p \"$BUNDLE/Contents/Frameworks\"\n\n");

    script.push_str("# Copy binary\n");
    if config.strip_binary {
        script.push_str("echo \"Copying and stripping binary...\"\n");
        script.push_str("cp \"$BINARY\" \"$BUNDLE/Contents/MacOS/$APP_NAME\"\n");
        script.push_str("strip -x \"$BUNDLE/Contents/MacOS/$APP_NAME\" 2>/dev/null || true\n");
    } else {
        script.push_str("echo \"Copying binary...\"\n");
        script.push_str("cp \"$BINARY\" \"$BUNDLE/Contents/MacOS/$APP_NAME\"\n");
    }
    script.push_str("chmod +x \"$BUNDLE/Contents/MacOS/$APP_NAME\"\n\n");

    script.push_str("# Generate Info.plist (inline)\n");
    script.push_str("cat > \"$BUNDLE/Contents/Info.plist\" << 'EOF'\n");
    script.push_str(&generate_info_plist(config));
    script.push_str("EOF\n\n");

    script.push_str("# Generate PkgInfo\n");
    script.push_str("echo -n 'APPL????' > \"$BUNDLE/Contents/PkgInfo\"\n\n");

    script.push_str("# Generate icon (placeholder - use iconutil for real icons)\n");
    script.push_str("echo \"Generating icon...\"\n");
    script.push_str("# For production, use:\n");
    script.push_str("# iconutil -c icns AppIcon.iconset -o \"$BUNDLE/Contents/Resources/AppIcon.icns\"\n\n");

    if config.code_signing.is_enabled() {
        script.push_str("# Code signing\n");
        script.push_str("echo \"Code signing...\"\n");
        if let Some(ref identity) = config.code_signing.identity {
            script.push_str(&format!(
                "codesign --sign \"{}\" --deep --force",
                identity
            ));
            if config.code_signing.hardened_runtime {
                script.push_str(" --options runtime");
            }
            if config.code_signing.timestamp {
                script.push_str(" --timestamp");
            }
            script.push_str(" \"$BUNDLE\"\n\n");
        }
    }

    if config.notarization.is_enabled() {
        script.push_str("# Notarization\n");
        script.push_str("echo \"Submitting for notarization...\"\n");
        script.push_str("ditto -c -k --keepParent \"$BUNDLE\" \"$BUNDLE.zip\"\n");
        script.push_str(&format!(
            "xcrun notarytool submit \"$BUNDLE.zip\" --apple-id \"{}\" --team-id \"{}\" --password \"{}\" --wait\n",
            config.notarization.apple_id.as_deref().unwrap_or(""),
            config.notarization.team_id.as_deref().unwrap_or(""),
            config.notarization.password.as_deref().unwrap_or("")
        ));
        script.push_str("xcrun stapler staple \"$BUNDLE\"\n");
        script.push_str("rm \"$BUNDLE.zip\"\n\n");
    }

    if config.create_dmg {
        script.push_str("# Create DMG\n");
        script.push_str("echo \"Creating DMG...\"\n");
        script.push_str("hdiutil create -volname \"$DISPLAY_NAME\" -srcfolder \"$BUNDLE\" -ov -format UDBZ \"$DIST_DIR/$DISPLAY_NAME.dmg\"\n\n");
    }

    script.push_str("echo \"Build complete: $BUNDLE\"\n");
    script.push_str("ls -la \"$BUNDLE\"\n");

    script
}

/// Writes the build script to a file.
pub fn write_build_script(path: impl AsRef<Path>, config: &AppBundleConfig) -> Result<()> {
    let script = generate_build_script(config);
    let path = path.as_ref();

    let mut file = File::create(path)?;
    file.write_all(script.as_bytes())?;

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
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- MacOSVersion tests ---

    #[test]
    fn test_macos_version_new() {
        let version = MacOSVersion::new(13, 2, 1);
        assert_eq!(version.major, 13);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 1);
    }

    #[test]
    fn test_macos_version_constants() {
        assert_eq!(MacOSVersion::MONTEREY.major, 12);
        assert_eq!(MacOSVersion::VENTURA.major, 13);
        assert_eq!(MacOSVersion::SONOMA.major, 14);
    }

    #[test]
    fn test_macos_version_as_string() {
        assert_eq!(MacOSVersion::MONTEREY.as_string(), "12.0.0");
        assert_eq!(MacOSVersion::new(13, 4, 1).as_string(), "13.4.1");
    }

    #[test]
    fn test_macos_version_as_short_string() {
        assert_eq!(MacOSVersion::MONTEREY.as_short_string(), "12.0");
        assert_eq!(MacOSVersion::new(13, 4, 1).as_short_string(), "13.4");
    }

    #[test]
    fn test_macos_version_default() {
        let version = MacOSVersion::default();
        assert_eq!(version.major, 12);
    }

    // --- AppCategory tests ---

    #[test]
    fn test_app_category_as_category_type() {
        assert_eq!(AppCategory::Security.as_category_type(), "public.app-category.security");
        assert_eq!(AppCategory::Utilities.as_category_type(), "public.app-category.utilities");
        assert_eq!(AppCategory::DeveloperTools.as_category_type(), "public.app-category.developer-tools");
    }

    #[test]
    fn test_app_category_as_str() {
        assert_eq!(AppCategory::Security.as_str(), "Security");
        assert_eq!(AppCategory::Business.as_str(), "Business");
    }

    #[test]
    fn test_app_category_default() {
        assert_eq!(AppCategory::default(), AppCategory::Security);
    }

    // --- Architecture tests ---

    #[test]
    fn test_architecture_as_str() {
        assert_eq!(Architecture::Arm64.as_str(), "arm64");
        assert_eq!(Architecture::X86_64.as_str(), "x86_64");
        assert_eq!(Architecture::Universal.as_str(), "universal");
    }

    #[test]
    fn test_architecture_as_array() {
        assert_eq!(Architecture::Arm64.as_array(), vec!["arm64"]);
        assert_eq!(Architecture::X86_64.as_array(), vec!["x86_64"]);
        assert_eq!(Architecture::Universal.as_array(), vec!["arm64", "x86_64"]);
    }

    #[test]
    fn test_architecture_default() {
        assert_eq!(Architecture::default(), Architecture::Arm64);
    }

    // --- DocumentRole tests ---

    #[test]
    fn test_document_role_as_str() {
        assert_eq!(DocumentRole::Editor.as_str(), "Editor");
        assert_eq!(DocumentRole::Viewer.as_str(), "Viewer");
        assert_eq!(DocumentRole::Shell.as_str(), "Shell");
        assert_eq!(DocumentRole::None.as_str(), "None");
    }

    #[test]
    fn test_document_role_default() {
        assert_eq!(DocumentRole::default(), DocumentRole::Editor);
    }

    // --- Bundle identifier validation tests ---

    #[test]
    fn test_valid_bundle_identifier() {
        assert!(is_valid_bundle_identifier("com.example.app"));
        assert!(is_valid_bundle_identifier("io.tesseract.encryption"));
        assert!(is_valid_bundle_identifier("org.my-app.test"));
        assert!(is_valid_bundle_identifier("com.app_name.v1"));
    }

    #[test]
    fn test_invalid_bundle_identifier() {
        assert!(!is_valid_bundle_identifier(""));
        assert!(!is_valid_bundle_identifier("app")); // Only one part
        assert!(!is_valid_bundle_identifier("com..app")); // Empty part
        assert!(!is_valid_bundle_identifier("123.app.name")); // Starts with number
        assert!(!is_valid_bundle_identifier("com.app name.test")); // Contains space
    }

    // --- CodeSigningConfig tests ---

    #[test]
    fn test_code_signing_config_default() {
        let config = CodeSigningConfig::default();
        assert!(config.identity.is_none());
        assert!(config.hardened_runtime);
        assert!(config.deep);
        assert!(config.timestamp);
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_code_signing_config_with_identity() {
        let config = CodeSigningConfig::with_identity("Developer ID Application: Test");
        assert!(config.is_enabled());
        assert_eq!(config.identity.as_deref(), Some("Developer ID Application: Test"));
    }

    // --- NotarizationConfig tests ---

    #[test]
    fn test_notarization_config_default() {
        let config = NotarizationConfig::default();
        assert!(config.apple_id.is_none());
        assert!(config.team_id.is_none());
        assert!(!config.is_enabled());
        assert_eq!(config.timeout_seconds, 3600);
    }

    #[test]
    fn test_notarization_config_validate_team_id() {
        let mut config = NotarizationConfig::default();
        config.team_id = Some("12345".to_string()); // Too short
        config.apple_id = Some("test@example.com".to_string());
        config.password = Some("pass".to_string());

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_notarization_config_valid() {
        let mut config = NotarizationConfig::default();
        config.team_id = Some("ABCD123456".to_string());
        config.apple_id = Some("test@example.com".to_string());
        config.password = Some("pass".to_string());

        assert!(config.is_enabled());
        assert!(config.validate().is_ok());
    }

    // --- AppBundleConfig tests ---

    #[test]
    fn test_app_bundle_config_default() {
        let config = AppBundleConfig::default();
        assert_eq!(config.app_name, "tesseract");
        assert_eq!(config.display_name, "TESSERACT");
        assert_eq!(config.bundle_identifier, "io.tesseract.encryption");
        assert_eq!(config.category, AppCategory::Security);
        assert!(config.high_resolution);
        assert!(!config.document_types.is_empty());
    }

    #[test]
    fn test_app_bundle_config_builder() {
        let config = AppBundleConfig::new("com.test.app")
            .with_app_name("myapp")
            .with_display_name("My App")
            .with_version("2.0.0")
            .with_build("42")
            .with_minimum_version(MacOSVersion::VENTURA)
            .with_architecture(Architecture::Universal);

        assert_eq!(config.bundle_identifier, "com.test.app");
        assert_eq!(config.app_name, "myapp");
        assert_eq!(config.display_name, "My App");
        assert_eq!(config.version, "2.0.0");
        assert_eq!(config.build, "42");
        assert_eq!(config.minimum_macos_version.major, 13);
        assert_eq!(config.architecture, Architecture::Universal);
    }

    #[test]
    fn test_app_bundle_config_validate() {
        let config = AppBundleConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_app_bundle_config_validate_invalid_identifier() {
        let mut config = AppBundleConfig::default();
        config.bundle_identifier = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_app_bundle_config_validate_empty_version() {
        let mut config = AppBundleConfig::default();
        config.version = String::new();
        assert!(config.validate().is_err());
    }

    // --- AppBundleBuilder tests ---

    #[test]
    fn test_app_bundle_builder_new() {
        let config = AppBundleConfig::default();
        let builder = AppBundleBuilder::new(config);
        assert!(builder.work_dir.is_none());
    }

    #[test]
    fn test_app_bundle_builder_with_work_dir() {
        let builder = AppBundleBuilder::default_config()
            .with_work_dir("/tmp/build");
        assert_eq!(builder.work_dir, Some(PathBuf::from("/tmp/build")));
    }

    #[test]
    fn test_app_bundle_builder_binary_not_found() {
        let builder = AppBundleBuilder::default_config();
        let result = builder.build("/nonexistent/binary", "/tmp/out.app");
        assert!(matches!(result, Err(AppBundleError::BinaryNotFound(_))));
    }

    // --- Info.plist generation tests ---

    #[test]
    fn test_info_plist_generation() {
        let config = AppBundleConfig::default();
        let plist = generate_info_plist(&config);

        assert!(plist.contains("<?xml version=\"1.0\""));
        assert!(plist.contains("<key>CFBundleName</key>"));
        assert!(plist.contains("<string>TESSERACT</string>"));
        assert!(plist.contains("<key>CFBundleIdentifier</key>"));
        assert!(plist.contains("<string>io.tesseract.encryption</string>"));
        assert!(plist.contains("CFBundleVersion"));
        assert!(plist.contains("LSMinimumSystemVersion"));
        assert!(plist.contains("12.0.0"));
    }

    #[test]
    fn test_info_plist_has_document_types() {
        let config = AppBundleConfig::default();
        let plist = generate_info_plist(&config);

        assert!(plist.contains("CFBundleDocumentTypes"));
        assert!(plist.contains("TESSERACT Vault"));
        assert!(plist.contains("vault"));
    }

    #[test]
    fn test_info_plist_has_url_schemes() {
        let config = AppBundleConfig::default();
        let plist = generate_info_plist(&config);

        assert!(plist.contains("CFBundleURLTypes"));
        assert!(plist.contains("tesseract"));
    }

    #[test]
    fn test_info_plist_architecture_priority() {
        let config = AppBundleConfig::default()
            .with_architecture(Architecture::Universal);
        let plist = generate_info_plist(&config);

        assert!(plist.contains("LSArchitecturePriority"));
        assert!(plist.contains("arm64"));
        assert!(plist.contains("x86_64"));
    }

    // --- XML escaping tests ---

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("Hello & World"), "Hello &amp; World");
        assert_eq!(escape_xml("<tag>"), "&lt;tag&gt;");
        assert_eq!(escape_xml("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_xml("it's"), "it&apos;s");
    }

    // --- Icon generation tests ---

    #[test]
    fn test_generate_icon_rgba() {
        let rgba = generate_icon_rgba(64);
        assert_eq!(rgba.len(), 64 * 64 * 4);
    }

    #[test]
    fn test_generate_icon_png() {
        let result = generate_icon_png(128);
        assert!(result.is_ok());

        let png = result.unwrap();
        // Check PNG signature
        assert_eq!(&png[0..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    #[test]
    fn test_generate_icns_icon() {
        let result = generate_icns_icon();
        assert!(result.is_ok());

        let icns = result.unwrap();
        // Check ICNS signature
        assert_eq!(&icns[0..4], b"icns");
    }

    // --- CRC32 tests ---

    #[test]
    fn test_crc32() {
        // Known test vector
        let crc = crc32(b"123456789");
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_crc32_empty() {
        let crc = crc32(b"");
        assert_eq!(crc, 0x00000000);
    }

    // --- Adler32 tests ---

    #[test]
    fn test_adler32() {
        // Known test vector
        let checksum = adler32(b"Wikipedia");
        assert_eq!(checksum, 0x11E60398);
    }

    #[test]
    fn test_adler32_empty() {
        let checksum = adler32(b"");
        assert_eq!(checksum, 1);
    }

    // --- Build script generation tests ---

    #[test]
    fn test_generate_build_script() {
        let config = AppBundleConfig::default();
        let script = generate_build_script(&config);

        assert!(script.starts_with("#!/bin/bash\n"));
        assert!(script.contains("cargo build --release"));
        assert!(script.contains("APP_NAME=\"tesseract\""));
        assert!(script.contains("mkdir -p"));
        assert!(script.contains("Info.plist"));
    }

    #[test]
    fn test_generate_build_script_universal() {
        let config = AppBundleConfig::default()
            .with_architecture(Architecture::Universal);
        let script = generate_build_script(&config);

        assert!(script.contains("aarch64-apple-darwin"));
        assert!(script.contains("x86_64-apple-darwin"));
        assert!(script.contains("lipo -create"));
    }

    #[test]
    fn test_generate_build_script_with_codesign() {
        let config = AppBundleConfig::default()
            .with_code_signing(CodeSigningConfig::with_identity("Developer ID"));
        let script = generate_build_script(&config);

        assert!(script.contains("codesign"));
        assert!(script.contains("Developer ID"));
    }

    #[test]
    fn test_generate_build_script_with_dmg() {
        let mut config = AppBundleConfig::default();
        config.create_dmg = true;
        let script = generate_build_script(&config);

        assert!(script.contains("hdiutil create"));
        assert!(script.contains(".dmg"));
    }

    // --- Support function tests ---

    #[test]
    fn test_is_macos_supported() {
        // This will return true on macOS, false elsewhere
        let supported = is_macos_supported();
        #[cfg(target_os = "macos")]
        assert!(supported);
        #[cfg(not(target_os = "macos"))]
        assert!(!supported);
    }

    #[test]
    fn test_get_code_signing_instructions() {
        let instructions = get_code_signing_instructions();
        assert!(instructions.contains("Apple Developer Account"));
        assert!(instructions.contains("codesigning"));
        assert!(instructions.contains("Developer ID"));
    }

    #[test]
    fn test_get_notarization_instructions() {
        let instructions = get_notarization_instructions();
        assert!(instructions.contains("notarytool"));
        assert!(instructions.contains("App-Specific Password"));
        assert!(instructions.contains("Team ID"));
    }

    // --- BuildResult tests ---

    #[test]
    fn test_build_result() {
        let result = BuildResult {
            bundle_path: PathBuf::from("/tmp/Test.app"),
            size_bytes: 10_485_760, // 10 MB
            size_mb: 10.0,
            stripped: true,
            code_signed: false,
            notarized: false,
            dmg_path: None,
        };

        assert_eq!(result.bundle_path, PathBuf::from("/tmp/Test.app"));
        assert!(result.stripped);
        assert!(!result.code_signed);
    }

    // --- Directory size calculation tests ---

    #[test]
    fn test_calculate_directory_size_empty() {
        let temp_dir = tempfile::tempdir().unwrap();
        let size = calculate_directory_size(temp_dir.path()).unwrap();
        assert_eq!(size, 0);
    }

    #[test]
    fn test_calculate_directory_size_with_files() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a file with known content
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Hello, World!").unwrap(); // 13 bytes

        let size = calculate_directory_size(temp_dir.path()).unwrap();
        assert_eq!(size, 13);
    }

    #[test]
    fn test_calculate_directory_size_nested() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create nested structure
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();

        fs::write(temp_dir.path().join("a.txt"), "12345").unwrap(); // 5 bytes
        fs::write(sub_dir.join("b.txt"), "67890").unwrap(); // 5 bytes

        let size = calculate_directory_size(temp_dir.path()).unwrap();
        assert_eq!(size, 10);
    }
}
