//! TESSERACT Packaging Utilities
//!
//! Provides tools for USB preparation, platform-specific packaging, and multi-platform bundling.
//!
//! # Modules
//!
//! - [`usb`] - USB drive preparation and validation
//! - [`bundle`] - Multi-platform executable bundling
//! - [`detection`] - Removable media detection (Windows/Linux/macOS)
//! - [`appimage`] - Linux AppImage packaging
//! - [`macos`] - macOS App Bundle packaging

#![warn(missing_docs)]
#![warn(clippy::all)]

/// USB drive preparation.
pub mod usb;

/// Multi-platform executable bundling.
pub mod bundle;

/// Removable media detection.
pub mod detection;

/// Linux AppImage packaging.
#[cfg(target_os = "linux")]
pub mod appimage;

/// Linux AppImage packaging (stub for non-Linux platforms).
#[cfg(not(target_os = "linux"))]
pub mod appimage {
    //! Linux AppImage packaging (stub for non-Linux platforms).
    //!
    //! This module is only fully implemented on Linux.
    //! On other platforms, it provides stub types for API compatibility.

    use std::path::PathBuf;
    use thiserror::Error;

    /// Errors that can occur during AppImage creation.
    #[derive(Debug, Error)]
    pub enum AppImageError {
        /// Platform not supported.
        #[error("AppImage packaging is only supported on Linux")]
        UnsupportedPlatform,
    }

    /// Result type for AppImage operations.
    pub type Result<T> = std::result::Result<T, AppImageError>;

    /// Checks if AppImage tools are installed.
    #[must_use]
    pub fn is_appimage_supported() -> bool {
        false
    }

    /// Returns instructions for installing AppImage tools.
    #[must_use]
    pub fn get_install_instructions() -> String {
        "AppImage packaging is only supported on Linux.".to_string()
    }
}

/// macOS App Bundle packaging.
#[cfg(target_os = "macos")]
pub mod macos;

/// macOS App Bundle packaging (stub for non-macOS platforms).
#[cfg(not(target_os = "macos"))]
pub mod macos {
    //! macOS App Bundle packaging (stub for non-macOS platforms).
    //!
    //! This module is only fully implemented on macOS.
    //! On other platforms, it provides stub types for API compatibility.

    use std::path::PathBuf;
    use thiserror::Error;

    /// Errors that can occur during app bundle creation.
    #[derive(Debug, Error)]
    pub enum AppBundleError {
        /// Platform not supported.
        #[error("macOS app bundle creation is only supported on macOS")]
        UnsupportedPlatform,
    }

    /// Result type for app bundle operations.
    pub type Result<T> = std::result::Result<T, AppBundleError>;

    /// Checks if macOS app bundle creation is supported.
    #[must_use]
    pub fn is_macos_supported() -> bool {
        false
    }

    /// Returns instructions for code signing setup.
    #[must_use]
    pub fn get_code_signing_instructions() -> String {
        "macOS app bundle creation is only supported on macOS.".to_string()
    }

    /// Returns instructions for notarization setup.
    #[must_use]
    pub fn get_notarization_instructions() -> String {
        "macOS app bundle creation is only supported on macOS.".to_string()
    }
}

// Re-export commonly used types
pub use detection::{
    DetectionError, DetectionResult, DriveInfo, DriveType,
    detect_drive_type, get_drive_root, get_fixed_disk_error_message, is_detection_supported,
    is_removable_drive, validate_removable_media,
};

#[cfg(target_os = "linux")]
pub use appimage::{
    AppCategory, AppImageBuilder, AppImageConfig, AppImageError, AppImageVersion,
    BuildResult, generate_build_script, get_install_instructions, is_appimage_supported,
    write_build_script,
};

#[cfg(target_os = "macos")]
pub use macos::{
    AppBundleBuilder, AppBundleConfig, AppBundleError, AppCategory as MacAppCategory,
    Architecture, BuildResult as MacBuildResult, CodeSigningConfig, DocumentRole,
    DocumentType, MacOSVersion, NotarizationConfig, generate_build_script as generate_macos_build_script,
    generate_icns_icon, generate_info_plist, get_code_signing_instructions,
    get_notarization_instructions, is_macos_supported, write_build_script as write_macos_build_script,
};

// Re-export USB preparation types
pub use usb::{
    PrepareConfig, PrepareError, PrepareResult, PrepareResult_ as UsbPrepareResult,
    InstallInfo, get_install_info, is_installed, prepare_drive,
    TESSERACT_DIR, VAULT_DIR, READY_TO_TEST_FILE, VERSION_FILE,
    WINDOWS_EXE, LINUX_APPIMAGE, MACOS_APP,
};

// Re-export bundle types
pub use bundle::{
    BundleConfig, BundleError, BundleResult, BundleResult_, BundleSizeSummary,
    ExecutableSource, PlatformExecutable, create_bundle, analyze_bundle,
    validate_executable, MAX_BUNDLE_SIZE_BYTES,
    TESSERACT_DIR as BUNDLE_TESSERACT_DIR, VERSION_FILE as BUNDLE_VERSION_FILE,
    WINDOWS_EXE as BUNDLE_WINDOWS_EXE, LINUX_APPIMAGE as BUNDLE_LINUX_APPIMAGE,
    MACOS_APP as BUNDLE_MACOS_APP,
};
