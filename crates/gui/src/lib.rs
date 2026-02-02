//! TESSERACT Cross-Platform GUI
//!
//! Provides a portable graphical interface using egui/eframe.
//!
//! # Features
//!
//! - Cross-platform support (Windows, Linux, macOS)
//! - Native look and feel with egui/eframe
//! - Vault selection and creation
//! - Password entry with lockout protection
//! - File browser with access level filtering
//! - Drag-and-drop file import
//!
//! # Usage
//!
//! Run the application using:
//! ```bash
//! cargo run --release -p tesseract-gui
//! ```
//!
//! Or import the library:
//! ```rust,ignore
//! use tesseract_gui::app::run;
//! run().expect("Failed to run TESSERACT GUI");
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

/// Main application state and entry point.
pub mod app;

/// Portable configuration storage.
pub mod config;

/// Vault selection screen.
pub mod screens;

/// Common UI components.
pub mod components;

/// Theme and styling.
pub mod theme;

// Re-export main types for convenience
pub use app::{AppScreen, TesseractApp, APP_NAME};
pub use app::{create_icon_data, create_native_options, has_hardware_acceleration, run};

// Re-export config types
pub use config::{AppConfig, RecentVault, load_config, save_config};

// Re-export screen types - vault selection
pub use screens::{
    VaultSelectionError, VaultSelectionResult, VaultSelectionState,
    format_relative_time, validate_vault, validate_new_vault_location,
};

// Re-export screen types - password entry
pub use screens::{
    AuthStatus, AuthError, AuthResult, PasswordEntryState,
    SharedAuthResult, create_shared_auth_result, attempt_authentication,
    current_timestamp, format_duration, calculate_backoff,
    should_trigger_lockout, default_lockout_duration,
};

// Re-export screen types - file browser
pub use screens::{
    FileBrowserState, SelectionMode, SortColumn, SortDirection,
    format_file_size, format_timestamp, entry_icon, level_label,
    ImportStatus, PendingImport,
};

// Re-export screen types - drive detection
pub use screens::{DriveDetectionState, DriveDisplayInfo};

// Re-export screen types - drive initialization wizard
pub use screens::{
    DriveInitWizardState, DriveInitStep, EncryptionStrength, AccessLevelConfig,
};
