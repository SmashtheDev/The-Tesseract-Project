//! Application screens.
//!
//! This module contains the logic for each screen in the TESSERACT application.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui;

use crate::config::RecentVault;
use tesseract_core::{vault_exists, is_vault_complete, validate_vault_structure};
use tesseract_core::{
    VaultHeader, unlock_header,
    BACKOFF_BASE_SECONDS, BACKOFF_MAX_SECONDS,
    DEFAULT_LOCKOUT_THRESHOLD, DEFAULT_LOCKOUT_DURATION_SECONDS,
};
use tesseract_crypto::kdf::Argon2Params;
use tracing::{debug, info, warn};

/// Result of vault selection operation.
#[derive(Debug, Clone)]
pub enum VaultSelectionResult {
    /// User selected an existing valid vault.
    OpenVault(PathBuf),
    /// User wants to create a new vault at the given location.
    CreateVault(PathBuf),
    /// User cancelled the selection.
    Cancelled,
}

/// Error that can occur during vault selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultSelectionError {
    /// Selected path does not contain a vault.
    NotAVault(PathBuf),
    /// Vault structure is incomplete or corrupted.
    InvalidVault(PathBuf, String),
    /// Selected path for new vault is not empty.
    DirectoryNotEmpty(PathBuf),
    /// Selected path is not writable.
    NotWritable(PathBuf),
    /// Operation was cancelled.
    Cancelled,
}

impl std::fmt::Display for VaultSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAVault(path) => {
                write!(f, "Not a valid vault: {}", path.display())
            }
            Self::InvalidVault(path, reason) => {
                write!(f, "Invalid vault at {}: {}", path.display(), reason)
            }
            Self::DirectoryNotEmpty(path) => {
                write!(
                    f,
                    "Directory is not empty: {}. Choose an empty folder for new vault.",
                    path.display()
                )
            }
            Self::NotWritable(path) => {
                write!(f, "Cannot write to: {}", path.display())
            }
            Self::Cancelled => write!(f, "Operation cancelled"),
        }
    }
}

impl std::error::Error for VaultSelectionError {}

/// Validates that a path contains a valid vault.
///
/// Checks:
/// 1. Vault header file exists
/// 2. Directory structure is complete
/// 3. Header file is valid size
pub fn validate_vault(path: &std::path::Path) -> Result<(), VaultSelectionError> {
    debug!("Validating vault at {:?}", path);

    // Check if path exists
    if !path.exists() {
        return Err(VaultSelectionError::NotAVault(path.to_path_buf()));
    }

    // Check if it's a directory
    if !path.is_dir() {
        return Err(VaultSelectionError::NotAVault(path.to_path_buf()));
    }

    // Check if vault header exists
    if !vault_exists(path) {
        return Err(VaultSelectionError::NotAVault(path.to_path_buf()));
    }

    // Check if vault structure is complete
    if !is_vault_complete(path) {
        return Err(VaultSelectionError::InvalidVault(
            path.to_path_buf(),
            "Vault structure is incomplete".to_string(),
        ));
    }

    // Validate structure (header size, etc.)
    if let Err(e) = validate_vault_structure(path) {
        return Err(VaultSelectionError::InvalidVault(
            path.to_path_buf(),
            e.to_string(),
        ));
    }

    info!("Vault validated successfully: {:?}", path);
    Ok(())
}

/// Validates that a path is suitable for creating a new vault.
///
/// Checks:
/// 1. Path is a directory or can be created
/// 2. Directory is empty (or doesn't exist yet)
/// 3. Path is writable
pub fn validate_new_vault_location(path: &std::path::Path) -> Result<(), VaultSelectionError> {
    debug!("Validating new vault location: {:?}", path);

    if path.exists() {
        // Check if it's a directory
        if !path.is_dir() {
            return Err(VaultSelectionError::NotWritable(path.to_path_buf()));
        }

        // Check if directory is empty
        let entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|_| VaultSelectionError::NotWritable(path.to_path_buf()))?
            .collect();

        if !entries.is_empty() {
            return Err(VaultSelectionError::DirectoryNotEmpty(path.to_path_buf()));
        }
    } else {
        // Check if parent exists and is writable
        let parent = path.parent().ok_or_else(|| {
            VaultSelectionError::NotWritable(path.to_path_buf())
        })?;

        if !parent.exists() || !parent.is_dir() {
            return Err(VaultSelectionError::NotWritable(path.to_path_buf()));
        }

        // Try to create and remove a test file to verify writability
        let test_path = parent.join(".tesseract_write_test");
        match std::fs::File::create(&test_path) {
            Ok(_) => {
                let _ = std::fs::remove_file(&test_path);
            }
            Err(_) => {
                return Err(VaultSelectionError::NotWritable(path.to_path_buf()));
            }
        }
    }

    info!("New vault location validated: {:?}", path);
    Ok(())
}

/// Opens a file dialog to select an existing vault.
///
/// Returns the selected vault path or None if cancelled.
pub fn open_vault_dialog() -> Option<PathBuf> {
    debug!("Opening vault selection dialog");

    let dialog = rfd::FileDialog::new()
        .set_title("Select Vault Folder")
        .set_directory(default_vault_directory());

    dialog.pick_folder()
}

/// Opens a file dialog to select a location for a new vault.
///
/// Returns the selected path or None if cancelled.
pub fn create_vault_dialog() -> Option<PathBuf> {
    debug!("Opening new vault location dialog");

    let dialog = rfd::FileDialog::new()
        .set_title("Select Location for New Vault")
        .set_directory(default_vault_directory());

    dialog.pick_folder()
}

/// Returns a sensible default directory for vault dialogs.
fn default_vault_directory() -> PathBuf {
    // Try to use the directory containing the executable (for portability)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            return parent.to_path_buf();
        }
    }

    // Fall back to user's home directory
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

// =============================================================================
// Vault Auto-Creation (US-062)
// =============================================================================

/// Default vault directory name (relative to executable).
pub const DEFAULT_VAULT_DIR_NAME: &str = "vault";

/// Returns the default vault path (adjacent to the executable).
///
/// For portable USB deployments, this will be `/TESSERACT/vault/`
/// when the executable is in `/TESSERACT/`.
#[must_use]
pub fn get_default_vault_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join(DEFAULT_VAULT_DIR_NAME)))
}

/// Checks if a valid vault exists at the default location.
///
/// Returns:
/// - `Some(path)` if a valid vault exists at the default location
/// - `None` if no vault exists or the vault is invalid
#[must_use]
pub fn check_default_vault_exists() -> Option<PathBuf> {
    let path = get_default_vault_path()?;

    // Check if vault exists and is valid
    if vault_exists(&path) && is_vault_complete(&path) {
        debug!("Found valid vault at default location: {:?}", path);
        Some(path)
    } else {
        debug!("No valid vault at default location: {:?}", path);
        None
    }
}

/// Result of checking for a default vault on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultAutoDetectionResult {
    /// A valid vault was found at the default location.
    Found(PathBuf),
    /// No vault found; the path where one could be created is provided.
    NotFound(PathBuf),
    /// Could not determine a default vault path.
    NoDefaultPath,
}

/// Performs vault auto-detection on startup.
///
/// Checks if a vault exists at the default location (adjacent to executable).
#[must_use]
pub fn detect_vault_on_startup() -> VaultAutoDetectionResult {
    match get_default_vault_path() {
        Some(path) => {
            if vault_exists(&path) && is_vault_complete(&path) {
                info!("Auto-detected valid vault at: {:?}", path);
                VaultAutoDetectionResult::Found(path)
            } else {
                info!("No vault found at default location: {:?}", path);
                VaultAutoDetectionResult::NotFound(path)
            }
        }
        None => {
            warn!("Could not determine default vault path");
            VaultAutoDetectionResult::NoDefaultPath
        }
    }
}

/// State for the vault auto-creation prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoCreationPromptState {
    /// No prompt needed (vault exists or already dismissed).
    None,
    /// Show the prompt to create a new vault.
    ShowPrompt(PathBuf),
    /// User confirmed vault creation.
    Confirmed(PathBuf),
    /// User dismissed the prompt.
    Dismissed,
}

impl Default for AutoCreationPromptState {
    fn default() -> Self {
        Self::None
    }
}

impl AutoCreationPromptState {
    /// Creates a new auto-creation prompt state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the prompt should be shown.
    #[must_use]
    pub fn should_show(&self) -> bool {
        matches!(self, Self::ShowPrompt(_))
    }

    /// Returns the path for vault creation if confirmed.
    #[must_use]
    pub fn get_confirmed_path(&self) -> Option<PathBuf> {
        if let Self::Confirmed(path) = self {
            Some(path.clone())
        } else {
            None
        }
    }

    /// Confirms the vault creation.
    pub fn confirm(&mut self) {
        if let Self::ShowPrompt(path) = self.clone() {
            *self = Self::Confirmed(path);
        }
    }

    /// Dismisses the prompt.
    pub fn dismiss(&mut self) {
        *self = Self::Dismissed;
    }

    /// Resets after handling the confirmation.
    pub fn reset(&mut self) {
        *self = Self::None;
    }
}

/// State for the vault selection screen.
#[derive(Debug, Clone, Default)]
pub struct VaultSelectionState {
    /// Current error message to display.
    pub error_message: Option<String>,
    /// Selected vault path (pending validation).
    pub selected_path: Option<PathBuf>,
    /// Whether we're in the process of opening a vault.
    pub is_opening: bool,
    /// Whether we're in the process of creating a vault.
    pub is_creating: bool,
}

impl VaultSelectionState {
    /// Creates a new vault selection state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears any error message.
    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    /// Sets an error message.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
    }

    /// Handles the "Open Existing Vault" action.
    ///
    /// Returns `Some(path)` if a valid vault was selected,
    /// or `None` if cancelled or invalid.
    pub fn handle_open_vault(&mut self) -> Option<PathBuf> {
        self.clear_error();
        self.is_opening = true;

        let result = if let Some(path) = open_vault_dialog() {
            match validate_vault(&path) {
                Ok(()) => {
                    info!("User selected vault: {:?}", path);
                    Some(path)
                }
                Err(e) => {
                    warn!("Invalid vault selection: {}", e);
                    self.set_error(e.to_string());
                    None
                }
            }
        } else {
            debug!("User cancelled vault selection");
            None
        };

        self.is_opening = false;
        result
    }

    /// Handles the "Create New Vault" action.
    ///
    /// Returns `Some(path)` if a valid location was selected,
    /// or `None` if cancelled or invalid.
    pub fn handle_create_vault(&mut self) -> Option<PathBuf> {
        self.clear_error();
        self.is_creating = true;

        let result = if let Some(path) = create_vault_dialog() {
            match validate_new_vault_location(&path) {
                Ok(()) => {
                    info!("User selected new vault location: {:?}", path);
                    Some(path)
                }
                Err(e) => {
                    warn!("Invalid new vault location: {}", e);
                    self.set_error(e.to_string());
                    None
                }
            }
        } else {
            debug!("User cancelled new vault creation");
            None
        };

        self.is_creating = false;
        result
    }

    /// Handles clicking on a recent vault entry.
    ///
    /// Returns `Some(path)` if the vault is valid,
    /// or `None` if it's no longer valid.
    pub fn handle_recent_vault_click(&mut self, vault: &RecentVault) -> Option<PathBuf> {
        self.clear_error();

        match validate_vault(&vault.path) {
            Ok(()) => {
                info!("Opening recent vault: {:?}", vault.path);
                Some(vault.path.clone())
            }
            Err(e) => {
                warn!("Recent vault no longer valid: {}", e);
                self.set_error(format!(
                    "This vault is no longer accessible: {}",
                    e
                ));
                None
            }
        }
    }
}

/// Formats a timestamp as a human-readable relative time string.
#[must_use]
pub fn format_relative_time(timestamp: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if timestamp > now {
        return "Just now".to_string();
    }

    let diff = now - timestamp;

    if diff < 60 {
        "Just now".to_string()
    } else if diff < 3600 {
        let mins = diff / 60;
        if mins == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", mins)
        }
    } else if diff < 86400 {
        let hours = diff / 3600;
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if diff < 604800 {
        let days = diff / 86400;
        if days == 1 {
            "Yesterday".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if diff < 2592000 {
        let weeks = diff / 604800;
        if weeks == 1 {
            "1 week ago".to_string()
        } else {
            format!("{} weeks ago", weeks)
        }
    } else {
        let months = diff / 2592000;
        if months == 1 {
            "1 month ago".to_string()
        } else {
            format!("{} months ago", months)
        }
    }
}

// =============================================================================
// Password Entry Screen
// =============================================================================

/// Authentication status for the password entry flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStatus {
    /// Initial state, waiting for password input.
    Idle,
    /// Argon2id key derivation in progress.
    Deriving,
    /// Authentication succeeded, transitioning to file browser.
    Success,
    /// Authentication failed with an error message.
    Failed(String),
    /// Account is locked out until the given timestamp.
    LockedOut {
        /// Unix timestamp when lockout expires.
        until: u64,
        /// Number of failed attempts.
        attempts: u32,
    },
}

impl Default for AuthStatus {
    fn default() -> Self {
        Self::Idle
    }
}

/// Error that can occur during password authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Wrong password provided.
    WrongPassword,
    /// Vault header is corrupted or tampered.
    IntegrityFailed,
    /// Account is locked out.
    LockedOut { until: u64, attempts: u32 },
    /// I/O error reading vault.
    IoError(String),
    /// Other errors.
    Other(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassword => write!(f, "Incorrect password"),
            Self::IntegrityFailed => write!(f, "Vault integrity check failed - possible tampering detected"),
            Self::LockedOut { until, attempts } => {
                let remaining = until.saturating_sub(current_timestamp());
                if remaining > 0 {
                    write!(
                        f,
                        "Account locked after {} failed attempts. Try again in {}",
                        attempts,
                        format_duration(remaining)
                    )
                } else {
                    write!(f, "Account locked after {} failed attempts", attempts)
                }
            }
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

/// State for the password entry screen.
#[derive(Debug, Default)]
pub struct PasswordEntryState {
    /// Current password input (sensitive, will be zeroized).
    pub password: String,
    /// Whether to show the password as plaintext.
    pub show_password: bool,
    /// Current authentication status.
    pub status: AuthStatus,
    /// Number of failed attempts in this session.
    pub failed_attempts: u32,
    /// Remaining lockout time in seconds (for display).
    pub lockout_remaining: u64,
    /// Vault path being authenticated.
    pub vault_path: Option<PathBuf>,
    /// Loaded vault header (None until header is loaded).
    pub header: Option<VaultHeader>,
    /// Argon2 parameters (loaded from vault or default).
    pub argon2_params: Option<Argon2Params>,
    /// Whether to auto-unlock on next render (US-026).
    /// When true, the password entry screen will attempt unlock immediately.
    pub auto_unlock: bool,
}

impl PasswordEntryState {
    /// Creates a new password entry state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new password entry state for a specific vault.
    #[must_use]
    pub fn for_vault(path: PathBuf) -> Self {
        Self {
            vault_path: Some(path),
            ..Self::default()
        }
    }

    /// Loads the vault header from disk.
    pub fn load_header(&mut self) -> Result<(), AuthError> {
        let path = self.vault_path.as_ref()
            .ok_or_else(|| AuthError::Other("No vault path set".to_string()))?;

        let header_path = tesseract_core::header_path(path);
        debug!("Loading vault header from {:?}", header_path);

        let header_bytes = std::fs::read(&header_path)
            .map_err(|e| AuthError::IoError(e.to_string()))?;

        // Convert Vec<u8> to [u8; 512] for from_bytes
        let header_array: [u8; 512] = header_bytes.as_slice().try_into()
            .map_err(|_| AuthError::Other(format!(
                "Invalid header size: expected 512 bytes, got {}",
                header_bytes.len()
            )))?;

        let header = VaultHeader::from_bytes(&header_array)
            .map_err(|e| AuthError::Other(format!("Failed to parse header: {}", e)))?;

        // Check if locked out
        if header.is_locked_out() {
            let until = header.lockout_until();
            let attempts = header.attempt_counter();
            self.status = AuthStatus::LockedOut { until, attempts };
            self.lockout_remaining = header.lockout_remaining();
            return Err(AuthError::LockedOut { until, attempts });
        }

        // Calculate backoff delay if there are failed attempts
        let backoff = header.calculate_backoff_seconds();
        if backoff > 0 {
            debug!("Backoff delay of {} seconds due to {} failed attempts",
                   backoff, header.attempt_counter());
        }

        self.argon2_params = Some(Argon2Params::default());
        self.header = Some(header);
        Ok(())
    }

    /// Clears the password and resets input state.
    pub fn clear_password(&mut self) {
        // Zeroize password
        self.password.clear();
        self.password.shrink_to_fit();
        self.show_password = false;
    }

    /// Resets the authentication state for a new attempt.
    pub fn reset(&mut self) {
        self.clear_password();
        self.status = AuthStatus::Idle;
    }

    /// Resets the entire state for a new vault.
    pub fn reset_for_vault(&mut self, path: PathBuf) {
        self.clear_password();
        self.vault_path = Some(path);
        self.header = None;
        self.argon2_params = None;
        self.status = AuthStatus::Idle;
        self.failed_attempts = 0;
        self.lockout_remaining = 0;
        self.auto_unlock = false;
    }

    /// Updates the lockout remaining time (call periodically).
    pub fn update_lockout_timer(&mut self) {
        if let Some(ref header) = self.header {
            self.lockout_remaining = header.lockout_remaining();
            if self.lockout_remaining == 0 && matches!(self.status, AuthStatus::LockedOut { .. }) {
                // Lockout expired, allow retry
                self.status = AuthStatus::Idle;
                info!("Lockout expired, user can retry");
            }
        }
    }

    /// Checks if authentication can proceed (not locked, not deriving).
    #[must_use]
    pub fn can_attempt_auth(&self) -> bool {
        matches!(self.status, AuthStatus::Idle | AuthStatus::Failed(_))
            && self.lockout_remaining == 0
            && self.header.is_some()
    }

    /// Returns true if currently deriving keys (show loading indicator).
    #[must_use]
    pub fn is_deriving(&self) -> bool {
        matches!(self.status, AuthStatus::Deriving)
    }

    /// Returns true if locked out.
    #[must_use]
    pub fn is_locked_out(&self) -> bool {
        matches!(self.status, AuthStatus::LockedOut { .. })
    }

    /// Returns the error message if authentication failed.
    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        match &self.status {
            AuthStatus::Failed(msg) => Some(msg.as_str()),
            AuthStatus::LockedOut { until, attempts } => {
                // This is handled specially in the UI
                None
            }
            _ => None,
        }
    }

    /// Returns the vault name for display.
    #[must_use]
    pub fn vault_name(&self) -> String {
        self.vault_path.as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown Vault")
            .to_string()
    }
}

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded, contains the master key.
    Success([u8; 32]),
    /// Authentication failed.
    Failed(AuthError),
    /// Still in progress (async).
    InProgress,
}

/// Shared state for async authentication.
pub type SharedAuthResult = Arc<Mutex<Option<AuthResult>>>;

/// Creates a new shared auth result for async operations.
#[must_use]
pub fn create_shared_auth_result() -> SharedAuthResult {
    Arc::new(Mutex::new(None))
}

/// Attempts to authenticate with the given password.
///
/// This function performs the synchronous authentication. For GUI use,
/// wrap this in a thread to avoid blocking the UI during Argon2id derivation.
pub fn attempt_authentication(
    header: &VaultHeader,
    password: &str,
    argon2_params: &Argon2Params,
) -> Result<[u8; 32], AuthError> {
    debug!("Attempting authentication with Argon2id derivation");

    // Check lockout before attempting
    if header.is_locked_out() {
        return Err(AuthError::LockedOut {
            until: header.lockout_until(),
            attempts: header.attempt_counter(),
        });
    }

    // Attempt unlock
    match unlock_header(header, password.as_bytes(), argon2_params) {
        Ok(master_key) => {
            info!("Authentication successful");
            Ok(master_key)
        }
        Err(e) => {
            warn!("Authentication failed: {}", e);
            // Determine error type
            let auth_error = if e.to_string().contains("integrity") {
                AuthError::IntegrityFailed
            } else {
                AuthError::WrongPassword
            };
            Err(auth_error)
        }
    }
}

/// Returns the current Unix timestamp.
#[must_use]
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Formats a duration in seconds as a human-readable string.
#[must_use]
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{} second{}", seconds, if seconds == 1 { "" } else { "s" })
    } else if seconds < 3600 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        if secs == 0 {
            format!("{} minute{}", mins, if mins == 1 { "" } else { "s" })
        } else {
            format!("{}:{:02}", mins, secs)
        }
    } else {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        format!("{}:{:02}:{:02}", hours, mins, seconds % 60)
    }
}

/// Calculates the backoff delay for a given number of attempts.
///
/// Uses exponential backoff: delay = base * 2^(attempts-1), capped at max.
#[must_use]
pub fn calculate_backoff(attempts: u32) -> u64 {
    if attempts == 0 {
        return 0;
    }
    let delay = BACKOFF_BASE_SECONDS.saturating_mul(1u64 << attempts.saturating_sub(1).min(20));
    delay.min(BACKOFF_MAX_SECONDS)
}

/// Checks if a lockout should be triggered based on attempt count.
#[must_use]
pub fn should_trigger_lockout(attempts: u32) -> bool {
    attempts >= DEFAULT_LOCKOUT_THRESHOLD
}

/// Returns the default lockout duration in seconds.
#[must_use]
pub fn default_lockout_duration() -> u64 {
    DEFAULT_LOCKOUT_DURATION_SECONDS
}

// =============================================================================
// File Browser Screen
// =============================================================================

use tesseract_core::files::{EntryType, FileEntry, file_count, list_all_files, list_files};

/// Selection mode for file browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionMode {
    /// No selection active.
    #[default]
    None,
    /// Single file selected.
    Single,
    /// Multiple files selected.
    Multi,
}

/// Sort column for file list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    /// Sort by name.
    #[default]
    Name,
    /// Sort by size.
    Size,
    /// Sort by modification time.
    Modified,
    /// Sort by access level.
    Level,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDirection {
    /// Ascending (A-Z, oldest first, smallest first).
    #[default]
    Ascending,
    /// Descending (Z-A, newest first, largest first).
    Descending,
}

/// Status of an import operation.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportStatus {
    /// No import in progress.
    Idle,
    /// Showing the import dialog for file selection.
    ShowingDialog,
    /// Importing files with progress.
    Importing {
        /// Current file being imported.
        current: usize,
        /// Total number of files.
        total: usize,
        /// Current filename being processed.
        current_file: String,
    },
    /// Import completed with results.
    Completed {
        /// Number of successfully imported files.
        success_count: usize,
        /// Number of failed imports.
        failure_count: usize,
        /// Error messages for failed imports.
        errors: Vec<String>,
    },
}

impl Default for ImportStatus {
    fn default() -> Self {
        Self::Idle
    }
}

// =============================================================================
// Context Menu Types
// =============================================================================

/// Context menu action types available for file operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMenuAction {
    /// Open the selected file (double-click behavior).
    Open,
    /// Export selected file(s) to host filesystem.
    Export,
    /// Delete selected file(s) from vault.
    Delete,
    /// Rename the selected file.
    Rename,
    /// Change access level of selected file(s).
    ChangeAccessLevel,
}

impl ContextMenuAction {
    /// Returns the display label for this action.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Export => "Export...",
            Self::Delete => "Delete",
            Self::Rename => "Rename",
            Self::ChangeAccessLevel => "Change Access Level",
        }
    }

    /// Returns the keyboard shortcut hint for this action.
    #[must_use]
    pub fn shortcut_hint(&self) -> Option<&'static str> {
        match self {
            Self::Open => Some("Enter"),
            Self::Export => Some("Ctrl+E"),
            Self::Delete => Some("Delete"),
            Self::Rename => Some("F2"),
            Self::ChangeAccessLevel => None,
        }
    }

    /// Returns true if this action supports multiple files.
    #[must_use]
    pub fn supports_multi_select(&self) -> bool {
        matches!(self, Self::Export | Self::Delete | Self::ChangeAccessLevel)
    }
}

/// State of a confirmation dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmationDialog {
    /// No dialog shown.
    None,
    /// Delete confirmation dialog.
    DeleteConfirmation {
        /// Number of files to delete.
        file_count: usize,
        /// UUIDs of files to delete.
        file_uuids: Vec<uuid::Uuid>,
    },
    /// Change access level confirmation.
    ChangeAccessLevelConfirmation {
        /// Number of files affected.
        file_count: usize,
        /// UUIDs of files to change.
        file_uuids: Vec<uuid::Uuid>,
        /// Target access level.
        target_level: u32,
    },
}

impl Default for ConfirmationDialog {
    fn default() -> Self {
        Self::None
    }
}

/// State for the rename dialog.
#[derive(Debug, Clone, Default)]
pub struct RenameState {
    /// Whether the rename dialog is shown.
    pub is_active: bool,
    /// UUID of the file being renamed.
    pub file_uuid: Option<uuid::Uuid>,
    /// Original filename.
    pub original_name: String,
    /// Current input text.
    pub new_name: String,
    /// Error message if rename failed.
    pub error_message: Option<String>,
}

impl RenameState {
    /// Creates a new rename state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts a rename operation for the given file.
    pub fn start(&mut self, file_uuid: uuid::Uuid, original_name: String) {
        self.is_active = true;
        self.file_uuid = Some(file_uuid);
        self.original_name = original_name.clone();
        self.new_name = original_name;
        self.error_message = None;
    }

    /// Cancels the rename operation.
    pub fn cancel(&mut self) {
        self.is_active = false;
        self.file_uuid = None;
        self.original_name.clear();
        self.new_name.clear();
        self.error_message = None;
    }

    /// Returns true if a rename is in progress.
    #[must_use]
    pub fn is_renaming(&self) -> bool {
        self.is_active && self.file_uuid.is_some()
    }
}

/// State for changing access level.
#[derive(Debug, Clone, Default)]
pub struct ChangeAccessLevelState {
    /// Whether the dialog is shown.
    pub is_active: bool,
    /// UUIDs of files to change.
    pub file_uuids: Vec<uuid::Uuid>,
    /// Selected target access level.
    pub target_level: u32,
}

impl ChangeAccessLevelState {
    /// Creates a new change access level state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts a change access level operation.
    pub fn start(&mut self, file_uuids: Vec<uuid::Uuid>, current_max_level: u32) {
        self.is_active = true;
        self.file_uuids = file_uuids;
        self.target_level = current_max_level.max(1);
    }

    /// Cancels the operation.
    pub fn cancel(&mut self) {
        self.is_active = false;
        self.file_uuids.clear();
        self.target_level = 1;
    }
}

/// State for the context menu.
#[derive(Debug, Clone, Default)]
pub struct ContextMenuState {
    /// Whether the context menu is visible.
    pub is_open: bool,
    /// Position where the context menu was opened (screen coordinates).
    pub position: egui::Pos2,
    /// UUIDs of files that were right-clicked (for context actions).
    pub target_file_uuids: Vec<uuid::Uuid>,
    /// Whether the target includes directories.
    pub has_directories: bool,
}

impl ContextMenuState {
    /// Creates a new context menu state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            is_open: false,
            position: egui::Pos2::ZERO,
            target_file_uuids: Vec::new(),
            has_directories: false,
        }
    }

    /// Opens the context menu at the given position.
    pub fn open(&mut self, position: egui::Pos2, file_uuids: Vec<uuid::Uuid>, has_directories: bool) {
        self.is_open = true;
        self.position = position;
        self.target_file_uuids = file_uuids;
        self.has_directories = has_directories;
    }

    /// Closes the context menu.
    pub fn close(&mut self) {
        self.is_open = false;
        self.target_file_uuids.clear();
        self.has_directories = false;
    }

    /// Returns true if multiple files are selected.
    #[must_use]
    pub fn is_multi_select(&self) -> bool {
        self.target_file_uuids.len() > 1
    }

    /// Returns the available actions for the current selection.
    #[must_use]
    pub fn available_actions(&self) -> Vec<ContextMenuAction> {
        let mut actions = Vec::new();

        if self.target_file_uuids.is_empty() {
            return actions;
        }

        // Single file only actions
        if !self.is_multi_select() && !self.has_directories {
            actions.push(ContextMenuAction::Open);
        }

        // Export - works for files (single or multi)
        if !self.has_directories {
            actions.push(ContextMenuAction::Export);
        }

        // Delete - works for files and directories
        actions.push(ContextMenuAction::Delete);

        // Rename - single file only
        if !self.is_multi_select() {
            actions.push(ContextMenuAction::Rename);
        }

        // Change access level - works for files (single or multi), not directories
        if !self.has_directories {
            actions.push(ContextMenuAction::ChangeAccessLevel);
        }

        actions
    }
}

/// Status of an export operation.
#[derive(Debug, Clone, PartialEq)]
pub enum ExportStatus {
    /// No export in progress.
    Idle,
    /// Showing the folder picker dialog.
    SelectingDestination,
    /// Exporting files with progress.
    Exporting {
        /// Current file being exported.
        current: usize,
        /// Total number of files.
        total: usize,
        /// Current filename being processed.
        current_file: String,
    },
    /// Export completed with results.
    Completed {
        /// Number of successfully exported files.
        success_count: usize,
        /// Number of failed exports.
        failure_count: usize,
        /// Error messages for failed exports.
        errors: Vec<String>,
        /// Destination folder path.
        destination: PathBuf,
    },
}

impl Default for ExportStatus {
    fn default() -> Self {
        Self::Idle
    }
}

/// A pending file to import.
#[derive(Debug, Clone)]
pub struct PendingImport {
    /// Original filename.
    pub filename: String,
    /// File path on disk (if available).
    pub path: Option<PathBuf>,
    /// File size in bytes.
    pub size: u64,
    /// File content (for dropped files).
    pub content: Option<Vec<u8>>,
}

impl PendingImport {
    /// Creates a new pending import from a file path.
    pub fn from_path(path: PathBuf) -> Result<Self, std::io::Error> {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string();
        let metadata = std::fs::metadata(&path)?;
        Ok(Self {
            filename,
            size: metadata.len(),
            path: Some(path),
            content: None,
        })
    }

    /// Creates a new pending import from bytes.
    pub fn from_bytes(filename: String, content: Vec<u8>) -> Self {
        let size = content.len() as u64;
        Self {
            filename,
            size,
            path: None,
            content: Some(content),
        }
    }
}

/// State for the file browser screen.
#[derive(Debug, Default)]
pub struct FileBrowserState {
    /// Current directory path (virtual path within vault).
    pub current_path: String,
    /// Breadcrumb path components for navigation.
    pub breadcrumbs: Vec<String>,
    /// Current list of files/folders in the directory.
    pub entries: Vec<FileEntry>,
    /// Set of selected file UUIDs.
    pub selected: std::collections::HashSet<uuid::Uuid>,
    /// Current selection mode.
    pub selection_mode: SelectionMode,
    /// Current sort column.
    pub sort_column: SortColumn,
    /// Current sort direction.
    pub sort_direction: SortDirection,
    /// Current access level being displayed.
    pub current_access_level: u32,
    /// Maximum access level available in session.
    pub max_access_level: u32,
    /// Total file count across all accessible levels.
    pub total_file_count: usize,
    /// Whether the file list is loading.
    pub is_loading: bool,
    /// Error message to display (if any).
    pub error_message: Option<String>,
    /// Whether to show hidden files (future feature).
    pub show_hidden: bool,
    /// Whether a drag hover is active over the file browser.
    pub drag_hover_active: bool,
    /// Current import status.
    pub import_status: ImportStatus,
    /// Files pending import (shown in dialog).
    pub pending_imports: Vec<PendingImport>,
    /// Selected access level for import dialog.
    pub import_access_level: u32,
    /// Current export status.
    pub export_status: ExportStatus,
    /// Destination folder for export.
    pub export_destination: Option<PathBuf>,
    /// Context menu state.
    pub context_menu: ContextMenuState,
    /// Rename dialog state.
    pub rename_state: RenameState,
    /// Change access level dialog state.
    pub change_access_level_state: ChangeAccessLevelState,
    /// Confirmation dialog state.
    pub confirmation_dialog: ConfirmationDialog,
}

impl FileBrowserState {
    /// Creates a new file browser state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_path: "/".to_string(),
            breadcrumbs: vec!["/".to_string()],
            import_access_level: 1,
            ..Default::default()
        }
    }

    /// Initializes the file browser for a vault session.
    ///
    /// Loads the file list from the vault and sets up the initial state.
    pub fn initialize(&mut self, session: &tesseract_core::session::VaultSession) {
        self.current_path = "/".to_string();
        self.breadcrumbs = vec!["/".to_string()];
        self.selected.clear();
        self.selection_mode = SelectionMode::None;
        self.error_message = None;
        self.is_loading = true;

        // Get access level info
        let accessible = session.accessible_levels();
        self.max_access_level = accessible.iter().copied().max().unwrap_or(1);
        self.current_access_level = self.max_access_level;

        // Get total file count
        self.total_file_count = file_count(session).unwrap_or(0);

        // Load initial file list
        self.refresh_entries(session);
    }

    /// Refreshes the file entry list from the vault.
    pub fn refresh_entries(&mut self, session: &tesseract_core::session::VaultSession) {
        self.is_loading = true;
        self.error_message = None;

        match list_files(session, &self.current_path) {
            Ok(mut entries) => {
                // Sort entries
                self.sort_entries(&mut entries);
                self.entries = entries;
                self.is_loading = false;
            }
            Err(e) => {
                self.error_message = Some(format!("Failed to load files: {}", e));
                self.entries.clear();
                self.is_loading = false;
            }
        }
    }

    /// Sorts the entry list based on current sort settings.
    fn sort_entries(&self, entries: &mut [FileEntry]) {
        entries.sort_by(|a, b| {
            // Directories always come first
            if a.is_directory() && !b.is_directory() {
                return std::cmp::Ordering::Less;
            }
            if !a.is_directory() && b.is_directory() {
                return std::cmp::Ordering::Greater;
            }

            let ordering = match self.sort_column {
                SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortColumn::Size => a.size.cmp(&b.size),
                SortColumn::Modified => a.modified_time.cmp(&b.modified_time),
                SortColumn::Level => a.access_level.cmp(&b.access_level),
            };

            match self.sort_direction {
                SortDirection::Ascending => ordering,
                SortDirection::Descending => ordering.reverse(),
            }
        });
    }

    /// Toggles the sort column and direction.
    pub fn toggle_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            // Toggle direction
            self.sort_direction = match self.sort_direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            // New column, default to ascending
            self.sort_column = column;
            self.sort_direction = SortDirection::Ascending;
        }

        // Re-sort entries
        let mut entries = std::mem::take(&mut self.entries);
        self.sort_entries(&mut entries);
        self.entries = entries;
    }

    /// Navigates to a subdirectory.
    pub fn navigate_to(&mut self, path: &str, session: &tesseract_core::session::VaultSession) {
        let normalized = normalize_path(path);
        self.current_path = normalized.clone();
        self.update_breadcrumbs();
        self.selected.clear();
        self.selection_mode = SelectionMode::None;
        self.refresh_entries(session);
    }

    /// Navigates up one directory level.
    pub fn navigate_up(&mut self, session: &tesseract_core::session::VaultSession) {
        if self.current_path == "/" {
            return;
        }

        // Find parent path
        let parent = parent_path(&self.current_path);
        self.navigate_to(&parent, session);
    }

    /// Navigates to a breadcrumb index.
    pub fn navigate_to_breadcrumb(&mut self, index: usize, session: &tesseract_core::session::VaultSession) {
        if index >= self.breadcrumbs.len() {
            return;
        }

        // Build path from breadcrumbs up to index
        let path = if index == 0 {
            "/".to_string()
        } else {
            format!("/{}", self.breadcrumbs[1..=index].join("/"))
        };

        self.navigate_to(&path, session);
    }

    /// Updates the breadcrumb list based on current path.
    fn update_breadcrumbs(&mut self) {
        self.breadcrumbs.clear();
        self.breadcrumbs.push("/".to_string());

        if self.current_path != "/" {
            let path = self.current_path.trim_start_matches('/');
            for component in path.split('/') {
                if !component.is_empty() {
                    self.breadcrumbs.push(component.to_string());
                }
            }
        }
    }

    /// Handles clicking on a file entry.
    ///
    /// - Single click on directory: navigate into it
    /// - Single click on file: select it
    /// - Ctrl+click on file: toggle selection
    pub fn handle_entry_click(
        &mut self,
        entry: &FileEntry,
        ctrl_held: bool,
        session: &tesseract_core::session::VaultSession,
    ) {
        if entry.is_directory() {
            // Navigate into directory
            let new_path = if self.current_path == "/" {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", self.current_path, entry.name)
            };
            self.navigate_to(&new_path, session);
        } else if let Some(uuid) = entry.uuid {
            // Select/deselect file
            if ctrl_held {
                // Toggle selection
                if self.selected.contains(&uuid) {
                    self.selected.remove(&uuid);
                } else {
                    self.selected.insert(uuid);
                }
                self.selection_mode = if self.selected.len() > 1 {
                    SelectionMode::Multi
                } else if self.selected.len() == 1 {
                    SelectionMode::Single
                } else {
                    SelectionMode::None
                };
            } else {
                // Single select (clear others)
                self.selected.clear();
                self.selected.insert(uuid);
                self.selection_mode = SelectionMode::Single;
            }
        }
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected.clear();
        self.selection_mode = SelectionMode::None;
    }

    /// Selects all files in the current directory.
    pub fn select_all(&mut self) {
        self.selected.clear();
        for entry in &self.entries {
            if entry.is_file() {
                if let Some(uuid) = entry.uuid {
                    self.selected.insert(uuid);
                }
            }
        }
        self.selection_mode = if self.selected.len() > 1 {
            SelectionMode::Multi
        } else if self.selected.len() == 1 {
            SelectionMode::Single
        } else {
            SelectionMode::None
        };
    }

    /// Returns the number of selected files.
    #[must_use]
    pub fn selection_count(&self) -> usize {
        self.selected.len()
    }

    /// Returns true if files are selected.
    #[must_use]
    pub fn has_selection(&self) -> bool {
        !self.selected.is_empty()
    }

    /// Returns the selected file UUID (if exactly one is selected).
    #[must_use]
    pub fn single_selection(&self) -> Option<uuid::Uuid> {
        if self.selected.len() == 1 {
            self.selected.iter().next().copied()
        } else {
            None
        }
    }

    /// Sets an error message.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
    }

    /// Clears the error message.
    pub fn clear_error(&mut self) {
        self.error_message = None;
    }

    // =========================================================================
    // Drag-and-Drop Import
    // =========================================================================

    /// Handles files dropped onto the file browser.
    ///
    /// Prepares the pending imports list and shows the import dialog.
    pub fn handle_dropped_files(&mut self, dropped_files: &[egui::DroppedFile]) {
        if dropped_files.is_empty() {
            return;
        }

        debug!("Handling {} dropped files", dropped_files.len());
        self.pending_imports.clear();

        for dropped in dropped_files {
            // Try to create a pending import from the dropped file
            if let Some(ref path) = dropped.path {
                match PendingImport::from_path(path.clone()) {
                    Ok(pending) => {
                        info!("Added pending import: {} ({} bytes)", pending.filename, pending.size);
                        self.pending_imports.push(pending);
                    }
                    Err(e) => {
                        warn!("Failed to read dropped file {:?}: {}", path, e);
                    }
                }
            } else if let Some(ref bytes) = dropped.bytes {
                // File dropped with bytes directly (some platforms)
                let filename = dropped.name.clone();
                let content = bytes.to_vec();
                let pending = PendingImport::from_bytes(filename, content);
                info!("Added pending import from bytes: {} ({} bytes)", pending.filename, pending.size);
                self.pending_imports.push(pending);
            }
        }

        if !self.pending_imports.is_empty() {
            // Set default access level to session's max level
            self.import_access_level = self.import_access_level.max(1).min(self.max_access_level.max(1));
            self.import_status = ImportStatus::ShowingDialog;
        }
    }

    /// Starts the import process for pending files.
    ///
    /// Returns true if import started successfully.
    pub fn start_import(&mut self) -> bool {
        if self.pending_imports.is_empty() {
            return false;
        }

        let total = self.pending_imports.len();
        let first_file = self.pending_imports.first()
            .map(|p| p.filename.clone())
            .unwrap_or_default();

        self.import_status = ImportStatus::Importing {
            current: 1,
            total,
            current_file: first_file,
        };

        true
    }

    /// Cancels the current import operation.
    pub fn cancel_import(&mut self) {
        self.pending_imports.clear();
        self.import_status = ImportStatus::Idle;
        self.drag_hover_active = false;
    }

    /// Dismisses the import completion notification.
    pub fn dismiss_import_result(&mut self) {
        self.import_status = ImportStatus::Idle;
    }

    /// Returns true if an import dialog should be shown.
    #[must_use]
    pub fn should_show_import_dialog(&self) -> bool {
        matches!(self.import_status, ImportStatus::ShowingDialog)
    }

    /// Returns true if import is in progress.
    #[must_use]
    pub fn is_importing(&self) -> bool {
        matches!(self.import_status, ImportStatus::Importing { .. })
    }

    /// Returns true if import completed (with or without errors).
    #[must_use]
    pub fn has_import_result(&self) -> bool {
        matches!(self.import_status, ImportStatus::Completed { .. })
    }

    /// Calculates the total size of pending imports.
    #[must_use]
    pub fn pending_imports_total_size(&self) -> u64 {
        self.pending_imports.iter().map(|p| p.size).sum()
    }

    // =========================================================================
    // Export Operations
    // =========================================================================

    /// Returns true if export is in progress.
    #[must_use]
    pub fn is_exporting(&self) -> bool {
        matches!(self.export_status, ExportStatus::Exporting { .. })
    }

    /// Returns true if export completed (with or without errors).
    #[must_use]
    pub fn has_export_result(&self) -> bool {
        matches!(self.export_status, ExportStatus::Completed { .. })
    }

    /// Dismisses the export completion notification.
    pub fn dismiss_export_result(&mut self) {
        self.export_status = ExportStatus::Idle;
        self.export_destination = None;
    }

    /// Cancels the current export operation.
    pub fn cancel_export(&mut self) {
        self.export_status = ExportStatus::Idle;
        self.export_destination = None;
    }

    /// Gets the list of selected file entries with their UUIDs.
    #[must_use]
    pub fn get_selected_entries(&self) -> Vec<&FileEntry> {
        self.entries
            .iter()
            .filter(|e| e.uuid.map(|u| self.selected.contains(&u)).unwrap_or(false))
            .collect()
    }
}

/// Normalizes a virtual path.
///
/// Ensures the path:
/// - Starts with "/"
/// - Has no trailing slash (except for root)
/// - Has no double slashes
fn normalize_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }

    let mut result = String::new();
    if !path.starts_with('/') {
        result.push('/');
    }

    for part in path.split('/') {
        if !part.is_empty() {
            if result.len() > 1 {
                result.push('/');
            }
            result.push_str(part);
        }
    }

    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

/// Gets the parent path of a virtual path.
fn parent_path(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return "/".to_string();
    }

    let path = path.trim_end_matches('/');
    if let Some(idx) = path.rfind('/') {
        if idx == 0 {
            "/".to_string()
        } else {
            path[..idx].to_string()
        }
    } else {
        "/".to_string()
    }
}

/// Formats a file size in human-readable format.
#[must_use]
pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Formats a Unix timestamp as a human-readable date/time.
#[must_use]
pub fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);
    let now = SystemTime::now();

    // Get difference for relative display
    let diff = now.duration_since(datetime).unwrap_or(Duration::ZERO);
    let days = diff.as_secs() / 86400;

    if days == 0 {
        // Today - show time
        let secs = timestamp % 86400;
        let hours = (secs / 3600) % 24;
        let mins = (secs / 60) % 60;
        format!("Today {:02}:{:02}", hours, mins)
    } else if days == 1 {
        "Yesterday".to_string()
    } else if days < 7 {
        format!("{} days ago", days)
    } else {
        // Older - just show "X weeks/months ago"
        let weeks = days / 7;
        if weeks < 4 {
            format!("{} week{} ago", weeks, if weeks == 1 { "" } else { "s" })
        } else {
            let months = days / 30;
            format!("{} month{} ago", months, if months == 1 { "" } else { "s" })
        }
    }
}

/// Returns the icon string for an entry type.
#[must_use]
pub fn entry_icon(entry: &FileEntry) -> &'static str {
    if entry.is_directory() {
        "📁"
    } else {
        // Get icon based on extension
        let name = entry.name.to_lowercase();
        if name.ends_with(".pdf") {
            "📄"
        } else if name.ends_with(".doc") || name.ends_with(".docx") {
            "📝"
        } else if name.ends_with(".xls") || name.ends_with(".xlsx") {
            "📊"
        } else if name.ends_with(".ppt") || name.ends_with(".pptx") {
            "📽"
        } else if name.ends_with(".jpg") || name.ends_with(".jpeg") || name.ends_with(".png") || name.ends_with(".gif") || name.ends_with(".bmp") {
            "🖼"
        } else if name.ends_with(".mp3") || name.ends_with(".wav") || name.ends_with(".flac") || name.ends_with(".m4a") {
            "🎵"
        } else if name.ends_with(".mp4") || name.ends_with(".mkv") || name.ends_with(".avi") || name.ends_with(".mov") {
            "🎬"
        } else if name.ends_with(".zip") || name.ends_with(".rar") || name.ends_with(".7z") || name.ends_with(".tar") || name.ends_with(".gz") {
            "📦"
        } else if name.ends_with(".txt") || name.ends_with(".md") || name.ends_with(".log") {
            "📃"
        } else if name.ends_with(".exe") || name.ends_with(".msi") || name.ends_with(".dmg") || name.ends_with(".app") {
            "⚙️"
        } else if name.ends_with(".key") || name.ends_with(".pem") || name.ends_with(".crt") {
            "🔑"
        } else {
            "📄"
        }
    }
}

/// Access level label with color hint.
#[must_use]
pub fn level_label(level: u32) -> &'static str {
    match level {
        1 => "L1",
        2 => "L2",
        3 => "L3",
        4 => "L4",
        5 => "L5",
        _ => "L?",
    }
}

// =============================================================================
// Settings / Access Level Management Screen (US-039)
// =============================================================================

/// Information about an access level for display in settings.
#[derive(Debug, Clone)]
pub struct AccessLevelDisplayInfo {
    /// Level ID (1-10).
    pub id: u32,
    /// Level name.
    pub name: String,
    /// Whether the level is enabled.
    pub enabled: bool,
    /// Optional description.
    pub description: Option<String>,
    /// Number of files at this level.
    pub file_count: usize,
    /// Whether the keystore exists for this level.
    pub has_keystore: bool,
}

impl AccessLevelDisplayInfo {
    /// Creates a new display info from a LevelInfo and file count.
    #[must_use]
    pub fn from_level_info(info: &tesseract_core::access::LevelInfo, file_count: usize) -> Self {
        Self {
            id: info.id,
            name: info.name.clone(),
            enabled: info.enabled,
            description: info.description.clone(),
            file_count,
            has_keystore: info.has_keystore,
        }
    }

    /// Returns whether this level can be deleted.
    ///
    /// A level can be deleted if:
    /// - It has no files
    /// - It's not the last remaining level (min 3 levels required)
    #[must_use]
    pub fn can_delete(&self, total_levels: usize) -> bool {
        self.file_count == 0 && total_levels > 3
    }
}

/// Dialog state for creating a new access level.
#[derive(Debug, Clone, Default)]
pub struct CreateLevelDialogState {
    /// Whether the dialog is open.
    pub is_open: bool,
    /// The new level name.
    pub name: String,
    /// The new level password.
    pub password: String,
    /// Confirm password.
    pub confirm_password: String,
    /// Whether to show the password.
    pub show_password: bool,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Whether creation is in progress.
    pub is_creating: bool,
}

impl CreateLevelDialogState {
    /// Opens the dialog.
    pub fn open(&mut self) {
        self.is_open = true;
        self.name.clear();
        self.password.clear();
        self.confirm_password.clear();
        self.show_password = false;
        self.error_message = None;
        self.is_creating = false;
    }

    /// Closes the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
        self.name.clear();
        self.password.clear();
        self.confirm_password.clear();
        self.error_message = None;
        self.is_creating = false;
    }

    /// Validates the input.
    ///
    /// Returns None if valid, or Some(error_message) if invalid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        if self.name.trim().is_empty() {
            return Some("Level name cannot be empty".to_string());
        }
        if self.password.is_empty() {
            return Some("Password cannot be empty".to_string());
        }
        if self.password != self.confirm_password {
            return Some("Passwords do not match".to_string());
        }
        if self.password.len() < 4 {
            return Some("Password must be at least 4 characters".to_string());
        }
        None
    }
}

/// Dialog state for changing a level's password.
#[derive(Debug, Clone, Default)]
pub struct ChangePasswordDialogState {
    /// Whether the dialog is open.
    pub is_open: bool,
    /// The level ID to change password for.
    pub level_id: u32,
    /// The level name (for display).
    pub level_name: String,
    /// Current password (for verification).
    pub current_password: String,
    /// New password.
    pub new_password: String,
    /// Confirm new password.
    pub confirm_password: String,
    /// Whether to show passwords.
    pub show_password: bool,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Whether change is in progress.
    pub is_changing: bool,
}

impl ChangePasswordDialogState {
    /// Opens the dialog for a specific level.
    pub fn open(&mut self, level_id: u32, level_name: &str) {
        self.is_open = true;
        self.level_id = level_id;
        self.level_name = level_name.to_string();
        self.current_password.clear();
        self.new_password.clear();
        self.confirm_password.clear();
        self.show_password = false;
        self.error_message = None;
        self.is_changing = false;
    }

    /// Closes the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
        self.level_id = 0;
        self.level_name.clear();
        self.current_password.clear();
        self.new_password.clear();
        self.confirm_password.clear();
        self.error_message = None;
        self.is_changing = false;
    }

    /// Validates the input.
    ///
    /// Returns None if valid, or Some(error_message) if invalid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        if self.current_password.is_empty() {
            return Some("Current password is required".to_string());
        }
        if self.new_password.is_empty() {
            return Some("New password cannot be empty".to_string());
        }
        if self.new_password != self.confirm_password {
            return Some("New passwords do not match".to_string());
        }
        if self.new_password.len() < 4 {
            return Some("Password must be at least 4 characters".to_string());
        }
        if self.current_password == self.new_password {
            return Some("New password must be different from current".to_string());
        }
        None
    }
}

/// Dialog state for confirming level deletion.
#[derive(Debug, Clone, Default)]
pub struct DeleteLevelDialogState {
    /// Whether the dialog is open.
    pub is_open: bool,
    /// The level ID to delete.
    pub level_id: u32,
    /// The level name (for display).
    pub level_name: String,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Whether deletion is in progress.
    pub is_deleting: bool,
}

impl DeleteLevelDialogState {
    /// Opens the dialog for a specific level.
    pub fn open(&mut self, level_id: u32, level_name: &str) {
        self.is_open = true;
        self.level_id = level_id;
        self.level_name = level_name.to_string();
        self.error_message = None;
        self.is_deleting = false;
    }

    /// Closes the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
        self.level_id = 0;
        self.level_name.clear();
        self.error_message = None;
        self.is_deleting = false;
    }
}

/// Dialog state for changing the drive master password (US-028).
#[derive(Debug, Clone, Default)]
pub struct DrivePasswordChangeState {
    /// Whether the dialog is open.
    pub is_open: bool,
    /// Current password (for verification).
    pub current_password: String,
    /// New password.
    pub new_password: String,
    /// Confirm new password.
    pub confirm_password: String,
    /// Whether to show passwords.
    pub show_password: bool,
    /// Password strength indicator.
    pub password_strength: PasswordStrength,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Success message (if any).
    pub success_message: Option<String>,
    /// Whether password change is in progress.
    pub is_changing: bool,
}

impl DrivePasswordChangeState {
    /// Opens the dialog.
    pub fn open(&mut self) {
        self.is_open = true;
        self.current_password.clear();
        self.new_password.clear();
        self.confirm_password.clear();
        self.show_password = false;
        self.password_strength = PasswordStrength::VeryWeak;
        self.error_message = None;
        self.success_message = None;
        self.is_changing = false;
    }

    /// Closes the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
        self.current_password.clear();
        self.new_password.clear();
        self.confirm_password.clear();
        self.error_message = None;
        self.success_message = None;
        self.is_changing = false;
    }

    /// Updates password strength from the new password.
    pub fn update_strength(&mut self) {
        self.password_strength = calculate_password_strength(&self.new_password);
    }

    /// Validates the input.
    ///
    /// Returns None if valid, or Some(error_message) if invalid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        if self.current_password.is_empty() {
            return Some("Current password is required".to_string());
        }
        if self.new_password.is_empty() {
            return Some("New password cannot be empty".to_string());
        }
        if self.new_password != self.confirm_password {
            return Some("New passwords do not match".to_string());
        }
        if !self.password_strength.is_acceptable() {
            return Some("Password strength must be at least Fair".to_string());
        }
        if self.current_password == self.new_password {
            return Some("New password must be different from current".to_string());
        }
        None
    }

    /// Sets an error message.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
        self.success_message = None;
        self.is_changing = false;
    }

    /// Sets a success message.
    pub fn set_success(&mut self, message: impl Into<String>) {
        self.success_message = Some(message.into());
        self.error_message = None;
        self.is_changing = false;
    }
}

/// State for the settings / access level management screen.
#[derive(Debug, Default)]
pub struct SettingsState {
    /// List of access levels with their info.
    pub levels: Vec<AccessLevelDisplayInfo>,
    /// Whether the levels list needs refresh.
    pub needs_refresh: bool,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Success message (if any).
    pub success_message: Option<String>,
    /// Create level dialog state.
    pub create_dialog: CreateLevelDialogState,
    /// Change password dialog state (for access levels).
    pub change_password_dialog: ChangePasswordDialogState,
    /// Delete level dialog state.
    pub delete_dialog: DeleteLevelDialogState,
    /// Drive password change dialog state (US-028).
    pub drive_password_change_dialog: DrivePasswordChangeState,
}

impl SettingsState {
    /// Creates a new settings state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            needs_refresh: true,
            ..Self::default()
        }
    }

    /// Clears any message.
    pub fn clear_messages(&mut self) {
        self.error_message = None;
        self.success_message = None;
    }

    /// Sets an error message.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
        self.success_message = None;
    }

    /// Sets a success message.
    pub fn set_success(&mut self, message: impl Into<String>) {
        self.success_message = Some(message.into());
        self.error_message = None;
    }

    /// Marks the levels list as needing refresh.
    pub fn mark_refresh_needed(&mut self) {
        self.needs_refresh = true;
    }

    /// Returns whether any dialog is open.
    #[must_use]
    pub fn has_open_dialog(&self) -> bool {
        self.create_dialog.is_open
            || self.change_password_dialog.is_open
            || self.delete_dialog.is_open
            || self.drive_password_change_dialog.is_open
    }

    /// Refreshes the access levels list from the vault.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the vault
    /// * `encryption_key` - Key for decrypting level config
    /// * `session` - Vault session for file count
    pub fn refresh_levels(
        &mut self,
        vault_path: &std::path::Path,
        encryption_key: &[u8; 32],
        session: &tesseract_core::session::VaultSession,
    ) {
        use tesseract_core::access::list_levels_info;

        self.levels.clear();
        self.needs_refresh = false;

        match list_levels_info(vault_path, encryption_key) {
            Ok(infos) => {
                for info in infos {
                    // Get file count for this level from session keystores
                    let file_count = session
                        .get_unlocked_keystore(info.id)
                        .map(|ks| ks.keystore().dek_count())
                        .unwrap_or(0);

                    self.levels.push(AccessLevelDisplayInfo::from_level_info(&info, file_count));
                }
            }
            Err(e) => {
                warn!("Failed to load access levels: {}", e);
                self.set_error(format!("Failed to load access levels: {}", e));
            }
        }
    }

    /// Returns the next available level ID (for creating new levels).
    #[must_use]
    pub fn next_available_level_id(&self) -> Option<u32> {
        if self.levels.len() >= 10 {
            return None; // Max 10 levels
        }

        // Find the first unused ID from 1 to 10
        let used_ids: std::collections::HashSet<u32> = self.levels.iter().map(|l| l.id).collect();
        (1..=10).find(|id| !used_ids.contains(id))
    }

    /// Returns whether a new level can be created.
    #[must_use]
    pub fn can_create_level(&self) -> bool {
        self.next_available_level_id().is_some()
    }
}

// =============================================================================
// Mount Point Selection
// =============================================================================

/// State for mount point (drive letter) selection.
#[derive(Debug, Clone)]
pub struct MountPointSelectionState {
    /// Currently selected drive letter (or None for auto-select).
    pub selected_letter: Option<char>,
    /// Whether auto-select mode is enabled.
    pub auto_select: bool,
    /// List of available drive letters with their status.
    pub drive_letters: Vec<DriveLetterDisplayInfo>,
    /// Whether the list needs refresh.
    pub needs_refresh: bool,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Success message (if any).
    pub success_message: Option<String>,
}

/// Display information for a drive letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveLetterDisplayInfo {
    /// The drive letter (A-Z).
    pub letter: char,
    /// Whether the drive letter is available.
    pub available: bool,
    /// Whether this is a reserved system drive.
    pub reserved: bool,
    /// Optional label if in use.
    pub label: Option<String>,
}

impl DriveLetterDisplayInfo {
    /// Creates a new display info from a VFS DriveLetterInfo.
    #[must_use]
    pub fn from_vfs(info: &tesseract_vfs::DriveLetterInfo) -> Self {
        Self {
            letter: info.letter,
            available: info.available,
            reserved: info.reserved,
            label: info.label.clone(),
        }
    }

    /// Returns a display string for the dropdown.
    #[must_use]
    pub fn display_string(&self) -> String {
        if self.reserved {
            format!("{}: (System)", self.letter)
        } else if self.available {
            format!("{}: (Available)", self.letter)
        } else if let Some(ref label) = self.label {
            format!("{}: {} (In Use)", self.letter, label)
        } else {
            format!("{}: (In Use)", self.letter)
        }
    }

    /// Returns true if this letter can be selected.
    #[must_use]
    pub fn is_selectable(&self) -> bool {
        self.available && !self.reserved
    }
}

impl Default for MountPointSelectionState {
    fn default() -> Self {
        Self {
            selected_letter: Some(tesseract_vfs::DEFAULT_DRIVE_LETTER),
            auto_select: false,
            drive_letters: Vec::new(),
            needs_refresh: true,
            error_message: None,
            success_message: None,
        }
    }
}

impl MountPointSelectionState {
    /// Creates a new mount point selection state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a mount point selection state from saved config.
    #[must_use]
    pub fn from_config(preferred_letter: Option<char>) -> Self {
        Self {
            selected_letter: preferred_letter,
            auto_select: preferred_letter.is_none(),
            needs_refresh: true,
            ..Self::default()
        }
    }

    /// Refreshes the list of available drive letters.
    pub fn refresh(&mut self) {
        self.drive_letters = tesseract_vfs::get_available_drive_letters()
            .iter()
            .map(DriveLetterDisplayInfo::from_vfs)
            .collect();
        self.needs_refresh = false;
        self.error_message = None;
    }

    /// Sets the selected drive letter.
    pub fn set_letter(&mut self, letter: char) {
        self.selected_letter = Some(letter.to_ascii_uppercase());
        self.auto_select = false;
        self.error_message = None;
        self.success_message = Some(format!("Drive letter set to {}: ", letter.to_ascii_uppercase()));
    }

    /// Enables auto-select mode.
    pub fn enable_auto_select(&mut self) {
        self.selected_letter = None;
        self.auto_select = true;
        self.error_message = None;
        self.success_message = Some("Auto-select enabled".to_string());
    }

    /// Returns the list of selectable drive letters.
    #[must_use]
    pub fn selectable_letters(&self) -> Vec<&DriveLetterDisplayInfo> {
        self.drive_letters
            .iter()
            .filter(|d| d.is_selectable())
            .collect()
    }

    /// Returns the first available drive letter.
    #[must_use]
    pub fn first_available(&self) -> Option<char> {
        // Try T first (default)
        if let Some(t) = self.drive_letters.iter().find(|d| d.letter == 'T') {
            if t.is_selectable() {
                return Some('T');
            }
        }

        // Otherwise, use preference order from VFS module
        for preferred in tesseract_vfs::PREFERRED_DRIVE_ORDER {
            if let Some(info) = self.drive_letters.iter().find(|d| d.letter == *preferred) {
                if info.is_selectable() {
                    return Some(info.letter);
                }
            }
        }

        // Fallback to any available
        self.drive_letters
            .iter()
            .find(|d| d.is_selectable())
            .map(|d| d.letter)
    }

    /// Gets the effective drive letter to use (resolves auto-select).
    #[must_use]
    pub fn get_effective_letter(&self) -> Option<char> {
        if self.auto_select {
            self.first_available()
        } else {
            self.selected_letter
        }
    }

    /// Validates the current selection.
    ///
    /// Returns Ok(letter) if valid, or Err with error message.
    pub fn validate(&self) -> Result<char, String> {
        let letter = self.get_effective_letter()
            .ok_or_else(|| "No available drive letters".to_string())?;

        // Check if the selected letter is available
        if let Some(info) = self.drive_letters.iter().find(|d| d.letter == letter) {
            if info.reserved {
                return Err(format!("Drive letter {}: is reserved for system use", letter));
            }
            if !info.available {
                return Err(format!("Drive letter {}: is already in use", letter));
            }
        }

        Ok(letter)
    }

    /// Returns whether drive letter selection is supported on this platform.
    #[must_use]
    pub fn is_supported() -> bool {
        tesseract_vfs::is_mount_point_selection_supported()
    }

    /// Returns help text for mount point selection.
    #[must_use]
    pub fn help_text() -> &'static str {
        tesseract_vfs::get_mount_point_help_message()
    }

    /// Clears messages.
    pub fn clear_messages(&mut self) {
        self.error_message = None;
        self.success_message = None;
    }

    /// Sets an error message.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
        self.success_message = None;
    }

    /// Sets a success message.
    pub fn set_success(&mut self, message: impl Into<String>) {
        self.success_message = Some(message.into());
        self.error_message = None;
    }
}

// =============================================================================
// Vault Creation Wizard
// =============================================================================

/// The current step in the vault creation wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardStep {
    /// Step 1: Choose vault location (must be on removable drive).
    #[default]
    Location,
    /// Step 2: Set master password with strength meter.
    Password,
    /// Step 3: Configure access levels (or use defaults).
    AccessLevels,
    /// Step 4: Display and confirm recovery key.
    RecoveryKey,
    /// Step 5: Creating vault (progress indicator).
    Creating,
    /// Step 6: Vault created successfully.
    Complete,
}

impl WizardStep {
    /// Returns the step number (1-indexed for display).
    #[must_use]
    pub fn number(&self) -> u8 {
        match self {
            Self::Location => 1,
            Self::Password => 2,
            Self::AccessLevels => 3,
            Self::RecoveryKey => 4,
            Self::Creating => 5,
            Self::Complete => 5,
        }
    }

    /// Returns the step title for display.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Self::Location => "Choose Location",
            Self::Password => "Set Password",
            Self::AccessLevels => "Access Levels",
            Self::RecoveryKey => "Recovery Key",
            Self::Creating => "Creating Vault",
            Self::Complete => "Complete",
        }
    }

    /// Returns true if this step allows going back.
    #[must_use]
    pub fn can_go_back(&self) -> bool {
        matches!(self, Self::Password | Self::AccessLevels | Self::RecoveryKey)
    }

    /// Returns true if this step allows going forward with Next button.
    #[must_use]
    pub fn has_next_button(&self) -> bool {
        matches!(self, Self::Location | Self::Password | Self::AccessLevels)
    }

    /// Returns the next step, if any.
    #[must_use]
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Location => Some(Self::Password),
            Self::Password => Some(Self::AccessLevels),
            Self::AccessLevels => Some(Self::RecoveryKey),
            Self::RecoveryKey => Some(Self::Creating),
            Self::Creating | Self::Complete => None,
        }
    }

    /// Returns the previous step, if any.
    #[must_use]
    pub fn previous(&self) -> Option<Self> {
        match self {
            Self::Location => None,
            Self::Password => Some(Self::Location),
            Self::AccessLevels => Some(Self::Password),
            Self::RecoveryKey => Some(Self::AccessLevels),
            Self::Creating | Self::Complete => None,
        }
    }
}

/// Password strength level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PasswordStrength {
    /// Password is too weak (< 8 chars or no variety).
    #[default]
    VeryWeak,
    /// Password is weak (minimal requirements only).
    Weak,
    /// Password is fair (meets basic requirements).
    Fair,
    /// Password is strong (good length and variety).
    Strong,
    /// Password is very strong (excellent).
    VeryStrong,
}

impl PasswordStrength {
    /// Returns a display label for the strength.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::VeryWeak => "Very Weak",
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Strong => "Strong",
            Self::VeryStrong => "Very Strong",
        }
    }

    /// Returns a color hint for display (0.0 = red, 1.0 = green).
    #[must_use]
    pub fn color_value(&self) -> f32 {
        match self {
            Self::VeryWeak => 0.0,
            Self::Weak => 0.25,
            Self::Fair => 0.5,
            Self::Strong => 0.75,
            Self::VeryStrong => 1.0,
        }
    }

    /// Returns the progress bar fill percentage (0.0 - 1.0).
    #[must_use]
    pub fn progress(&self) -> f32 {
        match self {
            Self::VeryWeak => 0.2,
            Self::Weak => 0.4,
            Self::Fair => 0.6,
            Self::Strong => 0.8,
            Self::VeryStrong => 1.0,
        }
    }

    /// Returns true if the password meets minimum requirements.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        matches!(self, Self::Fair | Self::Strong | Self::VeryStrong)
    }
}

/// Calculates password strength based on various criteria.
///
/// Criteria:
/// - Length (8+ minimum, 12+ better, 16+ excellent)
/// - Has lowercase letters
/// - Has uppercase letters
/// - Has digits
/// - Has special characters
/// - No common patterns (123, abc, qwerty, etc.)
#[must_use]
pub fn calculate_password_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::VeryWeak;
    }

    let len = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    // Count character classes
    let mut variety = 0;
    if has_lower { variety += 1; }
    if has_upper { variety += 1; }
    if has_digit { variety += 1; }
    if has_special { variety += 1; }

    // Check for common weak patterns
    let lower = password.to_lowercase();
    let has_common_pattern = lower.contains("123")
        || lower.contains("abc")
        || lower.contains("qwerty")
        || lower.contains("password")
        || lower.contains("admin")
        || lower.contains("letmein")
        || lower.contains("welcome");

    // Calculate score
    let mut score: i32 = 0;

    // Length scoring
    if len >= 8 { score += 1; }
    if len >= 12 { score += 1; }
    if len >= 16 { score += 1; }
    if len >= 20 { score += 1; }

    // Variety scoring
    score += variety as i32;

    // Penalties
    if has_common_pattern { score = score.saturating_sub(2); }
    if len < 8 { score = 0; } // Absolute minimum

    // Map score to strength
    match score {
        0 => PasswordStrength::VeryWeak,
        1..=2 => PasswordStrength::Weak,
        3..=4 => PasswordStrength::Fair,
        5..=6 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

/// Configuration for an access level during wizard setup.
#[derive(Debug, Clone)]
pub struct WizardAccessLevel {
    /// Level ID (1-10).
    pub id: u32,
    /// Display name for the level.
    pub name: String,
    /// Password for this level.
    pub password: String,
    /// Confirm password field.
    pub password_confirm: String,
    /// Whether password is shown.
    pub show_password: bool,
    /// Whether to use the same password as master.
    pub use_master_password: bool,
}

impl WizardAccessLevel {
    /// Creates a new level configuration with defaults.
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self {
            id,
            name: format!("Level {}", id),
            password: String::new(),
            password_confirm: String::new(),
            show_password: false,
            use_master_password: true,
        }
    }

    /// Returns true if passwords match.
    #[must_use]
    pub fn passwords_match(&self) -> bool {
        self.password == self.password_confirm
    }

    /// Returns true if this level configuration is valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.use_master_password {
            true
        } else {
            !self.password.is_empty() && self.passwords_match()
        }
    }
}

/// State for the vault creation wizard.
#[derive(Debug, Clone)]
pub struct VaultCreationWizardState {
    /// Current wizard step.
    pub step: WizardStep,
    /// Selected vault location path.
    pub vault_path: Option<PathBuf>,
    /// Whether we're checking if path is on removable drive.
    pub checking_removable: bool,
    /// Whether the path is on removable media (None = not checked yet).
    pub is_removable: Option<bool>,
    /// Error message for location step.
    pub location_error: Option<String>,
    /// Master password input.
    pub master_password: String,
    /// Master password confirmation input.
    pub master_password_confirm: String,
    /// Whether to show the master password.
    pub show_master_password: bool,
    /// Calculated password strength.
    pub password_strength: PasswordStrength,
    /// Access levels configuration.
    pub access_levels: Vec<WizardAccessLevel>,
    /// Whether to use default 3-level configuration.
    pub use_default_levels: bool,
    /// Number of levels (if not using defaults).
    pub level_count: u32,
    /// Recovery key mnemonic (set after creation).
    pub recovery_mnemonic: Option<String>,
    /// Recovery key base64 (set after creation).
    pub recovery_base64: Option<String>,
    /// Whether user has confirmed saving recovery key.
    pub recovery_confirmed: bool,
    /// Whether vault creation is in progress.
    pub creating: bool,
    /// Creation progress message.
    pub creation_progress: Option<String>,
    /// Creation error message (if failed).
    pub creation_error: Option<String>,
    /// The created master key (sensitive!).
    pub created_master_key: Option<[u8; 32]>,
    /// Timestamp when recovery key was copied to clipboard (for auto-clear).
    pub clipboard_copied_at: Option<Instant>,
}

impl Default for VaultCreationWizardState {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultCreationWizardState {
    /// Creates a new wizard state with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            step: WizardStep::Location,
            vault_path: None,
            checking_removable: false,
            is_removable: None,
            location_error: None,
            master_password: String::new(),
            master_password_confirm: String::new(),
            show_master_password: false,
            password_strength: PasswordStrength::VeryWeak,
            access_levels: vec![
                WizardAccessLevel::new(1),
                WizardAccessLevel::new(2),
                WizardAccessLevel::new(3),
            ],
            use_default_levels: true,
            level_count: 3,
            recovery_mnemonic: None,
            recovery_base64: None,
            recovery_confirmed: false,
            creating: false,
            creation_progress: None,
            creation_error: None,
            created_master_key: None,
            clipboard_copied_at: None,
        }
    }

    /// Creates a new wizard state starting at a specific path.
    #[must_use]
    pub fn with_path(path: PathBuf) -> Self {
        Self {
            vault_path: Some(path),
            ..Self::new()
        }
    }

    /// Resets the wizard to initial state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Updates password strength when master password changes.
    pub fn update_password_strength(&mut self) {
        self.password_strength = calculate_password_strength(&self.master_password);
    }

    /// Returns true if master passwords match.
    #[must_use]
    pub fn master_passwords_match(&self) -> bool {
        self.master_password == self.master_password_confirm
    }

    /// Returns true if the current step can proceed.
    #[must_use]
    pub fn can_proceed(&self) -> bool {
        match self.step {
            WizardStep::Location => {
                self.vault_path.is_some()
                    && self.location_error.is_none()
                    // For development, allow fixed disks (production would check is_removable)
                    && (self.is_removable.unwrap_or(true) || cfg!(debug_assertions))
            }
            WizardStep::Password => {
                self.password_strength.is_acceptable()
                    && self.master_passwords_match()
                    && !self.master_password.is_empty()
            }
            WizardStep::AccessLevels => {
                self.access_levels.iter().all(|l| l.is_valid())
            }
            WizardStep::RecoveryKey => {
                self.recovery_confirmed && self.recovery_mnemonic.is_some()
            }
            WizardStep::Creating | WizardStep::Complete => false,
        }
    }

    /// Advances to the next step if possible.
    pub fn next_step(&mut self) {
        if self.can_proceed() {
            if let Some(next) = self.step.next() {
                self.step = next;
            }
        }
    }

    /// Goes back to the previous step if possible.
    pub fn previous_step(&mut self) {
        if let Some(prev) = self.step.previous() {
            self.step = prev;
        }
    }

    /// Sets the vault path and validates it.
    pub fn set_vault_path(&mut self, path: PathBuf) {
        self.vault_path = Some(path.clone());
        self.location_error = None;
        self.is_removable = None;

        // Validate the path is suitable for a new vault
        match validate_new_vault_location(&path) {
            Ok(()) => {
                // Path is valid, check if removable
                #[cfg(any(windows, target_os = "linux"))]
                {
                    use tesseract_packaging::detection::is_removable_drive;
                    match is_removable_drive(&path) {
                        Ok(is_removable) => {
                            self.is_removable = Some(is_removable);
                            if !is_removable {
                                self.location_error = Some(
                                    "Warning: Selected location is not on a removable drive. \
                                     For maximum security, TESSERACT should be run from a USB drive."
                                        .to_string()
                                );
                            }
                        }
                        Err(_) => {
                            // Couldn't determine - allow anyway with warning
                            self.is_removable = Some(true);
                        }
                    }
                }
                #[cfg(not(any(windows, target_os = "linux")))]
                {
                    // macOS and other platforms: assume removable until detection is implemented
                    self.is_removable = Some(true);
                }
            }
            Err(e) => {
                self.location_error = Some(e.to_string());
            }
        }
    }

    /// Updates the level count and rebuilds access levels list.
    pub fn set_level_count(&mut self, count: u32) {
        let count = count.clamp(1, 10);
        self.level_count = count;

        // Adjust access_levels vector
        while self.access_levels.len() < count as usize {
            let id = (self.access_levels.len() + 1) as u32;
            self.access_levels.push(WizardAccessLevel::new(id));
        }
        self.access_levels.truncate(count as usize);
    }

    /// Returns the level passwords for vault creation.
    ///
    /// If use_master_password is set for a level, returns the master password.
    #[must_use]
    pub fn get_level_passwords(&self) -> Vec<String> {
        self.access_levels
            .iter()
            .map(|level| {
                if level.use_master_password {
                    self.master_password.clone()
                } else {
                    level.password.clone()
                }
            })
            .collect()
    }

    /// Sets the recovery key from vault creation result.
    pub fn set_recovery_key(&mut self, mnemonic: String, base64: String) {
        self.recovery_mnemonic = Some(mnemonic);
        self.recovery_base64 = Some(base64);
    }

    /// Records that the recovery key was copied to clipboard.
    pub fn mark_clipboard_copied(&mut self) {
        self.clipboard_copied_at = Some(Instant::now());
    }

    /// Returns true if clipboard should be cleared (60s elapsed).
    #[must_use]
    pub fn should_clear_clipboard(&self) -> bool {
        if let Some(copied_at) = self.clipboard_copied_at {
            copied_at.elapsed().as_secs() >= 60
        } else {
            false
        }
    }

    /// Returns remaining seconds until clipboard auto-clear, if applicable.
    #[must_use]
    pub fn clipboard_clear_countdown(&self) -> Option<u64> {
        self.clipboard_copied_at.map(|copied_at| {
            let elapsed = copied_at.elapsed().as_secs();
            if elapsed >= 60 { 0 } else { 60 - elapsed }
        })
    }

    /// Clears the clipboard timestamp after auto-clear.
    pub fn clear_clipboard_timestamp(&mut self) {
        self.clipboard_copied_at = None;
    }

    /// Generates a printable text format of the recovery key.
    ///
    /// Returns a formatted string suitable for printing or saving as a text file.
    #[must_use]
    pub fn generate_printable_recovery_key(&self) -> Option<String> {
        let mnemonic = self.recovery_mnemonic.as_ref()?;
        let base64 = self.recovery_base64.as_ref()?;
        let words: Vec<&str> = mnemonic.split_whitespace().collect();

        let mut output = String::new();
        output.push_str("═══════════════════════════════════════════════════════════════\n");
        output.push_str("                    TESSERACT RECOVERY KEY                      \n");
        output.push_str("═══════════════════════════════════════════════════════════════\n");
        output.push_str("\n");
        output.push_str("⚠ IMPORTANT: Store this document in a secure location!\n");
        output.push_str("   This is the ONLY way to recover access if you forget your password.\n");
        output.push_str("\n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str("                    24-Word Recovery Phrase                     \n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str("\n");

        // Display words in a 4-column grid
        for (i, word) in words.iter().enumerate() {
            output.push_str(&format!("  {:2}. {:<12}", i + 1, word));
            if (i + 1) % 4 == 0 {
                output.push('\n');
            }
        }
        output.push_str("\n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str("                    Base64 Format (Compact)                     \n");
        output.push_str("───────────────────────────────────────────────────────────────\n");
        output.push_str("\n");
        output.push_str(&format!("  {}\n", base64));
        output.push_str("\n");
        output.push_str("═══════════════════════════════════════════════════════════════\n");
        output.push_str("  Date Generated: ");
        // Add current date
        use std::time::{SystemTime, UNIX_EPOCH};
        if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let secs = duration.as_secs();
            // Simple date formatting (UTC)
            let days_since_epoch = secs / 86400;
            let years = 1970 + days_since_epoch / 365;
            let remaining_days = days_since_epoch % 365;
            let month = remaining_days / 30 + 1;
            let day = remaining_days % 30 + 1;
            output.push_str(&format!("{:04}-{:02}-{:02}\n", years, month, day));
        } else {
            output.push_str("Unknown\n");
        }
        output.push_str("═══════════════════════════════════════════════════════════════\n");

        Some(output)
    }

    /// Clears sensitive data from wizard state.
    pub fn clear_sensitive_data(&mut self) {
        // Zero out passwords
        self.master_password.clear();
        self.master_password.shrink_to_fit();
        self.master_password_confirm.clear();
        self.master_password_confirm.shrink_to_fit();

        for level in &mut self.access_levels {
            level.password.clear();
            level.password.shrink_to_fit();
            level.password_confirm.clear();
            level.password_confirm.shrink_to_fit();
        }

        // Zero out master key if present
        if let Some(ref mut key) = self.created_master_key {
            for byte in key.iter_mut() {
                *byte = 0;
            }
        }
        self.created_master_key = None;

        // Keep recovery key for final display, but it will be dropped when wizard closes
    }
}

// =============================================================================
// Password Recovery Flow
// =============================================================================

/// The current step in the password recovery flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryStep {
    /// Initial state: entering recovery key.
    #[default]
    EnterKey,
    /// Recovery key verified, entering new password.
    EnterNewPassword,
    /// Password reset successful.
    Success,
    /// Password reset failed.
    Failed,
}

impl RecoveryStep {
    /// Returns a display title for the current step.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Self::EnterKey => "Enter Recovery Key",
            Self::EnterNewPassword => "Set New Password",
            Self::Success => "Password Reset Complete",
            Self::Failed => "Password Reset Failed",
        }
    }
}

/// State for the password recovery flow.
#[derive(Debug, Clone, Default)]
pub struct PasswordRecoveryState {
    /// Current step in the recovery flow.
    pub step: RecoveryStep,
    /// Recovery key input (mnemonic phrase or base64).
    pub recovery_key_input: String,
    /// Whether to use base64 input mode (vs mnemonic).
    pub use_base64_mode: bool,
    /// Error message for recovery key validation.
    pub key_error: Option<String>,
    /// Whether key verification is in progress.
    pub verifying: bool,
    /// New password input.
    pub new_password: String,
    /// Confirm new password input.
    pub new_password_confirm: String,
    /// Whether to show the new password.
    pub show_password: bool,
    /// Calculated strength of new password.
    pub password_strength: PasswordStrength,
    /// Selected access level to reset (1-based).
    /// If None, resets master/level 1 password.
    pub target_level: u32,
    /// Available levels in the vault (loaded during recovery).
    pub available_levels: Vec<u32>,
    /// Whether password reset is in progress.
    pub resetting: bool,
    /// Success message after password reset.
    pub success_message: Option<String>,
    /// Error message if password reset failed.
    pub reset_error: Option<String>,
    /// Vault path being recovered.
    pub vault_path: Option<PathBuf>,
}

impl PasswordRecoveryState {
    /// Creates a new password recovery state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            step: RecoveryStep::EnterKey,
            recovery_key_input: String::new(),
            use_base64_mode: false,
            key_error: None,
            verifying: false,
            new_password: String::new(),
            new_password_confirm: String::new(),
            show_password: false,
            password_strength: PasswordStrength::VeryWeak,
            target_level: 1,
            available_levels: vec![1, 2, 3], // Default, will be updated after key verify
            resetting: false,
            success_message: None,
            reset_error: None,
            vault_path: None,
        }
    }

    /// Creates a new password recovery state for a specific vault.
    #[must_use]
    pub fn for_vault(path: PathBuf) -> Self {
        Self {
            vault_path: Some(path),
            ..Self::new()
        }
    }

    /// Resets the state to initial values.
    pub fn reset(&mut self) {
        let vault_path = self.vault_path.clone();
        *self = Self::new();
        self.vault_path = vault_path;
    }

    /// Resets the state completely including vault path.
    pub fn reset_completely(&mut self) {
        *self = Self::new();
    }

    /// Updates the password strength when the new password changes.
    pub fn update_password_strength(&mut self) {
        self.password_strength = calculate_password_strength(&self.new_password);
    }

    /// Returns true if the new passwords match.
    #[must_use]
    pub fn passwords_match(&self) -> bool {
        self.new_password == self.new_password_confirm
    }

    /// Returns true if the recovery key input is non-empty.
    #[must_use]
    pub fn has_recovery_key_input(&self) -> bool {
        !self.recovery_key_input.trim().is_empty()
    }

    /// Returns true if the recovery key can be verified.
    #[must_use]
    pub fn can_verify_key(&self) -> bool {
        self.has_recovery_key_input()
            && self.vault_path.is_some()
            && !self.verifying
            && self.key_error.is_none()
    }

    /// Returns true if the new password can be submitted.
    #[must_use]
    pub fn can_submit_password(&self) -> bool {
        !self.new_password.is_empty()
            && self.passwords_match()
            && self.password_strength.is_acceptable()
            && !self.resetting
    }

    /// Validates the recovery key format (basic check before API call).
    ///
    /// Returns Ok if format looks valid, Err with message otherwise.
    pub fn validate_recovery_key_format(&self) -> Result<(), String> {
        let input = self.recovery_key_input.trim();

        if input.is_empty() {
            return Err("Please enter your recovery key".to_string());
        }

        if self.use_base64_mode {
            // Base64: should be ~44 characters for 32 bytes
            if input.len() < 40 || input.len() > 48 {
                return Err("Base64 recovery key should be 44 characters".to_string());
            }
            // Basic character check
            if !input.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
                return Err("Invalid base64 characters".to_string());
            }
        } else {
            // Mnemonic: should be 24 words
            let words: Vec<&str> = input.split_whitespace().collect();
            if words.len() != 24 {
                return Err(format!(
                    "Recovery phrase must be exactly 24 words (you entered {})",
                    words.len()
                ));
            }
            // Words should be lowercase alphabetic
            for word in &words {
                if !word.chars().all(|c| c.is_ascii_lowercase()) {
                    return Err(format!(
                        "Word '{}' contains invalid characters. Use lowercase letters only.",
                        word
                    ));
                }
            }
        }

        Ok(())
    }

    /// Sets an error message for the recovery key input.
    pub fn set_key_error(&mut self, error: impl Into<String>) {
        self.key_error = Some(error.into());
    }

    /// Clears the key error message.
    pub fn clear_key_error(&mut self) {
        self.key_error = None;
    }

    /// Sets an error message for password reset.
    pub fn set_reset_error(&mut self, error: impl Into<String>) {
        self.reset_error = Some(error.into());
        self.step = RecoveryStep::Failed;
    }

    /// Marks recovery key as verified and moves to password step.
    pub fn key_verified(&mut self, levels: Vec<u32>) {
        self.step = RecoveryStep::EnterNewPassword;
        self.available_levels = if levels.is_empty() { vec![1] } else { levels };
        self.target_level = self.available_levels.first().copied().unwrap_or(1);
        self.verifying = false;
        self.key_error = None;
    }

    /// Marks password reset as successful.
    pub fn password_reset_success(&mut self) {
        self.step = RecoveryStep::Success;
        self.resetting = false;
        self.success_message = Some(format!(
            "Password for Level {} has been reset successfully!",
            self.target_level
        ));
        // Clear sensitive data
        self.clear_sensitive_data();
    }

    /// Clears sensitive data from the state.
    pub fn clear_sensitive_data(&mut self) {
        self.new_password.clear();
        self.new_password.shrink_to_fit();
        self.new_password_confirm.clear();
        self.new_password_confirm.shrink_to_fit();
        self.recovery_key_input.clear();
        self.recovery_key_input.shrink_to_fit();
    }

    /// Returns the vault name for display.
    #[must_use]
    pub fn vault_name(&self) -> String {
        self.vault_path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Unknown Vault".to_string())
    }
}

// ============================================================================
// Drive Detection State (US-022)
// ============================================================================

/// Display information for a detected USB drive.
#[derive(Debug, Clone)]
pub struct DriveDisplayInfo {
    /// The drive information from hardware detection.
    pub info: tesseract_hardware::detect::DriveInfo,
    /// Whether this drive is currently selected in the UI.
    pub selected: bool,
}

impl DriveDisplayInfo {
    /// Creates display info from hardware DriveInfo.
    #[must_use]
    pub fn from_drive_info(info: tesseract_hardware::detect::DriveInfo) -> Self {
        Self {
            info,
            selected: false,
        }
    }

    /// Returns the icon for this drive's encryption status.
    #[must_use]
    pub fn status_icon(&self) -> &'static str {
        use tesseract_hardware::detect::DriveType;
        match self.info.drive_type {
            DriveType::TesseractContainer if self.info.is_locked => "🔒",
            DriveType::TesseractContainer => "🔓",
            DriveType::SedOpal if self.info.is_locked => "🔒",
            DriveType::SedOpal => "🔓",
            DriveType::Unencrypted => "💽",
            DriveType::Unknown => "❓",
        }
    }

    /// Returns the status text for this drive.
    #[must_use]
    pub fn status_text(&self) -> &'static str {
        use tesseract_hardware::detect::DriveType;
        match self.info.drive_type {
            DriveType::TesseractContainer if self.info.is_locked => "Locked",
            DriveType::TesseractContainer => "Unlocked",
            DriveType::SedOpal if self.info.is_locked => "Opal Locked",
            DriveType::SedOpal => "Opal Unlocked",
            DriveType::Unencrypted => "Not Encrypted",
            DriveType::Unknown => "Unknown",
        }
    }

    /// Returns true if this drive can be initialized (encrypted).
    #[must_use]
    pub fn can_initialize(&self) -> bool {
        self.info.drive_type.can_initialize()
    }

    /// Returns true if this drive requires unlocking.
    #[must_use]
    pub fn can_unlock(&self) -> bool {
        self.info.requires_unlock()
    }
}

/// State for drive detection screen.
#[derive(Debug, Default)]
pub struct DriveDetectionState {
    /// List of detected drives.
    pub drives: Vec<DriveDisplayInfo>,
    /// Whether drives need to be refreshed.
    pub needs_refresh: bool,
    /// Error message (if any).
    pub error_message: Option<String>,
    /// Success message (if any).
    pub success_message: Option<String>,
    /// Info message (neutral, informational).
    pub info_message: Option<String>,
    /// Whether a scan is currently in progress.
    pub scanning: bool,
    /// Password input for unlock operation.
    pub unlock_password: String,
    /// Index of drive being unlocked (if any).
    pub unlocking_drive_index: Option<usize>,
    /// Whether the unlock dialog is open.
    pub show_unlock_dialog: bool,
    /// Whether to show the password in plain text.
    pub show_password: bool,
    /// Whether an unlock operation is in progress.
    pub unlocking: bool,
    /// Path to open after successful unlock (triggers vault browser transition).
    pub unlocked_vault_path: Option<std::path::PathBuf>,
    /// Index of drive being initialized (if any).
    pub initializing_drive_index: Option<usize>,
    /// Password for initialization.
    pub init_password: String,
    /// Password confirmation for initialization.
    pub init_password_confirm: String,
    /// Whether the initialize dialog is open.
    pub show_init_dialog: bool,
    /// Whether to show init password in plain text.
    pub show_init_password: bool,
    /// Whether an initialization operation is in progress.
    pub initializing: bool,
}

impl DriveDetectionState {
    /// Creates a new drive detection state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            needs_refresh: true,
            ..Self::default()
        }
    }

    /// Clears messages.
    pub fn clear_messages(&mut self) {
        self.error_message = None;
        self.success_message = None;
        self.info_message = None;
    }

    /// Sets an error message.
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error_message = Some(msg.into());
        self.success_message = None;
    }

    /// Sets a success message.
    pub fn set_success(&mut self, msg: impl Into<String>) {
        self.success_message = Some(msg.into());
        self.error_message = None;
        self.info_message = None;
    }

    /// Sets an informational message.
    pub fn set_info(&mut self, msg: impl Into<String>) {
        self.info_message = Some(msg.into());
        self.error_message = None;
        self.success_message = None;
    }

    /// Refreshes the drive list.
    pub fn refresh_drives(&mut self) {
        self.scanning = true;
        self.clear_messages();

        match tesseract_hardware::detect_drives() {
            Ok(drives) => {
                self.drives = drives.into_iter().map(DriveDisplayInfo::from_drive_info).collect();
                self.scanning = false;
                self.needs_refresh = false;
                if self.drives.is_empty() {
                    self.set_success("No USB drives detected. Connect a drive and click Refresh.");
                } else {
                    self.set_success(format!("Found {} drive(s)", self.drives.len()));
                }
            }
            Err(e) => {
                self.scanning = false;
                self.needs_refresh = false;
                self.set_error(format!("Failed to detect drives: {}", e));
            }
        }
    }

    /// Opens the unlock dialog for a drive.
    pub fn open_unlock_dialog(&mut self, index: usize) {
        self.unlocking_drive_index = Some(index);
        self.unlock_password.clear();
        self.show_unlock_dialog = true;
    }

    /// Closes the unlock dialog.
    pub fn close_unlock_dialog(&mut self) {
        self.unlocking_drive_index = None;
        self.unlock_password.clear();
        self.show_unlock_dialog = false;
        self.show_password = false;
        self.unlocking = false;
    }

    /// Opens the initialize dialog for a drive.
    pub fn open_init_dialog(&mut self, index: usize) {
        self.initializing_drive_index = Some(index);
        self.init_password.clear();
        self.init_password_confirm.clear();
        self.show_init_dialog = true;
    }

    /// Closes the initialize dialog.
    pub fn close_init_dialog(&mut self) {
        self.initializing_drive_index = None;
        self.init_password.clear();
        self.init_password_confirm.clear();
        self.show_init_dialog = false;
        self.show_init_password = false;
        self.initializing = false;
    }

    /// Clears sensitive password data.
    pub fn clear_sensitive_data(&mut self) {
        self.unlock_password.clear();
        self.unlock_password.shrink_to_fit();
        self.init_password.clear();
        self.init_password.shrink_to_fit();
        self.init_password_confirm.clear();
        self.init_password_confirm.shrink_to_fit();
    }
}

/// Encryption strength level for drive initialization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EncryptionStrength {
    /// Standard encryption (faster, suitable for most uses).
    #[default]
    Standard,
    /// High encryption (balanced security and performance).
    High,
    /// Maximum encryption (slowest but most secure).
    Maximum,
}

impl EncryptionStrength {
    /// Returns a description of this encryption strength level.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Standard => "Fast key derivation (64MB memory, 3 iterations). Suitable for most uses.",
            Self::High => "Balanced security (128MB memory, 4 iterations). Recommended for sensitive data.",
            Self::Maximum => "Maximum security (256MB memory, 6 iterations). For highly sensitive data.",
        }
    }

    /// Returns the Argon2id memory parameter in MB.
    #[must_use]
    pub fn memory_mb(&self) -> u32 {
        match self {
            Self::Standard => 64,
            Self::High => 128,
            Self::Maximum => 256,
        }
    }

    /// Returns the Argon2id iteration count.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        match self {
            Self::Standard => 3,
            Self::High => 4,
            Self::Maximum => 6,
        }
    }
}

/// Configuration for a single access level during initialization.
#[derive(Debug, Clone, Default)]
pub struct AccessLevelConfig {
    /// Name for this access level.
    pub name: String,
    /// Password for this access level.
    pub password: String,
    /// Confirmation of password.
    pub password_confirm: String,
    /// Whether this level is enabled.
    pub enabled: bool,
    /// Whether to show the password.
    pub show_password: bool,
}

impl AccessLevelConfig {
    /// Creates a new access level config with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            ..Self::default()
        }
    }

    /// Returns true if passwords match and meet minimum requirements.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if !self.enabled {
            return true;
        }
        !self.password.is_empty()
            && self.password.len() >= 8
            && self.password == self.password_confirm
    }

    /// Clears sensitive data.
    pub fn clear(&mut self) {
        self.password.clear();
        self.password.shrink_to_fit();
        self.password_confirm.clear();
        self.password_confirm.shrink_to_fit();
    }
}

/// Current step in the drive initialization wizard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DriveInitStep {
    /// Step 1: Drive selection and info display.
    #[default]
    DriveSelection,
    /// Step 2: Master password entry.
    MasterPassword,
    /// Step 3: Access level configuration.
    AccessLevels,
    /// Step 4: Encryption strength selection.
    EncryptionStrength,
    /// Step 5: Confirmation with warnings.
    Confirmation,
    /// Step 6: Progress display during initialization.
    Progress,
    /// Step 7: Success screen with recovery key.
    Success,
}

impl DriveInitStep {
    /// Returns the step number (1-indexed).
    #[must_use]
    pub fn number(&self) -> u8 {
        match self {
            Self::DriveSelection => 1,
            Self::MasterPassword => 2,
            Self::AccessLevels => 3,
            Self::EncryptionStrength => 4,
            Self::Confirmation => 5,
            Self::Progress => 6,
            Self::Success => 7,
        }
    }

    /// Returns the step title.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Self::DriveSelection => "Select Drive",
            Self::MasterPassword => "Set Master Password",
            Self::AccessLevels => "Configure Access Levels",
            Self::EncryptionStrength => "Encryption Strength",
            Self::Confirmation => "Confirm",
            Self::Progress => "Initializing",
            Self::Success => "Complete",
        }
    }

    /// Returns the next step, if any.
    #[must_use]
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::DriveSelection => Some(Self::MasterPassword),
            Self::MasterPassword => Some(Self::AccessLevels),
            Self::AccessLevels => Some(Self::EncryptionStrength),
            Self::EncryptionStrength => Some(Self::Confirmation),
            Self::Confirmation => Some(Self::Progress),
            Self::Progress => Some(Self::Success),
            Self::Success => None,
        }
    }

    /// Returns the previous step, if any.
    #[must_use]
    pub fn prev(&self) -> Option<Self> {
        match self {
            Self::DriveSelection => None,
            Self::MasterPassword => Some(Self::DriveSelection),
            Self::AccessLevels => Some(Self::MasterPassword),
            Self::EncryptionStrength => Some(Self::AccessLevels),
            Self::Confirmation => Some(Self::EncryptionStrength),
            Self::Progress => None, // Cannot go back during progress
            Self::Success => None,  // Cannot go back from success
        }
    }
}

/// State for the drive initialization wizard.
#[derive(Debug, Default)]
pub struct DriveInitWizardState {
    /// Whether the wizard is currently open.
    pub is_open: bool,
    /// Current wizard step.
    pub step: DriveInitStep,
    /// Index of the selected drive (from DriveDetectionState.drives).
    pub selected_drive_index: Option<usize>,
    /// Master password input.
    pub master_password: String,
    /// Master password confirmation.
    pub master_password_confirm: String,
    /// Whether to show master password.
    pub show_master_password: bool,
    /// Access level configurations (levels 1-4).
    pub access_levels: [AccessLevelConfig; 4],
    /// Selected encryption strength.
    pub encryption_strength: EncryptionStrength,
    /// User has confirmed data loss warning.
    pub confirmed_data_loss: bool,
    /// Progress percentage (0-100) during initialization.
    pub progress_percent: u8,
    /// Progress message.
    pub progress_message: String,
    /// Whether initialization is currently running.
    pub initializing: bool,
    /// Error message if initialization failed.
    pub error_message: Option<String>,
    /// Recovery key generated after successful initialization.
    pub recovery_key: Option<String>,
}

impl DriveInitWizardState {
    /// Creates a new wizard state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            access_levels: [
                AccessLevelConfig::new("Public"),
                AccessLevelConfig::new("Internal"),
                AccessLevelConfig::new("Confidential"),
                AccessLevelConfig::new("Restricted"),
            ],
            ..Self::default()
        }
    }

    /// Opens the wizard for the given drive index.
    pub fn open(&mut self, drive_index: usize) {
        self.reset();
        self.is_open = true;
        self.selected_drive_index = Some(drive_index);
        self.step = DriveInitStep::DriveSelection;
    }

    /// Closes the wizard without saving.
    pub fn close(&mut self) {
        self.reset();
    }

    /// Resets all wizard state to defaults.
    pub fn reset(&mut self) {
        self.is_open = false;
        self.step = DriveInitStep::DriveSelection;
        self.selected_drive_index = None;
        self.master_password.clear();
        self.master_password.shrink_to_fit();
        self.master_password_confirm.clear();
        self.master_password_confirm.shrink_to_fit();
        self.show_master_password = false;
        for level in &mut self.access_levels {
            level.clear();
            level.enabled = true;
        }
        self.encryption_strength = EncryptionStrength::default();
        self.confirmed_data_loss = false;
        self.progress_percent = 0;
        self.progress_message.clear();
        self.initializing = false;
        self.error_message = None;
        self.recovery_key = None;
    }

    /// Goes to the next step if allowed.
    pub fn next_step(&mut self) {
        if let Some(next) = self.step.next() {
            self.step = next;
        }
    }

    /// Goes to the previous step if allowed.
    pub fn prev_step(&mut self) {
        if let Some(prev) = self.step.prev() {
            self.step = prev;
        }
    }

    /// Returns true if the master password is valid.
    #[must_use]
    pub fn is_master_password_valid(&self) -> bool {
        !self.master_password.is_empty()
            && self.master_password.len() >= 8
            && self.master_password == self.master_password_confirm
    }

    /// Returns true if all enabled access levels are valid.
    #[must_use]
    pub fn are_access_levels_valid(&self) -> bool {
        self.access_levels.iter().all(|l| l.is_valid())
    }

    /// Returns true if the current step is complete and we can proceed.
    #[must_use]
    pub fn can_proceed(&self) -> bool {
        match self.step {
            DriveInitStep::DriveSelection => self.selected_drive_index.is_some(),
            DriveInitStep::MasterPassword => self.is_master_password_valid(),
            DriveInitStep::AccessLevels => self.are_access_levels_valid(),
            DriveInitStep::EncryptionStrength => true, // Always valid, has default
            DriveInitStep::Confirmation => self.confirmed_data_loss,
            DriveInitStep::Progress => false, // Cannot proceed during progress
            DriveInitStep::Success => true,   // Can close
        }
    }

    /// Returns true if we can go back from the current step.
    #[must_use]
    pub fn can_go_back(&self) -> bool {
        self.step.prev().is_some()
    }

    /// Sets the progress for the initialization.
    pub fn set_progress(&mut self, percent: u8, message: impl Into<String>) {
        self.progress_percent = percent.min(100);
        self.progress_message = message.into();
    }

    /// Sets an error message and allows retry.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
        self.initializing = false;
        // Go back to confirmation step to allow retry
        self.step = DriveInitStep::Confirmation;
    }

    /// Sets success and shows recovery key.
    pub fn set_success(&mut self, recovery_key: impl Into<String>) {
        self.recovery_key = Some(recovery_key.into());
        self.initializing = false;
        self.step = DriveInitStep::Success;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_vault_selection_error_display() {
        let path = PathBuf::from("/test/vault");

        let err = VaultSelectionError::NotAVault(path.clone());
        assert!(err.to_string().contains("Not a valid vault"));

        let err = VaultSelectionError::InvalidVault(path.clone(), "test".to_string());
        assert!(err.to_string().contains("Invalid vault"));
        assert!(err.to_string().contains("test"));

        let err = VaultSelectionError::DirectoryNotEmpty(path.clone());
        assert!(err.to_string().contains("not empty"));

        let err = VaultSelectionError::NotWritable(path);
        assert!(err.to_string().contains("Cannot write"));

        let err = VaultSelectionError::Cancelled;
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn test_validate_vault_nonexistent() {
        let path = PathBuf::from("/nonexistent/vault/path");
        let result = validate_vault(&path);

        assert!(matches!(result, Err(VaultSelectionError::NotAVault(_))));
    }

    #[test]
    fn test_validate_vault_file_not_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("not_a_directory");
        std::fs::write(&file_path, "test").unwrap();

        let result = validate_vault(&file_path);

        assert!(matches!(result, Err(VaultSelectionError::NotAVault(_))));
    }

    #[test]
    fn test_validate_vault_empty_directory() {
        let temp_dir = TempDir::new().unwrap();

        let result = validate_vault(temp_dir.path());

        assert!(matches!(result, Err(VaultSelectionError::NotAVault(_))));
    }

    #[test]
    fn test_validate_new_vault_location_empty_directory() {
        let temp_dir = TempDir::new().unwrap();

        let result = validate_new_vault_location(temp_dir.path());

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_new_vault_location_nonempty() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("file.txt"), "test").unwrap();

        let result = validate_new_vault_location(temp_dir.path());

        assert!(matches!(
            result,
            Err(VaultSelectionError::DirectoryNotEmpty(_))
        ));
    }

    #[test]
    fn test_validate_new_vault_location_new_directory() {
        let temp_dir = TempDir::new().unwrap();
        let new_path = temp_dir.path().join("new_vault");

        let result = validate_new_vault_location(&new_path);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_new_vault_location_invalid_parent() {
        let path = PathBuf::from("/nonexistent/parent/vault");

        let result = validate_new_vault_location(&path);

        assert!(matches!(result, Err(VaultSelectionError::NotWritable(_))));
    }

    #[test]
    fn test_vault_selection_state_new() {
        let state = VaultSelectionState::new();

        assert!(state.error_message.is_none());
        assert!(state.selected_path.is_none());
        assert!(!state.is_opening);
        assert!(!state.is_creating);
    }

    #[test]
    fn test_vault_selection_state_error_handling() {
        let mut state = VaultSelectionState::new();

        state.set_error("Test error");
        assert_eq!(state.error_message.as_deref(), Some("Test error"));

        state.clear_error();
        assert!(state.error_message.is_none());
    }

    #[test]
    fn test_format_relative_time_just_now() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(format_relative_time(now), "Just now");
        assert_eq!(format_relative_time(now - 30), "Just now");
    }

    #[test]
    fn test_format_relative_time_minutes() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(format_relative_time(now - 60), "1 minute ago");
        assert_eq!(format_relative_time(now - 120), "2 minutes ago");
        assert_eq!(format_relative_time(now - 3599), "59 minutes ago");
    }

    #[test]
    fn test_format_relative_time_hours() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(format_relative_time(now - 3600), "1 hour ago");
        assert_eq!(format_relative_time(now - 7200), "2 hours ago");
        assert_eq!(format_relative_time(now - 86399), "23 hours ago");
    }

    #[test]
    fn test_format_relative_time_days() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(format_relative_time(now - 86400), "Yesterday");
        assert_eq!(format_relative_time(now - 172800), "2 days ago");
    }

    #[test]
    fn test_format_relative_time_weeks() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(format_relative_time(now - 604800), "1 week ago");
        assert_eq!(format_relative_time(now - 1209600), "2 weeks ago");
    }

    #[test]
    fn test_format_relative_time_months() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(format_relative_time(now - 2592000), "1 month ago");
        assert_eq!(format_relative_time(now - 5184000), "2 months ago");
    }

    #[test]
    fn test_format_relative_time_future() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Future timestamp should show "Just now"
        assert_eq!(format_relative_time(now + 1000), "Just now");
    }

    #[test]
    fn test_handle_recent_vault_invalid() {
        let mut state = VaultSelectionState::new();
        let vault = crate::config::RecentVault::new(PathBuf::from("/nonexistent/vault"));

        let result = state.handle_recent_vault_click(&vault);

        assert!(result.is_none());
        assert!(state.error_message.is_some());
    }

    // =========================================================================
    // Password Entry Screen Tests
    // =========================================================================

    #[test]
    fn test_auth_status_default() {
        let status = AuthStatus::default();
        assert!(matches!(status, AuthStatus::Idle));
    }

    #[test]
    fn test_auth_status_variants() {
        // Test all variants can be created
        let _ = AuthStatus::Idle;
        let _ = AuthStatus::Deriving;
        let _ = AuthStatus::Success;
        let _ = AuthStatus::Failed("test".to_string());
        let _ = AuthStatus::LockedOut { until: 12345, attempts: 3 };
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::WrongPassword;
        assert!(err.to_string().contains("Incorrect password"));

        let err = AuthError::IntegrityFailed;
        assert!(err.to_string().contains("integrity"));

        let err = AuthError::IoError("read error".to_string());
        assert!(err.to_string().contains("read error"));

        let err = AuthError::Other("custom error".to_string());
        assert!(err.to_string().contains("custom error"));
    }

    #[test]
    fn test_auth_error_lockout_display() {
        let future_time = current_timestamp() + 600; // 10 minutes from now
        let err = AuthError::LockedOut { until: future_time, attempts: 5 };
        let display = err.to_string();
        assert!(display.contains("locked"));
        assert!(display.contains("5"));
    }

    #[test]
    fn test_password_entry_state_new() {
        let state = PasswordEntryState::new();

        assert!(state.password.is_empty());
        assert!(!state.show_password);
        assert!(matches!(state.status, AuthStatus::Idle));
        assert_eq!(state.failed_attempts, 0);
        assert_eq!(state.lockout_remaining, 0);
        assert!(state.vault_path.is_none());
        assert!(state.header.is_none());
        assert!(state.argon2_params.is_none());
    }

    #[test]
    fn test_password_entry_state_for_vault() {
        let path = PathBuf::from("/test/vault");
        let state = PasswordEntryState::for_vault(path.clone());

        assert_eq!(state.vault_path, Some(path));
        assert!(state.password.is_empty());
    }

    #[test]
    fn test_password_entry_state_clear_password() {
        let mut state = PasswordEntryState::new();
        state.password = "secret123".to_string();
        state.show_password = true;

        state.clear_password();

        assert!(state.password.is_empty());
        assert!(!state.show_password);
    }

    #[test]
    fn test_password_entry_state_reset() {
        let mut state = PasswordEntryState::new();
        state.password = "secret".to_string();
        state.status = AuthStatus::Failed("test".to_string());

        state.reset();

        assert!(state.password.is_empty());
        assert!(matches!(state.status, AuthStatus::Idle));
    }

    #[test]
    fn test_password_entry_state_reset_for_vault() {
        let mut state = PasswordEntryState::new();
        state.password = "old_password".to_string();
        state.failed_attempts = 3;
        state.status = AuthStatus::Failed("error".to_string());

        let new_path = PathBuf::from("/new/vault");
        state.reset_for_vault(new_path.clone());

        assert!(state.password.is_empty());
        assert_eq!(state.vault_path, Some(new_path));
        assert_eq!(state.failed_attempts, 0);
        assert!(matches!(state.status, AuthStatus::Idle));
    }

    #[test]
    fn test_password_entry_state_can_attempt_auth() {
        let mut state = PasswordEntryState::new();

        // No header loaded - cannot attempt
        assert!(!state.can_attempt_auth());

        // With header but deriving - cannot attempt
        state.header = Some(VaultHeader::new([0u8; 16], [0u8; 48], [0u8; 12]));
        state.status = AuthStatus::Deriving;
        assert!(!state.can_attempt_auth());

        // With header and idle - can attempt
        state.status = AuthStatus::Idle;
        assert!(state.can_attempt_auth());

        // With header and failed (retry) - can attempt
        state.status = AuthStatus::Failed("error".to_string());
        assert!(state.can_attempt_auth());

        // Locked out - cannot attempt
        state.lockout_remaining = 100;
        assert!(!state.can_attempt_auth());
    }

    #[test]
    fn test_password_entry_state_is_deriving() {
        let mut state = PasswordEntryState::new();

        assert!(!state.is_deriving());

        state.status = AuthStatus::Deriving;
        assert!(state.is_deriving());

        state.status = AuthStatus::Idle;
        assert!(!state.is_deriving());
    }

    #[test]
    fn test_password_entry_state_is_locked_out() {
        let mut state = PasswordEntryState::new();

        assert!(!state.is_locked_out());

        state.status = AuthStatus::LockedOut { until: 12345, attempts: 3 };
        assert!(state.is_locked_out());
    }

    #[test]
    fn test_password_entry_state_error_message() {
        let mut state = PasswordEntryState::new();

        assert!(state.error_message().is_none());

        state.status = AuthStatus::Failed("test error".to_string());
        assert_eq!(state.error_message(), Some("test error"));

        state.status = AuthStatus::Success;
        assert!(state.error_message().is_none());
    }

    #[test]
    fn test_password_entry_state_vault_name() {
        let state = PasswordEntryState::new();
        assert_eq!(state.vault_name(), "Unknown Vault");

        let state = PasswordEntryState::for_vault(PathBuf::from("/path/to/MyVault"));
        assert_eq!(state.vault_name(), "MyVault");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(0), "0 seconds");
        assert_eq!(format_duration(1), "1 second");
        assert_eq!(format_duration(30), "30 seconds");
        assert_eq!(format_duration(59), "59 seconds");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1 minute");
        assert_eq!(format_duration(120), "2 minutes");
        assert_eq!(format_duration(90), "1:30");
        assert_eq!(format_duration(3599), "59:59");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1:00:00");
        assert_eq!(format_duration(7261), "2:01:01");
    }

    #[test]
    fn test_calculate_backoff() {
        assert_eq!(calculate_backoff(0), 0);
        assert_eq!(calculate_backoff(1), BACKOFF_BASE_SECONDS);
        assert_eq!(calculate_backoff(2), BACKOFF_BASE_SECONDS * 2);
        assert_eq!(calculate_backoff(3), BACKOFF_BASE_SECONDS * 4);

        // Check cap at max
        assert!(calculate_backoff(30) <= BACKOFF_MAX_SECONDS);
    }

    #[test]
    fn test_should_trigger_lockout() {
        assert!(!should_trigger_lockout(0));
        assert!(!should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD - 1));
        assert!(should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD));
        assert!(should_trigger_lockout(DEFAULT_LOCKOUT_THRESHOLD + 1));
    }

    #[test]
    fn test_default_lockout_duration() {
        assert_eq!(default_lockout_duration(), DEFAULT_LOCKOUT_DURATION_SECONDS);
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        // Reasonable timestamp (after 2020)
        assert!(ts > 1577836800);
    }

    #[test]
    fn test_create_shared_auth_result() {
        let shared = create_shared_auth_result();

        // Initially None
        assert!(shared.lock().unwrap().is_none());

        // Can set value
        *shared.lock().unwrap() = Some(AuthResult::InProgress);
        assert!(shared.lock().unwrap().is_some());
    }

    #[test]
    fn test_auth_result_variants() {
        let _ = AuthResult::Success([0u8; 32]);
        let _ = AuthResult::Failed(AuthError::WrongPassword);
        let _ = AuthResult::InProgress;
    }

    // =========================================================================
    // File Browser Screen Tests
    // =========================================================================

    #[test]
    fn test_file_browser_state_new() {
        let state = FileBrowserState::new();

        assert_eq!(state.current_path, "/");
        assert_eq!(state.breadcrumbs, vec!["/"]);
        assert!(state.entries.is_empty());
        assert!(state.selected.is_empty());
        assert!(matches!(state.selection_mode, SelectionMode::None));
        assert!(matches!(state.sort_column, SortColumn::Name));
        assert!(matches!(state.sort_direction, SortDirection::Ascending));
        assert_eq!(state.current_access_level, 0);
        assert_eq!(state.max_access_level, 0);
        assert!(!state.is_loading);
        assert!(state.error_message.is_none());
    }

    #[test]
    fn test_file_browser_state_error_handling() {
        let mut state = FileBrowserState::new();

        assert!(state.error_message.is_none());

        state.set_error("Test error");
        assert_eq!(state.error_message.as_deref(), Some("Test error"));

        state.clear_error();
        assert!(state.error_message.is_none());
    }

    #[test]
    fn test_file_browser_state_selection() {
        let mut state = FileBrowserState::new();

        assert!(!state.has_selection());
        assert_eq!(state.selection_count(), 0);
        assert!(state.single_selection().is_none());

        // Add a selection
        let uuid1 = uuid::Uuid::new_v4();
        state.selected.insert(uuid1);
        state.selection_mode = SelectionMode::Single;

        assert!(state.has_selection());
        assert_eq!(state.selection_count(), 1);
        assert_eq!(state.single_selection(), Some(uuid1));

        // Add another selection
        let uuid2 = uuid::Uuid::new_v4();
        state.selected.insert(uuid2);
        state.selection_mode = SelectionMode::Multi;

        assert!(state.has_selection());
        assert_eq!(state.selection_count(), 2);
        assert!(state.single_selection().is_none()); // Not exactly 1

        // Clear selection
        state.clear_selection();

        assert!(!state.has_selection());
        assert_eq!(state.selection_count(), 0);
        assert!(matches!(state.selection_mode, SelectionMode::None));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("  /  "), "/");
        assert_eq!(normalize_path("/docs"), "/docs");
        assert_eq!(normalize_path("docs"), "/docs");
        assert_eq!(normalize_path("/docs/"), "/docs");
        assert_eq!(normalize_path("//docs//reports//"), "/docs/reports");
        assert_eq!(normalize_path("/a/b/c"), "/a/b/c");
    }

    #[test]
    fn test_parent_path() {
        assert_eq!(parent_path("/"), "/");
        assert_eq!(parent_path(""), "/");
        assert_eq!(parent_path("/docs"), "/");
        assert_eq!(parent_path("/docs/reports"), "/docs");
        assert_eq!(parent_path("/a/b/c"), "/a/b");
        assert_eq!(parent_path("/a/b/c/"), "/a/b");
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(500), "500 B");
        assert_eq!(format_file_size(1023), "1023 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.0 GB");
        assert_eq!(format_file_size(1099511627776), "1.0 TB");
    }

    #[test]
    fn test_format_timestamp_today() {
        let now = current_timestamp();
        let result = format_timestamp(now);
        assert!(result.contains("Today"));
    }

    #[test]
    fn test_format_timestamp_yesterday() {
        let yesterday = current_timestamp() - 86400;
        let result = format_timestamp(yesterday);
        assert_eq!(result, "Yesterday");
    }

    #[test]
    fn test_format_timestamp_days_ago() {
        let three_days_ago = current_timestamp() - (3 * 86400);
        let result = format_timestamp(three_days_ago);
        assert!(result.contains("days ago"));
    }

    #[test]
    fn test_format_timestamp_weeks_ago() {
        let two_weeks_ago = current_timestamp() - (14 * 86400);
        let result = format_timestamp(two_weeks_ago);
        assert!(result.contains("week"));
    }

    #[test]
    fn test_entry_icon_directory() {
        let entry = FileEntry::new_directory("test".to_string(), 1, 0);
        assert_eq!(entry_icon(&entry), "📁");
    }

    #[test]
    fn test_entry_icon_files() {
        // PDF
        let entry = FileEntry::new_file("doc.pdf".to_string(), 100, 0, 1, uuid::Uuid::new_v4());
        assert_eq!(entry_icon(&entry), "📄");

        // Image
        let entry = FileEntry::new_file("image.png".to_string(), 100, 0, 1, uuid::Uuid::new_v4());
        assert_eq!(entry_icon(&entry), "🖼");

        // Audio
        let entry = FileEntry::new_file("song.mp3".to_string(), 100, 0, 1, uuid::Uuid::new_v4());
        assert_eq!(entry_icon(&entry), "🎵");

        // Video
        let entry = FileEntry::new_file("video.mp4".to_string(), 100, 0, 1, uuid::Uuid::new_v4());
        assert_eq!(entry_icon(&entry), "🎬");

        // Archive
        let entry = FileEntry::new_file("archive.zip".to_string(), 100, 0, 1, uuid::Uuid::new_v4());
        assert_eq!(entry_icon(&entry), "📦");

        // Unknown
        let entry = FileEntry::new_file("unknown.xyz".to_string(), 100, 0, 1, uuid::Uuid::new_v4());
        assert_eq!(entry_icon(&entry), "📄");
    }

    #[test]
    fn test_level_label() {
        assert_eq!(level_label(1), "L1");
        assert_eq!(level_label(2), "L2");
        assert_eq!(level_label(3), "L3");
        assert_eq!(level_label(4), "L4");
        assert_eq!(level_label(5), "L5");
        assert_eq!(level_label(99), "L?");
    }

    #[test]
    fn test_selection_mode_default() {
        let mode = SelectionMode::default();
        assert!(matches!(mode, SelectionMode::None));
    }

    #[test]
    fn test_sort_column_default() {
        let col = SortColumn::default();
        assert!(matches!(col, SortColumn::Name));
    }

    #[test]
    fn test_sort_direction_default() {
        let dir = SortDirection::default();
        assert!(matches!(dir, SortDirection::Ascending));
    }

    #[test]
    fn test_file_browser_toggle_sort() {
        let mut state = FileBrowserState::new();

        // Initial state: Name ascending
        assert!(matches!(state.sort_column, SortColumn::Name));
        assert!(matches!(state.sort_direction, SortDirection::Ascending));

        // Toggle same column: becomes descending
        state.toggle_sort(SortColumn::Name);
        assert!(matches!(state.sort_column, SortColumn::Name));
        assert!(matches!(state.sort_direction, SortDirection::Descending));

        // Toggle same column again: becomes ascending
        state.toggle_sort(SortColumn::Name);
        assert!(matches!(state.sort_column, SortColumn::Name));
        assert!(matches!(state.sort_direction, SortDirection::Ascending));

        // Switch to different column: resets to ascending
        state.toggle_sort(SortColumn::Size);
        assert!(matches!(state.sort_column, SortColumn::Size));
        assert!(matches!(state.sort_direction, SortDirection::Ascending));
    }

    #[test]
    fn test_file_browser_breadcrumb_update() {
        let mut state = FileBrowserState::new();

        // Root path
        state.current_path = "/".to_string();
        state.update_breadcrumbs();
        assert_eq!(state.breadcrumbs, vec!["/"]);

        // Single level
        state.current_path = "/docs".to_string();
        state.update_breadcrumbs();
        assert_eq!(state.breadcrumbs, vec!["/", "docs"]);

        // Multiple levels
        state.current_path = "/docs/reports/2024".to_string();
        state.update_breadcrumbs();
        assert_eq!(state.breadcrumbs, vec!["/", "docs", "reports", "2024"]);
    }

    // =========================================================================
    // Import Status Tests
    // =========================================================================

    #[test]
    fn test_import_status_default() {
        let status = ImportStatus::default();
        assert!(matches!(status, ImportStatus::Idle));
    }

    #[test]
    fn test_import_status_variants() {
        // Test all variants can be created
        let _ = ImportStatus::Idle;
        let _ = ImportStatus::ShowingDialog;
        let _ = ImportStatus::Importing {
            current: 1,
            total: 5,
            current_file: "test.txt".to_string(),
        };
        let _ = ImportStatus::Completed {
            success_count: 3,
            failure_count: 2,
            errors: vec!["error1".to_string()],
        };
    }

    #[test]
    fn test_pending_import_from_bytes() {
        let content = vec![1u8, 2, 3, 4, 5];
        let pending = PendingImport::from_bytes("test.bin".to_string(), content.clone());

        assert_eq!(pending.filename, "test.bin");
        assert_eq!(pending.size, 5);
        assert!(pending.path.is_none());
        assert_eq!(pending.content, Some(content));
    }

    #[test]
    fn test_pending_import_from_path_nonexistent() {
        let path = PathBuf::from("/nonexistent/file.txt");
        let result = PendingImport::from_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_file_browser_state_import_initial() {
        let state = FileBrowserState::new();

        assert!(!state.drag_hover_active);
        assert!(matches!(state.import_status, ImportStatus::Idle));
        assert!(state.pending_imports.is_empty());
        assert_eq!(state.import_access_level, 1);
    }

    #[test]
    fn test_file_browser_state_import_helpers() {
        let mut state = FileBrowserState::new();

        // Initial state
        assert!(!state.should_show_import_dialog());
        assert!(!state.is_importing());
        assert!(!state.has_import_result());

        // ShowingDialog state
        state.import_status = ImportStatus::ShowingDialog;
        assert!(state.should_show_import_dialog());
        assert!(!state.is_importing());
        assert!(!state.has_import_result());

        // Importing state
        state.import_status = ImportStatus::Importing {
            current: 1,
            total: 3,
            current_file: "file.txt".to_string(),
        };
        assert!(!state.should_show_import_dialog());
        assert!(state.is_importing());
        assert!(!state.has_import_result());

        // Completed state
        state.import_status = ImportStatus::Completed {
            success_count: 2,
            failure_count: 1,
            errors: vec!["error".to_string()],
        };
        assert!(!state.should_show_import_dialog());
        assert!(!state.is_importing());
        assert!(state.has_import_result());
    }

    #[test]
    fn test_file_browser_state_cancel_import() {
        let mut state = FileBrowserState::new();

        // Set up import state
        state.pending_imports.push(PendingImport::from_bytes(
            "test.txt".to_string(),
            vec![1, 2, 3],
        ));
        state.import_status = ImportStatus::ShowingDialog;
        state.drag_hover_active = true;

        // Cancel
        state.cancel_import();

        assert!(state.pending_imports.is_empty());
        assert!(matches!(state.import_status, ImportStatus::Idle));
        assert!(!state.drag_hover_active);
    }

    #[test]
    fn test_file_browser_state_dismiss_import_result() {
        let mut state = FileBrowserState::new();
        state.import_status = ImportStatus::Completed {
            success_count: 5,
            failure_count: 0,
            errors: vec![],
        };

        state.dismiss_import_result();

        assert!(matches!(state.import_status, ImportStatus::Idle));
    }

    #[test]
    fn test_file_browser_state_pending_imports_total_size() {
        let mut state = FileBrowserState::new();

        assert_eq!(state.pending_imports_total_size(), 0);

        state.pending_imports.push(PendingImport::from_bytes(
            "file1.txt".to_string(),
            vec![0; 100],
        ));
        state.pending_imports.push(PendingImport::from_bytes(
            "file2.txt".to_string(),
            vec![0; 50],
        ));

        assert_eq!(state.pending_imports_total_size(), 150);
    }

    #[test]
    fn test_file_browser_state_start_import_empty() {
        let mut state = FileBrowserState::new();

        // Cannot start import with no pending files
        let result = state.start_import();
        assert!(!result);
        assert!(matches!(state.import_status, ImportStatus::Idle));
    }

    #[test]
    fn test_file_browser_state_start_import_with_files() {
        let mut state = FileBrowserState::new();

        state.pending_imports.push(PendingImport::from_bytes(
            "test1.txt".to_string(),
            vec![1, 2, 3],
        ));
        state.pending_imports.push(PendingImport::from_bytes(
            "test2.txt".to_string(),
            vec![4, 5, 6],
        ));

        let result = state.start_import();
        assert!(result);

        if let ImportStatus::Importing { current, total, current_file } = &state.import_status {
            assert_eq!(*current, 1);
            assert_eq!(*total, 2);
            assert_eq!(current_file, "test1.txt");
        } else {
            panic!("Expected ImportStatus::Importing");
        }
    }

    // =========================================================================
    // Export Status Tests
    // =========================================================================

    #[test]
    fn test_export_status_default() {
        let status = ExportStatus::default();
        assert!(matches!(status, ExportStatus::Idle));
    }

    #[test]
    fn test_export_status_variants() {
        // Test all variants can be created
        let _ = ExportStatus::Idle;
        let _ = ExportStatus::SelectingDestination;
        let _ = ExportStatus::Exporting {
            current: 1,
            total: 5,
            current_file: "test.txt".to_string(),
        };
        let _ = ExportStatus::Completed {
            success_count: 3,
            failure_count: 2,
            errors: vec!["error1".to_string()],
            destination: PathBuf::from("/tmp/export"),
        };
    }

    #[test]
    fn test_file_browser_state_export_initial() {
        let state = FileBrowserState::new();

        assert!(matches!(state.export_status, ExportStatus::Idle));
        assert!(state.export_destination.is_none());
    }

    #[test]
    fn test_file_browser_state_export_helpers() {
        let mut state = FileBrowserState::new();

        // Initial state
        assert!(!state.is_exporting());
        assert!(!state.has_export_result());

        // Exporting state
        state.export_status = ExportStatus::Exporting {
            current: 1,
            total: 3,
            current_file: "file.txt".to_string(),
        };
        assert!(state.is_exporting());
        assert!(!state.has_export_result());

        // Completed state
        state.export_status = ExportStatus::Completed {
            success_count: 2,
            failure_count: 1,
            errors: vec!["error".to_string()],
            destination: PathBuf::from("/tmp/export"),
        };
        assert!(!state.is_exporting());
        assert!(state.has_export_result());
    }

    #[test]
    fn test_file_browser_state_dismiss_export_result() {
        let mut state = FileBrowserState::new();
        state.export_status = ExportStatus::Completed {
            success_count: 5,
            failure_count: 0,
            errors: vec![],
            destination: PathBuf::from("/tmp/export"),
        };
        state.export_destination = Some(PathBuf::from("/tmp/export"));

        state.dismiss_export_result();

        assert!(matches!(state.export_status, ExportStatus::Idle));
        assert!(state.export_destination.is_none());
    }

    #[test]
    fn test_file_browser_state_cancel_export() {
        let mut state = FileBrowserState::new();
        state.export_status = ExportStatus::SelectingDestination;
        state.export_destination = Some(PathBuf::from("/tmp/export"));

        state.cancel_export();

        assert!(matches!(state.export_status, ExportStatus::Idle));
        assert!(state.export_destination.is_none());
    }

    #[test]
    fn test_file_browser_state_get_selected_entries() {
        let mut state = FileBrowserState::new();

        // No entries, no selection
        assert!(state.get_selected_entries().is_empty());

        // Add some entries
        let uuid1 = uuid::Uuid::new_v4();
        let uuid2 = uuid::Uuid::new_v4();
        let uuid3 = uuid::Uuid::new_v4();

        state.entries.push(FileEntry::new_file("file1.txt".to_string(), 100, 0, 1, uuid1));
        state.entries.push(FileEntry::new_file("file2.txt".to_string(), 200, 0, 1, uuid2));
        state.entries.push(FileEntry::new_file("file3.txt".to_string(), 300, 0, 1, uuid3));

        // Select two files
        state.selected.insert(uuid1);
        state.selected.insert(uuid3);

        let selected = state.get_selected_entries();
        assert_eq!(selected.len(), 2);

        let selected_names: Vec<&str> = selected.iter().map(|e| e.name.as_str()).collect();
        assert!(selected_names.contains(&"file1.txt"));
        assert!(selected_names.contains(&"file3.txt"));
        assert!(!selected_names.contains(&"file2.txt"));
    }

    // =========================================================================
    // Settings State Tests (US-039)
    // =========================================================================

    #[test]
    fn test_settings_state_new() {
        let state = SettingsState::new();
        assert!(state.levels.is_empty());
        assert!(state.needs_refresh);
        assert!(state.error_message.is_none());
        assert!(state.success_message.is_none());
    }

    #[test]
    fn test_settings_state_messages() {
        let mut state = SettingsState::new();

        state.set_error("Test error");
        assert_eq!(state.error_message, Some("Test error".to_string()));
        assert!(state.success_message.is_none());

        state.set_success("Test success");
        assert_eq!(state.success_message, Some("Test success".to_string()));
        assert!(state.error_message.is_none());

        state.clear_messages();
        assert!(state.error_message.is_none());
        assert!(state.success_message.is_none());
    }

    #[test]
    fn test_settings_state_has_open_dialog() {
        let mut state = SettingsState::new();
        assert!(!state.has_open_dialog());

        state.create_dialog.is_open = true;
        assert!(state.has_open_dialog());

        state.create_dialog.is_open = false;
        state.change_password_dialog.is_open = true;
        assert!(state.has_open_dialog());

        state.change_password_dialog.is_open = false;
        state.delete_dialog.is_open = true;
        assert!(state.has_open_dialog());
    }

    #[test]
    fn test_create_level_dialog_state() {
        let mut dialog = CreateLevelDialogState::default();
        assert!(!dialog.is_open);

        dialog.open();
        assert!(dialog.is_open);
        assert!(dialog.name.is_empty());
        assert!(dialog.password.is_empty());

        dialog.name = "Test".to_string();
        dialog.close();
        assert!(!dialog.is_open);
        assert!(dialog.name.is_empty());
    }

    #[test]
    fn test_create_level_dialog_validation() {
        let mut dialog = CreateLevelDialogState::default();

        // Empty name
        dialog.password = "test1234".to_string();
        dialog.confirm_password = "test1234".to_string();
        assert!(dialog.validate().is_some());

        // Empty password
        dialog.name = "Test".to_string();
        dialog.password.clear();
        dialog.confirm_password.clear();
        assert!(dialog.validate().is_some());

        // Passwords don't match
        dialog.password = "test1234".to_string();
        dialog.confirm_password = "different".to_string();
        assert!(dialog.validate().is_some());

        // Password too short
        dialog.password = "abc".to_string();
        dialog.confirm_password = "abc".to_string();
        assert!(dialog.validate().is_some());

        // Valid
        dialog.password = "test1234".to_string();
        dialog.confirm_password = "test1234".to_string();
        assert!(dialog.validate().is_none());
    }

    #[test]
    fn test_change_password_dialog_state() {
        let mut dialog = ChangePasswordDialogState::default();
        assert!(!dialog.is_open);

        dialog.open(1, "Level 1");
        assert!(dialog.is_open);
        assert_eq!(dialog.level_id, 1);
        assert_eq!(dialog.level_name, "Level 1");

        dialog.close();
        assert!(!dialog.is_open);
        assert_eq!(dialog.level_id, 0);
    }

    #[test]
    fn test_change_password_dialog_validation() {
        let mut dialog = ChangePasswordDialogState::default();

        // Empty current password
        dialog.new_password = "newpass1".to_string();
        dialog.confirm_password = "newpass1".to_string();
        assert!(dialog.validate().is_some());

        // Empty new password
        dialog.current_password = "oldpass".to_string();
        dialog.new_password.clear();
        dialog.confirm_password.clear();
        assert!(dialog.validate().is_some());

        // Passwords don't match
        dialog.new_password = "newpass1".to_string();
        dialog.confirm_password = "different".to_string();
        assert!(dialog.validate().is_some());

        // Password too short
        dialog.new_password = "abc".to_string();
        dialog.confirm_password = "abc".to_string();
        assert!(dialog.validate().is_some());

        // Same as current
        dialog.new_password = "oldpass".to_string();
        dialog.confirm_password = "oldpass".to_string();
        assert!(dialog.validate().is_some());

        // Valid
        dialog.new_password = "newpass1".to_string();
        dialog.confirm_password = "newpass1".to_string();
        assert!(dialog.validate().is_none());
    }

    #[test]
    fn test_delete_level_dialog_state() {
        let mut dialog = DeleteLevelDialogState::default();
        assert!(!dialog.is_open);

        dialog.open(2, "Level 2");
        assert!(dialog.is_open);
        assert_eq!(dialog.level_id, 2);
        assert_eq!(dialog.level_name, "Level 2");

        dialog.close();
        assert!(!dialog.is_open);
        assert_eq!(dialog.level_id, 0);
    }

    #[test]
    fn test_access_level_display_info_can_delete() {
        let info = AccessLevelDisplayInfo {
            id: 1,
            name: "Level 1".to_string(),
            enabled: true,
            description: None,
            file_count: 0,
            has_keystore: true,
        };

        // Can delete if empty and more than 3 levels
        assert!(info.can_delete(4));

        // Cannot delete if only 3 levels
        assert!(!info.can_delete(3));

        // Cannot delete if has files
        let info_with_files = AccessLevelDisplayInfo {
            file_count: 1,
            ..info.clone()
        };
        assert!(!info_with_files.can_delete(4));
    }

    #[test]
    fn test_settings_state_next_available_level_id() {
        let mut state = SettingsState::new();

        // Empty - first available is 1
        assert_eq!(state.next_available_level_id(), Some(1));

        // Add levels 1, 2, 3 - next is 4
        state.levels.push(AccessLevelDisplayInfo {
            id: 1,
            name: "L1".to_string(),
            enabled: true,
            description: None,
            file_count: 0,
            has_keystore: true,
        });
        state.levels.push(AccessLevelDisplayInfo {
            id: 2,
            name: "L2".to_string(),
            enabled: true,
            description: None,
            file_count: 0,
            has_keystore: true,
        });
        state.levels.push(AccessLevelDisplayInfo {
            id: 3,
            name: "L3".to_string(),
            enabled: true,
            description: None,
            file_count: 0,
            has_keystore: true,
        });

        assert_eq!(state.next_available_level_id(), Some(4));
        assert!(state.can_create_level());

        // Fill up to 10 levels
        for i in 4..=10 {
            state.levels.push(AccessLevelDisplayInfo {
                id: i,
                name: format!("L{}", i),
                enabled: true,
                description: None,
                file_count: 0,
                has_keystore: true,
            });
        }

        assert_eq!(state.next_available_level_id(), None);
        assert!(!state.can_create_level());
    }

    // =========================================================================
    // Vault Creation Wizard Tests
    // =========================================================================

    #[test]
    fn test_password_strength_empty() {
        assert_eq!(calculate_password_strength(""), PasswordStrength::VeryWeak);
    }

    #[test]
    fn test_password_strength_short() {
        // Less than 8 chars is always very weak
        assert_eq!(calculate_password_strength("abc123"), PasswordStrength::VeryWeak);
        assert_eq!(calculate_password_strength("short"), PasswordStrength::VeryWeak);
    }

    #[test]
    fn test_password_strength_weak() {
        // 8 chars but low variety
        assert_eq!(calculate_password_strength("password"), PasswordStrength::VeryWeak); // Contains "password"
        assert_eq!(calculate_password_strength("abcdefgh"), PasswordStrength::Weak); // No variety
    }

    #[test]
    fn test_password_strength_fair() {
        // Mix of chars, decent length
        let strength = calculate_password_strength("Abcdef12");
        assert!(strength.is_acceptable());
    }

    #[test]
    fn test_password_strength_strong() {
        // Good mix, longer
        let strength = calculate_password_strength("Abcdef12!@");
        assert!(matches!(strength, PasswordStrength::Strong | PasswordStrength::VeryStrong));
    }

    #[test]
    fn test_password_strength_very_strong() {
        // Excellent: long, all character types
        let strength = calculate_password_strength("MyStr0ng!P@ssw0rd2024");
        assert_eq!(strength, PasswordStrength::VeryStrong);
    }

    #[test]
    fn test_password_strength_common_patterns_penalized() {
        // Contains "123" pattern
        let strength = calculate_password_strength("Test123!@#");
        assert!(strength.progress() < PasswordStrength::VeryStrong.progress());
    }

    #[test]
    fn test_password_strength_is_acceptable() {
        assert!(!PasswordStrength::VeryWeak.is_acceptable());
        assert!(!PasswordStrength::Weak.is_acceptable());
        assert!(PasswordStrength::Fair.is_acceptable());
        assert!(PasswordStrength::Strong.is_acceptable());
        assert!(PasswordStrength::VeryStrong.is_acceptable());
    }

    #[test]
    fn test_wizard_step_navigation() {
        // Test step progression
        assert_eq!(WizardStep::Location.next(), Some(WizardStep::Password));
        assert_eq!(WizardStep::Password.next(), Some(WizardStep::AccessLevels));
        assert_eq!(WizardStep::AccessLevels.next(), Some(WizardStep::RecoveryKey));
        assert_eq!(WizardStep::RecoveryKey.next(), Some(WizardStep::Creating));
        assert_eq!(WizardStep::Creating.next(), None);
        assert_eq!(WizardStep::Complete.next(), None);

        // Test step back
        assert_eq!(WizardStep::Location.previous(), None);
        assert_eq!(WizardStep::Password.previous(), Some(WizardStep::Location));
        assert_eq!(WizardStep::AccessLevels.previous(), Some(WizardStep::Password));
        assert_eq!(WizardStep::RecoveryKey.previous(), Some(WizardStep::AccessLevels));
    }

    #[test]
    fn test_wizard_step_can_go_back() {
        assert!(!WizardStep::Location.can_go_back());
        assert!(WizardStep::Password.can_go_back());
        assert!(WizardStep::AccessLevels.can_go_back());
        assert!(WizardStep::RecoveryKey.can_go_back());
        assert!(!WizardStep::Creating.can_go_back());
        assert!(!WizardStep::Complete.can_go_back());
    }

    #[test]
    fn test_wizard_access_level_new() {
        let level = WizardAccessLevel::new(1);
        assert_eq!(level.id, 1);
        assert_eq!(level.name, "Level 1");
        assert!(level.password.is_empty());
        assert!(level.use_master_password);
        assert!(level.is_valid()); // Valid because uses master password
    }

    #[test]
    fn test_wizard_access_level_validation() {
        let mut level = WizardAccessLevel::new(1);

        // Using master password is always valid
        level.use_master_password = true;
        assert!(level.is_valid());

        // Not using master password requires own password
        level.use_master_password = false;
        assert!(!level.is_valid()); // Empty password

        level.password = "test".to_string();
        assert!(!level.is_valid()); // Passwords don't match

        level.password_confirm = "test".to_string();
        assert!(level.is_valid()); // Passwords match now
    }

    #[test]
    fn test_wizard_state_new() {
        let state = VaultCreationWizardState::new();
        assert_eq!(state.step, WizardStep::Location);
        assert!(state.vault_path.is_none());
        assert!(state.master_password.is_empty());
        assert_eq!(state.password_strength, PasswordStrength::VeryWeak);
        assert_eq!(state.access_levels.len(), 3); // Default 3 levels
        assert!(state.use_default_levels);
        assert!(!state.recovery_confirmed);
    }

    #[test]
    fn test_wizard_state_password_match() {
        let mut state = VaultCreationWizardState::new();

        assert!(state.master_passwords_match()); // Both empty

        state.master_password = "test".to_string();
        assert!(!state.master_passwords_match()); // Only one set

        state.master_password_confirm = "test".to_string();
        assert!(state.master_passwords_match()); // Both match

        state.master_password_confirm = "different".to_string();
        assert!(!state.master_passwords_match()); // Don't match
    }

    #[test]
    fn test_wizard_state_update_password_strength() {
        let mut state = VaultCreationWizardState::new();

        state.master_password = "weak".to_string();
        state.update_password_strength();
        assert_eq!(state.password_strength, PasswordStrength::VeryWeak);

        state.master_password = "StrongP@ss123!".to_string();
        state.update_password_strength();
        assert!(state.password_strength.is_acceptable());
    }

    #[test]
    fn test_wizard_state_set_level_count() {
        let mut state = VaultCreationWizardState::new();
        assert_eq!(state.access_levels.len(), 3);

        state.set_level_count(5);
        assert_eq!(state.access_levels.len(), 5);
        assert_eq!(state.level_count, 5);

        // Check level IDs are sequential
        for (i, level) in state.access_levels.iter().enumerate() {
            assert_eq!(level.id, (i + 1) as u32);
        }

        // Reducing count truncates
        state.set_level_count(2);
        assert_eq!(state.access_levels.len(), 2);
        assert_eq!(state.level_count, 2);

        // Clamp to valid range
        state.set_level_count(0);
        assert_eq!(state.level_count, 1);

        state.set_level_count(100);
        assert_eq!(state.level_count, 10);
    }

    #[test]
    fn test_wizard_state_get_level_passwords() {
        let mut state = VaultCreationWizardState::new();
        state.master_password = "master123".to_string();

        // All use master password by default
        let passwords = state.get_level_passwords();
        assert_eq!(passwords.len(), 3);
        for p in &passwords {
            assert_eq!(p, "master123");
        }

        // Set one level to use its own password
        state.access_levels[1].use_master_password = false;
        state.access_levels[1].password = "level2pass".to_string();

        let passwords = state.get_level_passwords();
        assert_eq!(passwords[0], "master123");
        assert_eq!(passwords[1], "level2pass");
        assert_eq!(passwords[2], "master123");
    }

    #[test]
    fn test_wizard_state_reset() {
        let mut state = VaultCreationWizardState::new();

        // Modify state
        state.step = WizardStep::Password;
        state.master_password = "test".to_string();
        state.recovery_confirmed = true;
        state.set_level_count(5);

        // Reset
        state.reset();

        // Verify reset to defaults
        assert_eq!(state.step, WizardStep::Location);
        assert!(state.master_password.is_empty());
        assert!(!state.recovery_confirmed);
        assert_eq!(state.access_levels.len(), 3);
    }

    #[test]
    fn test_wizard_clipboard_copied_at_initially_none() {
        let state = VaultCreationWizardState::new();
        assert!(state.clipboard_copied_at.is_none());
    }

    #[test]
    fn test_wizard_mark_clipboard_copied() {
        let mut state = VaultCreationWizardState::new();
        assert!(state.clipboard_copied_at.is_none());

        state.mark_clipboard_copied();

        assert!(state.clipboard_copied_at.is_some());
    }

    #[test]
    fn test_wizard_should_clear_clipboard_when_none() {
        let state = VaultCreationWizardState::new();
        assert!(!state.should_clear_clipboard());
    }

    #[test]
    fn test_wizard_should_clear_clipboard_just_copied() {
        let mut state = VaultCreationWizardState::new();
        state.mark_clipboard_copied();

        // Just copied - should not clear yet
        assert!(!state.should_clear_clipboard());
    }

    #[test]
    fn test_wizard_clipboard_clear_countdown_none_when_not_copied() {
        let state = VaultCreationWizardState::new();
        assert!(state.clipboard_clear_countdown().is_none());
    }

    #[test]
    fn test_wizard_clipboard_clear_countdown_after_copy() {
        let mut state = VaultCreationWizardState::new();
        state.mark_clipboard_copied();

        let countdown = state.clipboard_clear_countdown();
        assert!(countdown.is_some());

        // Should be close to 60 seconds (allow for test execution time)
        let seconds = countdown.unwrap();
        assert!(seconds >= 58 && seconds <= 60);
    }

    #[test]
    fn test_wizard_clear_clipboard_timestamp() {
        let mut state = VaultCreationWizardState::new();
        state.mark_clipboard_copied();
        assert!(state.clipboard_copied_at.is_some());

        state.clear_clipboard_timestamp();

        assert!(state.clipboard_copied_at.is_none());
    }

    #[test]
    fn test_wizard_generate_printable_recovery_key_none_when_no_mnemonic() {
        let state = VaultCreationWizardState::new();
        assert!(state.generate_printable_recovery_key().is_none());
    }

    #[test]
    fn test_wizard_generate_printable_recovery_key_none_when_only_mnemonic() {
        let mut state = VaultCreationWizardState::new();
        state.recovery_mnemonic = Some("word1 word2 word3".to_string());
        // Still None because base64 is required too
        assert!(state.generate_printable_recovery_key().is_none());
    }

    #[test]
    fn test_wizard_generate_printable_recovery_key_success() {
        let mut state = VaultCreationWizardState::new();
        state.recovery_mnemonic = Some(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about".to_string()
        );
        state.recovery_base64 = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());

        let printable = state.generate_printable_recovery_key();
        assert!(printable.is_some());

        let content = printable.unwrap();
        assert!(content.contains("TESSERACT RECOVERY KEY"));
        assert!(content.contains("24-Word Recovery Phrase"));
        assert!(content.contains("Base64 Format"));
        assert!(content.contains("abandon"));
        assert!(content.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(content.contains("IMPORTANT"));
        assert!(content.contains("Date Generated"));
    }

    #[test]
    fn test_wizard_generate_printable_recovery_key_has_word_numbers() {
        let mut state = VaultCreationWizardState::new();
        state.recovery_mnemonic = Some(
            "word1 word2 word3 word4 word5 word6 word7 word8 \
             word9 word10 word11 word12 word13 word14 word15 word16 \
             word17 word18 word19 word20 word21 word22 word23 word24".to_string()
        );
        state.recovery_base64 = Some("test_base64".to_string());

        let content = state.generate_printable_recovery_key().unwrap();

        // Check that words are numbered
        assert!(content.contains(" 1. word1"));
        assert!(content.contains("12. word12"));
        assert!(content.contains("24. word24"));
    }

    #[test]
    fn test_wizard_reset_clears_clipboard_timestamp() {
        let mut state = VaultCreationWizardState::new();
        state.mark_clipboard_copied();
        assert!(state.clipboard_copied_at.is_some());

        state.reset();

        assert!(state.clipboard_copied_at.is_none());
    }

    // =========================================================================
    // Password Recovery Flow Tests (US-044)
    // =========================================================================

    #[test]
    fn test_recovery_step_default() {
        let step = RecoveryStep::default();
        assert!(matches!(step, RecoveryStep::EnterKey));
    }

    #[test]
    fn test_recovery_step_titles() {
        assert_eq!(RecoveryStep::EnterKey.title(), "Enter Recovery Key");
        assert_eq!(RecoveryStep::EnterNewPassword.title(), "Set New Password");
        assert_eq!(RecoveryStep::Success.title(), "Password Reset Complete");
        assert_eq!(RecoveryStep::Failed.title(), "Password Reset Failed");
    }

    #[test]
    fn test_password_recovery_state_new() {
        let state = PasswordRecoveryState::new();

        assert!(matches!(state.step, RecoveryStep::EnterKey));
        assert!(state.recovery_key_input.is_empty());
        assert!(!state.use_base64_mode);
        assert!(state.key_error.is_none());
        assert!(!state.verifying);
        assert!(state.new_password.is_empty());
        assert!(state.new_password_confirm.is_empty());
        assert!(!state.show_password);
        assert!(matches!(state.password_strength, PasswordStrength::VeryWeak));
        assert_eq!(state.target_level, 1);
        assert_eq!(state.available_levels, vec![1, 2, 3]);
        assert!(!state.resetting);
        assert!(state.success_message.is_none());
        assert!(state.reset_error.is_none());
        assert!(state.vault_path.is_none());
    }

    #[test]
    fn test_password_recovery_state_for_vault() {
        let path = PathBuf::from("/test/vault");
        let state = PasswordRecoveryState::for_vault(path.clone());

        assert_eq!(state.vault_path, Some(path));
        assert!(matches!(state.step, RecoveryStep::EnterKey));
    }

    #[test]
    fn test_password_recovery_state_reset() {
        let mut state = PasswordRecoveryState::for_vault(PathBuf::from("/test/vault"));
        state.step = RecoveryStep::EnterNewPassword;
        state.recovery_key_input = "test input".to_string();
        state.key_error = Some("error".to_string());

        state.reset();

        // Vault path should be preserved
        assert_eq!(state.vault_path, Some(PathBuf::from("/test/vault")));
        // Other fields should be reset
        assert!(matches!(state.step, RecoveryStep::EnterKey));
        assert!(state.recovery_key_input.is_empty());
        assert!(state.key_error.is_none());
    }

    #[test]
    fn test_password_recovery_state_reset_completely() {
        let mut state = PasswordRecoveryState::for_vault(PathBuf::from("/test/vault"));
        state.step = RecoveryStep::Success;

        state.reset_completely();

        // Everything should be reset including vault path
        assert!(state.vault_path.is_none());
        assert!(matches!(state.step, RecoveryStep::EnterKey));
    }

    #[test]
    fn test_password_recovery_state_passwords_match() {
        let mut state = PasswordRecoveryState::new();

        state.new_password = "test123".to_string();
        state.new_password_confirm = "test123".to_string();
        assert!(state.passwords_match());

        state.new_password_confirm = "different".to_string();
        assert!(!state.passwords_match());
    }

    #[test]
    fn test_password_recovery_state_has_recovery_key_input() {
        let mut state = PasswordRecoveryState::new();

        assert!(!state.has_recovery_key_input());

        state.recovery_key_input = "   ".to_string();
        assert!(!state.has_recovery_key_input());

        state.recovery_key_input = "some input".to_string();
        assert!(state.has_recovery_key_input());
    }

    #[test]
    fn test_password_recovery_state_can_verify_key() {
        let mut state = PasswordRecoveryState::for_vault(PathBuf::from("/test"));

        // Missing input
        assert!(!state.can_verify_key());

        // Add input
        state.recovery_key_input = "test".to_string();
        assert!(state.can_verify_key());

        // While verifying
        state.verifying = true;
        assert!(!state.can_verify_key());

        // With error
        state.verifying = false;
        state.key_error = Some("error".to_string());
        assert!(!state.can_verify_key());
    }

    #[test]
    fn test_password_recovery_state_can_submit_password() {
        let mut state = PasswordRecoveryState::new();

        // Empty passwords
        assert!(!state.can_submit_password());

        // Weak password
        state.new_password = "short".to_string();
        state.new_password_confirm = "short".to_string();
        state.update_password_strength();
        assert!(!state.can_submit_password()); // Too weak

        // Strong password but non-matching
        state.new_password = "StrongPassword123!".to_string();
        state.new_password_confirm = "DifferentPassword".to_string();
        state.update_password_strength();
        assert!(!state.can_submit_password());

        // Strong password, matching
        state.new_password_confirm = "StrongPassword123!".to_string();
        assert!(state.can_submit_password());

        // While resetting
        state.resetting = true;
        assert!(!state.can_submit_password());
    }

    #[test]
    fn test_password_recovery_state_validate_mnemonic_format() {
        let mut state = PasswordRecoveryState::new();
        state.use_base64_mode = false;

        // Empty
        state.recovery_key_input = "".to_string();
        assert!(state.validate_recovery_key_format().is_err());

        // Wrong word count
        state.recovery_key_input = "one two three".to_string();
        let err = state.validate_recovery_key_format().unwrap_err();
        assert!(err.contains("24 words"));

        // Invalid characters
        state.recovery_key_input = "WORD1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24".to_string();
        let err = state.validate_recovery_key_format().unwrap_err();
        assert!(err.contains("invalid characters"));

        // Valid 24 words
        state.recovery_key_input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        assert!(state.validate_recovery_key_format().is_ok());
    }

    #[test]
    fn test_password_recovery_state_validate_base64_format() {
        let mut state = PasswordRecoveryState::new();
        state.use_base64_mode = true;

        // Empty
        state.recovery_key_input = "".to_string();
        assert!(state.validate_recovery_key_format().is_err());

        // Too short
        state.recovery_key_input = "short".to_string();
        let err = state.validate_recovery_key_format().unwrap_err();
        assert!(err.contains("44 characters"));

        // Invalid characters
        state.recovery_key_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!".to_string();
        let err = state.validate_recovery_key_format().unwrap_err();
        assert!(err.contains("Invalid base64"));

        // Valid base64 (44 chars)
        state.recovery_key_input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        assert!(state.validate_recovery_key_format().is_ok());
    }

    #[test]
    fn test_password_recovery_state_key_verified() {
        let mut state = PasswordRecoveryState::new();
        state.verifying = true;
        state.key_error = Some("old error".to_string());

        state.key_verified(vec![1, 2, 3, 4]);

        assert!(matches!(state.step, RecoveryStep::EnterNewPassword));
        assert_eq!(state.available_levels, vec![1, 2, 3, 4]);
        assert_eq!(state.target_level, 1);
        assert!(!state.verifying);
        assert!(state.key_error.is_none());
    }

    #[test]
    fn test_password_recovery_state_key_verified_empty_levels() {
        let mut state = PasswordRecoveryState::new();

        state.key_verified(vec![]);

        assert_eq!(state.available_levels, vec![1]); // Default to level 1
        assert_eq!(state.target_level, 1);
    }

    #[test]
    fn test_password_recovery_state_password_reset_success() {
        let mut state = PasswordRecoveryState::new();
        state.step = RecoveryStep::EnterNewPassword;
        state.target_level = 2;
        state.resetting = true;
        state.new_password = "secret".to_string();
        state.recovery_key_input = "key".to_string();

        state.password_reset_success();

        assert!(matches!(state.step, RecoveryStep::Success));
        assert!(!state.resetting);
        assert!(state.success_message.as_ref().unwrap().contains("Level 2"));
        // Sensitive data should be cleared
        assert!(state.new_password.is_empty());
        assert!(state.recovery_key_input.is_empty());
    }

    #[test]
    fn test_password_recovery_state_set_reset_error() {
        let mut state = PasswordRecoveryState::new();
        state.step = RecoveryStep::EnterNewPassword;

        state.set_reset_error("Test error");

        assert!(matches!(state.step, RecoveryStep::Failed));
        assert_eq!(state.reset_error.as_deref(), Some("Test error"));
    }

    #[test]
    fn test_password_recovery_state_clear_sensitive_data() {
        let mut state = PasswordRecoveryState::new();
        state.new_password = "password123".to_string();
        state.new_password_confirm = "password123".to_string();
        state.recovery_key_input = "sensitive key".to_string();

        state.clear_sensitive_data();

        assert!(state.new_password.is_empty());
        assert!(state.new_password_confirm.is_empty());
        assert!(state.recovery_key_input.is_empty());
    }

    #[test]
    fn test_password_recovery_state_vault_name() {
        let state = PasswordRecoveryState::new();
        assert_eq!(state.vault_name(), "Unknown Vault");

        let state = PasswordRecoveryState::for_vault(PathBuf::from("/path/to/MyVault"));
        assert_eq!(state.vault_name(), "MyVault");
    }

    #[test]
    fn test_password_recovery_state_update_password_strength() {
        let mut state = PasswordRecoveryState::new();

        state.new_password = "weak".to_string();
        state.update_password_strength();
        assert!(matches!(state.password_strength, PasswordStrength::VeryWeak));

        state.new_password = "StrongPassword123!".to_string();
        state.update_password_strength();
        assert!(state.password_strength.is_acceptable());
    }

    #[test]
    fn test_password_recovery_state_key_error_methods() {
        let mut state = PasswordRecoveryState::new();

        state.set_key_error("Test error");
        assert_eq!(state.key_error.as_deref(), Some("Test error"));

        state.clear_key_error();
        assert!(state.key_error.is_none());
    }

    // ========================================================================
    // MountPointSelectionState tests
    // ========================================================================

    #[test]
    fn test_mount_point_selection_state_default() {
        let state = MountPointSelectionState::default();
        assert_eq!(state.selected_letter, Some('T'));
        assert!(!state.auto_select);
        assert!(state.drive_letters.is_empty());
        assert!(state.needs_refresh);
        assert!(state.error_message.is_none());
        assert!(state.success_message.is_none());
    }

    #[test]
    fn test_mount_point_selection_state_new() {
        let state = MountPointSelectionState::new();
        assert_eq!(state.selected_letter, Some('T'));
        assert!(!state.auto_select);
    }

    #[test]
    fn test_mount_point_selection_state_from_config_with_letter() {
        let state = MountPointSelectionState::from_config(Some('S'));
        assert_eq!(state.selected_letter, Some('S'));
        assert!(!state.auto_select);
    }

    #[test]
    fn test_mount_point_selection_state_from_config_none() {
        let state = MountPointSelectionState::from_config(None);
        assert_eq!(state.selected_letter, None);
        assert!(state.auto_select);
    }

    #[test]
    fn test_mount_point_selection_state_set_letter() {
        let mut state = MountPointSelectionState::new();
        state.enable_auto_select();
        assert!(state.auto_select);

        state.set_letter('r'); // lowercase
        assert_eq!(state.selected_letter, Some('R')); // converted to uppercase
        assert!(!state.auto_select);
        assert!(state.error_message.is_none());
        assert!(state.success_message.is_some());
    }

    #[test]
    fn test_mount_point_selection_state_enable_auto_select() {
        let mut state = MountPointSelectionState::new();
        assert!(!state.auto_select);

        state.enable_auto_select();
        assert!(state.auto_select);
        assert!(state.selected_letter.is_none());
        assert!(state.success_message.is_some());
    }

    #[test]
    fn test_mount_point_selection_state_clear_messages() {
        let mut state = MountPointSelectionState::new();
        state.set_error("Error");
        state.set_success("Success");

        state.clear_messages();
        assert!(state.error_message.is_none());
        assert!(state.success_message.is_none());
    }

    #[test]
    fn test_mount_point_selection_state_set_error() {
        let mut state = MountPointSelectionState::new();
        state.set_success("Success first");

        state.set_error("Error message");
        assert_eq!(state.error_message.as_deref(), Some("Error message"));
        assert!(state.success_message.is_none());
    }

    #[test]
    fn test_mount_point_selection_state_set_success() {
        let mut state = MountPointSelectionState::new();
        state.set_error("Error first");

        state.set_success("Success message");
        assert!(state.error_message.is_none());
        assert_eq!(state.success_message.as_deref(), Some("Success message"));
    }

    #[test]
    fn test_mount_point_selection_state_get_effective_letter_manual() {
        let mut state = MountPointSelectionState::new();
        state.set_letter('S');
        assert_eq!(state.get_effective_letter(), Some('S'));
    }

    #[test]
    fn test_mount_point_selection_state_get_effective_letter_auto_empty() {
        let state = MountPointSelectionState::from_config(None);
        // With empty drive_letters, first_available returns None
        assert_eq!(state.get_effective_letter(), None);
    }

    #[test]
    fn test_mount_point_selection_state_help_text() {
        let text = MountPointSelectionState::help_text();
        assert!(!text.is_empty());
    }

    #[test]
    fn test_drive_letter_display_info_display_string_available() {
        let info = DriveLetterDisplayInfo {
            letter: 'T',
            available: true,
            reserved: false,
            label: None,
        };
        assert_eq!(info.display_string(), "T: (Available)");
    }

    #[test]
    fn test_drive_letter_display_info_display_string_in_use() {
        let info = DriveLetterDisplayInfo {
            letter: 'D',
            available: false,
            reserved: false,
            label: None,
        };
        assert_eq!(info.display_string(), "D: (In Use)");
    }

    #[test]
    fn test_drive_letter_display_info_display_string_with_label() {
        let info = DriveLetterDisplayInfo {
            letter: 'D',
            available: false,
            reserved: false,
            label: Some("Data".to_string()),
        };
        assert_eq!(info.display_string(), "D: Data (In Use)");
    }

    #[test]
    fn test_drive_letter_display_info_display_string_system() {
        let info = DriveLetterDisplayInfo {
            letter: 'C',
            available: false,
            reserved: true,
            label: None,
        };
        assert_eq!(info.display_string(), "C: (System)");
    }

    #[test]
    fn test_drive_letter_display_info_is_selectable() {
        let available = DriveLetterDisplayInfo {
            letter: 'T',
            available: true,
            reserved: false,
            label: None,
        };
        assert!(available.is_selectable());

        let in_use = DriveLetterDisplayInfo {
            letter: 'D',
            available: false,
            reserved: false,
            label: None,
        };
        assert!(!in_use.is_selectable());

        let reserved = DriveLetterDisplayInfo {
            letter: 'C',
            available: false,
            reserved: true,
            label: None,
        };
        assert!(!reserved.is_selectable());

        let reserved_but_available = DriveLetterDisplayInfo {
            letter: 'A',
            available: true, // hypothetically
            reserved: true,
            label: None,
        };
        assert!(!reserved_but_available.is_selectable());
    }

    #[test]
    fn test_mount_point_selection_state_selectable_letters() {
        let mut state = MountPointSelectionState::new();
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'C', available: false, reserved: true, label: None },
            DriveLetterDisplayInfo { letter: 'D', available: false, reserved: false, label: Some("Data".to_string()) },
            DriveLetterDisplayInfo { letter: 'T', available: true, reserved: false, label: None },
            DriveLetterDisplayInfo { letter: 'S', available: true, reserved: false, label: None },
        ];

        let selectable = state.selectable_letters();
        assert_eq!(selectable.len(), 2);
        assert!(selectable.iter().any(|d| d.letter == 'T'));
        assert!(selectable.iter().any(|d| d.letter == 'S'));
    }

    #[test]
    fn test_mount_point_selection_state_first_available_t_preferred() {
        let mut state = MountPointSelectionState::new();
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'S', available: true, reserved: false, label: None },
            DriveLetterDisplayInfo { letter: 'T', available: true, reserved: false, label: None },
            DriveLetterDisplayInfo { letter: 'R', available: true, reserved: false, label: None },
        ];

        // T is always preferred when available
        assert_eq!(state.first_available(), Some('T'));
    }

    #[test]
    fn test_mount_point_selection_state_first_available_t_unavailable() {
        let mut state = MountPointSelectionState::new();
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'S', available: true, reserved: false, label: None },
            DriveLetterDisplayInfo { letter: 'T', available: false, reserved: false, label: None },
            DriveLetterDisplayInfo { letter: 'R', available: true, reserved: false, label: None },
        ];

        // S comes before R in PREFERRED_DRIVE_ORDER
        assert_eq!(state.first_available(), Some('S'));
    }

    #[test]
    fn test_mount_point_selection_state_validate_success() {
        let mut state = MountPointSelectionState::new();
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'T', available: true, reserved: false, label: None },
        ];
        state.set_letter('T');

        let result = state.validate();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 'T');
    }

    #[test]
    fn test_mount_point_selection_state_validate_in_use() {
        let mut state = MountPointSelectionState::new();
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'T', available: false, reserved: false, label: None },
        ];
        state.set_letter('T');

        let result = state.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already in use"));
    }

    #[test]
    fn test_mount_point_selection_state_validate_reserved() {
        let mut state = MountPointSelectionState::new();
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'C', available: false, reserved: true, label: None },
        ];
        state.selected_letter = Some('C');
        state.auto_select = false;

        let result = state.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("reserved for system use"));
    }

    #[test]
    fn test_mount_point_selection_state_validate_auto_select() {
        let mut state = MountPointSelectionState::from_config(None);
        state.drive_letters = vec![
            DriveLetterDisplayInfo { letter: 'C', available: false, reserved: true, label: None },
            DriveLetterDisplayInfo { letter: 'T', available: true, reserved: false, label: None },
        ];

        let result = state.validate();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 'T');
    }

    #[test]
    fn test_mount_point_selection_state_validate_no_available() {
        let state = MountPointSelectionState::from_config(None);
        // Empty drive_letters

        let result = state.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No available drive letters"));
    }

    // =========================================================================
    // Vault Auto-Creation Tests (US-062)
    // =========================================================================

    #[test]
    fn test_auto_creation_prompt_state_default() {
        let state = AutoCreationPromptState::default();
        assert_eq!(state, AutoCreationPromptState::None);
    }

    #[test]
    fn test_auto_creation_prompt_state_new() {
        let state = AutoCreationPromptState::new();
        assert_eq!(state, AutoCreationPromptState::None);
        assert!(!state.should_show());
    }

    #[test]
    fn test_auto_creation_prompt_state_should_show() {
        let path = PathBuf::from("/test/vault");

        let state = AutoCreationPromptState::None;
        assert!(!state.should_show());

        let state = AutoCreationPromptState::ShowPrompt(path.clone());
        assert!(state.should_show());

        let state = AutoCreationPromptState::Confirmed(path.clone());
        assert!(!state.should_show());

        let state = AutoCreationPromptState::Dismissed;
        assert!(!state.should_show());
    }

    #[test]
    fn test_auto_creation_prompt_state_get_confirmed_path() {
        let path = PathBuf::from("/test/vault");

        let state = AutoCreationPromptState::None;
        assert!(state.get_confirmed_path().is_none());

        let state = AutoCreationPromptState::ShowPrompt(path.clone());
        assert!(state.get_confirmed_path().is_none());

        let state = AutoCreationPromptState::Confirmed(path.clone());
        assert_eq!(state.get_confirmed_path(), Some(path.clone()));

        let state = AutoCreationPromptState::Dismissed;
        assert!(state.get_confirmed_path().is_none());
    }

    #[test]
    fn test_auto_creation_prompt_state_confirm() {
        let path = PathBuf::from("/test/vault");

        // Confirm from ShowPrompt transitions to Confirmed
        let mut state = AutoCreationPromptState::ShowPrompt(path.clone());
        state.confirm();
        assert_eq!(state, AutoCreationPromptState::Confirmed(path.clone()));

        // Confirm from other states has no effect
        let mut state = AutoCreationPromptState::None;
        state.confirm();
        assert_eq!(state, AutoCreationPromptState::None);

        let mut state = AutoCreationPromptState::Dismissed;
        state.confirm();
        assert_eq!(state, AutoCreationPromptState::Dismissed);
    }

    #[test]
    fn test_auto_creation_prompt_state_dismiss() {
        let path = PathBuf::from("/test/vault");

        let mut state = AutoCreationPromptState::ShowPrompt(path);
        state.dismiss();
        assert_eq!(state, AutoCreationPromptState::Dismissed);

        let mut state = AutoCreationPromptState::None;
        state.dismiss();
        assert_eq!(state, AutoCreationPromptState::Dismissed);
    }

    #[test]
    fn test_auto_creation_prompt_state_reset() {
        let path = PathBuf::from("/test/vault");

        let mut state = AutoCreationPromptState::Confirmed(path);
        state.reset();
        assert_eq!(state, AutoCreationPromptState::None);

        let mut state = AutoCreationPromptState::Dismissed;
        state.reset();
        assert_eq!(state, AutoCreationPromptState::None);
    }

    #[test]
    fn test_auto_creation_prompt_full_workflow() {
        let path = PathBuf::from("/test/vault");

        // Start with no prompt
        let mut state = AutoCreationPromptState::None;
        assert!(!state.should_show());

        // Show prompt
        state = AutoCreationPromptState::ShowPrompt(path.clone());
        assert!(state.should_show());
        assert!(state.get_confirmed_path().is_none());

        // User confirms
        state.confirm();
        assert!(!state.should_show());
        assert_eq!(state.get_confirmed_path(), Some(path));

        // After handling confirmation, reset
        state.reset();
        assert_eq!(state, AutoCreationPromptState::None);
    }

    #[test]
    fn test_auto_creation_prompt_dismiss_workflow() {
        let path = PathBuf::from("/test/vault");

        // Show prompt
        let mut state = AutoCreationPromptState::ShowPrompt(path);
        assert!(state.should_show());

        // User dismisses
        state.dismiss();
        assert!(!state.should_show());
        assert!(state.get_confirmed_path().is_none());
        assert_eq!(state, AutoCreationPromptState::Dismissed);
    }

    #[test]
    fn test_vault_auto_detection_result_variants() {
        let path = PathBuf::from("/test/vault");

        let result = VaultAutoDetectionResult::Found(path.clone());
        if let VaultAutoDetectionResult::Found(p) = result {
            assert_eq!(p, path);
        } else {
            panic!("Expected Found variant");
        }

        let result = VaultAutoDetectionResult::NotFound(path.clone());
        if let VaultAutoDetectionResult::NotFound(p) = result {
            assert_eq!(p, path);
        } else {
            panic!("Expected NotFound variant");
        }

        let result = VaultAutoDetectionResult::NoDefaultPath;
        assert!(matches!(result, VaultAutoDetectionResult::NoDefaultPath));
    }

    #[test]
    fn test_default_vault_dir_name_constant() {
        // Verify the constant is as expected
        assert_eq!(DEFAULT_VAULT_DIR_NAME, "vault");
    }

    #[test]
    fn test_get_default_vault_path_returns_vault_subdir() {
        // This tests the structure of the path - it should end with "vault"
        if let Some(path) = get_default_vault_path() {
            assert!(path.ends_with("vault"));
        }
        // Note: May return None in some test environments
    }

    #[test]
    fn test_check_default_vault_exists_returns_none_when_no_vault() {
        // In a test environment without a vault, this should return None
        // We can't mock current_exe easily, but we can at least verify
        // it doesn't panic
        let _result = check_default_vault_exists();
        // Result will be None unless there's a vault adjacent to the test binary
    }

    #[test]
    fn test_detect_vault_on_startup_structure() {
        // Test that detect_vault_on_startup returns a valid variant
        let result = detect_vault_on_startup();

        // The result should be one of the valid variants
        match result {
            VaultAutoDetectionResult::Found(_) => {
                // Valid - vault exists
            }
            VaultAutoDetectionResult::NotFound(path) => {
                // Valid - path should end with "vault"
                assert!(path.ends_with("vault"));
            }
            VaultAutoDetectionResult::NoDefaultPath => {
                // Valid - couldn't determine path
            }
        }
    }
}
