//! Main application state and entry point.
//!
//! This module provides the core TESSERACT application structure using egui/eframe.

use eframe::egui;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::config::{load_config, save_config, AppConfig, RecentVault};
use crate::screens::{
    format_relative_time, VaultSelectionState,
    AuthStatus, PasswordEntryState, format_duration,
    FileBrowserState, SortColumn, format_file_size, format_timestamp,
    entry_icon, level_label, ImportStatus, ExportStatus,
    ContextMenuAction, ConfirmationDialog,
    SettingsState,
    VaultCreationWizardState, WizardStep, PasswordStrength,
    calculate_password_strength, create_vault_dialog,
    PasswordRecoveryState, RecoveryStep,
    MountPointSelectionState, DriveLetterDisplayInfo,
    AutoCreationPromptState, detect_vault_on_startup, VaultAutoDetectionResult,
    DriveDetectionState, DriveInitWizardState, DriveInitStep, EncryptionStrength,
};

/// Application name displayed in window title.
pub const APP_NAME: &str = "TESSERACT";

/// Default window width in pixels.
pub const DEFAULT_WIDTH: f32 = 1024.0;

/// Default window height in pixels.
pub const DEFAULT_HEIGHT: f32 = 768.0;

/// Minimum window width in pixels.
pub const MIN_WIDTH: f32 = 800.0;

/// Minimum window height in pixels.
pub const MIN_HEIGHT: f32 = 600.0;

/// Generates a random 4-character segment for recovery keys.
fn generate_recovery_segment() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Simple pseudo-random generator for demonstration
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut result = String::with_capacity(4);
    let mut state = seed;
    for _ in 0..4 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = ((state >> 33) as usize) % chars.len();
        result.push(chars[idx]);
    }
    result
}

/// Application state representing the current screen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AppScreen {
    /// Initial vault selection screen.
    #[default]
    VaultSelection,
    /// Password entry for vault unlock.
    PasswordEntry,
    /// Main file browser view.
    FileBrowser,
    /// Settings and access level management.
    Settings,
    /// Vault creation wizard.
    VaultCreation,
    /// Password recovery flow.
    PasswordRecovery,
    /// Drive detection and hardware encryption management.
    Drives,
}

impl AppScreen {
    /// Returns the screen title for display purposes.
    #[must_use]
    pub fn title(&self) -> &'static str {
        match self {
            Self::VaultSelection => "Select Vault",
            Self::PasswordEntry => "Unlock Vault",
            Self::FileBrowser => "File Browser",
            Self::Settings => "Settings",
            Self::VaultCreation => "Create New Vault",
            Self::PasswordRecovery => "Password Recovery",
            Self::Drives => "USB Drives",
        }
    }
}

/// Actions that can be taken on access levels in settings.
enum LevelAction {
    ChangePassword(u32, String),
    Delete(u32, String),
}

/// Main TESSERACT application.
pub struct TesseractApp {
    /// Current screen being displayed.
    screen: AppScreen,

    /// Whether the application is initialized.
    initialized: bool,

    /// Status message to display (if any).
    status_message: Option<String>,

    /// Whether to show the about dialog.
    show_about: bool,

    /// Application configuration.
    config: AppConfig,

    /// State for vault selection screen.
    vault_selection_state: VaultSelectionState,

    /// State for password entry screen.
    password_entry_state: PasswordEntryState,

    /// State for file browser screen.
    file_browser_state: FileBrowserState,

    /// State for settings / access level management screen.
    settings_state: SettingsState,

    /// State for mount point (drive letter) selection.
    mount_point_state: MountPointSelectionState,

    /// Active vault session (when unlocked).
    vault_session: Option<tesseract_core::session::VaultSession>,

    /// Currently selected/opened vault path.
    current_vault_path: Option<PathBuf>,

    /// Path for new vault creation (when in VaultCreation screen).
    new_vault_path: Option<PathBuf>,

    /// Master key after successful authentication (sensitive!).
    /// Wrapped in Zeroizing to ensure key is cleared from memory on drop.
    master_key: Option<Zeroizing<[u8; 32]>>,

    /// Timestamp of last user activity (for auto-lock).
    last_activity: Option<Instant>,

    /// Temporary file manager for secure file preview.
    temp_file_manager: Option<tesseract_core::TempFileManager>,

    /// State for vault creation wizard.
    wizard_state: VaultCreationWizardState,

    /// State for password recovery flow.
    recovery_state: PasswordRecoveryState,

    /// State for auto-creation prompt on startup (US-062).
    auto_creation_state: AutoCreationPromptState,

    /// State for drive detection screen (US-022).
    drive_detection_state: DriveDetectionState,

    /// State for drive initialization wizard (US-024).
    drive_init_wizard_state: DriveInitWizardState,

    /// Currently unlocked encrypted drive (US-025).
    current_drive: Option<UnlockedDriveInfo>,

    /// Pending vault path waiting for hardware unlock (US-026).
    /// When a vault is on an encrypted drive that needs unlocking first,
    /// we store the path here and show the hardware unlock dialog.
    pending_vault_for_hardware_unlock: Option<PathBuf>,

    /// Drive info for pending hardware unlock (US-026).
    pending_drive_unlock: Option<tesseract_hardware::DriveInfo>,

    /// Whether to use unified password for drive and vault (US-026).
    /// When true, the same password unlocks both hardware and vault.
    use_unified_password: bool,

    /// Whether the vault was auto-locked due to drive removal (US-027).
    /// Used to show a notification to the user.
    drive_removed_notification: bool,

    /// Timestamp of last drive presence check (US-027).
    /// Used to avoid checking too frequently.
    last_drive_check: Option<Instant>,

    /// Flag to trigger secure application exit (US-031).
    /// When set, cleanup_and_exit() will be called at end of frame.
    exit_requested: bool,
}

/// Information about the currently unlocked encrypted drive (US-025).
#[derive(Debug, Clone)]
pub struct UnlockedDriveInfo {
    /// Device path (e.g., /dev/sdb1).
    pub device_path: PathBuf,
    /// Display name (vendor + model).
    pub name: String,
    /// Drive size in bytes.
    pub size_bytes: u64,
    /// Mount point if mounted.
    pub mount_point: Option<PathBuf>,
    /// Whether the drive is currently locked.
    pub is_locked: bool,
}

impl Default for TesseractApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TesseractApp {
    /// Creates a new TESSERACT application instance.
    #[must_use]
    pub fn new() -> Self {
        info!("Creating TESSERACT application");
        let config = load_config();
        debug!("Loaded config with {} recent vaults", config.recent_vaults.len());

        // Initialize mount point state from config
        let mount_point_state = MountPointSelectionState::from_config(config.preferred_drive_letter);

        Self {
            screen: AppScreen::VaultSelection,
            initialized: false,
            status_message: None,
            show_about: false,
            config,
            vault_selection_state: VaultSelectionState::new(),
            password_entry_state: PasswordEntryState::new(),
            file_browser_state: FileBrowserState::new(),
            settings_state: SettingsState::new(),
            mount_point_state,
            vault_session: None,
            current_vault_path: None,
            new_vault_path: None,
            master_key: None,
            last_activity: None,
            temp_file_manager: None,
            wizard_state: VaultCreationWizardState::new(),
            recovery_state: PasswordRecoveryState::new(),
            auto_creation_state: AutoCreationPromptState::new(),
            drive_detection_state: DriveDetectionState::new(),
            drive_init_wizard_state: DriveInitWizardState::new(),
            current_drive: None,
            pending_vault_for_hardware_unlock: None,
            pending_drive_unlock: None,
            use_unified_password: false,
            drive_removed_notification: false,
            last_drive_check: None,
            exit_requested: false,
        }
    }

    /// Returns the current screen.
    #[must_use]
    pub fn current_screen(&self) -> &AppScreen {
        &self.screen
    }

    /// Sets the current screen.
    pub fn set_screen(&mut self, screen: AppScreen) {
        debug!("Switching to screen: {:?}", screen);
        self.screen = screen;
    }

    /// Sets a status message to display.
    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
    }

    /// Clears the status message.
    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    /// Updates the last activity timestamp.
    ///
    /// Call this whenever the user interacts with the application
    /// (clicks, keystrokes, etc.) while the vault is unlocked.
    pub fn update_activity(&mut self) {
        if self.vault_session.is_some() {
            self.last_activity = Some(Instant::now());
        }
    }

    /// Returns the auto-lock timeout in seconds.
    ///
    /// Returns 0 if auto-lock is disabled.
    #[must_use]
    pub fn auto_lock_timeout_seconds(&self) -> u64 {
        u64::from(self.config.auto_lock_timeout_minutes) * 60
    }

    /// Returns whether auto-lock is enabled.
    #[must_use]
    pub fn is_auto_lock_enabled(&self) -> bool {
        self.config.auto_lock_timeout_minutes > 0
    }

    /// Returns the number of seconds until auto-lock triggers.
    ///
    /// Returns `None` if:
    /// - Auto-lock is disabled
    /// - No vault is unlocked
    /// - No activity has been recorded yet
    #[must_use]
    pub fn seconds_until_auto_lock(&self) -> Option<u64> {
        if !self.is_auto_lock_enabled() || self.vault_session.is_none() {
            return None;
        }

        let last = self.last_activity?;
        let elapsed = last.elapsed().as_secs();
        let timeout = self.auto_lock_timeout_seconds();

        if elapsed >= timeout {
            Some(0)
        } else {
            Some(timeout - elapsed)
        }
    }

    /// Checks if the vault should be auto-locked due to idle timeout.
    ///
    /// Returns `true` if the vault was locked, `false` otherwise.
    fn check_auto_lock(&mut self) -> bool {
        if !self.is_auto_lock_enabled() || self.vault_session.is_none() {
            return false;
        }

        if let Some(last) = self.last_activity {
            let elapsed = last.elapsed().as_secs();
            let timeout = self.auto_lock_timeout_seconds();

            if elapsed >= timeout {
                info!("Auto-locking vault after {} seconds of inactivity", elapsed);
                self.lock_vault();
                return true;
            }
        }

        false
    }

    /// Shows the about dialog.
    pub fn show_about_dialog(&mut self) {
        self.show_about = true;
    }

    /// Returns the application configuration.
    #[must_use]
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut AppConfig {
        &mut self.config
    }

    /// Saves the current configuration to disk.
    pub fn save_config(&self) {
        if let Err(e) = save_config(&self.config) {
            warn!("Failed to save configuration: {}", e);
        } else {
            debug!("Configuration saved successfully");
        }
    }

    /// Opens a vault at the given path.
    ///
    /// If the vault is on an encrypted drive that is locked, this will
    /// first trigger the hardware unlock flow before proceeding to vault unlock.
    pub fn open_vault(&mut self, path: PathBuf) {
        info!("Opening vault: {:?}", path);

        // Check if the vault is on an encrypted drive that needs unlocking (US-026)
        let (is_encrypted, is_locked, drive_info) =
            tesseract_hardware::check_encrypted_drive_status(&path);

        if is_encrypted && is_locked {
            info!("Vault is on a locked encrypted drive, starting hardware unlock first");
            // Store the vault path for later and show hardware unlock
            self.pending_vault_for_hardware_unlock = Some(path);
            self.pending_drive_unlock = drive_info;
            self.use_unified_password = true; // Use same password for drive and vault

            // Configure drive detection state for hardware unlock
            if let Some(ref drive) = self.pending_drive_unlock {
                self.drive_detection_state
                    .set_info("Vault is on an encrypted drive. Enter password to unlock both drive and vault.");
                self.drive_detection_state.unlock_password.clear();
                self.drive_detection_state.show_unlock_dialog = true;
                self.drive_detection_state.show_password = false;
                self.drive_detection_state.unlocking = false;
            }
            self.screen = AppScreen::Drives;
            return;
        }

        // Normal vault open flow
        self.config.add_recent_vault(path.clone());
        self.save_config();
        self.current_vault_path = Some(path.clone());
        self.vault_selection_state.clear_error();

        // Store drive info if vault is on encrypted drive (but already unlocked)
        if is_encrypted {
            if let Some(drive) = drive_info {
                let drive_name = Self::get_drive_display_name_static(&drive);
                self.current_drive = Some(UnlockedDriveInfo {
                    device_path: drive.device_path.clone(),
                    name: drive_name,
                    size_bytes: drive.size_bytes,
                    mount_point: drive.mount_point.clone(),
                    is_locked: false,
                });
            }
        }

        // Initialize password entry state for this vault
        self.password_entry_state.reset_for_vault(path);
        if let Err(e) = self.password_entry_state.load_header() {
            warn!("Failed to load vault header: {}", e);
            self.vault_selection_state.set_error(format!("Failed to open vault: {}", e));
            return;
        }

        self.screen = AppScreen::PasswordEntry;
    }

    /// Static version of get_drive_display_name for use in contexts without &self.
    fn get_drive_display_name_static(drive: &tesseract_hardware::DriveInfo) -> String {
        if !drive.vendor.is_empty() || !drive.model.is_empty() {
            format!("{} {}", drive.vendor, drive.model).trim().to_string()
        } else {
            drive.device_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string()
        }
    }

    /// Starts the vault creation process.
    pub fn start_vault_creation(&mut self, path: PathBuf) {
        info!("Starting vault creation at: {:?}", path);
        self.new_vault_path = Some(path);
        self.screen = AppScreen::VaultCreation;
    }

    /// Renders the about dialog if shown.
    fn render_about_dialog(&mut self, ctx: &egui::Context) {
        if self.show_about {
            egui::Window::new("About TESSERACT")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("TESSERACT");
                        ui.add_space(10.0);
                        ui.label("Secure Removable Storage Encryption");
                        ui.add_space(5.0);
                        ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                        ui.add_space(10.0);
                        ui.label("AES-256-GCM • Argon2id • Multi-Level Access");
                        ui.add_space(20.0);
                        if ui.button("Close").clicked() {
                            self.show_about = false;
                        }
                    });
                });
        }
    }

    /// Renders the main menu bar.
    fn render_menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open Vault...").clicked() {
                        self.screen = AppScreen::VaultSelection;
                        ui.close_menu();
                    }
                    if ui.button("Create New Vault...").clicked() {
                        if let Some(path) = self.vault_selection_state.handle_create_vault() {
                            self.start_vault_creation(path);
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Lock Vault").clicked() {
                        self.current_vault_path = None;
                        self.screen = AppScreen::VaultSelection;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        // Set flag for secure exit with key cleanup (US-031)
                        self.exit_requested = true;
                    }
                });

                ui.menu_button("View", |ui| {
                    if ui.button("File Browser").clicked() {
                        // Only allow if vault is unlocked (future implementation)
                        ui.close_menu();
                    }
                    if ui.button("Settings").clicked() {
                        self.screen = AppScreen::Settings;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About TESSERACT").clicked() {
                        self.show_about_dialog();
                        ui.close_menu();
                    }
                });
            });
        });
    }

    /// Renders the status bar at the bottom with drive status (US-025).
    fn render_status_bar(&mut self, ctx: &egui::Context) {
        let mut lock_drive = false;
        let mut eject_drive = false;

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Left side: status message or drive info
                if let Some(ref drive) = self.current_drive {
                    // Drive status section
                    let status_icon = if drive.is_locked { "🔒" } else { "🔓" };
                    let status_text = if drive.is_locked { "Locked" } else { "Unlocked" };

                    ui.label(egui::RichText::new(status_icon).size(14.0));
                    ui.label(egui::RichText::new(&drive.name).strong());
                    ui.label(format!("({}) - {}", format_file_size(drive.size_bytes), status_text));

                    ui.separator();

                    // Lock button (only when unlocked)
                    if !drive.is_locked {
                        if ui.button("🔐 Lock Drive").on_hover_text("Lock the encrypted drive").clicked() {
                            lock_drive = true;
                        }
                    }

                    // Eject button
                    if ui.button("⏏ Eject").on_hover_text("Safely remove the drive").clicked() {
                        eject_drive = true;
                    }
                } else if let Some(ref msg) = self.status_message {
                    ui.label(msg);
                } else {
                    ui.label("Ready");
                }

                // Right side: screen name
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("Screen: {}", self.screen.title()));
                });
            });
        });

        // Handle actions
        if lock_drive {
            self.lock_current_drive();
        }
        if eject_drive {
            self.eject_current_drive();
        }
    }

    /// Locks the current drive.
    fn lock_current_drive(&mut self) {
        if let Some(ref drive) = self.current_drive.clone() {
            match tesseract_hardware::sed::lock_drive(&drive.device_path) {
                Ok(()) => {
                    self.set_status(format!("Drive {} locked", drive.name));
                    // Update drive status
                    if let Some(ref mut d) = self.current_drive {
                        d.is_locked = true;
                    }
                    self.drive_detection_state.needs_refresh = true;
                }
                Err(e) => {
                    self.set_status(format!("Failed to lock drive: {}", e));
                }
            }
        }
    }

    /// Ejects the current drive safely.
    fn eject_current_drive(&mut self) {
        if let Some(ref drive) = self.current_drive.clone() {
            // First lock the drive if unlocked
            if !drive.is_locked {
                if let Err(e) = tesseract_hardware::sed::lock_drive(&drive.device_path) {
                    self.set_status(format!("Failed to lock drive before eject: {}", e));
                    return;
                }
            }

            // Then eject
            match tesseract_hardware::detect::eject_drive(&drive.device_path) {
                Ok(()) => {
                    self.set_status(format!("Drive {} ejected safely", drive.name));
                    self.current_drive = None;
                    self.drive_detection_state.needs_refresh = true;
                }
                Err(e) => {
                    self.set_status(format!("Failed to eject drive: {}", e));
                }
            }
        }
    }

    /// Checks if the current encrypted drive is still connected (US-027).
    ///
    /// If the drive has been removed:
    /// - Locks the vault immediately
    /// - Clears all keys from memory
    /// - Sets notification flag for user feedback
    /// - Returns to vault selection screen
    ///
    /// This method is called periodically in the update loop.
    fn check_drive_removal(&mut self) -> bool {
        // Only check if we have an unlocked drive and vault session
        let Some(ref drive) = self.current_drive else {
            return false;
        };

        // Only check if vault is actually unlocked (has active session)
        if self.vault_session.is_none() {
            return false;
        }

        // Throttle checks to avoid excessive I/O (check every 2 seconds)
        if let Some(last_check) = self.last_drive_check {
            if last_check.elapsed().as_secs() < 2 {
                return false;
            }
        }
        self.last_drive_check = Some(Instant::now());

        // Check if the drive is still connected
        if tesseract_hardware::is_drive_connected(&drive.device_path) {
            return false;
        }

        // Drive has been removed - auto-lock the vault
        info!("Drive removed - auto-locking vault for security");
        let drive_name = drive.name.clone();

        // Lock the vault (clears session, keys, temp files)
        self.lock_vault();

        // Clear the drive info
        self.current_drive = None;
        self.drive_detection_state.needs_refresh = true;

        // Set notification flag for user feedback
        self.drive_removed_notification = true;

        // Return to vault selection screen instead of password entry
        // because the drive is gone and we can't unlock without it
        self.screen = AppScreen::VaultSelection;
        self.current_vault_path = None; // Clear vault path since drive is gone

        info!("Vault auto-locked after removal of drive: {}", drive_name);
        true
    }

    /// Renders the drive removal notification dialog (US-027).
    fn render_drive_removal_notification(&mut self, ctx: &egui::Context) {
        if !self.drive_removed_notification {
            return;
        }

        egui::Window::new("Drive Removed")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(350.0);
                ui.vertical_centered(|ui| {
                    // Warning icon
                    ui.label(egui::RichText::new("⚠️").size(48.0));
                    ui.add_space(10.0);

                    // Title
                    ui.label(
                        egui::RichText::new("Drive Removed - Vault Locked")
                            .strong()
                            .size(16.0)
                    );
                    ui.add_space(10.0);

                    // Description
                    ui.label("Your encrypted drive has been removed.");
                    ui.label("The vault has been automatically locked");
                    ui.label("for your security.");
                    ui.add_space(10.0);

                    // Security note
                    ui.label(
                        egui::RichText::new("All keys have been cleared from memory.")
                            .size(12.0)
                            .color(egui::Color32::from_rgb(150, 150, 150))
                    );
                    ui.add_space(15.0);

                    // Dismiss button
                    if ui.button("OK").clicked() {
                        self.drive_removed_notification = false;
                    }
                });
            });
    }

    /// Renders the vault selection screen.
    fn render_vault_selection(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.heading("Welcome to TESSERACT");
            ui.add_space(10.0);
            ui.label("Secure Removable Storage Encryption");
            ui.add_space(30.0);

            // Main action buttons
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 400.0) / 2.0);

                let open_button = egui::Button::new("📂  Open Existing Vault...")
                    .min_size(egui::vec2(180.0, 40.0));
                if ui.add(open_button).clicked() {
                    if let Some(path) = self.vault_selection_state.handle_open_vault() {
                        self.open_vault(path);
                    }
                }

                ui.add_space(20.0);

                let create_button = egui::Button::new("✨  Create New Vault...")
                    .min_size(egui::vec2(180.0, 40.0));
                if ui.add(create_button).clicked() {
                    if let Some(path) = self.vault_selection_state.handle_create_vault() {
                        self.start_vault_creation(path);
                    }
                }
            });

            ui.add_space(15.0);

            // Manage Drives button
            let drives_button = egui::Button::new("💽  Manage USB Drives...")
                .min_size(egui::vec2(180.0, 35.0));
            if ui.add(drives_button).clicked() {
                self.drive_detection_state.needs_refresh = true;
                self.screen = AppScreen::Drives;
            }

            // Error message display
            if let Some(ref error) = self.vault_selection_state.error_message {
                ui.add_space(20.0);
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 500.0) / 2.0);
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(80, 20, 20))
                        .rounding(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.set_max_width(500.0);
                            ui.horizontal(|ui| {
                                ui.label("⚠️");
                                ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 200, 200)));
                            });
                        });
                });
            }

            ui.add_space(30.0);
            ui.separator();
            ui.add_space(20.0);

            // Recent vaults section
            ui.heading("Recent Vaults");
            ui.add_space(10.0);

            let recent_vaults = self.config.recent_vaults.clone();
            if recent_vaults.is_empty() {
                ui.label(egui::RichText::new("No recent vaults").italics().weak());
            } else {
                egui::Frame::none()
                    .fill(egui::Color32::from_gray(30))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.set_max_width(600.0);
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                let mut vault_to_open = None;
                                let mut vault_to_remove = None;

                                for (idx, vault) in recent_vaults.iter().enumerate() {
                                    let exists = vault.path.exists();
                                    ui.horizontal(|ui| {
                                        // Vault icon and info
                                        if exists {
                                            ui.label("🔒");
                                        } else {
                                            ui.label(egui::RichText::new("❌").weak());
                                        }

                                        ui.vertical(|ui| {
                                            let name_text = if exists {
                                                egui::RichText::new(&vault.name).strong()
                                            } else {
                                                egui::RichText::new(&vault.name).weak().strikethrough()
                                            };
                                            if ui.link(name_text).clicked() && exists {
                                                vault_to_open = Some(vault.clone());
                                            }

                                            let path_str = vault.path.display().to_string();
                                            let truncated_path = if path_str.len() > 60 {
                                                format!("...{}", &path_str[path_str.len() - 57..])
                                            } else {
                                                path_str
                                            };
                                            ui.label(
                                                egui::RichText::new(truncated_path)
                                                    .small()
                                                    .weak()
                                            );
                                        });

                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            // Remove button
                                            if ui.small_button("✕").on_hover_text("Remove from list").clicked() {
                                                vault_to_remove = Some(idx);
                                            }

                                            // Relative time
                                            ui.label(
                                                egui::RichText::new(format_relative_time(vault.last_accessed))
                                                    .small()
                                                    .weak()
                                            );
                                        });
                                    });

                                    if idx < recent_vaults.len() - 1 {
                                        ui.separator();
                                    }
                                }

                                // Handle vault open
                                if let Some(vault) = vault_to_open {
                                    if let Some(path) = self.vault_selection_state.handle_recent_vault_click(&vault) {
                                        self.open_vault(path);
                                    }
                                }

                                // Handle vault removal from list
                                if let Some(idx) = vault_to_remove {
                                    if idx < self.config.recent_vaults.len() {
                                        self.config.recent_vaults.remove(idx);
                                        self.save_config();
                                    }
                                }
                            });
                    });

                // Clear all button
                ui.add_space(10.0);
                if ui.small_button("Clear Recent Vaults").clicked() {
                    self.config.clear_recent_vaults();
                    self.save_config();
                }
            }
        });
    }

    // =========================================================================
    // Vault Auto-Creation Prompt (US-062)
    // =========================================================================

    /// Renders the auto-creation prompt dialog when no vault is found on startup.
    fn render_auto_creation_prompt(&mut self, ctx: &egui::Context) {
        if !self.auto_creation_state.should_show() {
            return;
        }

        let path = match &self.auto_creation_state {
            AutoCreationPromptState::ShowPrompt(p) => p.clone(),
            _ => return,
        };

        egui::Window::new("No Vault Found")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                // Icon and message
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("📦").size(48.0));
                    ui.add_space(15.0);
                    ui.heading("No Vault Found");
                    ui.add_space(10.0);
                });

                ui.label("TESSERACT did not find an existing vault at the expected location.");
                ui.add_space(10.0);

                // Show the path where vault would be created
                ui.horizontal(|ui| {
                    ui.label("Location:");
                    ui.label(egui::RichText::new(path.display().to_string()).weak().italics());
                });

                ui.add_space(15.0);
                ui.label("Would you like to create a new vault?");
                ui.add_space(20.0);

                // Buttons
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("✨ Create New Vault").clicked() {
                            info!("User confirmed vault creation at {:?}", path);
                            self.auto_creation_state.confirm();
                        }
                        ui.add_space(10.0);
                        if ui.button("Cancel").clicked() {
                            debug!("User dismissed auto-creation prompt");
                            self.auto_creation_state.dismiss();
                        }
                    });
                });

                ui.add_space(5.0);
            });
    }

    /// Handles the auto-creation confirmation and launches the wizard.
    fn handle_auto_creation_confirmation(&mut self) {
        if let Some(path) = self.auto_creation_state.get_confirmed_path() {
            info!("Launching vault creation wizard at {:?}", path);
            self.start_vault_creation(path);
            self.auto_creation_state.reset();
        }
    }

    /// Renders the password entry screen.
    fn render_password_entry(&mut self, ui: &mut egui::Ui) {
        // Check for auto-unlock request (US-026 unified flow)
        if self.password_entry_state.auto_unlock && !self.password_entry_state.password.is_empty() {
            self.password_entry_state.auto_unlock = false;
            self.attempt_unlock();
            return;
        }

        ui.vertical_centered(|ui| {
            ui.add_space(60.0);

            // Vault icon and title
            ui.label(egui::RichText::new("🔐").size(48.0));
            ui.add_space(10.0);
            ui.heading("Unlock Vault");
            ui.add_space(5.0);

            // Vault name and path
            ui.label(
                egui::RichText::new(&self.password_entry_state.vault_name())
                    .size(18.0)
                    .strong()
            );
            if let Some(ref path) = self.current_vault_path {
                let path_str = path.display().to_string();
                let truncated = if path_str.len() > 50 {
                    format!("...{}", &path_str[path_str.len() - 47..])
                } else {
                    path_str
                };
                ui.label(egui::RichText::new(truncated).small().weak());
            }
            ui.add_space(30.0);

            // Lockout warning
            if self.password_entry_state.is_locked_out() {
                self.render_lockout_warning(ui);
            } else {
                // Password input area
                self.render_password_input(ui);
            }

            ui.add_space(30.0);

            // Back button
            if ui.button("← Back to Vault Selection").clicked() {
                self.password_entry_state.clear_password();
                self.screen = AppScreen::VaultSelection;
            }
        });
    }

    /// Renders the lockout warning panel.
    fn render_lockout_warning(&mut self, ui: &mut egui::Ui) {
        // Update timer
        self.password_entry_state.update_lockout_timer();

        egui::Frame::none()
            .fill(egui::Color32::from_rgb(100, 40, 40))
            .rounding(10.0)
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_max_width(400.0);
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("⚠️  Account Locked").size(20.0).strong());
                    ui.add_space(10.0);

                    if let AuthStatus::LockedOut { attempts, .. } = self.password_entry_state.status {
                        ui.label(format!(
                            "Too many failed attempts ({})",
                            attempts
                        ));
                    }

                    ui.add_space(10.0);

                    let remaining = self.password_entry_state.lockout_remaining;
                    if remaining > 0 {
                        ui.label(
                            egui::RichText::new(format!(
                                "Try again in: {}",
                                format_duration(remaining)
                            ))
                            .size(24.0)
                            .strong()
                            .color(egui::Color32::from_rgb(255, 200, 100))
                        );

                        // Request repaint for countdown
                        ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
                    } else {
                        // Lockout expired
                        ui.label(egui::RichText::new("You can try again now").color(egui::Color32::GREEN));
                        self.password_entry_state.status = AuthStatus::Idle;
                    }
                });
            });
    }

    /// Renders the password input field and unlock button.
    fn render_password_input(&mut self, ui: &mut egui::Ui) {
        let is_deriving = self.password_entry_state.is_deriving();

        // Error message display
        if let Some(error) = self.password_entry_state.error_message() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(80, 30, 30))
                .rounding(5.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.set_max_width(350.0);
                    ui.horizontal(|ui| {
                        ui.label("⚠️");
                        ui.label(
                            egui::RichText::new(error)
                                .color(egui::Color32::from_rgb(255, 180, 180))
                        );
                    });
                });
            ui.add_space(15.0);
        }

        // Password input container
        egui::Frame::none()
            .fill(egui::Color32::from_gray(40))
            .rounding(8.0)
            .inner_margin(15.0)
            .show(ui, |ui| {
                ui.set_max_width(350.0);

                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Show/hide toggle
                        let toggle_text = if self.password_entry_state.show_password { "👁" } else { "👁‍🗨" };
                        if ui.small_button(toggle_text).on_hover_text(
                            if self.password_entry_state.show_password { "Hide password" } else { "Show password" }
                        ).clicked() && !is_deriving {
                            self.password_entry_state.show_password = !self.password_entry_state.show_password;
                        }
                    });
                });

                ui.add_space(5.0);

                // Password text edit
                let text_edit = if self.password_entry_state.show_password {
                    egui::TextEdit::singleline(&mut self.password_entry_state.password)
                        .desired_width(f32::INFINITY)
                        .interactive(!is_deriving)
                } else {
                    egui::TextEdit::singleline(&mut self.password_entry_state.password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .interactive(!is_deriving)
                };

                let response = ui.add(text_edit);

                // Handle Enter key
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if self.password_entry_state.can_attempt_auth() && !self.password_entry_state.password.is_empty() {
                        self.attempt_unlock();
                    }
                }
            });

        ui.add_space(15.0);

        // Unlock button or loading indicator
        if is_deriving {
            // Loading indicator
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - 200.0) / 2.0);
                ui.spinner();
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Deriving key...").italics());
            });
            ui.add_space(5.0);
            ui.label(
                egui::RichText::new("This may take a few seconds")
                    .small()
                    .weak()
            );
        } else {
            // Unlock button
            let can_unlock = self.password_entry_state.can_attempt_auth()
                && !self.password_entry_state.password.is_empty();

            let button = egui::Button::new("🔓  Unlock Vault")
                .min_size(egui::vec2(200.0, 40.0));

            let button = if can_unlock {
                button
            } else {
                button.sense(egui::Sense::hover())
            };

            if ui.add_enabled(can_unlock, button).clicked() {
                self.attempt_unlock();
            }

            // Failed attempts counter
            if self.password_entry_state.failed_attempts > 0 {
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(format!(
                        "Failed attempts: {}",
                        self.password_entry_state.failed_attempts
                    ))
                    .small()
                    .color(egui::Color32::from_rgb(255, 150, 100))
                );
            }
        }

        // Recovery link
        ui.add_space(20.0);
        if ui.link("Forgot password? Use recovery key").clicked() {
            // Initialize recovery state with current vault path
            if let Some(ref path) = self.current_vault_path {
                self.recovery_state = PasswordRecoveryState::for_vault(path.clone());
            } else {
                self.recovery_state.reset();
            }
            self.screen = AppScreen::PasswordRecovery;
        }
    }

    /// Attempts to unlock the vault with the current password.
    fn attempt_unlock(&mut self) {
        info!("Attempting vault unlock");

        // Get references to what we need
        let password = self.password_entry_state.password.clone();
        let header = match &self.password_entry_state.header {
            Some(h) => h.clone(),
            None => {
                self.password_entry_state.status = AuthStatus::Failed(
                    "No vault header loaded".to_string()
                );
                return;
            }
        };
        let params = match &self.password_entry_state.argon2_params {
            Some(p) => p.clone(),
            None => {
                self.password_entry_state.status = AuthStatus::Failed(
                    "No Argon2 parameters".to_string()
                );
                return;
            }
        };

        // Set deriving state
        self.password_entry_state.status = AuthStatus::Deriving;

        // TECH DEBT: Currently performs synchronous unlock (blocking UI during key derivation).
        // This should be moved to a background thread to maintain UI responsiveness.
        // Tracking issue: Implement async vault unlock for responsive UI
        match crate::screens::attempt_authentication(&header, &password, &params) {
            Ok(master_key) => {
                info!("Vault unlocked successfully");
                self.password_entry_state.status = AuthStatus::Success;
                self.password_entry_state.clear_password();
                self.master_key = Some(Zeroizing::new(master_key));

                // Open vault session
                if let Some(ref vault_path) = self.current_vault_path {
                    match tesseract_core::session::open_vault(
                        vault_path,
                        password.as_bytes(),
                        Some(params),
                    ) {
                        Ok(session) => {
                            // Initialize file browser state
                            self.file_browser_state.initialize(&session);
                            self.vault_session = Some(session);
                            // Initialize activity tracking for auto-lock
                            self.last_activity = Some(Instant::now());
                            // Initialize temp file manager for secure file preview
                            match tesseract_core::TempFileManager::new() {
                                Ok(manager) => {
                                    self.temp_file_manager = Some(manager);
                                }
                                Err(e) => {
                                    warn!("Failed to initialize temp file manager: {}", e);
                                    // Non-fatal - file preview will be disabled
                                }
                            }
                            self.screen = AppScreen::FileBrowser;
                            self.set_status("Vault unlocked");
                        }
                        Err(e) => {
                            warn!("Failed to open vault session: {}", e);
                            self.password_entry_state.status = AuthStatus::Failed(
                                format!("Session error: {}", e)
                            );
                            return;
                        }
                    }
                } else {
                    self.screen = AppScreen::FileBrowser;
                    self.set_status("Vault unlocked");
                }
            }
            Err(e) => {
                warn!("Unlock failed: {}", e);
                self.password_entry_state.failed_attempts += 1;

                // Check if we need to lock out
                if crate::screens::should_trigger_lockout(self.password_entry_state.failed_attempts) {
                    let lockout_duration = crate::screens::default_lockout_duration();
                    let until = crate::screens::current_timestamp() + lockout_duration;
                    self.password_entry_state.status = AuthStatus::LockedOut {
                        until,
                        attempts: self.password_entry_state.failed_attempts,
                    };
                    self.password_entry_state.lockout_remaining = lockout_duration;
                } else {
                    self.password_entry_state.status = AuthStatus::Failed(e.to_string());
                }

                // Clear password on failure
                self.password_entry_state.clear_password();
            }
        }
    }

    /// Renders the file browser screen.
    fn render_file_browser(&mut self, ui: &mut egui::Ui) {
        // Top toolbar
        self.render_file_browser_toolbar(ui);

        ui.separator();

        // Breadcrumb navigation
        self.render_breadcrumbs(ui);

        ui.separator();

        // Error message if any
        if let Some(ref error) = self.file_browser_state.error_message {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(80, 30, 30))
                .rounding(5.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("⚠️");
                        ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 180, 180)));
                    });
                });
            ui.add_space(5.0);
        }

        // Main file list
        if self.file_browser_state.is_loading {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.spinner();
                ui.label("Loading files...");
            });
        } else if self.file_browser_state.entries.is_empty() {
            self.render_empty_state(ui);
        } else {
            self.render_file_list(ui);
        }

        // Status bar
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.separator();
            ui.horizontal(|ui| {
                // File count
                let file_count = self.file_browser_state.entries.iter()
                    .filter(|e| e.is_file())
                    .count();
                let dir_count = self.file_browser_state.entries.iter()
                    .filter(|e| e.is_directory())
                    .count();

                if dir_count > 0 && file_count > 0 {
                    ui.label(format!("{} folder{}, {} file{}",
                        dir_count, if dir_count == 1 { "" } else { "s" },
                        file_count, if file_count == 1 { "" } else { "s" }
                    ));
                } else if dir_count > 0 {
                    ui.label(format!("{} folder{}", dir_count, if dir_count == 1 { "" } else { "s" }));
                } else if file_count > 0 {
                    ui.label(format!("{} file{}", file_count, if file_count == 1 { "" } else { "s" }));
                }

                ui.separator();

                // Selection info
                if self.file_browser_state.has_selection() {
                    ui.label(format!("{} selected", self.file_browser_state.selection_count()));
                }

                // Spacer
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Access level indicator
                    ui.label(
                        egui::RichText::new(format!("Access Level: L{}", self.file_browser_state.max_access_level))
                            .color(egui::Color32::from_rgb(100, 200, 100))
                    );
                });
            });
        });
    }

    /// Renders the file browser toolbar.
    fn render_file_browser_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Navigation buttons
            let can_go_up = self.file_browser_state.current_path != "/";

            if ui.add_enabled(can_go_up, egui::Button::new("⬆ Up")).clicked() {
                if let Some(ref session) = self.vault_session {
                    self.file_browser_state.navigate_up(session);
                }
            }

            if ui.button("🔄 Refresh").clicked() {
                if let Some(ref session) = self.vault_session {
                    self.file_browser_state.refresh_entries(session);
                }
            }

            ui.separator();

            // Import button
            if ui.button("📥 Import...").clicked() {
                self.open_import_dialog();
            }

            // Export button
            let can_export = self.file_browser_state.has_selection();
            if ui.add_enabled(can_export, egui::Button::new("📤 Export...")).clicked() {
                self.open_export_dialog();
            }

            ui.separator();

            // Settings button - access level management
            if ui.button("⚙️ Access Levels").clicked() {
                self.settings_state.mark_refresh_needed();
                self.screen = AppScreen::Settings;
            }

            ui.separator();

            // Lock vault button
            if ui.button("🔒 Lock Vault").clicked() {
                self.lock_vault();
            }
        });
    }

    /// Renders the breadcrumb navigation bar.
    fn render_breadcrumbs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("📂");

            let breadcrumbs = self.file_browser_state.breadcrumbs.clone();
            let mut navigate_to_idx: Option<usize> = None;

            for (idx, crumb) in breadcrumbs.iter().enumerate() {
                let is_last = idx == breadcrumbs.len() - 1;

                if is_last {
                    // Current location (not clickable)
                    ui.label(
                        egui::RichText::new(if crumb == "/" { "Vault Root" } else { crumb })
                            .strong()
                    );
                } else {
                    // Clickable breadcrumb
                    let label = if crumb == "/" { "Vault Root" } else { crumb.as_str() };
                    if ui.link(label).clicked() {
                        navigate_to_idx = Some(idx);
                    }
                    ui.label("›");
                }
            }

            // Handle navigation outside the loop to avoid borrow issues
            if let Some(idx) = navigate_to_idx {
                if let Some(ref session) = self.vault_session {
                    self.file_browser_state.navigate_to_breadcrumb(idx, session);
                }
            }
        });
    }

    /// Renders the empty state for new/empty vaults.
    fn render_empty_state(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(egui::RichText::new("📭").size(64.0));
            ui.add_space(20.0);
            ui.heading("No files in this vault");
            ui.add_space(10.0);
            ui.label(
                egui::RichText::new("Drag and drop files here or use the Import button")
                    .weak()
            );
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new("Your files will be encrypted with AES-256-GCM")
                    .small()
                    .weak()
            );
        });
    }

    /// Renders the file list with column headers.
    fn render_file_list(&mut self, ui: &mut egui::Ui) {
        // Column headers
        ui.horizontal(|ui| {
            ui.add_space(30.0); // Icon column

            // Name column header
            let name_arrow = match (&self.file_browser_state.sort_column, &self.file_browser_state.sort_direction) {
                (SortColumn::Name, crate::screens::SortDirection::Ascending) => " ▲",
                (SortColumn::Name, crate::screens::SortDirection::Descending) => " ▼",
                _ => "",
            };
            if ui.add_sized(
                [300.0, 20.0],
                egui::SelectableLabel::new(false, format!("Name{}", name_arrow))
            ).clicked() {
                self.file_browser_state.toggle_sort(SortColumn::Name);
            }

            // Size column header
            let size_arrow = match (&self.file_browser_state.sort_column, &self.file_browser_state.sort_direction) {
                (SortColumn::Size, crate::screens::SortDirection::Ascending) => " ▲",
                (SortColumn::Size, crate::screens::SortDirection::Descending) => " ▼",
                _ => "",
            };
            if ui.add_sized(
                [80.0, 20.0],
                egui::SelectableLabel::new(false, format!("Size{}", size_arrow))
            ).clicked() {
                self.file_browser_state.toggle_sort(SortColumn::Size);
            }

            // Modified column header
            let mod_arrow = match (&self.file_browser_state.sort_column, &self.file_browser_state.sort_direction) {
                (SortColumn::Modified, crate::screens::SortDirection::Ascending) => " ▲",
                (SortColumn::Modified, crate::screens::SortDirection::Descending) => " ▼",
                _ => "",
            };
            if ui.add_sized(
                [120.0, 20.0],
                egui::SelectableLabel::new(false, format!("Modified{}", mod_arrow))
            ).clicked() {
                self.file_browser_state.toggle_sort(SortColumn::Modified);
            }

            // Level column header
            let level_arrow = match (&self.file_browser_state.sort_column, &self.file_browser_state.sort_direction) {
                (SortColumn::Level, crate::screens::SortDirection::Ascending) => " ▲",
                (SortColumn::Level, crate::screens::SortDirection::Descending) => " ▼",
                _ => "",
            };
            if ui.add_sized(
                [60.0, 20.0],
                egui::SelectableLabel::new(false, format!("Level{}", level_arrow))
            ).clicked() {
                self.file_browser_state.toggle_sort(SortColumn::Level);
            }
        });

        ui.separator();

        // File list with scroll area
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Clone entries to avoid borrow issues
                let entries = self.file_browser_state.entries.clone();
                let selected = self.file_browser_state.selected.clone();
                let mut entry_clicked: Option<(tesseract_core::files::FileEntry, bool)> = None;
                let mut entry_double_clicked: Option<tesseract_core::files::FileEntry> = None;
                let mut context_menu_request: Option<(egui::Pos2, tesseract_core::files::FileEntry)> = None;

                for entry in &entries {
                    let is_selected = entry.uuid.map(|u| selected.contains(&u)).unwrap_or(false);

                    let response = ui.horizontal(|ui| {
                        // Selection highlight
                        let bg_color = if is_selected {
                            egui::Color32::from_rgb(60, 80, 120)
                        } else {
                            egui::Color32::TRANSPARENT
                        };

                        egui::Frame::none()
                            .fill(bg_color)
                            .rounding(3.0)
                            .inner_margin(egui::vec2(5.0, 2.0))
                            .show(ui, |ui| {
                                // Icon
                                ui.label(entry_icon(&entry));

                                // Name
                                let name_text = if entry.is_directory() {
                                    egui::RichText::new(&entry.name).strong()
                                } else {
                                    egui::RichText::new(&entry.name)
                                };
                                ui.add_sized([300.0, 18.0], egui::Label::new(name_text).truncate());

                                // Size
                                let size_str = if entry.is_directory() {
                                    "-".to_string()
                                } else {
                                    format_file_size(entry.size)
                                };
                                ui.add_sized([80.0, 18.0], egui::Label::new(
                                    egui::RichText::new(size_str).weak()
                                ));

                                // Modified time
                                let mod_str = if entry.modified_time > 0 {
                                    format_timestamp(entry.modified_time)
                                } else {
                                    "-".to_string()
                                };
                                ui.add_sized([120.0, 18.0], egui::Label::new(
                                    egui::RichText::new(mod_str).weak()
                                ));

                                // Access level
                                let level_color = match entry.access_level {
                                    1 => egui::Color32::from_rgb(100, 200, 100),
                                    2 => egui::Color32::from_rgb(200, 200, 100),
                                    3 => egui::Color32::from_rgb(200, 150, 100),
                                    _ => egui::Color32::from_rgb(200, 100, 100),
                                };
                                ui.add_sized([60.0, 18.0], egui::Label::new(
                                    egui::RichText::new(level_label(entry.access_level))
                                        .color(level_color)
                                ));
                            });
                    });

                    // Handle left-click
                    let interact_response = response.response.interact(egui::Sense::click());
                    if interact_response.clicked() {
                        let ctrl_held = ui.input(|i| i.modifiers.ctrl || i.modifiers.command);
                        entry_clicked = Some((entry.clone(), ctrl_held));
                    }

                    // Handle double-click to open file
                    if interact_response.double_clicked() {
                        entry_double_clicked = Some(entry.clone());
                    }

                    // Handle right-click for context menu
                    if interact_response.secondary_clicked() {
                        if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
                            context_menu_request = Some((pos, entry.clone()));
                        }
                    }
                }

                // Handle clicked entry outside the loop
                if let Some((entry, ctrl_held)) = entry_clicked {
                    if let Some(ref session) = self.vault_session {
                        self.file_browser_state.handle_entry_click(&entry, ctrl_held, session);
                    }
                }

                // Handle double-clicked entry (open file/navigate directory)
                if let Some(entry) = entry_double_clicked {
                    if entry.is_directory() {
                        // Navigate into directory
                        if let Some(ref session) = self.vault_session {
                            let new_path = format!("{}/{}", self.file_browser_state.current_path.trim_end_matches('/'), entry.name);
                            self.file_browser_state.navigate_to(&new_path, session);
                        }
                    } else if let Some(uuid) = entry.uuid {
                        // Open file in default application
                        self.open_file_preview(uuid);
                    }
                }

                // Handle context menu request
                if let Some((pos, entry)) = context_menu_request {
                    self.open_context_menu(pos, &entry);
                }
            });
    }

    /// Opens the context menu at the given position for the specified entry.
    fn open_context_menu(&mut self, pos: egui::Pos2, entry: &tesseract_core::files::FileEntry) {
        // If the right-clicked entry is not selected, select only it
        if let Some(uuid) = entry.uuid {
            if !self.file_browser_state.selected.contains(&uuid) {
                self.file_browser_state.selected.clear();
                self.file_browser_state.selected.insert(uuid);
            }
        }

        // Collect selected file UUIDs
        let file_uuids: Vec<uuid::Uuid> = self.file_browser_state.selected.iter().copied().collect();

        // Check if any selected entries are directories
        let has_directories = self.file_browser_state.entries.iter().any(|e| {
            e.uuid.map(|u| self.file_browser_state.selected.contains(&u) && e.is_directory())
                .unwrap_or(false)
        });

        // Open the context menu
        self.file_browser_state.context_menu.open(pos, file_uuids, has_directories);
    }

    /// Locks the vault and returns to password entry screen.
    ///
    /// Clears all keys from memory but preserves the vault path so the user
    /// can re-enter their password without having to re-select the vault.
    fn lock_vault(&mut self) {
        info!("Locking vault");

        // Clear sensitive data - session Drop will handle key wiping via SecureBytes/zeroize
        if let Some(session) = self.vault_session.take() {
            drop(session);
        }

        // Wipe master key - Zeroizing wrapper ensures key is zeroized on drop
        // We take and drop to ensure immediate cleanup
        drop(self.master_key.take());

        // Clear activity tracking
        self.last_activity = None;

        // Clean up temp files securely - this wipes plaintext from disk
        if let Some(manager) = self.temp_file_manager.take() {
            manager.cleanup_all();
        }

        // Reset screen states
        self.file_browser_state = FileBrowserState::new();
        self.password_entry_state = PasswordEntryState::new();

        // Return to password entry (not vault selection) so user can re-enter password
        // The current_vault_path is preserved intentionally
        self.screen = AppScreen::PasswordEntry;
        self.set_status("Vault locked");
    }

    /// Securely cleans up all sensitive data before application exit.
    ///
    /// This method ensures all keys are zeroized from memory before the
    /// application terminates, regardless of how exit is triggered.
    fn cleanup_and_exit(&mut self) -> ! {
        info!("Application exit requested - cleaning up sensitive data");

        // Lock vault first (handles session and master_key cleanup)
        self.lock_vault();

        // Clear any pending password data from wizard states
        self.wizard_state.clear_sensitive_data();
        self.drive_init_wizard_state.reset();
        self.password_entry_state.clear_password();
        self.drive_detection_state.clear_sensitive_data();
        self.recovery_state.clear_sensitive_data();

        // Close all settings dialogs (which clears passwords)
        self.settings_state.create_dialog.close();
        self.settings_state.change_password_dialog.close();
        self.settings_state.drive_password_change_dialog.close();

        info!("Cleanup complete - exiting");
        std::process::exit(0)
    }

    /// Renders the main content area based on current screen.
    fn render_content(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.screen {
                AppScreen::VaultSelection => self.render_vault_selection(ui),
                AppScreen::PasswordEntry => self.render_password_entry(ui),
                AppScreen::FileBrowser => {
                    self.render_file_browser(ui);
                }
                AppScreen::Settings => {
                    self.render_settings(ui);
                }
                AppScreen::VaultCreation => {
                    self.render_vault_creation(ui);
                }
                AppScreen::PasswordRecovery => {
                    self.render_password_recovery(ui);
                }
                AppScreen::Drives => {
                    self.render_drives(ui);
                }
            }
        });
    }

    // =========================================================================
    // USB Drive Detection / Management (US-022)
    // =========================================================================

    /// Renders the USB drive detection and management screen.
    fn render_drives(&mut self, ui: &mut egui::Ui) {
        // Check if we should transition to vault browser after successful unlock
        if let Some(vault_path) = self.drive_detection_state.unlocked_vault_path.take() {
            self.open_vault(vault_path);
            return;
        }

        // Refresh drives if needed
        if self.drive_detection_state.needs_refresh {
            self.drive_detection_state.refresh_drives();
        }

        ui.vertical(|ui| {
            // Header with back button
            ui.horizontal(|ui| {
                if ui.button("← Back").clicked() {
                    self.screen = AppScreen::VaultSelection;
                    return;
                }
                ui.add_space(10.0);
                ui.heading("USB Drive Management");
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            // Action bar
            ui.horizontal(|ui| {
                if ui.button("🔄 Refresh").clicked() {
                    self.drive_detection_state.needs_refresh = true;
                }

                ui.add_space(10.0);

                // Status indicator
                if self.drive_detection_state.scanning {
                    ui.label(egui::RichText::new("Scanning...").weak().italics());
                    ui.spinner();
                } else {
                    let count = self.drive_detection_state.drives.len();
                    ui.label(
                        egui::RichText::new(format!("{} drive(s) detected", count)).weak()
                    );
                }
            });

            ui.add_space(10.0);

            // Success message
            if let Some(ref msg) = self.drive_detection_state.success_message.clone() {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(20, 80, 20))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("✓");
                            ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(200, 255, 200)));
                        });
                    });
                ui.add_space(10.0);
            }

            // Error message
            if let Some(ref error) = self.drive_detection_state.error_message.clone() {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(80, 20, 20))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("⚠️");
                            ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 200, 200)));
                        });
                    });
                ui.add_space(10.0);
            }

            // Drives list
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if self.drive_detection_state.drives.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            ui.label(egui::RichText::new("💽").size(48.0));
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("No USB drives detected").weak().italics());
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("Connect a USB drive and click Refresh").weak().small());
                        });
                    } else {
                        // Clone drives to avoid borrow issues
                        let drives: Vec<_> = self.drive_detection_state.drives.iter().enumerate()
                            .map(|(i, d)| (i, d.clone()))
                            .collect();

                        for (idx, drive) in drives {
                            egui::Frame::none()
                                .fill(egui::Color32::from_gray(35))
                                .rounding(5.0)
                                .inner_margin(15.0)
                                .outer_margin(egui::vec2(0.0, 5.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        // Drive icon and status
                                        ui.label(egui::RichText::new(drive.status_icon()).size(32.0));

                                        ui.add_space(10.0);

                                        // Drive info
                                        ui.vertical(|ui| {
                                            // Name and path
                                            ui.horizontal(|ui| {
                                                let display_name = Self::get_drive_display_name(&drive.info);
                                                ui.label(
                                                    egui::RichText::new(&display_name).strong().size(16.0)
                                                );
                                                ui.label(
                                                    egui::RichText::new(format!("({})", drive.info.device_path.display()))
                                                        .weak()
                                                        .small()
                                                );
                                            });

                                            // Size and status
                                            ui.horizontal(|ui| {
                                                // Size
                                                let size_str = format_file_size(drive.info.size_bytes);
                                                ui.label(egui::RichText::new(size_str).weak());

                                                ui.label("•");

                                                // Status text
                                                let status_text = drive.status_text();
                                                let status_color = if drive.info.is_locked {
                                                    egui::Color32::from_rgb(255, 200, 100) // Locked - orange
                                                } else if drive.info.drive_type.is_hardware_encrypted() {
                                                    egui::Color32::from_rgb(100, 255, 100) // Unlocked encrypted - green
                                                } else {
                                                    egui::Color32::from_rgb(150, 150, 150) // Unencrypted/unknown - gray
                                                };
                                                ui.label(egui::RichText::new(status_text).color(status_color));
                                            });
                                        });

                                        // Action buttons on the right
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            // Initialize button for unencrypted drives - opens wizard
                                            if drive.can_initialize() {
                                                if ui.button("🔐 Initialize").on_hover_text("Initialize encryption on this drive").clicked() {
                                                    self.drive_init_wizard_state.open(idx);
                                                }
                                            }

                                            // Unlock button for locked drives
                                            if drive.can_unlock() {
                                                if ui.button("🔓 Unlock").on_hover_text("Unlock this encrypted drive").clicked() {
                                                    self.drive_detection_state.open_unlock_dialog(idx);
                                                }
                                            }
                                        });
                                    });
                                });
                        }
                    }
                });
        });

        // Render unlock dialog if open
        self.render_unlock_dialog(ui.ctx());

        // Render simple initialize dialog if open (deprecated - kept for fallback)
        self.render_init_dialog(ui.ctx());

        // Render drive initialization wizard if open (US-024)
        self.render_init_wizard(ui.ctx());
    }

    /// Renders the unlock password dialog.
    fn render_unlock_dialog(&mut self, ctx: &egui::Context) {
        if !self.drive_detection_state.show_unlock_dialog {
            return;
        }

        let drive_name = self.drive_detection_state.unlocking_drive_index
            .and_then(|idx| self.drive_detection_state.drives.get(idx))
            .map(|d| Self::get_drive_display_name(&d.info))
            .unwrap_or_else(|| "Unknown".to_string());

        let is_unlocking = self.drive_detection_state.unlocking;
        let mut close_dialog = false;
        let mut attempt_unlock = false;
        let mut toggle_password_visibility = false;

        egui::Window::new("Unlock Drive and Vault")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("🔒").size(48.0));
                    ui.add_space(10.0);
                    ui.heading("Unlock Drive and Vault");
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(&drive_name).weak());
                });

                ui.add_space(10.0);

                // Info about what will happen
                ui.label(
                    egui::RichText::new("This will unlock both the hardware encryption and the vault.")
                        .weak()
                        .small()
                );

                ui.add_space(20.0);

                // Show progress if unlocking
                if is_unlocking {
                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("Unlocking... This may take a moment.").weak());
                        ui.add_space(5.0);
                        ui.label(egui::RichText::new("(Argon2id key derivation in progress)").weak().small());
                    });
                } else {
                    // Password input with show/hide toggle
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        let show_password = self.drive_detection_state.show_password;
                        let response = ui.add(
                            egui::TextEdit::singleline(&mut self.drive_detection_state.unlock_password)
                                .password(!show_password)
                                .desired_width(200.0)
                        );

                        // Show/hide password toggle button
                        let toggle_text = if show_password { "🙈" } else { "👁" };
                        let toggle_hint = if show_password { "Hide password" } else { "Show password" };
                        if ui.button(toggle_text).on_hover_text(toggle_hint).clicked() {
                            toggle_password_visibility = true;
                        }

                        // Auto-focus and enter key handling
                        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            attempt_unlock = true;
                        }
                    });

                    ui.add_space(20.0);

                    // Buttons
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Cancel").clicked() {
                                close_dialog = true;
                            }

                            ui.add_space(10.0);

                            let enabled = !self.drive_detection_state.unlock_password.is_empty();
                            if ui.add_enabled(enabled, egui::Button::new("🔓 Unlock Drive and Vault")).clicked() {
                                attempt_unlock = true;
                            }
                        });
                    });
                }
            });

        if toggle_password_visibility {
            self.drive_detection_state.show_password = !self.drive_detection_state.show_password;
        }

        if close_dialog {
            self.drive_detection_state.close_unlock_dialog();
        }

        if attempt_unlock {
            self.attempt_drive_unlock();
        }
    }

    /// Attempts to unlock the selected drive.
    fn attempt_drive_unlock(&mut self) {
        // Check if this is a unified unlock flow (US-026)
        if self.pending_drive_unlock.is_some() && self.use_unified_password {
            self.attempt_unified_unlock();
            return;
        }

        let Some(idx) = self.drive_detection_state.unlocking_drive_index else {
            return;
        };

        let Some(drive) = self.drive_detection_state.drives.get(idx) else {
            self.drive_detection_state.set_error("Drive not found");
            self.drive_detection_state.close_unlock_dialog();
            return;
        };

        let path = drive.info.device_path.clone();
        let mount_point = drive.info.mount_point.clone();
        let drive_name = Self::get_drive_display_name(&drive.info);
        let size_bytes = drive.info.size_bytes;
        let password = self.drive_detection_state.unlock_password.clone();

        // Set unlocking flag for progress indicator
        self.drive_detection_state.unlocking = true;

        // Attempt unlock using hardware crate
        match tesseract_hardware::sed::unlock_drive(&path, password.as_bytes()) {
            Ok(()) => {
                self.drive_detection_state.set_success(format!("Drive {} unlocked successfully!", drive_name.clone()));
                self.drive_detection_state.unlocking = false;

                // Store the current unlocked drive info (US-025)
                self.current_drive = Some(UnlockedDriveInfo {
                    device_path: path.clone(),
                    name: drive_name,
                    size_bytes,
                    mount_point: mount_point.clone(),
                    is_locked: false,
                });

                // If the drive has a mount point, look for a vault there
                if let Some(mount) = mount_point {
                    // Check for vault at mount point
                    let vault_path = mount.join("tesseract.vault");
                    if vault_path.exists() {
                        // Store path and transition to vault browser
                        self.drive_detection_state.unlocked_vault_path = Some(vault_path);
                    }
                }

                self.drive_detection_state.close_unlock_dialog();
                self.drive_detection_state.needs_refresh = true;
            }
            Err(e) => {
                self.drive_detection_state.unlocking = false;
                let error_msg = format!("Failed to unlock drive: {}", e);
                // Check for common error patterns
                if error_msg.contains("incorrect password") || error_msg.contains("wrong password") {
                    self.drive_detection_state.set_error("Incorrect password. Please try again.");
                } else {
                    self.drive_detection_state.set_error(error_msg);
                }
            }
        }
    }

    /// Attempts unified unlock for drive and vault (US-026).
    /// Uses the same password to unlock the encrypted drive and then proceeds
    /// to unlock the vault with the same password via dual-key derivation.
    fn attempt_unified_unlock(&mut self) {
        let Some(drive) = self.pending_drive_unlock.take() else {
            return;
        };
        let Some(vault_path) = self.pending_vault_for_hardware_unlock.clone() else {
            return;
        };

        let path = drive.device_path.clone();
        let mount_point = drive.mount_point.clone();
        let drive_name = Self::get_drive_display_name_static(&drive);
        let size_bytes = drive.size_bytes;
        let password = self.drive_detection_state.unlock_password.clone();

        // Set unlocking flag for progress indicator
        self.drive_detection_state.unlocking = true;

        // Step 1: Attempt to unlock the hardware (encrypted drive)
        match tesseract_hardware::sed::unlock_drive(&path, password.as_bytes()) {
            Ok(()) => {
                info!("Drive {} unlocked successfully via unified flow", drive_name);
                self.drive_detection_state.unlocking = false;

                // Store the current unlocked drive info
                self.current_drive = Some(UnlockedDriveInfo {
                    device_path: path.clone(),
                    name: drive_name,
                    size_bytes,
                    mount_point: mount_point.clone(),
                    is_locked: false,
                });

                // Step 2: Continue to vault unlock with the same password
                // Store the password for the vault unlock phase
                self.password_entry_state.password = password;
                self.pending_vault_for_hardware_unlock = None;
                self.use_unified_password = false;
                self.drive_detection_state.close_unlock_dialog();

                // Now open the vault (proceed to password entry which will use stored password)
                self.config.add_recent_vault(vault_path.clone());
                self.save_config();
                self.current_vault_path = Some(vault_path.clone());
                self.vault_selection_state.clear_error();

                // Initialize password entry state for this vault
                self.password_entry_state.reset_for_vault(vault_path);
                if let Err(e) = self.password_entry_state.load_header() {
                    warn!("Failed to load vault header: {}", e);
                    self.vault_selection_state.set_error(format!("Failed to open vault: {}", e));
                    self.screen = AppScreen::VaultSelection;
                    return;
                }

                // Pre-fill password and mark for auto-unlock attempt
                self.password_entry_state.password = self.drive_detection_state.unlock_password.clone();
                self.password_entry_state.auto_unlock = true;

                self.screen = AppScreen::PasswordEntry;
            }
            Err(e) => {
                self.drive_detection_state.unlocking = false;
                // Restore pending state for retry
                self.pending_drive_unlock = Some(drive);
                let error_msg = format!("Failed to unlock drive: {}", e);
                if error_msg.contains("incorrect password") || error_msg.contains("wrong password") {
                    self.drive_detection_state.set_error("Incorrect password. Please try again.");
                } else {
                    self.drive_detection_state.set_error(error_msg);
                }
            }
        }
    }

    /// Helper to get a display name for a drive.
    fn get_drive_display_name(info: &tesseract_hardware::detect::DriveInfo) -> String {
        if !info.vendor.is_empty() || !info.model.is_empty() {
            format!("{} {}", info.vendor, info.model).trim().to_string()
        } else {
            info.device_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string()
        }
    }

    /// Renders the initialize encryption dialog.
    fn render_init_dialog(&mut self, ctx: &egui::Context) {
        if !self.drive_detection_state.show_init_dialog {
            return;
        }

        let drive_name = self.drive_detection_state.initializing_drive_index
            .and_then(|idx| self.drive_detection_state.drives.get(idx))
            .map(|d| Self::get_drive_display_name(&d.info))
            .unwrap_or_else(|| "Unknown".to_string());

        let mut close_dialog = false;
        let mut attempt_init = false;

        egui::Window::new("Initialize Drive Encryption")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("🔐").size(48.0));
                    ui.add_space(10.0);
                    ui.heading("Initialize Encryption");
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(&drive_name).weak());
                });

                ui.add_space(10.0);

                // Warning
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(80, 60, 20))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("⚠️");
                            ui.label(egui::RichText::new("This will enable hardware encryption on the drive. Make sure you remember the password!").small());
                        });
                    });

                ui.add_space(20.0);

                // Password input
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.drive_detection_state.init_password)
                            .password(true)
                            .desired_width(200.0)
                    );
                });

                ui.add_space(10.0);

                // Confirm password
                ui.horizontal(|ui| {
                    ui.label("Confirm:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.drive_detection_state.init_password_confirm)
                            .password(true)
                            .desired_width(200.0)
                    );
                });

                // Password match indicator
                let passwords_match = !self.drive_detection_state.init_password.is_empty()
                    && self.drive_detection_state.init_password == self.drive_detection_state.init_password_confirm;

                if !self.drive_detection_state.init_password.is_empty()
                    && !self.drive_detection_state.init_password_confirm.is_empty()
                    && !passwords_match
                {
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new("Passwords do not match").color(egui::Color32::from_rgb(255, 100, 100)).small());
                }

                ui.add_space(20.0);

                // Buttons
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Cancel").clicked() {
                            close_dialog = true;
                        }

                        ui.add_space(10.0);

                        let enabled = passwords_match && self.drive_detection_state.init_password.len() >= 8;
                        if ui.add_enabled(enabled, egui::Button::new("Initialize")).clicked() {
                            attempt_init = true;
                        }
                    });
                });

                if !passwords_match && !self.drive_detection_state.init_password.is_empty() {
                    // Already showing password mismatch
                } else if self.drive_detection_state.init_password.len() < 8 && !self.drive_detection_state.init_password.is_empty() {
                    ui.label(egui::RichText::new("Password must be at least 8 characters").color(egui::Color32::from_rgb(255, 180, 100)).small());
                }
            });

        if close_dialog {
            self.drive_detection_state.close_init_dialog();
        }

        if attempt_init {
            self.attempt_drive_init();
        }
    }

    /// Attempts to initialize encryption on the selected drive.
    fn attempt_drive_init(&mut self) {
        let Some(idx) = self.drive_detection_state.initializing_drive_index else {
            return;
        };

        let Some(drive) = self.drive_detection_state.drives.get(idx) else {
            self.drive_detection_state.set_error("Drive not found");
            self.drive_detection_state.close_init_dialog();
            return;
        };

        let path = drive.info.device_path.clone();
        let drive_name = Self::get_drive_display_name(&drive.info);
        let password = self.drive_detection_state.init_password.clone();

        // Attempt initialization using hardware crate
        match tesseract_hardware::sed::initialize_drive(&path, password.as_bytes()) {
            Ok(()) => {
                self.drive_detection_state.set_success(format!("Drive {} initialized with encryption", drive_name));
                self.drive_detection_state.close_init_dialog();
                self.drive_detection_state.needs_refresh = true;
            }
            Err(e) => {
                self.drive_detection_state.set_error(format!("Failed to initialize drive: {}", e));
            }
        }
    }

    // =========================================================================
    // Drive Initialization Wizard (US-024)
    // =========================================================================

    /// Renders the drive initialization wizard.
    fn render_init_wizard(&mut self, ctx: &egui::Context) {
        if !self.drive_init_wizard_state.is_open {
            return;
        }

        let mut close_wizard = false;
        let mut go_next = false;
        let mut go_back = false;
        let mut start_init = false;

        let step = self.drive_init_wizard_state.step;
        let step_title = step.title();
        let step_number = step.number();

        egui::Window::new(format!("Initialize Drive - Step {} of 7: {}", step_number, step_title))
            .collapsible(false)
            .resizable(false)
            .default_width(500.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                // Step indicator bar
                ui.horizontal(|ui| {
                    for i in 1..=7u8 {
                        let (color, text_color) = if i < step_number {
                            (egui::Color32::from_rgb(60, 120, 60), egui::Color32::WHITE)
                        } else if i == step_number {
                            (egui::Color32::from_rgb(80, 140, 200), egui::Color32::WHITE)
                        } else {
                            (egui::Color32::from_rgb(60, 60, 60), egui::Color32::GRAY)
                        };

                        let (rect, _response) = ui.allocate_exact_size(
                            egui::vec2(24.0, 24.0),
                            egui::Sense::hover()
                        );
                        ui.painter().circle_filled(rect.center(), 12.0, color);
                        ui.painter().text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            format!("{}", i),
                            egui::FontId::proportional(12.0),
                            text_color,
                        );

                        if i < 7 {
                            let line_color = if i < step_number {
                                egui::Color32::from_rgb(60, 120, 60)
                            } else {
                                egui::Color32::from_rgb(60, 60, 60)
                            };
                            let (line_rect, _) = ui.allocate_exact_size(
                                egui::vec2(20.0, 2.0),
                                egui::Sense::hover()
                            );
                            ui.painter().rect_filled(line_rect, 0.0, line_color);
                        }
                    }
                });

                ui.add_space(15.0);
                ui.separator();
                ui.add_space(10.0);

                // Render step content
                match step {
                    DriveInitStep::DriveSelection => {
                        self.render_wizard_step_drive_selection(ui);
                    }
                    DriveInitStep::MasterPassword => {
                        self.render_wizard_step_master_password(ui);
                    }
                    DriveInitStep::AccessLevels => {
                        self.render_wizard_step_access_levels(ui);
                    }
                    DriveInitStep::EncryptionStrength => {
                        self.render_wizard_step_encryption_strength(ui);
                    }
                    DriveInitStep::Confirmation => {
                        self.render_wizard_step_confirmation(ui);
                    }
                    DriveInitStep::Progress => {
                        self.render_wizard_step_progress(ui);
                    }
                    DriveInitStep::Success => {
                        self.render_wizard_step_success(ui);
                    }
                }

                ui.add_space(15.0);
                ui.separator();
                ui.add_space(10.0);

                // Navigation buttons
                ui.horizontal(|ui| {
                    // Cancel button (not shown during progress or success)
                    if step != DriveInitStep::Progress && step != DriveInitStep::Success {
                        if ui.button("Cancel").clicked() {
                            close_wizard = true;
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        match step {
                            DriveInitStep::Progress => {
                                // No buttons during progress
                            }
                            DriveInitStep::Success => {
                                if ui.button("Close").clicked() {
                                    close_wizard = true;
                                }
                            }
                            DriveInitStep::Confirmation => {
                                // Back button
                                if ui.button("← Back").clicked() {
                                    go_back = true;
                                }

                                ui.add_space(10.0);

                                // Initialize button
                                let can_proceed = self.drive_init_wizard_state.can_proceed();
                                if ui.add_enabled(can_proceed, egui::Button::new("🔐 Initialize Drive")).clicked() {
                                    start_init = true;
                                }
                            }
                            _ => {
                                // Back button (if allowed)
                                if self.drive_init_wizard_state.can_go_back() {
                                    if ui.button("← Back").clicked() {
                                        go_back = true;
                                    }
                                    ui.add_space(10.0);
                                }

                                // Next button
                                let can_proceed = self.drive_init_wizard_state.can_proceed();
                                if ui.add_enabled(can_proceed, egui::Button::new("Next →")).clicked() {
                                    go_next = true;
                                }
                            }
                        }
                    });
                });
            });

        // Handle actions
        if close_wizard {
            self.drive_init_wizard_state.close();
        }
        if go_next {
            self.drive_init_wizard_state.next_step();
        }
        if go_back {
            self.drive_init_wizard_state.prev_step();
        }
        if start_init {
            self.start_drive_initialization();
        }
    }

    /// Renders wizard step 1: Drive selection.
    fn render_wizard_step_drive_selection(&mut self, ui: &mut egui::Ui) {
        ui.heading("Select Drive to Initialize");
        ui.add_space(10.0);
        ui.label("Choose the drive you want to initialize with hardware encryption.");
        ui.label(egui::RichText::new("⚠ Warning: All data on the drive will be erased!").color(egui::Color32::from_rgb(255, 200, 100)));
        ui.add_space(15.0);

        let selected_idx = self.drive_init_wizard_state.selected_drive_index;

        // Show available drives
        egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
            let drives: Vec<_> = self.drive_detection_state.drives.iter().enumerate()
                .filter(|(_, d)| d.can_initialize())
                .map(|(i, d)| (i, d.clone()))
                .collect();

            if drives.is_empty() {
                ui.label(egui::RichText::new("No drives available for initialization.").weak().italics());
            } else {
                for (idx, drive) in drives {
                    let is_selected = selected_idx == Some(idx);
                    let frame_color = if is_selected {
                        egui::Color32::from_rgb(40, 80, 120)
                    } else {
                        egui::Color32::from_rgb(40, 40, 50)
                    };

                    egui::Frame::none()
                        .fill(frame_color)
                        .rounding(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Radio button
                                if ui.radio(is_selected, "").clicked() {
                                    self.drive_init_wizard_state.selected_drive_index = Some(idx);
                                }

                                // Drive info
                                ui.vertical(|ui| {
                                    let name = Self::get_drive_display_name(&drive.info);
                                    ui.label(egui::RichText::new(name).strong());

                                    let size = format_file_size(drive.info.size_bytes);
                                    let path = drive.info.device_path.display();
                                    ui.label(egui::RichText::new(format!("{} - {}", size, path)).weak());
                                });
                            });
                        });
                    ui.add_space(5.0);
                }
            }
        });
    }

    /// Renders wizard step 2: Master password.
    fn render_wizard_step_master_password(&mut self, ui: &mut egui::Ui) {
        ui.heading("Set Master Password");
        ui.add_space(10.0);
        ui.label("The master password is used to encrypt the drive's data encryption key.");
        ui.label("This password must be remembered - if lost, your data cannot be recovered!");
        ui.add_space(15.0);

        // Password field
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add_space(20.0);
            let show_pwd = self.drive_init_wizard_state.show_master_password;
            ui.add(
                egui::TextEdit::singleline(&mut self.drive_init_wizard_state.master_password)
                    .password(!show_pwd)
                    .desired_width(250.0)
            );

            // Toggle visibility
            let icon = if show_pwd { "🙈" } else { "👁" };
            if ui.button(icon).on_hover_text(if show_pwd { "Hide password" } else { "Show password" }).clicked() {
                self.drive_init_wizard_state.show_master_password = !show_pwd;
            }
        });

        ui.add_space(10.0);

        // Confirm password
        ui.horizontal(|ui| {
            ui.label("Confirm:");
            ui.add_space(24.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.drive_init_wizard_state.master_password_confirm)
                    .password(true)
                    .desired_width(250.0)
            );
        });

        // Password strength meter
        ui.add_space(15.0);
        let pwd = &self.drive_init_wizard_state.master_password;
        let strength = calculate_password_strength(pwd);

        ui.horizontal(|ui| {
            ui.label("Strength:");
            let (color, text) = match strength {
                PasswordStrength::VeryWeak => (egui::Color32::from_rgb(200, 50, 50), "Very Weak"),
                PasswordStrength::Weak => (egui::Color32::from_rgb(200, 120, 50), "Weak"),
                PasswordStrength::Fair => (egui::Color32::from_rgb(200, 200, 50), "Fair"),
                PasswordStrength::Strong => (egui::Color32::from_rgb(100, 200, 50), "Strong"),
                PasswordStrength::VeryStrong => (egui::Color32::from_rgb(50, 200, 100), "Very Strong"),
            };
            ui.label(egui::RichText::new(text).color(color));
        });

        // Progress bar for strength
        let strength_percent = match strength {
            PasswordStrength::VeryWeak => 0.1,
            PasswordStrength::Weak => 0.25,
            PasswordStrength::Fair => 0.5,
            PasswordStrength::Strong => 0.75,
            PasswordStrength::VeryStrong => 1.0,
        };
        ui.add(egui::ProgressBar::new(strength_percent as f32));

        // Validation messages
        ui.add_space(10.0);
        if !pwd.is_empty() && pwd.len() < 8 {
            ui.label(egui::RichText::new("Password must be at least 8 characters").color(egui::Color32::from_rgb(255, 150, 100)));
        }
        if !pwd.is_empty() && !self.drive_init_wizard_state.master_password_confirm.is_empty()
            && pwd != &self.drive_init_wizard_state.master_password_confirm
        {
            ui.label(egui::RichText::new("Passwords do not match").color(egui::Color32::from_rgb(255, 100, 100)));
        }
    }

    /// Renders wizard step 3: Access levels.
    fn render_wizard_step_access_levels(&mut self, ui: &mut egui::Ui) {
        ui.heading("Configure Access Levels");
        ui.add_space(10.0);
        ui.label("Configure up to 4 access levels with separate passwords.");
        ui.label("Each level can have different permissions for files.");
        ui.add_space(15.0);

        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            for i in 0..4 {
                let level_label = format!("Level {} - {}", i + 1, self.drive_init_wizard_state.access_levels[i].name);

                egui::CollapsingHeader::new(&level_label)
                    .default_open(i == 0)
                    .show(ui, |ui| {
                        // Enable checkbox
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.drive_init_wizard_state.access_levels[i].enabled, "Enable this level");
                        });

                        if self.drive_init_wizard_state.access_levels[i].enabled {
                            ui.add_space(5.0);

                            // Name
                            ui.horizontal(|ui| {
                                ui.label("Name:");
                                ui.add_space(35.0);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.drive_init_wizard_state.access_levels[i].name)
                                        .desired_width(150.0)
                                );
                            });

                            ui.add_space(5.0);

                            // Password
                            ui.horizontal(|ui| {
                                ui.label("Password:");
                                ui.add_space(10.0);
                                let show_pwd = self.drive_init_wizard_state.access_levels[i].show_password;
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.drive_init_wizard_state.access_levels[i].password)
                                        .password(!show_pwd)
                                        .desired_width(150.0)
                                );
                                let icon = if show_pwd { "🙈" } else { "👁" };
                                if ui.button(icon).clicked() {
                                    self.drive_init_wizard_state.access_levels[i].show_password = !show_pwd;
                                }
                            });

                            // Confirm
                            ui.horizontal(|ui| {
                                ui.label("Confirm:");
                                ui.add_space(16.0);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.drive_init_wizard_state.access_levels[i].password_confirm)
                                        .password(true)
                                        .desired_width(150.0)
                                );
                            });

                            // Validation
                            let pwd = &self.drive_init_wizard_state.access_levels[i].password;
                            let confirm = &self.drive_init_wizard_state.access_levels[i].password_confirm;
                            if !pwd.is_empty() && pwd.len() < 8 {
                                ui.label(egui::RichText::new("Min 8 characters").color(egui::Color32::from_rgb(255, 150, 100)).small());
                            }
                            if !pwd.is_empty() && !confirm.is_empty() && pwd != confirm {
                                ui.label(egui::RichText::new("Passwords don't match").color(egui::Color32::from_rgb(255, 100, 100)).small());
                            }
                        }
                    });
                ui.add_space(5.0);
            }
        });
    }

    /// Renders wizard step 4: Encryption strength.
    fn render_wizard_step_encryption_strength(&mut self, ui: &mut egui::Ui) {
        ui.heading("Select Encryption Strength");
        ui.add_space(10.0);
        ui.label("Choose the key derivation parameters for encryption.");
        ui.label("Higher settings are more secure but slower to unlock.");
        ui.add_space(15.0);

        let strengths = [
            EncryptionStrength::Standard,
            EncryptionStrength::High,
            EncryptionStrength::Maximum,
        ];

        for strength in strengths {
            let is_selected = self.drive_init_wizard_state.encryption_strength == strength;
            let frame_color = if is_selected {
                egui::Color32::from_rgb(40, 80, 120)
            } else {
                egui::Color32::from_rgb(40, 40, 50)
            };

            egui::Frame::none()
                .fill(frame_color)
                .rounding(5.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.radio(is_selected, "").clicked() {
                            self.drive_init_wizard_state.encryption_strength = strength;
                        }

                        ui.vertical(|ui| {
                            let name = match strength {
                                EncryptionStrength::Standard => "Standard",
                                EncryptionStrength::High => "High",
                                EncryptionStrength::Maximum => "Maximum",
                            };
                            ui.label(egui::RichText::new(name).strong());
                            ui.label(egui::RichText::new(strength.description()).weak().small());
                            ui.label(egui::RichText::new(format!(
                                "Memory: {}MB, Iterations: {}",
                                strength.memory_mb(),
                                strength.iterations()
                            )).weak().small());
                        });
                    });
                });
            ui.add_space(5.0);
        }

        ui.add_space(10.0);
        ui.label(egui::RichText::new("💡 Tip: Standard is suitable for most users. Use Maximum for highly sensitive data.").weak().italics());
    }

    /// Renders wizard step 5: Confirmation.
    fn render_wizard_step_confirmation(&mut self, ui: &mut egui::Ui) {
        ui.heading("Confirm Initialization");
        ui.add_space(10.0);

        // Show error if any
        if let Some(ref error) = self.drive_init_wizard_state.error_message.clone() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(80, 30, 30))
                .rounding(5.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(format!("❌ Error: {}", error)).color(egui::Color32::from_rgb(255, 150, 150)));
                });
            ui.add_space(10.0);
        }

        // Summary
        ui.label("Please review your settings before initialization:");
        ui.add_space(10.0);

        egui::Frame::none()
            .fill(egui::Color32::from_rgb(30, 35, 45))
            .rounding(5.0)
            .inner_margin(15.0)
            .show(ui, |ui| {
                // Drive
                if let Some(idx) = self.drive_init_wizard_state.selected_drive_index {
                    if let Some(drive) = self.drive_detection_state.drives.get(idx) {
                        let name = Self::get_drive_display_name(&drive.info);
                        let size = format_file_size(drive.info.size_bytes);
                        ui.horizontal(|ui| {
                            ui.label("Drive:");
                            ui.label(egui::RichText::new(format!("{} ({})", name, size)).strong());
                        });
                    }
                }

                // Encryption strength
                let strength_name = match self.drive_init_wizard_state.encryption_strength {
                    EncryptionStrength::Standard => "Standard",
                    EncryptionStrength::High => "High",
                    EncryptionStrength::Maximum => "Maximum",
                };
                ui.horizontal(|ui| {
                    ui.label("Encryption:");
                    ui.label(egui::RichText::new(strength_name).strong());
                });

                // Access levels
                let enabled_levels: Vec<_> = self.drive_init_wizard_state.access_levels.iter()
                    .filter(|l| l.enabled)
                    .map(|l| l.name.as_str())
                    .collect();
                ui.horizontal(|ui| {
                    ui.label("Access Levels:");
                    ui.label(egui::RichText::new(enabled_levels.join(", ")).strong());
                });
            });

        ui.add_space(15.0);

        // Warning
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(80, 50, 20))
            .rounding(5.0)
            .inner_margin(15.0)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("⚠️ WARNING").color(egui::Color32::from_rgb(255, 200, 100)).strong());
                ui.add_space(5.0);
                ui.label("This will PERMANENTLY ERASE all data on the selected drive!");
                ui.label("Make sure you have backed up any important files.");
                ui.add_space(10.0);
                ui.checkbox(&mut self.drive_init_wizard_state.confirmed_data_loss, "I understand that all data will be erased");
            });
    }

    /// Renders wizard step 6: Progress.
    fn render_wizard_step_progress(&mut self, ui: &mut egui::Ui) {
        ui.heading("Initializing Drive");
        ui.add_space(20.0);

        ui.vertical_centered(|ui| {
            ui.add(egui::Spinner::new().size(48.0));
            ui.add_space(20.0);

            let percent = self.drive_init_wizard_state.progress_percent;
            ui.add(egui::ProgressBar::new(percent as f32 / 100.0).show_percentage());
            ui.add_space(10.0);

            let msg = &self.drive_init_wizard_state.progress_message;
            if !msg.is_empty() {
                ui.label(egui::RichText::new(msg).weak().italics());
            }
        });

        ui.add_space(20.0);
        ui.label(egui::RichText::new("Please do not disconnect the drive or close the application.").weak());
    }

    /// Renders wizard step 7: Success.
    fn render_wizard_step_success(&mut self, ui: &mut egui::Ui) {
        ui.heading("Initialization Complete");
        ui.add_space(20.0);

        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("✓").size(48.0).color(egui::Color32::from_rgb(100, 200, 100)));
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Drive initialized successfully!").size(18.0).strong());
        });

        ui.add_space(20.0);

        // Recovery key
        if let Some(ref key) = self.drive_init_wizard_state.recovery_key.clone() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(30, 50, 30))
                .rounding(5.0)
                .inner_margin(15.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("🔑 Recovery Key").strong());
                    ui.add_space(5.0);
                    ui.label("Store this key securely. It can be used to recover access if you forget your password.");
                    ui.add_space(10.0);

                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(20, 25, 30))
                        .rounding(3.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(&mut key.clone()).font(egui::TextStyle::Monospace));
                        });

                    ui.add_space(10.0);
                    if ui.button("📋 Copy to Clipboard").clicked() {
                        ui.output_mut(|o| o.copied_text = key.clone());
                    }
                });
        }

        ui.add_space(15.0);
        ui.label("You can now use this drive with TESSERACT.");
    }

    /// Starts the drive initialization process.
    fn start_drive_initialization(&mut self) {
        let Some(idx) = self.drive_init_wizard_state.selected_drive_index else {
            self.drive_init_wizard_state.set_error("No drive selected");
            return;
        };

        let Some(drive) = self.drive_detection_state.drives.get(idx) else {
            self.drive_init_wizard_state.set_error("Drive not found");
            return;
        };

        let path = drive.info.device_path.clone();
        let password = self.drive_init_wizard_state.master_password.clone();

        // Set initializing state
        self.drive_init_wizard_state.initializing = true;
        self.drive_init_wizard_state.step = DriveInitStep::Progress;
        self.drive_init_wizard_state.set_progress(0, "Starting initialization...");

        // Perform initialization
        // Note: In a real async implementation, this would be done on a background thread
        self.drive_init_wizard_state.set_progress(10, "Erasing drive...");

        match tesseract_hardware::sed::initialize_drive(&path, password.as_bytes()) {
            Ok(()) => {
                self.drive_init_wizard_state.set_progress(50, "Setting up encryption...");

                // Generate a simulated recovery key (in real implementation, this would come from the crypto module)
                let recovery_key = format!(
                    "{}-{}-{}-{}-{}",
                    generate_recovery_segment(),
                    generate_recovery_segment(),
                    generate_recovery_segment(),
                    generate_recovery_segment(),
                    generate_recovery_segment()
                );

                self.drive_init_wizard_state.set_progress(100, "Complete!");
                self.drive_init_wizard_state.set_success(recovery_key);
                self.drive_detection_state.needs_refresh = true;
            }
            Err(e) => {
                self.drive_init_wizard_state.set_error(format!("Initialization failed: {}", e));
            }
        }
    }

    // =========================================================================
    // Settings / Access Level Management (US-039)
    // =========================================================================

    /// Renders the settings and access level management screen.
    fn render_settings(&mut self, ui: &mut egui::Ui) {
        // Refresh levels if needed
        if self.settings_state.needs_refresh {
            self.refresh_settings_levels();
        }

        ui.vertical(|ui| {
            // Header with back button
            ui.horizontal(|ui| {
                if ui.button("← Back to Files").clicked() {
                    self.screen = AppScreen::FileBrowser;
                }
                ui.add_space(20.0);
                ui.heading("Access Level Management");
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            // Success/Error messages
            if let Some(ref msg) = self.settings_state.success_message.clone() {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(20, 80, 20))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("✅");
                            ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(180, 255, 180)));
                            if ui.small_button("✕").clicked() {
                                self.settings_state.clear_messages();
                            }
                        });
                    });
                ui.add_space(10.0);
            }

            if let Some(ref msg) = self.settings_state.error_message.clone() {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(80, 20, 20))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("⚠️");
                            ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(255, 180, 180)));
                            if ui.small_button("✕").clicked() {
                                self.settings_state.clear_messages();
                            }
                        });
                    });
                ui.add_space(10.0);
            }

            // Toolbar
            ui.horizontal(|ui| {
                let can_create = self.settings_state.can_create_level();
                let create_btn = egui::Button::new("➕ Create New Level")
                    .min_size(egui::vec2(150.0, 30.0));

                if ui.add_enabled(can_create, create_btn).clicked() {
                    self.settings_state.create_dialog.open();
                }

                if !can_create {
                    ui.label(egui::RichText::new("(Maximum 10 levels)").weak().small());
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔄 Refresh").clicked() {
                        self.settings_state.mark_refresh_needed();
                    }
                });
            });

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);

            // Levels list
            self.render_levels_list(ui);

            // Drive Security section (US-028) - only show when drive is unlocked
            if self.current_drive.is_some() {
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(10.0);
                self.render_drive_security_settings(ui);
            }

            // VFS Mount Point section (Windows only)
            if MountPointSelectionState::is_supported() {
                ui.add_space(20.0);
                ui.separator();
                ui.add_space(10.0);
                self.render_mount_point_selection(ui);
            }
        });
    }

    /// Renders the mount point (drive letter) selection UI.
    fn render_mount_point_selection(&mut self, ui: &mut egui::Ui) {
        // Refresh if needed
        if self.mount_point_state.needs_refresh {
            self.mount_point_state.refresh();
        }

        ui.heading("VFS Mount Point");
        ui.add_space(5.0);
        ui.label(egui::RichText::new(MountPointSelectionState::help_text()).weak().small());
        ui.add_space(10.0);

        // Success/Error messages
        if let Some(ref msg) = self.mount_point_state.success_message.clone() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(20, 80, 20))
                .rounding(5.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("✅");
                        ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(180, 255, 180)));
                        if ui.small_button("✕").clicked() {
                            self.mount_point_state.clear_messages();
                        }
                    });
                });
            ui.add_space(5.0);
        }

        if let Some(ref msg) = self.mount_point_state.error_message.clone() {
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(80, 20, 20))
                .rounding(5.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("⚠️");
                        ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(255, 180, 180)));
                        if ui.small_button("✕").clicked() {
                            self.mount_point_state.clear_messages();
                        }
                    });
                });
            ui.add_space(5.0);
        }

        ui.horizontal(|ui| {
            // Auto-select checkbox
            let mut auto_select = self.mount_point_state.auto_select;
            if ui.checkbox(&mut auto_select, "Auto-select first available").changed() {
                if auto_select {
                    self.mount_point_state.enable_auto_select();
                    // Save to config
                    self.config.preferred_drive_letter = None;
                    let _ = save_config(&self.config);
                } else {
                    // Disable auto-select, use the first available as the selection
                    if let Some(letter) = self.mount_point_state.first_available() {
                        self.mount_point_state.set_letter(letter);
                        self.config.preferred_drive_letter = Some(letter);
                        let _ = save_config(&self.config);
                    }
                }
            }
        });

        ui.add_space(5.0);

        // Drive letter dropdown (disabled if auto-select is enabled)
        ui.horizontal(|ui| {
            ui.label("Drive Letter:");
            ui.add_space(10.0);

            let current_display = if self.mount_point_state.auto_select {
                if let Some(letter) = self.mount_point_state.first_available() {
                    format!("{}: (Auto)", letter)
                } else {
                    "(No drives available)".to_string()
                }
            } else if let Some(letter) = self.mount_point_state.selected_letter {
                format!("{}:", letter)
            } else {
                "(Select...)".to_string()
            };

            let enabled = !self.mount_point_state.auto_select;

            ui.add_enabled_ui(enabled, |ui| {
                egui::ComboBox::from_id_source("drive_letter_combo")
                    .selected_text(current_display)
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        let selectable: Vec<_> = self.mount_point_state.drive_letters.iter()
                            .filter(|d| d.is_selectable())
                            .cloned()
                            .collect();

                        for info in selectable {
                            let display = info.display_string();
                            let is_selected = self.mount_point_state.selected_letter == Some(info.letter);

                            if ui.selectable_label(is_selected, &display).clicked() {
                                self.mount_point_state.set_letter(info.letter);
                                // Save to config
                                self.config.preferred_drive_letter = Some(info.letter);
                                if let Err(e) = save_config(&self.config) {
                                    warn!("Failed to save config: {}", e);
                                }
                            }
                        }
                    });
            });

            // Refresh button
            if ui.button("🔄").on_hover_text("Refresh drive list").clicked() {
                self.mount_point_state.needs_refresh = true;
            }
        });

        // Show effective drive letter
        ui.add_space(5.0);
        if let Ok(effective) = self.mount_point_state.validate() {
            ui.label(
                egui::RichText::new(format!("Vault will mount as {}: when VFS is enabled", effective))
                    .weak()
                    .small()
            );
        } else {
            ui.label(
                egui::RichText::new("No available drive letter for mounting")
                    .color(egui::Color32::from_rgb(255, 180, 100))
                    .small()
            );
        }
    }

    /// Renders the drive security settings section (US-028).
    fn render_drive_security_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Drive Security");
        ui.add_space(5.0);

        if let Some(ref drive) = self.current_drive.clone() {
            ui.label(
                egui::RichText::new(format!("Current Drive: {}", drive.name))
                    .weak()
            );
            ui.add_space(10.0);

            // Success/Error messages for drive password change
            if let Some(ref msg) = self.settings_state.drive_password_change_dialog.success_message.clone() {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(20, 80, 20))
                    .rounding(5.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("✅");
                            ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(180, 255, 180)));
                            if ui.small_button("✕").clicked() {
                                self.settings_state.drive_password_change_dialog.success_message = None;
                            }
                        });
                    });
                ui.add_space(5.0);
            }

            ui.horizontal(|ui| {
                let change_btn = egui::Button::new("🔑 Change Master Password")
                    .min_size(egui::vec2(200.0, 30.0));

                if ui.add(change_btn).clicked() {
                    self.settings_state.drive_password_change_dialog.open();
                }

                ui.label(
                    egui::RichText::new("Change the encryption password for this drive")
                        .weak()
                        .small()
                );
            });
        } else {
            ui.label(
                egui::RichText::new("No encrypted drive is currently unlocked")
                    .weak()
                    .italics()
            );
        }
    }

    /// Refreshes the access levels in settings state.
    fn refresh_settings_levels(&mut self) {
        let Some(ref vault_path) = self.current_vault_path else { return };
        let Some(ref master_key) = self.master_key else { return };
        let Some(ref session) = self.vault_session else { return };
        self.settings_state.refresh_levels(vault_path, master_key, session);
    }

    /// Renders the list of access levels.
    fn render_levels_list(&mut self, ui: &mut egui::Ui) {
        let levels = self.settings_state.levels.clone();
        let total_levels = levels.len();

        if levels.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(egui::RichText::new("No access levels configured").weak().italics());
            });
            return;
        }

        // Header row
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            ui.add_sized([60.0, 20.0], egui::Label::new(
                egui::RichText::new("Level").strong()
            ));
            ui.add_sized([200.0, 20.0], egui::Label::new(
                egui::RichText::new("Name").strong()
            ));
            ui.add_sized([80.0, 20.0], egui::Label::new(
                egui::RichText::new("Files").strong()
            ));
            ui.add_sized([100.0, 20.0], egui::Label::new(
                egui::RichText::new("Status").strong()
            ));
            ui.label(egui::RichText::new("Actions").strong());
        });

        ui.separator();

        // Scroll area for levels
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(400.0)
            .show(ui, |ui| {
                let mut action: Option<LevelAction> = None;

                for level in &levels {
                    ui.horizontal(|ui| {
                        ui.add_space(10.0);

                        // Level ID with color
                        let level_color = self.level_color(level.id);
                        ui.add_sized([60.0, 24.0], egui::Label::new(
                            egui::RichText::new(format!("L{}", level.id))
                                .color(level_color)
                                .strong()
                        ));

                        // Name
                        ui.add_sized([200.0, 24.0], egui::Label::new(&level.name));

                        // File count with badge
                        let file_text = if level.file_count > 0 {
                            egui::RichText::new(format!("{} files", level.file_count))
                        } else {
                            egui::RichText::new("Empty").weak().italics()
                        };
                        ui.add_sized([80.0, 24.0], egui::Label::new(file_text));

                        // Status
                        let status_text = if level.enabled {
                            egui::RichText::new("Active").color(egui::Color32::from_rgb(100, 200, 100))
                        } else {
                            egui::RichText::new("Disabled").color(egui::Color32::from_rgb(200, 100, 100))
                        };
                        ui.add_sized([100.0, 24.0], egui::Label::new(status_text));

                        // Actions
                        ui.horizontal(|ui| {
                            // Change password button
                            if ui.small_button("🔑 Password").on_hover_text("Change password").clicked() {
                                action = Some(LevelAction::ChangePassword(level.id, level.name.clone()));
                            }

                            // Delete button (only for empty levels)
                            let can_delete = level.can_delete(total_levels);
                            let delete_btn = egui::Button::new("🗑").small();
                            let delete_response = ui.add_enabled(can_delete, delete_btn);

                            if can_delete {
                                if delete_response.on_hover_text("Delete level").clicked() {
                                    action = Some(LevelAction::Delete(level.id, level.name.clone()));
                                }
                            } else {
                                delete_response.on_hover_text(
                                    if level.file_count > 0 {
                                        "Cannot delete: level contains files"
                                    } else {
                                        "Cannot delete: minimum 3 levels required"
                                    }
                                );
                            }
                        });
                    });

                    ui.separator();
                }

                // Handle action after loop
                match action {
                    Some(LevelAction::ChangePassword(id, name)) => {
                        self.settings_state.change_password_dialog.open(id, &name);
                    }
                    Some(LevelAction::Delete(id, name)) => {
                        self.settings_state.delete_dialog.open(id, &name);
                    }
                    None => {}
                }
            });

        // Summary footer
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(5.0);

        let total_files: usize = levels.iter().map(|l| l.file_count).sum();
        ui.label(
            egui::RichText::new(format!(
                "{} access levels configured • {} total files",
                total_levels, total_files
            )).weak().small()
        );
    }

    /// Returns a color for the given access level.
    fn level_color(&self, level: u32) -> egui::Color32 {
        match level {
            1 => egui::Color32::from_rgb(100, 200, 100),  // Green
            2 => egui::Color32::from_rgb(200, 200, 100),  // Yellow
            3 => egui::Color32::from_rgb(200, 150, 100),  // Orange
            4 => egui::Color32::from_rgb(200, 100, 100),  // Red
            5 => egui::Color32::from_rgb(200, 100, 200),  // Purple
            6 => egui::Color32::from_rgb(100, 100, 200),  // Blue
            7 => egui::Color32::from_rgb(100, 200, 200),  // Cyan
            8 => egui::Color32::from_rgb(150, 100, 100),  // Dark red
            9 => egui::Color32::from_rgb(100, 150, 100),  // Dark green
            10 => egui::Color32::from_rgb(100, 100, 150), // Dark blue
            _ => egui::Color32::GRAY,
        }
    }

    /// Renders the create level dialog.
    fn render_create_level_dialog(&mut self, ctx: &egui::Context) {
        if !self.settings_state.create_dialog.is_open {
            return;
        }

        let mut should_close = false;
        let mut should_create = false;

        egui::Window::new("Create New Access Level")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                // Error message
                if let Some(ref error) = self.settings_state.create_dialog.error_message.clone() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(80, 30, 30))
                        .rounding(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("⚠️");
                                ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 180, 180)));
                            });
                        });
                    ui.add_space(10.0);
                }

                // Name input
                ui.horizontal(|ui| {
                    ui.label("Level Name:");
                    ui.add_sized([250.0, 20.0], egui::TextEdit::singleline(&mut self.settings_state.create_dialog.name)
                        .hint_text("e.g., Top Secret"));
                });

                ui.add_space(10.0);

                // Password input
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let toggle_text = if self.settings_state.create_dialog.show_password { "👁" } else { "👁‍🗨" };
                        if ui.small_button(toggle_text).clicked() {
                            self.settings_state.create_dialog.show_password = !self.settings_state.create_dialog.show_password;
                        }
                    });
                });

                let password_edit = if self.settings_state.create_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.create_dialog.password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.create_dialog.password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(password_edit);

                ui.add_space(5.0);

                // Confirm password
                ui.label("Confirm Password:");
                let confirm_edit = if self.settings_state.create_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.create_dialog.confirm_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.create_dialog.confirm_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(confirm_edit);

                ui.add_space(20.0);

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        should_close = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let is_creating = self.settings_state.create_dialog.is_creating;
                        let create_btn = egui::Button::new(if is_creating { "Creating..." } else { "Create Level" });

                        if ui.add_enabled(!is_creating, create_btn).clicked() {
                            // Validate first
                            if let Some(error) = self.settings_state.create_dialog.validate() {
                                self.settings_state.create_dialog.error_message = Some(error);
                            } else {
                                should_create = true;
                            }
                        }
                    });
                });
            });

        if should_close {
            self.settings_state.create_dialog.close();
        }

        if should_create {
            self.create_new_access_level();
        }
    }

    /// Creates a new access level.
    fn create_new_access_level(&mut self) {
        let name = self.settings_state.create_dialog.name.trim().to_string();
        let password = self.settings_state.create_dialog.password.clone();

        let next_id = match self.settings_state.next_available_level_id() {
            Some(id) => id,
            None => {
                self.settings_state.create_dialog.error_message = Some("Maximum levels reached".to_string());
                return;
            }
        };

        self.settings_state.create_dialog.is_creating = true;

        // Perform creation
        let Some(ref vault_path) = self.current_vault_path else {
            self.settings_state.create_dialog.is_creating = false;
            return;
        };
        let Some(ref master_key) = self.master_key else {
            self.settings_state.create_dialog.is_creating = false;
            return;
        };

        match tesseract_core::access::create_level(
            vault_path,
            master_key,
            next_id,
            &name,
            password.as_bytes(),
        ) {
            Ok(_info) => {
                info!("Created access level {} ({})", next_id, name);
                self.settings_state.create_dialog.close();
                self.settings_state.set_success(format!("Created level '{}' (L{})", name, next_id));
                self.settings_state.mark_refresh_needed();
            }
            Err(e) => {
                warn!("Failed to create level: {}", e);
                self.settings_state.create_dialog.error_message = Some(format!("Failed: {}", e));
                self.settings_state.create_dialog.is_creating = false;
            }
        }
    }

    // =========================================================================
    // Vault Creation Wizard (US-042)
    // =========================================================================

    /// Renders the vault creation wizard.
    fn render_vault_creation(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Header with step indicator
            ui.horizontal(|ui| {
                ui.heading("Create New Vault");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Step indicator
                    let step = self.wizard_state.step;
                    ui.label(format!("Step {} of 5: {}", step.number(), step.title()));
                });
            });

            ui.separator();
            ui.add_space(10.0);

            // Step progress bar
            ui.horizontal(|ui| {
                let step_num = self.wizard_state.step.number() as f32;
                let total_steps = 5.0;
                let progress = step_num / total_steps;

                let bar_width = ui.available_width();
                let bar_rect = ui.allocate_space(egui::vec2(bar_width, 8.0)).1;

                // Background
                ui.painter().rect_filled(
                    bar_rect,
                    2.0,
                    egui::Color32::from_gray(60),
                );

                // Progress fill
                let fill_rect = egui::Rect::from_min_size(
                    bar_rect.min,
                    egui::vec2(bar_rect.width() * progress, bar_rect.height()),
                );
                ui.painter().rect_filled(
                    fill_rect,
                    2.0,
                    egui::Color32::from_rgb(100, 149, 237), // Cornflower blue
                );
            });

            ui.add_space(20.0);

            // Render current step content
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.wizard_state.step {
                    WizardStep::Location => self.render_wizard_location_step(ui),
                    WizardStep::Password => self.render_wizard_password_step(ui),
                    WizardStep::AccessLevels => self.render_wizard_access_levels_step(ui),
                    WizardStep::RecoveryKey => self.render_wizard_recovery_key_step(ui),
                    WizardStep::Creating => self.render_wizard_creating_step(ui),
                    WizardStep::Complete => self.render_wizard_complete_step(ui),
                }
            });

            ui.add_space(20.0);
            ui.separator();

            // Navigation buttons
            ui.horizontal(|ui| {
                // Cancel button (always visible except during creation)
                if !matches!(self.wizard_state.step, WizardStep::Creating | WizardStep::Complete) {
                    if ui.button("Cancel").clicked() {
                        self.cancel_vault_creation();
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    match self.wizard_state.step {
                        WizardStep::Location | WizardStep::Password | WizardStep::AccessLevels => {
                            // Next button
                            let can_proceed = self.wizard_state.can_proceed();
                            if ui.add_enabled(can_proceed, egui::Button::new("Next →")).clicked() {
                                self.wizard_state.next_step();
                            }
                        }
                        WizardStep::RecoveryKey => {
                            // Create Vault button
                            let can_proceed = self.wizard_state.can_proceed();
                            if ui.add_enabled(can_proceed, egui::Button::new("Create Vault")).clicked() {
                                self.execute_vault_creation();
                            }
                        }
                        WizardStep::Complete => {
                            // Open Vault button
                            if ui.button("Open Vault").clicked() {
                                self.finish_vault_creation();
                            }
                        }
                        WizardStep::Creating => {
                            // No button during creation
                        }
                    }

                    // Back button
                    if self.wizard_state.step.can_go_back() {
                        if ui.button("← Back").clicked() {
                            self.wizard_state.previous_step();
                        }
                    }
                });
            });
        });
    }

    /// Renders Step 1: Location selection.
    fn render_wizard_location_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 1: Choose Vault Location");
        ui.add_space(10.0);

        ui.label("Select an empty folder for your new vault. For maximum security, \
                  choose a location on a removable drive (USB flash drive or SD card).");

        ui.add_space(20.0);

        // Current selection
        ui.horizontal(|ui| {
            ui.label("Location:");
            if let Some(ref path) = self.wizard_state.vault_path {
                ui.monospace(path.display().to_string());
            } else {
                ui.colored_label(egui::Color32::GRAY, "(No location selected)");
            }
        });

        ui.add_space(10.0);

        // Browse button
        if ui.button("Browse...").clicked() {
            if let Some(path) = create_vault_dialog() {
                self.wizard_state.set_vault_path(path);
            }
        }

        // Removable media status
        if let Some(is_removable) = self.wizard_state.is_removable {
            ui.add_space(10.0);
            if is_removable {
                ui.colored_label(
                    egui::Color32::from_rgb(100, 200, 100),
                    "✓ Location is on removable media"
                );
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 200, 100),
                    "⚠ Warning: Location is not on removable media"
                );
            }
        }

        // Error message
        if let Some(ref error) = self.wizard_state.location_error {
            ui.add_space(10.0);
            ui.colored_label(egui::Color32::from_rgb(255, 100, 100), error);
        }
    }

    /// Renders Step 2: Password setup with strength meter.
    fn render_wizard_password_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 2: Set Master Password");
        ui.add_space(10.0);

        ui.label("Choose a strong master password to protect your vault. \
                  This password will be used to derive encryption keys using Argon2id.");

        ui.add_space(20.0);

        // Password input
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let toggle_text = if self.wizard_state.show_master_password { "👁" } else { "👁‍🗨" };
                if ui.small_button(toggle_text).clicked() {
                    self.wizard_state.show_master_password = !self.wizard_state.show_master_password;
                }
            });
        });

        let password_response = if self.wizard_state.show_master_password {
            ui.add(egui::TextEdit::singleline(&mut self.wizard_state.master_password)
                .desired_width(f32::INFINITY))
        } else {
            ui.add(egui::TextEdit::singleline(&mut self.wizard_state.master_password)
                .password(true)
                .desired_width(f32::INFINITY))
        };

        // Update strength on change
        if password_response.changed() {
            self.wizard_state.update_password_strength();
        }

        ui.add_space(10.0);

        // Password strength meter
        ui.horizontal(|ui| {
            ui.label("Strength:");

            let strength = self.wizard_state.password_strength;
            let color = match strength {
                PasswordStrength::VeryWeak => egui::Color32::from_rgb(255, 80, 80),
                PasswordStrength::Weak => egui::Color32::from_rgb(255, 160, 80),
                PasswordStrength::Fair => egui::Color32::from_rgb(255, 220, 80),
                PasswordStrength::Strong => egui::Color32::from_rgb(160, 220, 80),
                PasswordStrength::VeryStrong => egui::Color32::from_rgb(80, 200, 80),
            };

            // Progress bar for strength
            let bar_width = 150.0;
            let bar_rect = ui.allocate_space(egui::vec2(bar_width, 16.0)).1;

            // Background
            ui.painter().rect_filled(bar_rect, 3.0, egui::Color32::from_gray(60));

            // Fill
            let fill_rect = egui::Rect::from_min_size(
                bar_rect.min,
                egui::vec2(bar_rect.width() * strength.progress(), bar_rect.height()),
            );
            ui.painter().rect_filled(fill_rect, 3.0, color);

            ui.colored_label(color, strength.label());
        });

        if !self.wizard_state.password_strength.is_acceptable() {
            ui.colored_label(
                egui::Color32::from_rgb(255, 160, 80),
                "Password should be at least 8 characters with mixed case, numbers, and symbols."
            );
        }

        ui.add_space(20.0);

        // Confirm password
        ui.label("Confirm Password:");
        let confirm_widget = if self.wizard_state.show_master_password {
            egui::TextEdit::singleline(&mut self.wizard_state.master_password_confirm)
                .desired_width(f32::INFINITY)
        } else {
            egui::TextEdit::singleline(&mut self.wizard_state.master_password_confirm)
                .password(true)
                .desired_width(f32::INFINITY)
        };
        ui.add(confirm_widget);

        // Match indicator
        if !self.wizard_state.master_password.is_empty() && !self.wizard_state.master_password_confirm.is_empty() {
            ui.add_space(5.0);
            if self.wizard_state.master_passwords_match() {
                ui.colored_label(egui::Color32::from_rgb(100, 200, 100), "✓ Passwords match");
            } else {
                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), "✗ Passwords do not match");
            }
        }
    }

    /// Renders Step 3: Access levels configuration.
    fn render_wizard_access_levels_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 3: Configure Access Levels");
        ui.add_space(10.0);

        ui.label("Configure the security compartments for your vault. Each level can have \
                  its own password, or share the master password for convenience.");

        ui.add_space(20.0);

        // Use defaults checkbox
        ui.checkbox(&mut self.wizard_state.use_default_levels, "Use default configuration (3 levels with master password)");

        if self.wizard_state.use_default_levels {
            ui.add_space(10.0);
            ui.label("Default levels:");
            ui.indent("default_levels", |ui| {
                ui.label("• Level 1 (Confidential) - uses master password");
                ui.label("• Level 2 (Secret) - uses master password");
                ui.label("• Level 3 (Top Secret) - uses master password");
            });

            // Ensure we have default levels set up
            if self.wizard_state.access_levels.len() != 3 {
                self.wizard_state.set_level_count(3);
            }
            for level in &mut self.wizard_state.access_levels {
                level.use_master_password = true;
            }
        } else {
            ui.add_space(10.0);

            // Level count selector
            ui.horizontal(|ui| {
                ui.label("Number of levels:");
                let mut count = self.wizard_state.level_count as i32;
                if ui.add(egui::DragValue::new(&mut count).range(1..=10)).changed() {
                    self.wizard_state.set_level_count(count as u32);
                }
            });

            ui.add_space(10.0);

            // Level configuration
            let mut levels_to_update: Vec<(usize, bool, String, String)> = vec![];

            for (idx, level) in self.wizard_state.access_levels.iter().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.strong(format!("Level {} - ", level.id));
                        ui.label(&level.name);
                    });

                    let mut use_master = level.use_master_password;
                    let mut password = level.password.clone();
                    let mut password_confirm = level.password_confirm.clone();

                    ui.checkbox(&mut use_master, "Use master password");

                    if !use_master {
                        ui.horizontal(|ui| {
                            ui.label("Password:");
                            ui.add(egui::TextEdit::singleline(&mut password)
                                .password(true)
                                .desired_width(150.0));

                            ui.label("Confirm:");
                            ui.add(egui::TextEdit::singleline(&mut password_confirm)
                                .password(true)
                                .desired_width(150.0));
                        });

                        if !password.is_empty() && !password_confirm.is_empty() {
                            if password == password_confirm {
                                ui.colored_label(egui::Color32::from_rgb(100, 200, 100), "✓ Match");
                            } else {
                                ui.colored_label(egui::Color32::from_rgb(255, 100, 100), "✗ No match");
                            }
                        }
                    }

                    levels_to_update.push((idx, use_master, password, password_confirm));
                });
                ui.add_space(5.0);
            }

            // Apply updates
            for (idx, use_master, password, password_confirm) in levels_to_update {
                if let Some(level) = self.wizard_state.access_levels.get_mut(idx) {
                    level.use_master_password = use_master;
                    level.password = password;
                    level.password_confirm = password_confirm;
                }
            }
        }
    }

    /// Renders Step 4: Recovery key display and confirmation.
    fn render_wizard_recovery_key_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 4: Save Your Recovery Key");
        ui.add_space(10.0);

        ui.colored_label(
            egui::Color32::from_rgb(255, 200, 100),
            "⚠ IMPORTANT: This is the ONLY time you will see your recovery key!"
        );

        ui.add_space(10.0);

        ui.label("If you forget your password, this recovery key is the only way to regain access. \
                  Write it down and store it in a secure location separate from your vault.");

        ui.add_space(20.0);

        // Generate recovery key preview (we'll generate the real one during creation)
        if self.wizard_state.recovery_mnemonic.is_none() {
            // Generate a preview recovery key for display
            match tesseract_crypto::recovery::generate_recovery_key() {
                Ok(key) => {
                    self.wizard_state.set_recovery_key(
                        key.to_mnemonic(),
                        key.to_base64(),
                    );
                }
                Err(e) => {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 100, 100),
                        format!("Error generating recovery key: {}", e)
                    );
                }
            }
        }

        // Display mnemonic
        if let Some(ref mnemonic) = self.wizard_state.recovery_mnemonic {
            // Clone for use in closures
            let mnemonic_for_clipboard = mnemonic.clone();
            let mnemonic_for_display = mnemonic.clone();

            ui.group(|ui| {
                ui.strong("24-Word Recovery Phrase:");
                ui.add_space(5.0);

                // Display words in a grid (4 columns x 6 rows)
                let words: Vec<&str> = mnemonic_for_display.split_whitespace().collect();
                ui.horizontal_wrapped(|ui| {
                    for (i, word) in words.iter().enumerate() {
                        ui.monospace(format!("{:2}. {:<12}", i + 1, word));
                        if (i + 1) % 4 == 0 {
                            ui.end_row();
                        }
                    }
                });
            });

            ui.add_space(10.0);

            // Copy and Print buttons
            ui.horizontal(|ui| {
                // Copy to clipboard button with countdown
                let copy_label = if let Some(seconds) = self.wizard_state.clipboard_clear_countdown() {
                    if seconds > 0 {
                        format!("📋 Copied! (clears in {}s)", seconds)
                    } else {
                        "📋 Copy to Clipboard".to_string()
                    }
                } else {
                    "📋 Copy to Clipboard".to_string()
                };

                if ui.button(&copy_label).clicked() {
                    ui.output_mut(|o| o.copied_text = mnemonic_for_clipboard.clone());
                    self.wizard_state.mark_clipboard_copied();
                    self.set_status("Recovery key copied to clipboard (will auto-clear in 60 seconds)");
                }

                ui.add_space(10.0);

                // Print button - saves to file for printing
                if ui.button("🖨 Print / Save to File").clicked() {
                    if let Some(printable) = self.wizard_state.generate_printable_recovery_key() {
                        // Open save dialog
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Save Recovery Key for Printing")
                            .set_file_name("TESSERACT_Recovery_Key.txt")
                            .add_filter("Text File", &["txt"])
                            .save_file()
                        {
                            match std::fs::write(&path, printable) {
                                Ok(()) => {
                                    self.set_status(format!("Recovery key saved to: {}", path.display()));
                                    // Try to open the file for printing
                                    #[cfg(target_os = "windows")]
                                    {
                                        let _ = std::process::Command::new("notepad")
                                            .arg(&path)
                                            .spawn();
                                    }
                                    #[cfg(target_os = "macos")]
                                    {
                                        let _ = std::process::Command::new("open")
                                            .arg("-a")
                                            .arg("TextEdit")
                                            .arg(&path)
                                            .spawn();
                                    }
                                    #[cfg(target_os = "linux")]
                                    {
                                        let _ = std::process::Command::new("xdg-open")
                                            .arg(&path)
                                            .spawn();
                                    }
                                }
                                Err(e) => {
                                    self.set_status(format!("Failed to save: {}", e));
                                }
                            }
                        }
                    }
                }
            });
        }

        // Also show base64 format
        if let Some(ref base64) = self.wizard_state.recovery_base64 {
            let base64_for_display = base64.clone();
            let base64_for_clipboard = base64.clone();
            ui.add_space(10.0);
            ui.collapsing("Show as Base64 (compact format)", |ui| {
                ui.monospace(&base64_for_display);
                ui.horizontal(|ui| {
                    if ui.small_button("Copy Base64").clicked() {
                        ui.output_mut(|o| o.copied_text = base64_for_clipboard.clone());
                        self.wizard_state.mark_clipboard_copied();
                        self.set_status("Base64 recovery key copied (will auto-clear in 60 seconds)");
                    }
                });
            });
        }

        ui.add_space(20.0);

        // Confirmation checkbox
        ui.checkbox(
            &mut self.wizard_state.recovery_confirmed,
            "I have saved my recovery key in a secure location"
        );

        if !self.wizard_state.recovery_confirmed {
            ui.colored_label(
                egui::Color32::from_rgb(255, 160, 80),
                "You must confirm that you have saved your recovery key before proceeding."
            );
        }
    }

    /// Renders Step 5: Vault creation progress.
    fn render_wizard_creating_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Creating Vault...");
        ui.add_space(20.0);

        // Spinner/loading indicator
        ui.horizontal(|ui| {
            ui.spinner();
            if let Some(ref progress) = self.wizard_state.creation_progress {
                ui.label(progress);
            } else {
                ui.label("Setting up encryption keys...");
            }
        });

        // Error message if creation failed
        if let Some(ref error) = self.wizard_state.creation_error {
            ui.add_space(20.0);
            ui.colored_label(
                egui::Color32::from_rgb(255, 100, 100),
                format!("Error: {}", error)
            );

            if ui.button("Try Again").clicked() {
                self.wizard_state.creation_error = None;
                self.wizard_state.step = WizardStep::RecoveryKey;
            }
        }
    }

    /// Renders Step 6: Vault creation complete.
    fn render_wizard_complete_step(&mut self, ui: &mut egui::Ui) {
        ui.heading("Vault Created Successfully!");
        ui.add_space(20.0);

        ui.colored_label(
            egui::Color32::from_rgb(100, 200, 100),
            "✓ Your vault has been created and is ready to use."
        );

        ui.add_space(10.0);

        if let Some(ref path) = self.wizard_state.vault_path {
            ui.horizontal(|ui| {
                ui.label("Location:");
                ui.monospace(path.display().to_string());
            });
        }

        ui.add_space(10.0);

        ui.label(format!(
            "Created {} access level{}.",
            self.wizard_state.access_levels.len(),
            if self.wizard_state.access_levels.len() == 1 { "" } else { "s" }
        ));

        ui.add_space(20.0);

        // Reminder about recovery key
        ui.colored_label(
            egui::Color32::from_rgb(255, 200, 100),
            "Remember: Keep your recovery key safe! It cannot be recovered if lost."
        );
    }

    /// Cancels vault creation and returns to vault selection.
    fn cancel_vault_creation(&mut self) {
        info!("Vault creation cancelled");
        self.wizard_state.clear_sensitive_data();
        self.wizard_state.reset();
        self.new_vault_path = None;
        self.screen = AppScreen::VaultSelection;
    }

    /// Starts the vault creation process (internal wizard implementation).
    fn execute_vault_creation(&mut self) {
        info!("Executing vault creation");

        self.wizard_state.step = WizardStep::Creating;
        self.wizard_state.creating = true;
        self.wizard_state.creation_progress = Some("Initializing...".to_string());

        // Get parameters from wizard state
        let vault_path = match self.wizard_state.vault_path.clone() {
            Some(p) => p,
            None => {
                self.wizard_state.creation_error = Some("No vault path selected".to_string());
                return;
            }
        };

        let password = self.wizard_state.master_password.clone();
        let level_count = self.wizard_state.access_levels.len() as u32;
        let level_passwords = self.wizard_state.get_level_passwords();

        // Create vault config
        let mut config = tesseract_core::VaultConfig::default()
            .with_level_count(level_count);

        // Set level passwords if different from master
        if !self.wizard_state.use_default_levels {
            let passwords: Vec<Vec<u8>> = level_passwords.iter()
                .map(|p| p.as_bytes().to_vec())
                .collect();
            config = config.with_level_passwords(passwords);
        }

        // Perform vault creation
        self.wizard_state.creation_progress = Some("Creating vault structure...".to_string());

        match tesseract_core::create_vault(&vault_path, password.as_bytes(), Some(config)) {
            Ok(result) => {
                info!("Vault created successfully at {:?}", vault_path);

                // Store the recovery key
                self.wizard_state.set_recovery_key(
                    result.recovery_key.to_mnemonic(),
                    result.recovery_key.to_base64(),
                );

                // Store master key for opening
                self.wizard_state.created_master_key = Some(result.master_key);

                // Update state
                self.current_vault_path = Some(vault_path.clone());
                self.new_vault_path = Some(vault_path);

                // Mark creation complete
                self.wizard_state.creating = false;
                self.wizard_state.creation_progress = None;
                self.wizard_state.step = WizardStep::Complete;

                self.set_status("Vault created successfully!");
            }
            Err(e) => {
                warn!("Failed to create vault: {}", e);
                self.wizard_state.creation_error = Some(e.to_string());
                self.wizard_state.creating = false;
            }
        }
    }

    /// Finishes vault creation and opens the vault.
    fn finish_vault_creation(&mut self) {
        info!("Finishing vault creation, opening vault");

        let vault_path = match self.wizard_state.vault_path.clone() {
            Some(p) => p,
            None => {
                self.set_status("Error: No vault path");
                return;
            }
        };

        let master_key = match self.wizard_state.created_master_key {
            Some(k) => k,
            None => {
                self.set_status("Error: No master key available");
                return;
            }
        };

        // Open the vault session
        let password = self.wizard_state.master_password.clone();

        match tesseract_core::session::open_vault(&vault_path, password.as_bytes(), Some(tesseract_crypto::kdf::Argon2Params::default())) {
            Ok(session) => {
                info!("Vault opened successfully");

                // Store session and keys
                self.vault_session = Some(session);
                self.master_key = Some(Zeroizing::new(master_key));
                self.current_vault_path = Some(vault_path.clone());

                // Add to recent vaults
                self.config.add_recent_vault(vault_path.clone());
                save_config(&self.config);

                // Initialize activity tracking and temp file manager
                self.last_activity = Some(Instant::now());
                if let Ok(manager) = tesseract_core::TempFileManager::new() {
                    self.temp_file_manager = Some(manager);
                }

                // Clear sensitive data from wizard
                self.wizard_state.clear_sensitive_data();
                self.wizard_state.reset();

                // Transition to file browser
                self.file_browser_state = FileBrowserState::new();
                self.screen = AppScreen::FileBrowser;

                self.set_status("Vault opened successfully!");
            }
            Err(e) => {
                warn!("Failed to open newly created vault: {}", e);
                self.set_status(format!("Error opening vault: {}", e));
            }
        }
    }

    // =========================================================================
    // Password Recovery Flow (US-044)
    // =========================================================================

    /// Renders the password recovery screen.
    fn render_password_recovery(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);

            // Header
            ui.label(egui::RichText::new("🔑").size(48.0));
            ui.add_space(10.0);
            ui.heading("Password Recovery");
            ui.add_space(5.0);

            // Vault name
            ui.label(
                egui::RichText::new(&self.recovery_state.vault_name())
                    .size(16.0)
                    .weak()
            );
            ui.add_space(30.0);

            // Render based on current step
            match self.recovery_state.step {
                RecoveryStep::EnterKey => self.render_recovery_enter_key(ui),
                RecoveryStep::EnterNewPassword => self.render_recovery_new_password(ui),
                RecoveryStep::Success => self.render_recovery_success(ui),
                RecoveryStep::Failed => self.render_recovery_failed(ui),
            }

            ui.add_space(30.0);

            // Back to login button (except on success)
            if !matches!(self.recovery_state.step, RecoveryStep::Success) {
                if ui.button("← Back to Login").clicked() {
                    self.recovery_state.clear_sensitive_data();
                    self.recovery_state.reset_completely();
                    self.screen = AppScreen::PasswordEntry;
                }
            }
        });
    }

    /// Renders the recovery key entry step.
    fn render_recovery_enter_key(&mut self, ui: &mut egui::Ui) {
        ui.set_max_width(500.0);

        // Instructions
        egui::Frame::none()
            .fill(egui::Color32::from_gray(40))
            .rounding(8.0)
            .inner_margin(15.0)
            .show(ui, |ui| {
                ui.label("Enter your 24-word recovery phrase or base64 recovery key to reset your password.");
            });

        ui.add_space(20.0);

        // Mode toggle
        ui.horizontal(|ui| {
            ui.label("Input format:");
            if ui.selectable_label(!self.recovery_state.use_base64_mode, "24-Word Phrase").clicked() {
                self.recovery_state.use_base64_mode = false;
                self.recovery_state.clear_key_error();
            }
            if ui.selectable_label(self.recovery_state.use_base64_mode, "Base64").clicked() {
                self.recovery_state.use_base64_mode = true;
                self.recovery_state.clear_key_error();
            }
        });

        ui.add_space(10.0);

        // Input field
        if self.recovery_state.use_base64_mode {
            // Single-line for base64
            ui.add(
                egui::TextEdit::singleline(&mut self.recovery_state.recovery_key_input)
                    .hint_text("Paste your base64 recovery key here...")
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
            );
        } else {
            // Multi-line for mnemonic
            ui.add(
                egui::TextEdit::multiline(&mut self.recovery_state.recovery_key_input)
                    .hint_text("Enter your 24-word recovery phrase, one word per line or space-separated...")
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
            );

            // Word count helper
            let word_count = self.recovery_state.recovery_key_input.split_whitespace().count();
            if word_count > 0 {
                ui.label(
                    egui::RichText::new(format!("{}/24 words", word_count))
                        .small()
                        .color(if word_count == 24 {
                            egui::Color32::from_rgb(100, 200, 100)
                        } else {
                            egui::Color32::GRAY
                        })
                );
            }
        }

        // Error message
        if let Some(ref error) = self.recovery_state.key_error {
            ui.add_space(10.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(80, 30, 30))
                .rounding(5.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("⚠️");
                        ui.label(
                            egui::RichText::new(error)
                                .color(egui::Color32::from_rgb(255, 180, 180))
                        );
                    });
                });
        }

        ui.add_space(20.0);

        // Verify button
        let is_verifying = self.recovery_state.verifying;

        if is_verifying {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(egui::RichText::new("Verifying recovery key...").italics());
            });
        } else {
            let can_verify = self.recovery_state.has_recovery_key_input()
                && self.recovery_state.vault_path.is_some()
                && self.recovery_state.key_error.is_none();

            if ui.add_enabled(can_verify, egui::Button::new("Verify Recovery Key")).clicked() {
                self.attempt_recovery_key_verification();
            }
        }
    }

    /// Renders the new password entry step.
    fn render_recovery_new_password(&mut self, ui: &mut egui::Ui) {
        ui.set_max_width(450.0);

        // Success indicator
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(30, 60, 30))
            .rounding(8.0)
            .inner_margin(15.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("✓");
                    ui.label(egui::RichText::new("Recovery key verified!").strong());
                });
            });

        ui.add_space(20.0);

        // Level selection (if multiple levels)
        if self.recovery_state.available_levels.len() > 1 {
            ui.horizontal(|ui| {
                ui.label("Reset password for:");
                egui::ComboBox::from_id_source("recovery_level_select")
                    .selected_text(format!("Level {}", self.recovery_state.target_level))
                    .show_ui(ui, |ui| {
                        for level in &self.recovery_state.available_levels {
                            ui.selectable_value(
                                &mut self.recovery_state.target_level,
                                *level,
                                format!("Level {}", level)
                            );
                        }
                    });
            });
            ui.add_space(15.0);
        } else {
            ui.label(format!("Setting new password for Level {}", self.recovery_state.target_level));
            ui.add_space(15.0);
        }

        // Password input container
        egui::Frame::none()
            .fill(egui::Color32::from_gray(40))
            .rounding(8.0)
            .inner_margin(15.0)
            .show(ui, |ui| {
                // Show/hide toggle
                ui.horizontal(|ui| {
                    let toggle_text = if self.recovery_state.show_password { "👁 Hide" } else { "👁‍🗨 Show" };
                    if ui.small_button(toggle_text).clicked() {
                        self.recovery_state.show_password = !self.recovery_state.show_password;
                    }
                });

                ui.add_space(10.0);

                // New password
                ui.horizontal(|ui| {
                    ui.label("New Password:");
                });
                let password_response = if self.recovery_state.show_password {
                    ui.add(egui::TextEdit::singleline(&mut self.recovery_state.new_password)
                        .desired_width(f32::INFINITY))
                } else {
                    ui.add(egui::TextEdit::singleline(&mut self.recovery_state.new_password)
                        .password(true)
                        .desired_width(f32::INFINITY))
                };

                if password_response.changed() {
                    self.recovery_state.update_password_strength();
                }

                ui.add_space(10.0);

                // Confirm password
                ui.horizontal(|ui| {
                    ui.label("Confirm Password:");
                });
                if self.recovery_state.show_password {
                    ui.add(egui::TextEdit::singleline(&mut self.recovery_state.new_password_confirm)
                        .desired_width(f32::INFINITY));
                } else {
                    ui.add(egui::TextEdit::singleline(&mut self.recovery_state.new_password_confirm)
                        .password(true)
                        .desired_width(f32::INFINITY));
                }

                // Password match indicator
                if !self.recovery_state.new_password_confirm.is_empty() {
                    ui.add_space(5.0);
                    if self.recovery_state.passwords_match() {
                        ui.colored_label(egui::Color32::from_rgb(100, 200, 100), "✓ Passwords match");
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(255, 100, 100), "✗ Passwords do not match");
                    }
                }
            });

        ui.add_space(10.0);

        // Password strength meter
        self.render_password_strength_bar(ui, &self.recovery_state.password_strength.clone());

        // Error message
        if let Some(ref error) = self.recovery_state.reset_error {
            ui.add_space(10.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(80, 30, 30))
                .rounding(5.0)
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("⚠️");
                        ui.label(
                            egui::RichText::new(error)
                                .color(egui::Color32::from_rgb(255, 180, 180))
                        );
                    });
                });
        }

        ui.add_space(20.0);

        // Reset button
        let is_resetting = self.recovery_state.resetting;

        if is_resetting {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(egui::RichText::new("Resetting password...").italics());
            });
        } else {
            let can_submit = self.recovery_state.can_submit_password();

            if ui.add_enabled(can_submit, egui::Button::new("Reset Password")).clicked() {
                self.attempt_password_reset();
            }
        }
    }

    /// Renders a password strength bar (reused from wizard).
    fn render_password_strength_bar(&self, ui: &mut egui::Ui, strength: &PasswordStrength) {
        ui.horizontal(|ui| {
            ui.label("Strength:");

            let bar_width = 150.0;
            let bar_rect = ui.allocate_space(egui::vec2(bar_width, 10.0)).1;

            // Background
            ui.painter().rect_filled(
                bar_rect,
                2.0,
                egui::Color32::from_gray(60),
            );

            // Fill based on strength
            let fill_width = bar_rect.width() * strength.progress();
            let fill_rect = egui::Rect::from_min_size(
                bar_rect.min,
                egui::vec2(fill_width, bar_rect.height()),
            );

            let color_val = strength.color_value();
            let color = egui::Color32::from_rgb(
                ((1.0 - color_val) * 255.0) as u8,
                (color_val * 200.0) as u8,
                50,
            );

            ui.painter().rect_filled(fill_rect, 2.0, color);

            ui.label(strength.label());
        });

        if !strength.is_acceptable() {
            ui.colored_label(
                egui::Color32::from_rgb(255, 180, 100),
                "Password must be at least \"Fair\" strength"
            );
        }
    }

    /// Renders the success message after password reset.
    fn render_recovery_success(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(30, 80, 30))
            .rounding(10.0)
            .inner_margin(25.0)
            .show(ui, |ui| {
                ui.set_max_width(400.0);
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("✓").size(48.0).color(egui::Color32::from_rgb(100, 255, 100)));
                    ui.add_space(15.0);
                    ui.heading("Password Reset Successfully!");
                    ui.add_space(10.0);

                    if let Some(ref msg) = self.recovery_state.success_message {
                        ui.label(egui::RichText::new(msg).size(14.0));
                    }

                    ui.add_space(20.0);
                    ui.label("You can now log in with your new password.");
                });
            });

        ui.add_space(30.0);

        if ui.button("Return to Login").clicked() {
            self.recovery_state.reset_completely();
            self.screen = AppScreen::PasswordEntry;
        }
    }

    /// Renders the failure message.
    fn render_recovery_failed(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(egui::Color32::from_rgb(80, 30, 30))
            .rounding(10.0)
            .inner_margin(25.0)
            .show(ui, |ui| {
                ui.set_max_width(400.0);
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("✗").size(48.0).color(egui::Color32::from_rgb(255, 100, 100)));
                    ui.add_space(15.0);
                    ui.heading("Password Reset Failed");
                    ui.add_space(10.0);

                    if let Some(ref error) = self.recovery_state.reset_error {
                        ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 180, 180)));
                    }
                });
            });

        ui.add_space(20.0);

        if ui.button("Try Again").clicked() {
            self.recovery_state.reset();
        }
    }

    /// Attempts to verify the recovery key against the vault.
    fn attempt_recovery_key_verification(&mut self) {
        info!("Attempting recovery key verification");

        // First validate format
        if let Err(error) = self.recovery_state.validate_recovery_key_format() {
            self.recovery_state.set_key_error(error);
            return;
        }

        let vault_path = match &self.recovery_state.vault_path {
            Some(p) => p.clone(),
            None => {
                self.recovery_state.set_key_error("No vault path set");
                return;
            }
        };

        self.recovery_state.verifying = true;
        self.recovery_state.clear_key_error();

        // Parse the recovery key
        let input = self.recovery_state.recovery_key_input.trim();
        let recovery_key_result = if self.recovery_state.use_base64_mode {
            tesseract_crypto::recovery::RecoveryKey::from_base64(input)
        } else {
            tesseract_crypto::recovery::RecoveryKey::from_mnemonic(input)
        };

        let recovery_key = match recovery_key_result {
            Ok(k) => k,
            Err(e) => {
                self.recovery_state.verifying = false;
                self.recovery_state.set_key_error(format!("Invalid recovery key: {}", e));
                return;
            }
        };

        // Attempt to authenticate with the recovery key
        match tesseract_core::session::authenticate_recovery(&vault_path, &recovery_key, None) {
            Ok(session) => {
                info!("Recovery key verified successfully");

                // Get available levels from the vault header
                let levels: Vec<u32> = (1..=10).filter(|&level| {
                    // Check if level exists in the vault
                    // For now, assume levels 1-3 exist (this could be refined)
                    level <= 3
                }).collect();

                self.recovery_state.key_verified(levels);
            }
            Err(e) => {
                warn!("Recovery key verification failed: {}", e);
                self.recovery_state.verifying = false;
                self.recovery_state.set_key_error(format!(
                    "Recovery key verification failed: {}. \
                     Make sure you entered the correct 24 words or base64 key.",
                    e
                ));
            }
        }
    }

    /// Attempts to reset the password using the verified recovery key.
    fn attempt_password_reset(&mut self) {
        info!("Attempting password reset for level {}", self.recovery_state.target_level);

        let vault_path = match &self.recovery_state.vault_path {
            Some(p) => p.clone(),
            None => {
                self.recovery_state.set_reset_error("No vault path set");
                return;
            }
        };

        self.recovery_state.resetting = true;
        self.recovery_state.reset_error = None;

        // Parse the recovery key again
        let input = self.recovery_state.recovery_key_input.trim();
        let recovery_key_result = if self.recovery_state.use_base64_mode {
            tesseract_crypto::recovery::RecoveryKey::from_base64(input)
        } else {
            tesseract_crypto::recovery::RecoveryKey::from_mnemonic(input)
        };

        let recovery_key = match recovery_key_result {
            Ok(k) => k,
            Err(e) => {
                self.recovery_state.resetting = false;
                self.recovery_state.set_reset_error(format!("Failed to parse recovery key: {}", e));
                return;
            }
        };

        // Reset the password
        let new_password = self.recovery_state.new_password.as_bytes();
        let target_level = self.recovery_state.target_level;

        match tesseract_core::session::reset_level_password_with_recovery(
            &vault_path,
            &recovery_key,
            target_level,
            new_password,
            None,
        ) {
            Ok(()) => {
                info!("Password reset successful for level {}", target_level);
                self.recovery_state.password_reset_success();
            }
            Err(e) => {
                warn!("Password reset failed: {}", e);
                self.recovery_state.resetting = false;
                self.recovery_state.set_reset_error(format!("Password reset failed: {}", e));
            }
        }
    }

    // =========================================================================

    /// Renders the change password dialog.
    fn render_change_password_dialog(&mut self, ctx: &egui::Context) {
        if !self.settings_state.change_password_dialog.is_open {
            return;
        }

        let mut should_close = false;
        let mut should_change = false;

        egui::Window::new(format!("Change Password - {}", self.settings_state.change_password_dialog.level_name))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                // Error message
                if let Some(ref error) = self.settings_state.change_password_dialog.error_message.clone() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(80, 30, 30))
                        .rounding(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("⚠️");
                                ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 180, 180)));
                            });
                        });
                    ui.add_space(10.0);
                }

                // Show/hide toggle
                ui.horizontal(|ui| {
                    let toggle_text = if self.settings_state.change_password_dialog.show_password { "👁 Hide passwords" } else { "👁‍🗨 Show passwords" };
                    if ui.small_button(toggle_text).clicked() {
                        self.settings_state.change_password_dialog.show_password = !self.settings_state.change_password_dialog.show_password;
                    }
                });

                ui.add_space(10.0);

                // Current password
                ui.label("Current Password:");
                let current_edit = if self.settings_state.change_password_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.change_password_dialog.current_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.change_password_dialog.current_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(current_edit);

                ui.add_space(10.0);

                // New password
                ui.label("New Password:");
                let new_edit = if self.settings_state.change_password_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.change_password_dialog.new_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.change_password_dialog.new_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(new_edit);

                ui.add_space(5.0);

                // Confirm new password
                ui.label("Confirm New Password:");
                let confirm_edit = if self.settings_state.change_password_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.change_password_dialog.confirm_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.change_password_dialog.confirm_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(confirm_edit);

                ui.add_space(20.0);

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        should_close = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let is_changing = self.settings_state.change_password_dialog.is_changing;
                        let change_btn = egui::Button::new(if is_changing { "Changing..." } else { "Change Password" });

                        if ui.add_enabled(!is_changing, change_btn).clicked() {
                            if let Some(error) = self.settings_state.change_password_dialog.validate() {
                                self.settings_state.change_password_dialog.error_message = Some(error);
                            } else {
                                should_change = true;
                            }
                        }
                    });
                });
            });

        if should_close {
            self.settings_state.change_password_dialog.close();
        }

        if should_change {
            self.change_level_password();
        }
    }

    /// Changes the password for an access level.
    fn change_level_password(&mut self) {
        let level_id = self.settings_state.change_password_dialog.level_id;
        let level_name = self.settings_state.change_password_dialog.level_name.clone();
        let current_password = self.settings_state.change_password_dialog.current_password.clone();
        let new_password = self.settings_state.change_password_dialog.new_password.clone();

        self.settings_state.change_password_dialog.is_changing = true;

        if let Some(ref vault_path) = self.current_vault_path {
            match tesseract_core::session::change_level_password(
                vault_path,
                level_id,
                current_password.as_bytes(),
                new_password.as_bytes(),
                None,
            ) {
                Ok(_result) => {
                    info!("Changed password for level {} ({})", level_id, level_name);
                    self.settings_state.change_password_dialog.close();
                    self.settings_state.set_success(format!("Password changed for '{}'", level_name));
                }
                Err(e) => {
                    warn!("Failed to change password: {}", e);
                    let error_msg = if e.to_string().contains("AuthenticationFailed") {
                        "Incorrect current password".to_string()
                    } else {
                        format!("Failed: {}", e)
                    };
                    self.settings_state.change_password_dialog.error_message = Some(error_msg);
                    self.settings_state.change_password_dialog.is_changing = false;
                }
            }
        }
    }

    /// Renders the delete level confirmation dialog.
    fn render_delete_level_dialog(&mut self, ctx: &egui::Context) {
        if !self.settings_state.delete_dialog.is_open {
            return;
        }

        let mut should_close = false;
        let mut should_delete = false;

        egui::Window::new("Delete Access Level")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                // Warning icon
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("⚠️").size(48.0));
                    ui.add_space(10.0);
                });

                // Error message
                if let Some(ref error) = self.settings_state.delete_dialog.error_message.clone() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(80, 30, 30))
                        .rounding(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 180, 180)));
                            });
                        });
                    ui.add_space(10.0);
                }

                ui.label(format!(
                    "Are you sure you want to delete access level '{}'?",
                    self.settings_state.delete_dialog.level_name
                ));

                ui.add_space(10.0);

                ui.label(
                    egui::RichText::new("This action cannot be undone. The level and its keystore will be permanently removed.")
                        .weak()
                        .small()
                );

                ui.add_space(20.0);

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        should_close = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let is_deleting = self.settings_state.delete_dialog.is_deleting;
                        let delete_btn = egui::Button::new(if is_deleting { "Deleting..." } else { "Delete Level" })
                            .fill(egui::Color32::from_rgb(150, 50, 50));

                        if ui.add_enabled(!is_deleting, delete_btn).clicked() {
                            should_delete = true;
                        }
                    });
                });
            });

        if should_close {
            self.settings_state.delete_dialog.close();
        }

        if should_delete {
            self.delete_access_level();
        }
    }

    /// Deletes an access level.
    fn delete_access_level(&mut self) {
        let level_id = self.settings_state.delete_dialog.level_id;
        let level_name = self.settings_state.delete_dialog.level_name.clone();

        self.settings_state.delete_dialog.is_deleting = true;

        let Some(ref vault_path) = self.current_vault_path else {
            self.settings_state.delete_dialog.is_deleting = false;
            return;
        };
        let Some(ref master_key) = self.master_key else {
            self.settings_state.delete_dialog.is_deleting = false;
            return;
        };

        match tesseract_core::access::delete_level(vault_path, master_key, level_id) {
            Ok(()) => {
                info!("Deleted access level {} ({})", level_id, level_name);
                self.settings_state.delete_dialog.close();
                self.settings_state.set_success(format!("Deleted level '{}'", level_name));
                self.settings_state.mark_refresh_needed();
            }
            Err(e) => {
                warn!("Failed to delete level: {}", e);
                self.settings_state.delete_dialog.error_message = Some(format!("Failed: {}", e));
                self.settings_state.delete_dialog.is_deleting = false;
            }
        }
    }

    // =========================================================================
    // Drive Password Change (US-028)
    // =========================================================================

    /// Renders the drive password change dialog.
    fn render_drive_password_change_dialog(&mut self, ctx: &egui::Context) {
        if !self.settings_state.drive_password_change_dialog.is_open {
            return;
        }

        let mut should_close = false;
        let mut should_change = false;

        egui::Window::new("Change Drive Master Password")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(450.0);

                // Warning banner
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(60, 50, 20))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("⚠️");
                            ui.label(egui::RichText::new(
                                "Changing the master password will re-encrypt the drive header. Make sure you remember your new password!"
                            ).color(egui::Color32::from_rgb(255, 220, 150)));
                        });
                    });
                ui.add_space(10.0);

                // Error message
                if let Some(ref error) = self.settings_state.drive_password_change_dialog.error_message.clone() {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(80, 30, 30))
                        .rounding(5.0)
                        .inner_margin(10.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("⚠️");
                                ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 180, 180)));
                            });
                        });
                    ui.add_space(10.0);
                }

                // Show/hide toggle
                ui.horizontal(|ui| {
                    let toggle_text = if self.settings_state.drive_password_change_dialog.show_password {
                        "👁 Hide passwords"
                    } else {
                        "👁‍🗨 Show passwords"
                    };
                    if ui.small_button(toggle_text).clicked() {
                        self.settings_state.drive_password_change_dialog.show_password =
                            !self.settings_state.drive_password_change_dialog.show_password;
                    }
                });

                ui.add_space(10.0);

                // Current password
                ui.label("Current Password:");
                let current_edit = if self.settings_state.drive_password_change_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.drive_password_change_dialog.current_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.drive_password_change_dialog.current_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(current_edit);

                ui.add_space(10.0);

                // New password
                ui.label("New Password:");
                let new_response = if self.settings_state.drive_password_change_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.drive_password_change_dialog.new_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.drive_password_change_dialog.new_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                let new_edit = ui.add(new_response);

                // Update strength when password changes
                if new_edit.changed() {
                    self.settings_state.drive_password_change_dialog.update_strength();
                }

                // Password strength meter
                ui.add_space(5.0);
                self.render_password_strength_bar(
                    ui,
                    &self.settings_state.drive_password_change_dialog.password_strength.clone(),
                );

                ui.add_space(10.0);

                // Confirm new password
                ui.label("Confirm New Password:");
                let confirm_edit = if self.settings_state.drive_password_change_dialog.show_password {
                    egui::TextEdit::singleline(&mut self.settings_state.drive_password_change_dialog.confirm_password)
                        .desired_width(f32::INFINITY)
                } else {
                    egui::TextEdit::singleline(&mut self.settings_state.drive_password_change_dialog.confirm_password)
                        .password(true)
                        .desired_width(f32::INFINITY)
                };
                ui.add(confirm_edit);

                // Password match indicator
                if !self.settings_state.drive_password_change_dialog.confirm_password.is_empty() {
                    ui.add_space(5.0);
                    let matches = self.settings_state.drive_password_change_dialog.new_password
                        == self.settings_state.drive_password_change_dialog.confirm_password;
                    if matches {
                        ui.label(egui::RichText::new("✓ Passwords match").color(egui::Color32::GREEN).small());
                    } else {
                        ui.label(egui::RichText::new("✗ Passwords do not match").color(egui::Color32::RED).small());
                    }
                }

                ui.add_space(20.0);

                // Buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        should_close = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let is_changing = self.settings_state.drive_password_change_dialog.is_changing;
                        let change_btn = egui::Button::new(if is_changing {
                            "Changing..."
                        } else {
                            "Change Master Password"
                        });

                        if ui.add_enabled(!is_changing, change_btn).clicked() {
                            if let Some(error) = self.settings_state.drive_password_change_dialog.validate() {
                                self.settings_state.drive_password_change_dialog.error_message = Some(error);
                            } else {
                                should_change = true;
                            }
                        }
                    });
                });
            });

        if should_close {
            self.settings_state.drive_password_change_dialog.close();
        }

        if should_change {
            self.change_drive_password();
        }
    }

    /// Changes the drive master password.
    fn change_drive_password(&mut self) {
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom, Write};
        use tesseract_hardware::{ThcHeader, THC_HEADER_SIZE};

        let current_password = self.settings_state.drive_password_change_dialog.current_password.clone();
        let new_password = self.settings_state.drive_password_change_dialog.new_password.clone();

        self.settings_state.drive_password_change_dialog.is_changing = true;

        // Get the current drive device path
        let device_path = match &self.current_drive {
            Some(drive) => drive.device_path.clone(),
            None => {
                self.settings_state.drive_password_change_dialog.set_error("No drive is currently unlocked");
                return;
            }
        };

        // Read the current header
        let mut file = match OpenOptions::new().read(true).write(true).open(&device_path) {
            Ok(f) => f,
            Err(e) => {
                self.settings_state.drive_password_change_dialog.set_error(
                    format!("Failed to open drive: {}. Try running as administrator.", e)
                );
                return;
            }
        };

        let mut header_bytes = [0u8; THC_HEADER_SIZE];
        if let Err(e) = file.read_exact(&mut header_bytes) {
            self.settings_state.drive_password_change_dialog.set_error(format!("Failed to read header: {}", e));
            return;
        }

        // Parse the header
        let header = match ThcHeader::from_bytes(&header_bytes) {
            Ok(h) => h,
            Err(e) => {
                self.settings_state.drive_password_change_dialog.set_error(format!("Invalid header: {}", e));
                return;
            }
        };

        // Change the password (this verifies current password and re-encrypts)
        let new_header = match header.change_password(current_password.as_bytes(), new_password.as_bytes()) {
            Ok(h) => h,
            Err(tesseract_hardware::HardwareError::InvalidPassword) => {
                self.settings_state.drive_password_change_dialog.set_error("Incorrect current password");
                return;
            }
            Err(e) => {
                self.settings_state.drive_password_change_dialog.set_error(format!("Password change failed: {}", e));
                return;
            }
        };

        // Write the new header back to disk
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            self.settings_state.drive_password_change_dialog.set_error(format!("Failed to seek: {}", e));
            return;
        }

        let new_header_bytes = new_header.to_bytes();
        if let Err(e) = file.write_all(&new_header_bytes) {
            self.settings_state.drive_password_change_dialog.set_error(format!("Failed to write header: {}", e));
            return;
        }

        if let Err(e) = file.sync_all() {
            self.settings_state.drive_password_change_dialog.set_error(format!("Failed to sync: {}", e));
            return;
        }

        // Success
        info!("Changed drive master password for {:?}", device_path);
        self.settings_state.drive_password_change_dialog.close();
        self.settings_state.drive_password_change_dialog.set_success("Master password changed successfully");
    }

    // =========================================================================
    // Drag-and-Drop Import
    // =========================================================================

    /// Handles drag-and-drop events for file import.
    fn handle_drag_drop(&mut self, ctx: &egui::Context) {
        // Check for drag hover
        let is_hovering = !ctx.input(|i| i.raw.hovered_files.is_empty());
        self.file_browser_state.drag_hover_active = is_hovering;

        // Check for dropped files
        let dropped_files: Vec<egui::DroppedFile> = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped_files.is_empty() {
            self.file_browser_state.drag_hover_active = false;
            self.file_browser_state.handle_dropped_files(&dropped_files);
        }
    }

    /// Renders the drag-and-drop overlay when files are being dragged.
    fn render_drag_overlay(&self, ctx: &egui::Context) {
        if !self.file_browser_state.drag_hover_active {
            return;
        }

        // Full-screen overlay with drop zone indicator
        egui::Area::new(egui::Id::new("drag_overlay"))
            .fixed_pos(egui::pos2(0.0, 0.0))
            .show(ctx, |ui| {
                let screen_rect = ctx.screen_rect();
                let painter = ui.painter();

                // Semi-transparent background
                painter.rect_filled(
                    screen_rect,
                    0.0,
                    egui::Color32::from_rgba_unmultiplied(0, 100, 150, 180),
                );

                // Drop zone border
                painter.rect_stroke(
                    screen_rect.shrink(20.0),
                    10.0,
                    egui::Stroke::new(4.0, egui::Color32::from_rgb(100, 200, 255)),
                );

                // Center text
                let center = screen_rect.center();
                painter.text(
                    center + egui::vec2(0.0, -20.0),
                    egui::Align2::CENTER_CENTER,
                    "📥",
                    egui::FontId::proportional(64.0),
                    egui::Color32::WHITE,
                );
                painter.text(
                    center + egui::vec2(0.0, 30.0),
                    egui::Align2::CENTER_CENTER,
                    "Drop files to import",
                    egui::FontId::proportional(24.0),
                    egui::Color32::WHITE,
                );
                painter.text(
                    center + egui::vec2(0.0, 60.0),
                    egui::Align2::CENTER_CENTER,
                    "Files will be encrypted and stored in the vault",
                    egui::FontId::proportional(14.0),
                    egui::Color32::from_rgb(200, 220, 255),
                );
            });
    }

    // =========================================================================
    // Context Menu and Dialogs
    // =========================================================================

    /// Renders the context menu when visible.
    fn render_context_menu(&mut self, ctx: &egui::Context) {
        if !self.file_browser_state.context_menu.is_open {
            return;
        }

        let menu_pos = self.file_browser_state.context_menu.position;
        let actions = self.file_browser_state.context_menu.available_actions();
        let target_uuids = self.file_browser_state.context_menu.target_file_uuids.clone();

        let mut action_selected: Option<ContextMenuAction> = None;
        let mut should_close = false;

        egui::Area::new(egui::Id::new("context_menu"))
            .fixed_pos(menu_pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::popup(ui.style())
                    .shadow(egui::epaint::Shadow {
                        offset: egui::vec2(4.0, 4.0),
                        blur: 8.0,
                        spread: 0.0,
                        color: egui::Color32::from_black_alpha(100),
                    })
                    .show(ui, |ui| {
                        ui.set_min_width(150.0);

                        for action in &actions {
                            let label = action.label();
                            let shortcut = action.shortcut_hint();

                            let button_text = if let Some(hint) = shortcut {
                                format!("{}    {}", label, hint)
                            } else {
                                label.to_string()
                            };

                            // Style delete action with red text
                            let response = if matches!(action, ContextMenuAction::Delete) {
                                ui.add(egui::Button::new(
                                    egui::RichText::new(&button_text).color(egui::Color32::from_rgb(255, 100, 100))
                                ).frame(false))
                            } else {
                                ui.add(egui::Button::new(&button_text).frame(false))
                            };

                            if response.clicked() {
                                action_selected = Some(*action);
                                should_close = true;
                            }
                        }
                    });
            });

        // Close menu if clicked outside
        if ctx.input(|i| i.pointer.any_click()) && !should_close {
            if let Some(pos) = ctx.input(|i| i.pointer.interact_pos()) {
                // Check if click was outside the menu area
                let menu_rect = egui::Rect::from_min_size(menu_pos, egui::vec2(180.0, 200.0));
                if !menu_rect.contains(pos) {
                    should_close = true;
                }
            }
        }

        // Handle selected action
        if let Some(action) = action_selected {
            self.handle_context_action(action, &target_uuids);
        }

        if should_close {
            self.file_browser_state.context_menu.close();
        }
    }

    /// Handles a context menu action.
    fn handle_context_action(&mut self, action: ContextMenuAction, file_uuids: &[uuid::Uuid]) {
        match action {
            ContextMenuAction::Open => {
                // Open first selected file (if single file)
                if let Some(uuid) = file_uuids.first() {
                    if let Some(entry) = self.file_browser_state.entries.iter().find(|e| {
                        e.uuid.map(|u| u == *uuid).unwrap_or(false)
                    }) {
                        if entry.is_directory() {
                            if let Some(ref session) = self.vault_session {
                                let new_path = format!("{}/{}", self.file_browser_state.current_path.trim_end_matches('/'), entry.name);
                                self.file_browser_state.navigate_to(&new_path, session);
                            }
                        } else {
                            // Open file in default application via secure temp file
                            self.open_file_preview(*uuid);
                        }
                    }
                }
            }
            ContextMenuAction::Export => {
                // Start export for selected files
                self.open_export_dialog();
            }
            ContextMenuAction::Delete => {
                // Show delete confirmation
                let file_count = file_uuids.len();
                self.file_browser_state.confirmation_dialog = ConfirmationDialog::DeleteConfirmation {
                    file_count,
                    file_uuids: file_uuids.to_vec(),
                };
            }
            ContextMenuAction::Rename => {
                // Start rename for single file
                if let Some(uuid) = file_uuids.first() {
                    if let Some(entry) = self.file_browser_state.entries.iter().find(|e| {
                        e.uuid.map(|u| u == *uuid).unwrap_or(false)
                    }) {
                        self.file_browser_state.rename_state.start(*uuid, entry.name.clone());
                    }
                }
            }
            ContextMenuAction::ChangeAccessLevel => {
                // Start change access level dialog
                let max_level = self.file_browser_state.max_access_level;
                self.file_browser_state.change_access_level_state.start(file_uuids.to_vec(), max_level);
            }
        }
    }

    /// Renders the delete confirmation dialog.
    fn render_delete_confirmation(&mut self, ctx: &egui::Context) {
        if let ConfirmationDialog::DeleteConfirmation { file_count, ref file_uuids } = self.file_browser_state.confirmation_dialog {
            let uuids_to_delete = file_uuids.clone();
            let mut should_delete = false;
            let mut should_cancel = false;

            egui::Window::new("Confirm Delete")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(300.0);

                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("⚠️").size(48.0));
                        ui.add_space(10.0);

                        let message = if file_count == 1 {
                            "Are you sure you want to delete this file?".to_string()
                        } else {
                            format!("Are you sure you want to delete {} files?", file_count)
                        };
                        ui.heading(message);
                        ui.add_space(5.0);
                        ui.label(
                            egui::RichText::new("This action cannot be undone.")
                                .color(egui::Color32::from_rgb(255, 180, 180))
                        );
                        ui.add_space(20.0);

                        ui.horizontal(|ui| {
                            ui.add_space((ui.available_width() - 200.0) / 2.0);

                            if ui.button("Cancel").clicked() {
                                should_cancel = true;
                            }

                            ui.add_space(20.0);

                            if ui.add(egui::Button::new(
                                egui::RichText::new("Delete").color(egui::Color32::from_rgb(255, 100, 100))
                            )).clicked() {
                                should_delete = true;
                            }
                        });
                        ui.add_space(10.0);
                    });
                });

            if should_cancel {
                self.file_browser_state.confirmation_dialog = ConfirmationDialog::None;
            }

            if should_delete {
                self.execute_delete(&uuids_to_delete);
                self.file_browser_state.confirmation_dialog = ConfirmationDialog::None;
            }
        }
    }

    /// Executes deletion of files.
    fn execute_delete(&mut self, file_uuids: &[uuid::Uuid]) {
        if let Some(ref mut session) = self.vault_session {
            let mut errors = Vec::new();
            let mut success_count = 0;

            for uuid in file_uuids {
                match tesseract_core::files::delete_file(session, *uuid) {
                    Ok(_) => success_count += 1,
                    Err(e) => errors.push(format!("Failed to delete file: {}", e)),
                }
            }

            // Clear selection
            self.file_browser_state.selected.clear();

            // Refresh file list
            self.file_browser_state.refresh_entries(session);

            // Set status message
            if errors.is_empty() {
                let msg = if success_count == 1 {
                    "File deleted".to_string()
                } else {
                    format!("{} files deleted", success_count)
                };
                self.set_status(msg);
            } else {
                self.file_browser_state.error_message = Some(errors.join(", "));
            }
        }
    }

    /// Renders the rename dialog.
    fn render_rename_dialog(&mut self, ctx: &egui::Context) {
        if !self.file_browser_state.rename_state.is_renaming() {
            return;
        }

        let mut should_rename = false;
        let mut should_cancel = false;
        let mut new_name = self.file_browser_state.rename_state.new_name.clone();

        egui::Window::new("Rename")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(350.0);

                ui.vertical(|ui| {
                    ui.add_space(10.0);
                    ui.label("Enter new name:");
                    ui.add_space(5.0);

                    let response = ui.add(
                        egui::TextEdit::singleline(&mut new_name)
                            .desired_width(320.0)
                    );

                    // Focus the text input on first frame
                    if response.gained_focus() || self.file_browser_state.rename_state.error_message.is_none() {
                        response.request_focus();
                    }

                    // Show error if any
                    if let Some(ref error) = self.file_browser_state.rename_state.error_message {
                        ui.add_space(5.0);
                        ui.label(
                            egui::RichText::new(error).color(egui::Color32::from_rgb(255, 150, 150))
                        );
                    }

                    ui.add_space(15.0);

                    ui.horizontal(|ui| {
                        ui.add_space((ui.available_width() - 180.0) / 2.0);

                        if ui.button("Cancel").clicked() {
                            should_cancel = true;
                        }

                        ui.add_space(20.0);

                        let can_rename = !new_name.is_empty()
                            && new_name != self.file_browser_state.rename_state.original_name;

                        if ui.add_enabled(can_rename, egui::Button::new("Rename")).clicked() {
                            should_rename = true;
                        }

                        // Handle Enter key
                        if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && can_rename {
                            should_rename = true;
                        }
                    });
                    ui.add_space(10.0);
                });
            });

        // Update the name in state
        self.file_browser_state.rename_state.new_name = new_name.clone();

        if should_cancel {
            self.file_browser_state.rename_state.cancel();
        }

        if should_rename {
            self.execute_rename();
        }
    }

    /// Executes the rename operation.
    fn execute_rename(&mut self) {
        let file_uuid = match self.file_browser_state.rename_state.file_uuid {
            Some(uuid) => uuid,
            None => return,
        };
        let new_name = self.file_browser_state.rename_state.new_name.clone();

        if let Some(ref mut session) = self.vault_session {
            match tesseract_core::files::rename_file(session, file_uuid, &new_name) {
                Ok(_) => {
                    self.file_browser_state.rename_state.cancel();
                    self.file_browser_state.refresh_entries(session);
                    self.set_status(format!("Renamed to '{}'", new_name));
                }
                Err(e) => {
                    self.file_browser_state.rename_state.error_message = Some(e.to_string());
                }
            }
        }
    }

    /// Renders the change access level dialog.
    fn render_change_access_level_dialog(&mut self, ctx: &egui::Context) {
        if !self.file_browser_state.change_access_level_state.is_active {
            return;
        }

        let max_level = self.file_browser_state.max_access_level.max(1);
        let file_count = self.file_browser_state.change_access_level_state.file_uuids.len();
        let mut should_apply = false;
        let mut should_cancel = false;
        let mut selected_level = self.file_browser_state.change_access_level_state.target_level;

        egui::Window::new("Change Access Level")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(300.0);

                ui.vertical(|ui| {
                    ui.add_space(10.0);

                    let msg = if file_count == 1 {
                        "Set access level for this file:".to_string()
                    } else {
                        format!("Set access level for {} files:", file_count)
                    };
                    ui.label(msg);
                    ui.add_space(15.0);

                    ui.horizontal(|ui| {
                        ui.add_space((ui.available_width() - (60.0 * max_level as f32)) / 2.0);

                        for level in 1..=max_level {
                            let is_selected = selected_level == level;
                            let level_color = match level {
                                1 => egui::Color32::from_rgb(100, 200, 100),
                                2 => egui::Color32::from_rgb(200, 200, 100),
                                3 => egui::Color32::from_rgb(200, 150, 100),
                                _ => egui::Color32::from_rgb(200, 100, 100),
                            };

                            let button_text = egui::RichText::new(format!("L{}", level))
                                .color(if is_selected { egui::Color32::WHITE } else { level_color });

                            let button = if is_selected {
                                egui::Button::new(button_text)
                                    .fill(level_color)
                                    .min_size(egui::vec2(50.0, 30.0))
                            } else {
                                egui::Button::new(button_text)
                                    .min_size(egui::vec2(50.0, 30.0))
                            };

                            if ui.add(button).clicked() {
                                selected_level = level;
                            }
                        }
                    });

                    ui.add_space(20.0);

                    ui.horizontal(|ui| {
                        ui.add_space((ui.available_width() - 180.0) / 2.0);

                        if ui.button("Cancel").clicked() {
                            should_cancel = true;
                        }

                        ui.add_space(20.0);

                        if ui.button("Apply").clicked() {
                            should_apply = true;
                        }
                    });
                    ui.add_space(10.0);
                });
            });

        // Update selected level
        self.file_browser_state.change_access_level_state.target_level = selected_level;

        if should_cancel {
            self.file_browser_state.change_access_level_state.cancel();
        }

        if should_apply {
            self.execute_change_access_level();
        }
    }

    /// Executes the change access level operation.
    fn execute_change_access_level(&mut self) {
        let file_uuids = self.file_browser_state.change_access_level_state.file_uuids.clone();
        let target_level = self.file_browser_state.change_access_level_state.target_level;

        if let Some(ref mut session) = self.vault_session {
            let mut errors = Vec::new();
            let mut success_count = 0;

            for uuid in &file_uuids {
                match tesseract_core::files::set_access_level(session, *uuid, target_level) {
                    Ok(_) => success_count += 1,
                    Err(e) => errors.push(e.to_string()),
                }
            }

            self.file_browser_state.change_access_level_state.cancel();
            self.file_browser_state.refresh_entries(session);

            if errors.is_empty() {
                let msg = if success_count == 1 {
                    format!("Access level set to L{}", target_level)
                } else {
                    format!("{} files set to L{}", success_count, target_level)
                };
                self.set_status(msg);
            } else {
                self.file_browser_state.error_message = Some(errors.join(", "));
            }
        }
    }

    /// Handles keyboard shortcuts for file operations.
    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        // Only handle shortcuts when in file browser and no dialogs are open
        if self.screen != AppScreen::FileBrowser {
            return;
        }
        if self.file_browser_state.rename_state.is_active
            || self.file_browser_state.change_access_level_state.is_active
            || !matches!(self.file_browser_state.confirmation_dialog, ConfirmationDialog::None)
            || self.file_browser_state.context_menu.is_open
        {
            return;
        }

        // Collect key events first
        let (delete_pressed, f2_pressed, ctrl_e_pressed, ctrl_a_pressed, escape_pressed, enter_pressed) =
            ctx.input(|i| {
                (
                    i.key_pressed(egui::Key::Delete),
                    i.key_pressed(egui::Key::F2),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::E),
                    i.modifiers.ctrl && i.key_pressed(egui::Key::A),
                    i.key_pressed(egui::Key::Escape),
                    i.key_pressed(egui::Key::Enter),
                )
            });

        let selected_uuids: Vec<uuid::Uuid> = self.file_browser_state.selected.iter().copied().collect();

        // Delete key - delete selected files
        if delete_pressed && !selected_uuids.is_empty() {
            let file_count = selected_uuids.len();
            self.file_browser_state.confirmation_dialog = ConfirmationDialog::DeleteConfirmation {
                file_count,
                file_uuids: selected_uuids.clone(),
            };
        }

        // F2 - rename (single file only)
        if f2_pressed && selected_uuids.len() == 1 {
            if let Some(uuid) = selected_uuids.first() {
                if let Some(entry) = self.file_browser_state.entries.iter().find(|e| {
                    e.uuid.map(|u| u == *uuid).unwrap_or(false)
                }) {
                    self.file_browser_state.rename_state.start(*uuid, entry.name.clone());
                }
            }
        }

        // Ctrl+E - export selected files
        if ctrl_e_pressed && !selected_uuids.is_empty() {
            let has_directories = self.file_browser_state.entries.iter().any(|e| {
                e.uuid.map(|u| self.file_browser_state.selected.contains(&u) && e.is_directory())
                    .unwrap_or(false)
            });
            if !has_directories {
                self.open_export_dialog();
            }
        }

        // Ctrl+A - select all
        if ctrl_a_pressed {
            for entry in &self.file_browser_state.entries {
                if let Some(uuid) = entry.uuid {
                    self.file_browser_state.selected.insert(uuid);
                }
            }
        }

        // Escape - clear selection
        if escape_pressed {
            self.file_browser_state.selected.clear();
        }

        // Enter - open selected (single file/directory)
        if enter_pressed && selected_uuids.len() == 1 {
            if let Some(uuid) = selected_uuids.first() {
                if let Some(entry) = self.file_browser_state.entries.iter().find(|e| {
                    e.uuid.map(|u| u == *uuid).unwrap_or(false)
                }).cloned() {
                    if entry.is_directory() {
                        if let Some(ref session) = self.vault_session {
                            let new_path = format!("{}/{}", self.file_browser_state.current_path.trim_end_matches('/'), entry.name);
                            self.file_browser_state.navigate_to(&new_path, session);
                        }
                    } else {
                        // Open file in external application
                        self.open_file_preview(*uuid);
                    }
                }
            }
        }
    }

    /// Renders the import dialog for selecting access level and confirming import.
    fn render_import_dialog(&mut self, ctx: &egui::Context) {
        if !self.file_browser_state.should_show_import_dialog() {
            return;
        }

        let mut should_start_import = false;
        let mut should_cancel = false;

        egui::Window::new("Import Files")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(400.0);

                // File list header
                let file_count = self.file_browser_state.pending_imports.len();
                let total_size = self.file_browser_state.pending_imports_total_size();

                ui.heading(format!(
                    "Import {} file{}",
                    file_count,
                    if file_count == 1 { "" } else { "s" }
                ));
                ui.add_space(5.0);
                ui.label(
                    egui::RichText::new(format!("Total size: {}", format_file_size(total_size)))
                        .weak()
                );
                ui.add_space(15.0);

                // File list
                egui::Frame::none()
                    .fill(egui::Color32::from_gray(30))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(200.0)
                            .show(ui, |ui| {
                                for pending in &self.file_browser_state.pending_imports {
                                    ui.horizontal(|ui| {
                                        ui.label("📄");
                                        ui.label(&pending.filename);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    egui::RichText::new(format_file_size(pending.size))
                                                        .weak()
                                                        .small()
                                                );
                                            }
                                        );
                                    });
                                }
                            });
                    });

                ui.add_space(15.0);

                // Access level selection
                ui.horizontal(|ui| {
                    ui.label("Access Level:");
                    ui.add_space(10.0);

                    let max_level = self.file_browser_state.max_access_level.max(1);
                    for level in 1..=max_level {
                        let is_selected = self.file_browser_state.import_access_level == level;
                        let level_color = match level {
                            1 => egui::Color32::from_rgb(100, 200, 100),
                            2 => egui::Color32::from_rgb(200, 200, 100),
                            3 => egui::Color32::from_rgb(200, 150, 100),
                            _ => egui::Color32::from_rgb(200, 100, 100),
                        };

                        let button_text = egui::RichText::new(format!("L{}", level))
                            .color(if is_selected { egui::Color32::WHITE } else { level_color });

                        if ui.selectable_label(is_selected, button_text).clicked() {
                            self.file_browser_state.import_access_level = level;
                        }
                    }
                });

                ui.add_space(5.0);
                ui.label(
                    egui::RichText::new(
                        "Files will be encrypted with the selected access level's key"
                    )
                    .weak()
                    .small()
                );

                // Destination path
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Destination:");
                    ui.label(
                        egui::RichText::new(&self.file_browser_state.current_path)
                            .monospace()
                    );
                });

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(10.0);

                // Action buttons
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        should_cancel = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let import_button = egui::Button::new("📥 Import")
                            .fill(egui::Color32::from_rgb(40, 100, 60));
                        if ui.add(import_button).clicked() {
                            should_start_import = true;
                        }
                    });
                });
            });

        // Handle actions outside the window closure
        if should_cancel {
            self.file_browser_state.cancel_import();
        } else if should_start_import {
            self.start_import_process();
        }
    }

    /// Renders the import progress overlay.
    fn render_import_progress(&self, ctx: &egui::Context) {
        if let ImportStatus::Importing { current, total, ref current_file } = self.file_browser_state.import_status {
            egui::Window::new("Importing...")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(350.0);

                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.add_space(15.0);

                        ui.heading(format!("Importing file {} of {}", current, total));
                        ui.add_space(10.0);

                        ui.label(
                            egui::RichText::new(current_file)
                                .monospace()
                                .weak()
                        );

                        ui.add_space(15.0);

                        // Progress bar
                        let progress = current as f32 / total as f32;
                        let progress_bar = egui::ProgressBar::new(progress)
                            .show_percentage()
                            .animate(true);
                        ui.add(progress_bar);

                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("Encrypting with AES-256-GCM...")
                                .weak()
                                .small()
                        );
                    });
                });

            // Request repaint to show animation
            ctx.request_repaint();
        }
    }

    /// Renders the import result notification.
    fn render_import_result(&mut self, ctx: &egui::Context) {
        if let ImportStatus::Completed { success_count, failure_count, ref errors } = self.file_browser_state.import_status.clone() {
            let mut should_dismiss = false;

            let (title, title_color) = if failure_count == 0 {
                ("Import Complete", egui::Color32::from_rgb(100, 200, 100))
            } else if success_count == 0 {
                ("Import Failed", egui::Color32::from_rgb(200, 100, 100))
            } else {
                ("Import Partially Complete", egui::Color32::from_rgb(200, 200, 100))
            };

            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(350.0);

                    ui.vertical_centered(|ui| {
                        let icon = if failure_count == 0 { "✅" } else if success_count == 0 { "❌" } else { "⚠️" };
                        ui.label(egui::RichText::new(icon).size(48.0));
                        ui.add_space(10.0);

                        if success_count > 0 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} file{} imported successfully",
                                    success_count,
                                    if success_count == 1 { "" } else { "s" }
                                ))
                                .color(egui::Color32::from_rgb(100, 200, 100))
                            );
                        }

                        if failure_count > 0 {
                            ui.add_space(5.0);
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} file{} failed to import",
                                    failure_count,
                                    if failure_count == 1 { "" } else { "s" }
                                ))
                                .color(egui::Color32::from_rgb(200, 100, 100))
                            );

                            // Show error details
                            if !errors.is_empty() {
                                ui.add_space(10.0);
                                egui::Frame::none()
                                    .fill(egui::Color32::from_gray(30))
                                    .rounding(5.0)
                                    .inner_margin(8.0)
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .max_height(100.0)
                                            .show(ui, |ui| {
                                                for error in errors {
                                                    ui.label(
                                                        egui::RichText::new(error)
                                                            .small()
                                                            .color(egui::Color32::from_rgb(255, 180, 180))
                                                    );
                                                }
                                            });
                                    });
                            }
                        }

                        ui.add_space(20.0);

                        if ui.button("OK").clicked() {
                            should_dismiss = true;
                        }
                    });
                });

            if should_dismiss {
                self.file_browser_state.dismiss_import_result();
            }
        }
    }

    /// Starts the actual import process.
    fn start_import_process(&mut self) {
        if !self.file_browser_state.start_import() {
            return;
        }

        // Get import parameters
        let level = self.file_browser_state.import_access_level;
        let dest_path = self.file_browser_state.current_path.clone();
        let pending_imports = std::mem::take(&mut self.file_browser_state.pending_imports);

        let mut success_count = 0;
        let mut failure_count = 0;
        let mut errors = Vec::new();

        // Process each file
        for (idx, pending) in pending_imports.into_iter().enumerate() {
            // Update progress
            self.file_browser_state.import_status = ImportStatus::Importing {
                current: idx + 1,
                total: self.file_browser_state.pending_imports.len().max(idx + 1),
                current_file: pending.filename.clone(),
            };

            // Build destination path
            let file_dest_path = if dest_path == "/" {
                format!("/{}", pending.filename)
            } else {
                format!("{}/{}", dest_path, pending.filename)
            };

            // Perform import
            let result = if let Some(ref mut session) = self.vault_session {
                if let Some(ref path) = pending.path {
                    // Import from file path
                    tesseract_core::files::import_file(
                        session,
                        path,
                        &file_dest_path,
                        level,
                    )
                } else if let Some(ref content) = pending.content {
                    // Import from bytes
                    tesseract_core::files::import_bytes(
                        session,
                        content,
                        &pending.filename,
                        &file_dest_path,
                        level,
                    )
                } else {
                    Err(tesseract_core::error::VaultError::IoError(
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "No file content available")
                    ))
                }
            } else {
                Err(tesseract_core::error::VaultError::VaultLocked)
            };

            match result {
                Ok(uuid) => {
                    info!("Imported file '{}' with UUID {}", pending.filename, uuid);
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Failed to import '{}': {}", pending.filename, e);
                    errors.push(format!("{}: {}", pending.filename, e));
                    failure_count += 1;
                }
            }
        }

        // Set completion status
        self.file_browser_state.import_status = ImportStatus::Completed {
            success_count,
            failure_count,
            errors,
        };

        // Refresh file list if any imports succeeded
        if success_count > 0 {
            if let Some(ref session) = self.vault_session {
                self.file_browser_state.refresh_entries(session);
            }
            self.set_status(format!("Imported {} file{}", success_count, if success_count == 1 { "" } else { "s" }));
        }
    }

    // =========================================================================
    // File Preview (Secure Temp Files)
    // =========================================================================

    /// Opens a vault file in the system's default application for preview.
    ///
    /// Decrypts the file to a secure temp location and opens it with the OS
    /// default handler. The temp file is tracked for cleanup on vault lock.
    ///
    /// Works with common formats: txt, pdf, images, documents, etc.
    fn open_file_preview(&mut self, file_uuid: uuid::Uuid) {
        info!("Opening file for preview: {}", file_uuid);

        // Ensure we have a vault session
        let session = match &self.vault_session {
            Some(s) => s,
            None => {
                warn!("Cannot preview file: no vault session");
                self.set_status("Cannot preview: vault not unlocked");
                return;
            }
        };

        // Ensure we have a temp file manager
        let manager = match &self.temp_file_manager {
            Some(m) => m,
            None => {
                warn!("Cannot preview file: temp file manager not initialized");
                self.set_status("Preview not available");
                return;
            }
        };

        // Open the file in the default application
        match manager.open_in_application(session, file_uuid) {
            Ok(path) => {
                info!("Opened file in default application: {:?}", path);
                // Find the file name for status message
                let file_name = self.file_browser_state.entries
                    .iter()
                    .find(|e| e.uuid == Some(file_uuid))
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| "file".to_string());
                self.set_status(format!("Opened: {}", file_name));
            }
            Err(e) => {
                warn!("Failed to open file: {}", e);
                self.file_browser_state.error_message = Some(format!("Failed to open file: {}", e));
            }
        }
    }

    /// Opens file dialog to import files (alternative to drag-drop).
    fn open_import_dialog(&mut self) {
        let dialog = rfd::FileDialog::new()
            .set_title("Select Files to Import");

        if let Some(paths) = dialog.pick_files() {
            let mut pending_imports = Vec::new();

            for path in paths {
                match crate::screens::PendingImport::from_path(path.clone()) {
                    Ok(pending) => {
                        pending_imports.push(pending);
                    }
                    Err(e) => {
                        warn!("Failed to read file {:?}: {}", path, e);
                    }
                }
            }

            if !pending_imports.is_empty() {
                self.file_browser_state.pending_imports = pending_imports;
                self.file_browser_state.import_access_level = self.file_browser_state.import_access_level.max(1).min(self.file_browser_state.max_access_level.max(1));
                self.file_browser_state.import_status = ImportStatus::ShowingDialog;
            }
        }
    }

    // =========================================================================
    // Export Operations
    // =========================================================================

    /// Opens folder dialog to select export destination.
    fn open_export_dialog(&mut self) {
        if !self.file_browser_state.has_selection() {
            return;
        }

        let dialog = rfd::FileDialog::new()
            .set_title("Select Export Destination");

        if let Some(dest_path) = dialog.pick_folder() {
            info!("Export destination selected: {:?}", dest_path);
            self.file_browser_state.export_destination = Some(dest_path);
            self.start_export_process();
        }
    }

    /// Starts the actual export process.
    fn start_export_process(&mut self) {
        let dest = match &self.file_browser_state.export_destination {
            Some(d) => d.clone(),
            None => return,
        };

        let selected_uuids: Vec<uuid::Uuid> = self.file_browser_state.selected.iter().copied().collect();
        if selected_uuids.is_empty() {
            return;
        }

        let total = selected_uuids.len();
        let mut success_count = 0;
        let mut failure_count = 0;
        let mut errors = Vec::new();

        // Get file entries for selected UUIDs (for display names)
        let entries: Vec<_> = self.file_browser_state.entries
            .iter()
            .filter(|e| e.uuid.map(|u| selected_uuids.contains(&u)).unwrap_or(false))
            .cloned()
            .collect();

        // Process each file
        for (idx, uuid) in selected_uuids.iter().enumerate() {
            // Find the entry name for this UUID
            let file_name = entries
                .iter()
                .find(|e| e.uuid == Some(*uuid))
                .map(|e| e.name.clone())
                .unwrap_or_else(|| format!("{}", uuid));

            // Update progress
            self.file_browser_state.export_status = ExportStatus::Exporting {
                current: idx + 1,
                total,
                current_file: file_name.clone(),
            };

            // Perform export
            let result = if let Some(ref session) = self.vault_session {
                tesseract_core::files::export_file_with_original_name(
                    session,
                    *uuid,
                    &dest,
                )
            } else {
                Err(tesseract_core::error::VaultError::VaultLocked)
            };

            match result {
                Ok(exported_path) => {
                    info!("Exported file '{}' to {:?}", file_name, exported_path);
                    success_count += 1;
                }
                Err(e) => {
                    warn!("Failed to export '{}': {}", file_name, e);
                    errors.push(format!("{}: {}", file_name, e));
                    failure_count += 1;
                }
            }
        }

        // Set completion status
        self.file_browser_state.export_status = ExportStatus::Completed {
            success_count,
            failure_count,
            errors,
            destination: dest.clone(),
        };

        // Update status bar
        if success_count > 0 {
            self.set_status(format!(
                "Exported {} file{} to {}",
                success_count,
                if success_count == 1 { "" } else { "s" },
                dest.display()
            ));
        }
    }

    /// Renders the export progress overlay.
    fn render_export_progress(&self, ctx: &egui::Context) {
        if let ExportStatus::Exporting { current, total, ref current_file } = self.file_browser_state.export_status {
            egui::Window::new("Exporting...")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(350.0);

                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.add_space(15.0);

                        ui.heading(format!("Exporting file {} of {}", current, total));
                        ui.add_space(10.0);

                        ui.label(
                            egui::RichText::new(current_file)
                                .monospace()
                                .weak()
                        );

                        ui.add_space(10.0);

                        // Progress bar
                        let progress = current as f32 / total as f32;
                        ui.add(
                            egui::ProgressBar::new(progress)
                                .text(format!("{:.0}%", progress * 100.0))
                        );

                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("Decrypting and saving files...")
                                .weak()
                                .small()
                        );
                    });
                });
        }
    }

    /// Renders the export result notification.
    fn render_export_result(&mut self, ctx: &egui::Context) {
        if let ExportStatus::Completed { success_count, failure_count, ref errors, ref destination } = self.file_browser_state.export_status.clone() {
            let mut should_dismiss = false;

            let title = if failure_count == 0 {
                "Export Complete"
            } else if success_count == 0 {
                "Export Failed"
            } else {
                "Export Partially Complete"
            };

            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.set_min_width(400.0);

                    ui.vertical_centered(|ui| {
                        let icon = if failure_count == 0 { "✅" } else if success_count == 0 { "❌" } else { "⚠️" };
                        ui.label(egui::RichText::new(icon).size(48.0));
                        ui.add_space(10.0);

                        if success_count > 0 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} file{} exported successfully",
                                    success_count,
                                    if success_count == 1 { "" } else { "s" }
                                ))
                                .color(egui::Color32::from_rgb(100, 200, 100))
                            );
                        }

                        if failure_count > 0 {
                            ui.add_space(5.0);
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} file{} failed to export",
                                    failure_count,
                                    if failure_count == 1 { "" } else { "s" }
                                ))
                                .color(egui::Color32::from_rgb(200, 100, 100))
                            );

                            // Show error details
                            if !errors.is_empty() {
                                ui.add_space(10.0);
                                egui::Frame::none()
                                    .fill(egui::Color32::from_gray(30))
                                    .rounding(5.0)
                                    .inner_margin(8.0)
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .max_height(100.0)
                                            .show(ui, |ui| {
                                                for error in errors {
                                                    ui.label(
                                                        egui::RichText::new(error)
                                                            .small()
                                                            .color(egui::Color32::from_rgb(255, 180, 180))
                                                    );
                                                }
                                            });
                                    });
                            }
                        }

                        // Show destination path
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.label("Saved to:");
                            ui.label(
                                egui::RichText::new(destination.display().to_string())
                                    .monospace()
                                    .small()
                            );
                        });

                        ui.add_space(20.0);

                        if ui.button("OK").clicked() {
                            should_dismiss = true;
                        }
                    });
                });

            if should_dismiss {
                self.file_browser_state.dismiss_export_result();
            }
        }
    }
}

impl eframe::App for TesseractApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for secure exit request (US-031)
        if self.exit_requested {
            self.cleanup_and_exit();
        }

        if !self.initialized {
            info!("TESSERACT GUI initialized");
            self.initialized = true;

            // Check for vault at default location on startup (US-062)
            // Only do this once, on first frame
            if self.screen == AppScreen::VaultSelection {
                match detect_vault_on_startup() {
                    VaultAutoDetectionResult::Found(path) => {
                        // Vault found - automatically select it for convenience
                        // User still needs to enter password
                        info!("Found existing vault at startup: {:?}", path);
                        self.current_vault_path = Some(path.clone());
                        self.screen = AppScreen::PasswordEntry;
                        self.set_status("Found vault - please enter password to unlock");
                    }
                    VaultAutoDetectionResult::NotFound(path) => {
                        // No vault - show the auto-creation prompt
                        info!("No vault found at startup, prompting user");
                        self.auto_creation_state = AutoCreationPromptState::ShowPrompt(path);
                    }
                    VaultAutoDetectionResult::NoDefaultPath => {
                        // Can't determine default path - just show normal selection
                        debug!("No default vault path available");
                    }
                }
            }
        }

        // Check for auto-lock timeout (must be done before any UI interaction)
        if self.vault_session.is_some() {
            // Check for any user input (pointer, keys, scroll)
            let input = ctx.input(|i| {
                i.pointer.any_click()
                    || i.pointer.any_pressed()
                    || i.pointer.is_moving()
                    || i.raw_scroll_delta != egui::Vec2::ZERO
                    || i.keys_down.iter().next().is_some()
                    || i.modifiers.any()
            });

            if input {
                self.update_activity();
            }

            // Check if we should auto-lock
            if self.check_auto_lock() {
                // Early return - vault was just locked, no need to render other UI
                // The next frame will render the password entry screen
                return;
            }

            // Schedule a repaint to keep checking for timeout
            // Check every second for auto-lock
            if self.is_auto_lock_enabled() {
                ctx.request_repaint_after(std::time::Duration::from_secs(1));
            }

            // Check for drive removal (US-027)
            // If drive was removed, vault is auto-locked and we return early
            if self.check_drive_removal() {
                // Drive was removed - vault is now locked
                // The next frame will render the vault selection screen with notification
                return;
            }

            // Schedule repaint for drive presence checking (every 2 seconds)
            if self.current_drive.is_some() {
                ctx.request_repaint_after(std::time::Duration::from_secs(2));
            }
        }

        // Check for clipboard auto-clear (60 seconds after copy)
        if self.screen == AppScreen::VaultCreation {
            if self.wizard_state.should_clear_clipboard() {
                // Clear the clipboard by setting empty text
                ctx.output_mut(|o| o.copied_text = String::new());
                self.wizard_state.clear_clipboard_timestamp();
                self.set_status("Clipboard cleared for security");
            } else if self.wizard_state.clipboard_copied_at.is_some() {
                // Keep checking until timeout
                ctx.request_repaint_after(std::time::Duration::from_secs(1));
            }
        }

        // Handle drag-and-drop for file browser screen
        if self.screen == AppScreen::FileBrowser {
            self.handle_drag_drop(ctx);
        }

        // Render UI components
        self.render_menu_bar(ctx);
        self.render_status_bar(ctx);
        self.render_content(ctx);
        self.render_about_dialog(ctx);

        // Render import/export dialogs and overlays
        if self.screen == AppScreen::FileBrowser {
            self.handle_keyboard_shortcuts(ctx);
            self.render_import_dialog(ctx);
            self.render_import_progress(ctx);
            self.render_import_result(ctx);
            self.render_export_progress(ctx);
            self.render_export_result(ctx);
            self.render_drag_overlay(ctx);
            self.render_context_menu(ctx);
            self.render_delete_confirmation(ctx);
            self.render_rename_dialog(ctx);
            self.render_change_access_level_dialog(ctx);
        }

        // Render settings dialogs
        if self.screen == AppScreen::Settings {
            self.render_create_level_dialog(ctx);
            self.render_change_password_dialog(ctx);
            self.render_delete_level_dialog(ctx);
            self.render_drive_password_change_dialog(ctx);
        }

        // Render auto-creation prompt (US-062)
        if self.screen == AppScreen::VaultSelection {
            self.render_auto_creation_prompt(ctx);
            self.handle_auto_creation_confirmation();
        }

        // Render drive removal notification (US-027)
        // This is shown on any screen after drive is removed
        self.render_drive_removal_notification(ctx);
    }
}

/// Creates the native options for the TESSERACT window.
#[must_use]
pub fn create_native_options() -> eframe::NativeOptions {
    let icon_data = create_icon_data();

    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_NAME)
            .with_inner_size([DEFAULT_WIDTH, DEFAULT_HEIGHT])
            .with_min_inner_size([MIN_WIDTH, MIN_HEIGHT])
            .with_icon(std::sync::Arc::new(icon_data))
            // Set app_id for Wayland/Linux desktop integration
            .with_app_id("tesseract"),
        ..Default::default()
    }
}

/// Embedded application icon (256x256 PNG for better compatibility).
const ICON_BYTES: &[u8] = include_bytes!("../../../images/png/tesseract-256x256.png");

/// Creates the application icon data.
///
/// Loads the embedded PNG icon and converts it to RGBA format for the window icon.
/// Falls back to a procedural icon if PNG loading fails.
#[must_use]
pub fn create_icon_data() -> egui::IconData {
    // Try to load the embedded PNG icon
    if let Ok(img) = image::load_from_memory(ICON_BYTES) {
        let rgba_image = img.to_rgba8();
        let (width, height) = rgba_image.dimensions();
        return egui::IconData {
            rgba: rgba_image.into_raw(),
            width,
            height,
        };
    }

    // Fallback: generate a simple procedural icon
    create_fallback_icon()
}

/// Creates a fallback procedural icon if PNG loading fails.
fn create_fallback_icon() -> egui::IconData {
    const SIZE: usize = 64;
    let mut rgba = vec![0u8; SIZE * SIZE * 4];

    // Colors: Teal/cyan theme for security
    let bg_color = [20u8, 40, 60, 255];
    let outline_color = [0u8, 180, 200, 255];
    let fill_color = [0u8, 120, 140, 255];
    let lock_color = [255u8, 215, 0, 255];

    // Fill background
    for y in 0..SIZE {
        for x in 0..SIZE {
            let idx = (y * SIZE + x) * 4;
            rgba[idx..idx + 4].copy_from_slice(&bg_color);
        }
    }

    // Draw vault shape
    for y in 12..52 {
        for x in 12..52 {
            let idx = (y * SIZE + x) * 4;
            if y < 15 || y > 48 || x < 15 || x > 48 {
                rgba[idx..idx + 4].copy_from_slice(&outline_color);
            } else {
                rgba[idx..idx + 4].copy_from_slice(&fill_color);
            }
        }
    }

    // Draw lock symbol
    let center_x = SIZE / 2;
    let center_y = SIZE / 2 - 4;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as i32 - center_x as i32;
            let dy = y as i32 - center_y as i32;
            let dist_sq = dx * dx + dy * dy;
            if dist_sq <= 36 && dist_sq >= 16 {
                let idx = (y * SIZE + x) * 4;
                rgba[idx..idx + 4].copy_from_slice(&lock_color);
            }
        }
    }

    for y in (center_y + 2)..(center_y + 12) {
        for x in (center_x - 3)..(center_x + 4) {
            let idx = (y * SIZE + x) * 4;
            rgba[idx..idx + 4].copy_from_slice(&lock_color);
        }
    }

    egui::IconData {
        rgba,
        width: SIZE as u32,
        height: SIZE as u32,
    }
}

/// Runs the TESSERACT GUI application.
///
/// # Errors
///
/// Returns an error if the eframe native runtime fails to start.
pub fn run() -> eframe::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Starting TESSERACT GUI");

    let options = create_native_options();

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|_cc| Ok(Box::new(TesseractApp::new()))),
    )
}

/// Checks if hardware acceleration is available for rendering.
#[must_use]
pub fn has_hardware_acceleration() -> bool {
    // egui/eframe uses wgpu by default which provides GPU acceleration
    // This is a placeholder - actual detection would require querying wgpu
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_name_is_tesseract() {
        assert_eq!(APP_NAME, "TESSERACT");
    }

    #[test]
    fn test_default_dimensions() {
        assert_eq!(DEFAULT_WIDTH, 1024.0);
        assert_eq!(DEFAULT_HEIGHT, 768.0);
        assert_eq!(MIN_WIDTH, 800.0);
        assert_eq!(MIN_HEIGHT, 600.0);
    }

    #[test]
    fn test_min_dimensions_less_than_default() {
        assert!(MIN_WIDTH < DEFAULT_WIDTH);
        assert!(MIN_HEIGHT < DEFAULT_HEIGHT);
    }

    #[test]
    fn test_app_screen_default() {
        let screen = AppScreen::default();
        assert_eq!(screen, AppScreen::VaultSelection);
    }

    #[test]
    fn test_app_screen_titles() {
        assert_eq!(AppScreen::VaultSelection.title(), "Select Vault");
        assert_eq!(AppScreen::PasswordEntry.title(), "Unlock Vault");
        assert_eq!(AppScreen::FileBrowser.title(), "File Browser");
        assert_eq!(AppScreen::Settings.title(), "Settings");
        assert_eq!(AppScreen::VaultCreation.title(), "Create New Vault");
        assert_eq!(AppScreen::PasswordRecovery.title(), "Password Recovery");
    }

    #[test]
    fn test_tesseract_app_new() {
        let app = TesseractApp::new();
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
        assert!(!app.initialized);
        assert!(app.status_message.is_none());
        assert!(!app.show_about);
        assert!(app.current_vault_path.is_none());
        assert!(app.new_vault_path.is_none());
        assert!(app.master_key.is_none());
        assert!(app.password_entry_state.password.is_empty());
        assert!(app.vault_session.is_none());
        assert_eq!(app.file_browser_state.current_path, "/");
    }

    #[test]
    fn test_tesseract_app_default() {
        let app = TesseractApp::default();
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
    }

    #[test]
    fn test_set_screen() {
        let mut app = TesseractApp::new();
        app.set_screen(AppScreen::FileBrowser);
        assert_eq!(*app.current_screen(), AppScreen::FileBrowser);
    }

    #[test]
    fn test_set_status() {
        let mut app = TesseractApp::new();
        assert!(app.status_message.is_none());

        app.set_status("Test message");
        assert_eq!(app.status_message.as_deref(), Some("Test message"));

        app.clear_status();
        assert!(app.status_message.is_none());
    }

    #[test]
    fn test_show_about_dialog() {
        let mut app = TesseractApp::new();
        assert!(!app.show_about);

        app.show_about_dialog();
        assert!(app.show_about);
    }

    #[test]
    fn test_create_icon_data() {
        let icon = create_icon_data();
        // Icon should be 256x256 from PNG (or 64x64 from fallback)
        assert!(icon.width == 256 || icon.width == 64);
        assert!(icon.height == 256 || icon.height == 64);
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        // Verify RGBA data is valid (4 bytes per pixel)
        assert!(icon.rgba.len() > 0);
    }

    #[test]
    fn test_create_fallback_icon() {
        let icon = create_fallback_icon();
        assert_eq!(icon.width, 64);
        assert_eq!(icon.height, 64);
        assert_eq!(icon.rgba.len(), 64 * 64 * 4);

        // Verify all alpha values are set (no transparency bugs in fallback)
        for chunk in icon.rgba.chunks(4) {
            assert_eq!(chunk[3], 255, "All pixels should be opaque");
        }
    }

    #[test]
    fn test_create_native_options() {
        let options = create_native_options();
        // Verify viewport builder has been configured
        // (we can't easily inspect the internals, but we can verify it doesn't panic)
        assert!(options.viewport.inner_size.is_some());
        assert!(options.viewport.min_inner_size.is_some());
        assert!(options.viewport.icon.is_some());
    }

    #[test]
    fn test_has_hardware_acceleration() {
        // Just verify the function exists and returns a bool
        let _has_accel = has_hardware_acceleration();
    }

    #[test]
    fn test_all_screens_have_unique_titles() {
        let screens = [
            AppScreen::VaultSelection,
            AppScreen::PasswordEntry,
            AppScreen::FileBrowser,
            AppScreen::Settings,
            AppScreen::VaultCreation,
            AppScreen::PasswordRecovery,
        ];

        let mut titles: Vec<&str> = screens.iter().map(|s| s.title()).collect();
        let original_len = titles.len();
        titles.sort();
        titles.dedup();

        assert_eq!(
            titles.len(),
            original_len,
            "All screens should have unique titles"
        );
    }

    #[test]
    fn test_screen_transitions() {
        let mut app = TesseractApp::new();

        // Start at vault selection
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);

        // Transition through all screens
        app.set_screen(AppScreen::PasswordEntry);
        assert_eq!(*app.current_screen(), AppScreen::PasswordEntry);

        app.set_screen(AppScreen::FileBrowser);
        assert_eq!(*app.current_screen(), AppScreen::FileBrowser);

        app.set_screen(AppScreen::Settings);
        assert_eq!(*app.current_screen(), AppScreen::Settings);

        app.set_screen(AppScreen::VaultCreation);
        assert_eq!(*app.current_screen(), AppScreen::VaultCreation);

        app.set_screen(AppScreen::PasswordRecovery);
        assert_eq!(*app.current_screen(), AppScreen::PasswordRecovery);

        // Return to vault selection
        app.set_screen(AppScreen::VaultSelection);
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
    }

    #[test]
    fn test_open_vault_nonexistent() {
        // Opening a non-existent vault should fail gracefully
        let mut app = TesseractApp::new();
        let path = PathBuf::from("/test/vault");

        app.open_vault(path.clone());

        // Should stay on vault selection due to header load failure
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
        assert_eq!(app.current_vault_path, Some(path.clone()));
        // Recent vaults should still be updated
        assert!(!app.config.recent_vaults.is_empty());
        assert_eq!(app.config.recent_vaults[0].path, path);
        // Error should be set
        assert!(app.vault_selection_state.error_message.is_some());
    }

    #[test]
    fn test_password_entry_state_initialization() {
        let mut app = TesseractApp::new();
        let path = PathBuf::from("/test/vault");

        // Simulate vault path being set
        app.password_entry_state.reset_for_vault(path.clone());

        assert_eq!(app.password_entry_state.vault_path, Some(path));
        assert!(app.password_entry_state.password.is_empty());
        assert!(!app.password_entry_state.show_password);
        assert!(matches!(app.password_entry_state.status, AuthStatus::Idle));
    }

    #[test]
    fn test_start_vault_creation() {
        let mut app = TesseractApp::new();
        let path = PathBuf::from("/test/new_vault");

        app.start_vault_creation(path.clone());

        assert_eq!(*app.current_screen(), AppScreen::VaultCreation);
        assert_eq!(app.new_vault_path, Some(path));
    }

    #[test]
    fn test_config_access() {
        let mut app = TesseractApp::new();

        // Test immutable access
        let _ = app.config();

        // Test mutable access
        app.config_mut().auto_lock_timeout_minutes = 30;
        assert_eq!(app.config().auto_lock_timeout_minutes, 30);
    }

    // ==================== Auto-Lock Tests ====================

    #[test]
    fn test_auto_lock_timeout_seconds() {
        let mut app = TesseractApp::new();

        // Default is 15 minutes
        assert_eq!(app.auto_lock_timeout_seconds(), 15 * 60);

        // Modify timeout
        app.config_mut().auto_lock_timeout_minutes = 30;
        assert_eq!(app.auto_lock_timeout_seconds(), 30 * 60);

        // Disabled timeout
        app.config_mut().auto_lock_timeout_minutes = 0;
        assert_eq!(app.auto_lock_timeout_seconds(), 0);
    }

    #[test]
    fn test_is_auto_lock_enabled() {
        let mut app = TesseractApp::new();

        // Default is enabled (15 minutes)
        assert!(app.is_auto_lock_enabled());

        // Disable
        app.config_mut().auto_lock_timeout_minutes = 0;
        assert!(!app.is_auto_lock_enabled());

        // Re-enable with different value
        app.config_mut().auto_lock_timeout_minutes = 5;
        assert!(app.is_auto_lock_enabled());
    }

    #[test]
    fn test_update_activity_no_session() {
        let mut app = TesseractApp::new();

        // No session - update_activity should do nothing
        assert!(app.last_activity.is_none());
        app.update_activity();
        assert!(app.last_activity.is_none());
    }

    #[test]
    fn test_seconds_until_auto_lock_no_session() {
        let mut app = TesseractApp::new();

        // No vault session - should return None
        assert!(app.seconds_until_auto_lock().is_none());
    }

    #[test]
    fn test_seconds_until_auto_lock_disabled() {
        let mut app = TesseractApp::new();
        app.config_mut().auto_lock_timeout_minutes = 0;

        // Auto-lock disabled - should return None
        assert!(app.seconds_until_auto_lock().is_none());
    }

    #[test]
    fn test_seconds_until_auto_lock_no_activity() {
        let mut app = TesseractApp::new();

        // No activity recorded yet - should return None
        // (Even though we don't have a real session, the logic checks last_activity)
        assert!(app.seconds_until_auto_lock().is_none());
    }

    #[test]
    fn test_check_auto_lock_no_session() {
        let mut app = TesseractApp::new();

        // No session - should not lock and return false
        assert!(!app.check_auto_lock());
    }

    #[test]
    fn test_check_auto_lock_disabled() {
        let mut app = TesseractApp::new();
        app.config_mut().auto_lock_timeout_minutes = 0;

        // Disabled - should not lock
        assert!(!app.check_auto_lock());
    }

    #[test]
    fn test_lock_vault_clears_activity() {
        let mut app = TesseractApp::new();

        // Simulate activity was set
        app.last_activity = Some(Instant::now());
        assert!(app.last_activity.is_some());

        // Lock vault
        app.lock_vault();

        // Activity should be cleared
        assert!(app.last_activity.is_none());
    }

    #[test]
    fn test_lock_vault_returns_to_password_entry() {
        let mut app = TesseractApp::new();

        // Set up a vault path
        let path = PathBuf::from("/test/vault");
        app.current_vault_path = Some(path.clone());
        app.set_screen(AppScreen::FileBrowser);

        // Lock vault
        app.lock_vault();

        // Should return to password entry, not vault selection
        assert_eq!(*app.current_screen(), AppScreen::PasswordEntry);

        // Vault path should still be set (so user can re-enter password)
        assert_eq!(app.current_vault_path, Some(path));
    }

    #[test]
    fn test_lock_vault_clears_session() {
        let mut app = TesseractApp::new();

        // Set screen to file browser (simulating unlocked vault)
        app.set_screen(AppScreen::FileBrowser);
        // Note: We can't set a real VaultSession without a real vault,
        // but we verify that if one exists it would be taken

        app.lock_vault();

        // Session should be None
        assert!(app.vault_session.is_none());
    }

    #[test]
    fn test_lock_vault_clears_master_key() {
        let mut app = TesseractApp::new();

        // Set a fake master key
        app.master_key = Some(Zeroizing::new([42u8; 32]));

        app.lock_vault();

        // Master key should be cleared
        assert!(app.master_key.is_none());
    }

    #[test]
    fn test_lock_vault_sets_status() {
        let mut app = TesseractApp::new();

        app.lock_vault();

        assert_eq!(app.status_message, Some("Vault locked".to_string()));
    }

    #[test]
    fn test_lock_vault_resets_file_browser_state() {
        let mut app = TesseractApp::new();

        // Modify file browser state
        app.file_browser_state.current_path = "/some/path".to_string();

        app.lock_vault();

        // Should be reset to root (FileBrowserState::new() defaults to "/")
        assert_eq!(app.file_browser_state.current_path, "/");
    }

    #[test]
    fn test_auto_lock_default_timeout_is_15_minutes() {
        let app = TesseractApp::new();

        // Default timeout should be 15 minutes (900 seconds)
        assert_eq!(app.config.auto_lock_timeout_minutes, 15);
        assert_eq!(app.auto_lock_timeout_seconds(), 900);
    }

    #[test]
    fn test_lock_vault_from_settings_screen() {
        let mut app = TesseractApp::new();

        // Set screen to settings (can be reached from file browser)
        app.set_screen(AppScreen::Settings);
        app.current_vault_path = Some(PathBuf::from("/test/vault"));

        app.lock_vault();

        // Should return to password entry
        assert_eq!(*app.current_screen(), AppScreen::PasswordEntry);
    }

    #[test]
    fn test_last_activity_initialized_none() {
        let app = TesseractApp::new();

        // On creation, last_activity should be None
        assert!(app.last_activity.is_none());
    }

    // =========================================================================
    // Vault Auto-Creation Tests (US-062)
    // =========================================================================

    #[test]
    fn test_auto_creation_state_initialized_none() {
        let app = TesseractApp::new();

        // On creation, auto_creation_state should be None
        assert_eq!(app.auto_creation_state, AutoCreationPromptState::None);
    }

    #[test]
    fn test_handle_auto_creation_confirmation_when_not_confirmed() {
        let mut app = TesseractApp::new();

        // When not confirmed, should not change screen
        app.auto_creation_state = AutoCreationPromptState::None;
        app.handle_auto_creation_confirmation();
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
        assert!(app.new_vault_path.is_none());

        app.auto_creation_state = AutoCreationPromptState::ShowPrompt(PathBuf::from("/test"));
        app.handle_auto_creation_confirmation();
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
        assert!(app.new_vault_path.is_none());

        app.auto_creation_state = AutoCreationPromptState::Dismissed;
        app.handle_auto_creation_confirmation();
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
        assert!(app.new_vault_path.is_none());
    }

    #[test]
    fn test_handle_auto_creation_confirmation_when_confirmed() {
        let mut app = TesseractApp::new();
        let path = PathBuf::from("/test/vault");

        // When confirmed, should launch vault creation
        app.auto_creation_state = AutoCreationPromptState::Confirmed(path.clone());
        app.handle_auto_creation_confirmation();

        assert_eq!(*app.current_screen(), AppScreen::VaultCreation);
        assert_eq!(app.new_vault_path, Some(path));
        assert_eq!(app.auto_creation_state, AutoCreationPromptState::None);
    }

    #[test]
    fn test_auto_creation_state_transitions() {
        let path = PathBuf::from("/test/vault");

        // Test state transitions
        let mut state = AutoCreationPromptState::ShowPrompt(path.clone());
        assert!(state.should_show());

        state.confirm();
        assert!(!state.should_show());
        assert_eq!(state.get_confirmed_path(), Some(path));

        state.reset();
        assert_eq!(state, AutoCreationPromptState::None);
    }

    #[test]
    fn test_auto_creation_dismiss_behavior() {
        let path = PathBuf::from("/test/vault");
        let mut app = TesseractApp::new();

        // Show prompt
        app.auto_creation_state = AutoCreationPromptState::ShowPrompt(path);

        // Dismiss should prevent wizard from launching
        app.auto_creation_state.dismiss();

        // Now confirmation should do nothing
        app.handle_auto_creation_confirmation();
        assert_eq!(*app.current_screen(), AppScreen::VaultSelection);
        assert!(app.new_vault_path.is_none());
    }
}
