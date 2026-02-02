//! Portable configuration storage for TESSERACT GUI.
//!
//! Stores user preferences and recent vault history on the same USB drive
//! as the application, enabling portable operation across different computers.
//!
//! # Configuration Location
//!
//! The configuration file is stored relative to the executable:
//! - Windows: `<exe_dir>\.tesseract\config.json`
//! - Linux/macOS: `<exe_dir>/.tesseract/config.json`
//!
//! This allows the configuration to travel with the USB drive.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, error, warn};

/// Configuration file name.
const CONFIG_FILENAME: &str = "config.json";

/// Configuration directory name.
const CONFIG_DIR: &str = ".tesseract";

/// Maximum number of recent vaults to remember.
const MAX_RECENT_VAULTS: usize = 10;

/// A recent vault entry with path and metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentVault {
    /// Path to the vault directory.
    pub path: PathBuf,
    /// Display name (vault directory name or custom name).
    pub name: String,
    /// Unix timestamp of last access.
    pub last_accessed: u64,
}

impl RecentVault {
    /// Creates a new recent vault entry.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unnamed Vault")
            .to_string();

        let last_accessed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            path,
            name,
            last_accessed,
        }
    }

    /// Updates the last accessed timestamp to now.
    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Recently accessed vaults, newest first.
    pub recent_vaults: Vec<RecentVault>,
    /// Preferred drive letter for VFS mounting (Windows only).
    pub preferred_drive_letter: Option<char>,
    /// Auto-lock timeout in minutes (0 = disabled).
    pub auto_lock_timeout_minutes: u32,
    /// Whether to check for removable media.
    pub check_removable_media: bool,
}

impl AppConfig {
    /// Creates a new configuration with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            recent_vaults: Vec::new(),
            preferred_drive_letter: Some('T'),
            auto_lock_timeout_minutes: 15,
            check_removable_media: true,
        }
    }

    /// Adds a vault to the recent list.
    ///
    /// If the vault is already in the list, it's moved to the front
    /// and its timestamp is updated.
    pub fn add_recent_vault(&mut self, path: PathBuf) {
        // Remove existing entry with same path
        self.recent_vaults
            .retain(|v| v.path.canonicalize().ok() != path.canonicalize().ok());

        // Add new entry at the front
        let vault = RecentVault::new(path);
        self.recent_vaults.insert(0, vault);

        // Trim to max size
        self.recent_vaults.truncate(MAX_RECENT_VAULTS);
    }

    /// Removes a vault from the recent list.
    pub fn remove_recent_vault(&mut self, path: &Path) {
        self.recent_vaults
            .retain(|v| v.path.canonicalize().ok() != path.canonicalize().ok());
    }

    /// Clears all recent vaults.
    pub fn clear_recent_vaults(&mut self) {
        self.recent_vaults.clear();
    }

    /// Returns the most recently accessed vault, if any.
    #[must_use]
    pub fn most_recent_vault(&self) -> Option<&RecentVault> {
        self.recent_vaults.first()
    }

    /// Returns recent vaults that still exist on the filesystem.
    #[must_use]
    pub fn valid_recent_vaults(&self) -> Vec<&RecentVault> {
        self.recent_vaults
            .iter()
            .filter(|v| v.path.exists())
            .collect()
    }
}

/// Returns the configuration directory path.
///
/// The configuration is stored relative to the executable for portability.
#[must_use]
pub fn config_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.join(CONFIG_DIR)))
}

/// Returns the configuration file path.
#[must_use]
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join(CONFIG_FILENAME))
}

/// Loads the configuration from disk.
///
/// Returns default configuration if the file doesn't exist or can't be parsed.
#[must_use]
pub fn load_config() -> AppConfig {
    let Some(path) = config_path() else {
        warn!("Could not determine config path, using defaults");
        return AppConfig::new();
    };

    if !path.exists() {
        debug!("Config file not found, using defaults");
        return AppConfig::new();
    }

    match File::open(&path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            match serde_json::from_reader(reader) {
                Ok(config) => {
                    debug!("Loaded configuration from {:?}", path);
                    config
                }
                Err(e) => {
                    error!("Failed to parse config file: {}", e);
                    AppConfig::new()
                }
            }
        }
        Err(e) => {
            error!("Failed to open config file: {}", e);
            AppConfig::new()
        }
    }
}

/// Saves the configuration to disk.
///
/// # Errors
///
/// Returns an error if the configuration cannot be saved.
pub fn save_config(config: &AppConfig) -> Result<(), ConfigError> {
    let dir = config_dir().ok_or(ConfigError::PathNotFound)?;
    let path = dir.join(CONFIG_FILENAME);

    // Create config directory if needed
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| ConfigError::IoError(e.to_string()))?;
        debug!("Created config directory: {:?}", dir);
    }

    // Write config file
    let file = File::create(&path).map_err(|e| ConfigError::IoError(e.to_string()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, config)
        .map_err(|e| ConfigError::SerializationError(e.to_string()))?;

    debug!("Saved configuration to {:?}", path);
    Ok(())
}

/// Configuration-related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Configuration path could not be determined.
    PathNotFound,
    /// I/O error occurred.
    IoError(String),
    /// Serialization/deserialization error.
    SerializationError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotFound => write!(f, "Configuration path not found"),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_recent_vault_new() {
        let path = PathBuf::from("/test/vault");
        let vault = RecentVault::new(path.clone());

        assert_eq!(vault.path, path);
        assert_eq!(vault.name, "vault");
        assert!(vault.last_accessed > 0);
    }

    #[test]
    fn test_recent_vault_touch() {
        let path = PathBuf::from("/test/vault");
        let mut vault = RecentVault::new(path);
        let first_time = vault.last_accessed;

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));
        vault.touch();

        assert!(vault.last_accessed >= first_time);
    }

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();

        assert!(config.recent_vaults.is_empty());
        assert_eq!(config.preferred_drive_letter, None);
        assert_eq!(config.auto_lock_timeout_minutes, 0);
        assert!(!config.check_removable_media);
    }

    #[test]
    fn test_app_config_new() {
        let config = AppConfig::new();

        assert!(config.recent_vaults.is_empty());
        assert_eq!(config.preferred_drive_letter, Some('T'));
        assert_eq!(config.auto_lock_timeout_minutes, 15);
        assert!(config.check_removable_media);
    }

    #[test]
    fn test_add_recent_vault() {
        let mut config = AppConfig::new();
        let path = PathBuf::from("/test/vault1");

        config.add_recent_vault(path.clone());

        assert_eq!(config.recent_vaults.len(), 1);
        assert_eq!(config.recent_vaults[0].path, path);
    }

    #[test]
    fn test_add_recent_vault_moves_to_front() {
        let mut config = AppConfig::new();
        let path1 = PathBuf::from("/test/vault1");
        let path2 = PathBuf::from("/test/vault2");

        config.add_recent_vault(path1.clone());
        config.add_recent_vault(path2.clone());
        config.add_recent_vault(path1.clone()); // Add path1 again

        assert_eq!(config.recent_vaults.len(), 2);
        assert_eq!(config.recent_vaults[0].path, path1);
        assert_eq!(config.recent_vaults[1].path, path2);
    }

    #[test]
    fn test_add_recent_vault_max_size() {
        let mut config = AppConfig::new();

        for i in 0..15 {
            config.add_recent_vault(PathBuf::from(format!("/test/vault{}", i)));
        }

        assert_eq!(config.recent_vaults.len(), MAX_RECENT_VAULTS);
        // Most recent should be at front
        assert_eq!(
            config.recent_vaults[0].path,
            PathBuf::from("/test/vault14")
        );
    }

    #[test]
    fn test_remove_recent_vault() {
        let mut config = AppConfig::new();
        let path1 = PathBuf::from("/test/vault1");
        let path2 = PathBuf::from("/test/vault2");

        config.add_recent_vault(path1.clone());
        config.add_recent_vault(path2.clone());
        config.remove_recent_vault(&path2);

        assert_eq!(config.recent_vaults.len(), 1);
        assert_eq!(config.recent_vaults[0].path, path1);
    }

    #[test]
    fn test_clear_recent_vaults() {
        let mut config = AppConfig::new();
        config.add_recent_vault(PathBuf::from("/test/vault1"));
        config.add_recent_vault(PathBuf::from("/test/vault2"));

        config.clear_recent_vaults();

        assert!(config.recent_vaults.is_empty());
    }

    #[test]
    fn test_most_recent_vault() {
        let mut config = AppConfig::new();

        assert!(config.most_recent_vault().is_none());

        config.add_recent_vault(PathBuf::from("/test/vault1"));
        config.add_recent_vault(PathBuf::from("/test/vault2"));

        let most_recent = config.most_recent_vault().unwrap();
        assert_eq!(most_recent.path, PathBuf::from("/test/vault2"));
    }

    #[test]
    fn test_valid_recent_vaults() {
        let temp_dir = TempDir::new().unwrap();
        let existing_path = temp_dir.path().to_path_buf();
        let nonexistent_path = PathBuf::from("/nonexistent/vault");

        let mut config = AppConfig::new();
        config.add_recent_vault(existing_path.clone());
        config.add_recent_vault(nonexistent_path);

        let valid = config.valid_recent_vaults();

        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].path, existing_path);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let mut config = AppConfig::new();
        config.add_recent_vault(PathBuf::from("/test/vault"));
        config.preferred_drive_letter = Some('X');
        config.auto_lock_timeout_minutes = 30;

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AppConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.recent_vaults.len(), deserialized.recent_vaults.len());
        assert_eq!(config.preferred_drive_letter, deserialized.preferred_drive_letter);
        assert_eq!(config.auto_lock_timeout_minutes, deserialized.auto_lock_timeout_minutes);
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::PathNotFound;
        assert_eq!(format!("{}", err), "Configuration path not found");

        let err = ConfigError::IoError("test".to_string());
        assert_eq!(format!("{}", err), "I/O error: test");

        let err = ConfigError::SerializationError("test".to_string());
        assert_eq!(format!("{}", err), "Serialization error: test");
    }

    #[test]
    fn test_recent_vault_name_extraction() {
        // Path with valid filename
        let vault = RecentVault::new(PathBuf::from("/path/to/MyVault"));
        assert_eq!(vault.name, "MyVault");

        // Root path
        let vault = RecentVault::new(PathBuf::from("/"));
        assert_eq!(vault.name, "Unnamed Vault");
    }

    #[test]
    fn test_recent_vault_equality() {
        let vault1 = RecentVault::new(PathBuf::from("/test/vault"));
        let mut vault2 = RecentVault::new(PathBuf::from("/test/vault"));
        vault2.last_accessed = vault1.last_accessed;

        assert_eq!(vault1, vault2);
    }
}
