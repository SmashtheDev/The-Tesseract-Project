//! Secure temporary file management for file preview.
//!
//! This module provides secure temporary file handling for previewing encrypted
//! vault files in external applications. Files are decrypted to a secure temp
//! directory, opened with the OS default application, and securely deleted
//! when no longer needed.
//!
//! # Security Features
//!
//! - Files are created in a dedicated secure temp directory
//! - All temp files are tracked for cleanup
//! - Secure deletion: files are overwritten with random data before deletion
//! - Automatic cleanup on vault lock or manager drop
//! - Works with common formats: txt, pdf, images, documents
//!
//! # Examples
//!
//! ```ignore
//! use tesseract_core::tempfile::TempFileManager;
//! use tesseract_core::session::open_vault;
//!
//! let session = open_vault("/vault", b"password", None)?;
//! let mut temp_manager = TempFileManager::new()?;
//!
//! // Open a file in the default application
//! temp_manager.open_in_application(&session, file_uuid)?;
//!
//! // Files are automatically cleaned up when temp_manager is dropped
//! // or when cleanup_all() is called
//! temp_manager.cleanup_all();
//! ```

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::error::VaultError;
use crate::files::export_to_bytes;
use crate::session::VaultSession;

// ============================================================================
// Constants
// ============================================================================

/// Size of random data blocks used for secure overwriting.
pub const OVERWRITE_BLOCK_SIZE: usize = 4096;

/// Number of overwrite passes for secure deletion.
pub const OVERWRITE_PASSES: usize = 3;

/// Subdirectory name for temp files.
pub const TEMP_SUBDIR: &str = "tesseract_temp";

// ============================================================================
// TempFile Types
// ============================================================================

/// Information about a tracked temporary file.
#[derive(Debug, Clone)]
pub struct TempFileInfo {
    /// Path to the temporary file.
    pub path: PathBuf,
    /// Original file UUID from the vault.
    pub file_uuid: Uuid,
    /// Original filename from vault metadata.
    pub original_name: String,
    /// File size in bytes.
    pub size: u64,
    /// Timestamp when the file was created.
    pub created_at: std::time::Instant,
}

/// Status of a temporary file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TempFileStatus {
    /// File is active and may be in use by an application.
    Active,
    /// File is being deleted.
    Deleting,
    /// File has been securely deleted.
    Deleted,
}

/// Error type for temporary file operations.
#[derive(Debug)]
pub enum TempFileError {
    /// Failed to create temp directory.
    CreateDirFailed(std::io::Error),
    /// Failed to write temp file.
    WriteFailed(std::io::Error),
    /// Failed to read temp file for overwriting.
    ReadFailed(std::io::Error),
    /// Failed to delete temp file.
    DeleteFailed(std::io::Error),
    /// Failed to open file with system application.
    OpenFailed(std::io::Error),
    /// Vault operation error.
    VaultError(VaultError),
    /// Random data generation failed.
    RandomFailed,
}

impl std::fmt::Display for TempFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TempFileError::CreateDirFailed(e) => write!(f, "Failed to create temp directory: {}", e),
            TempFileError::WriteFailed(e) => write!(f, "Failed to write temp file: {}", e),
            TempFileError::ReadFailed(e) => write!(f, "Failed to read temp file: {}", e),
            TempFileError::DeleteFailed(e) => write!(f, "Failed to delete temp file: {}", e),
            TempFileError::OpenFailed(e) => write!(f, "Failed to open file with application: {}", e),
            TempFileError::VaultError(e) => write!(f, "Vault error: {}", e),
            TempFileError::RandomFailed => write!(f, "Failed to generate random data"),
        }
    }
}

impl std::error::Error for TempFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TempFileError::CreateDirFailed(e) |
            TempFileError::WriteFailed(e) |
            TempFileError::ReadFailed(e) |
            TempFileError::DeleteFailed(e) |
            TempFileError::OpenFailed(e) => Some(e),
            TempFileError::VaultError(e) => Some(e),
            TempFileError::RandomFailed => None,
        }
    }
}

impl From<VaultError> for TempFileError {
    fn from(e: VaultError) -> Self {
        TempFileError::VaultError(e)
    }
}

// ============================================================================
// TempFileManager
// ============================================================================

/// Manager for secure temporary file operations.
///
/// Tracks all temporary files created for preview and ensures they are
/// securely deleted when no longer needed. The manager creates a dedicated
/// temp directory and handles cleanup on drop.
#[derive(Debug)]
pub struct TempFileManager {
    /// Path to the temp directory.
    temp_dir: PathBuf,
    /// Tracked temporary files by UUID.
    files: Arc<Mutex<HashMap<Uuid, TempFileInfo>>>,
}

impl TempFileManager {
    /// Creates a new temp file manager.
    ///
    /// Creates a dedicated temp directory for storing preview files.
    ///
    /// # Errors
    ///
    /// Returns `TempFileError::CreateDirFailed` if the temp directory cannot be created.
    pub fn new() -> Result<Self, TempFileError> {
        let temp_dir = std::env::temp_dir().join(TEMP_SUBDIR);

        // Create temp directory if it doesn't exist
        if !temp_dir.exists() {
            fs::create_dir_all(&temp_dir).map_err(TempFileError::CreateDirFailed)?;
        }

        Ok(Self {
            temp_dir,
            files: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Creates a temp file manager with a custom temp directory.
    ///
    /// # Arguments
    ///
    /// * `temp_dir` - Path to the temp directory to use
    ///
    /// # Errors
    ///
    /// Returns `TempFileError::CreateDirFailed` if the directory cannot be created.
    pub fn with_temp_dir<P: AsRef<Path>>(temp_dir: P) -> Result<Self, TempFileError> {
        let temp_dir = temp_dir.as_ref().to_path_buf();

        if !temp_dir.exists() {
            fs::create_dir_all(&temp_dir).map_err(TempFileError::CreateDirFailed)?;
        }

        Ok(Self {
            temp_dir,
            files: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Returns the temp directory path.
    #[must_use]
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Returns the number of tracked temp files.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.lock().unwrap().len()
    }

    /// Checks if a file UUID has an active temp file.
    #[must_use]
    pub fn has_temp_file(&self, file_uuid: &Uuid) -> bool {
        let files = self.files.lock().unwrap();
        if let Some(info) = files.get(file_uuid) {
            info.path.exists()
        } else {
            false
        }
    }

    /// Gets info about a tracked temp file.
    #[must_use]
    pub fn get_temp_file(&self, file_uuid: &Uuid) -> Option<TempFileInfo> {
        self.files.lock().unwrap().get(file_uuid).cloned()
    }

    /// Decrypts a file from the vault to a temporary file.
    ///
    /// Creates a temp file with the original filename and returns its path.
    /// The temp file is tracked for cleanup.
    ///
    /// # Arguments
    ///
    /// * `session` - Active vault session
    /// * `file_uuid` - UUID of the file to decrypt
    ///
    /// # Returns
    ///
    /// Path to the created temp file.
    ///
    /// # Errors
    ///
    /// * `TempFileError::VaultError` - Failed to export file from vault
    /// * `TempFileError::WriteFailed` - Failed to write temp file
    pub fn create_temp_file(
        &self,
        session: &VaultSession,
        file_uuid: Uuid,
    ) -> Result<PathBuf, TempFileError> {
        // Export file from vault to memory
        let (content, metadata) = export_to_bytes(session, file_uuid)?;

        // Generate unique temp file name with original extension
        let original_name = &metadata.plaintext.name;
        let temp_name = format!("{}_{}", file_uuid, original_name);
        let temp_path = self.temp_dir.join(&temp_name);

        // Write content to temp file
        let mut file = File::create(&temp_path).map_err(TempFileError::WriteFailed)?;
        file.write_all(&content).map_err(TempFileError::WriteFailed)?;
        file.sync_all().map_err(TempFileError::WriteFailed)?;

        // Track the temp file
        let info = TempFileInfo {
            path: temp_path.clone(),
            file_uuid,
            original_name: original_name.clone(),
            size: content.len() as u64,
            created_at: std::time::Instant::now(),
        };

        self.files.lock().unwrap().insert(file_uuid, info);

        Ok(temp_path)
    }

    /// Opens a vault file in the system's default application.
    ///
    /// Decrypts the file to a temp location and opens it with the OS default
    /// handler for that file type. The temp file is tracked for cleanup.
    ///
    /// # Arguments
    ///
    /// * `session` - Active vault session
    /// * `file_uuid` - UUID of the file to open
    ///
    /// # Returns
    ///
    /// Path to the temp file that was opened.
    ///
    /// # Errors
    ///
    /// * `TempFileError::VaultError` - Failed to export file from vault
    /// * `TempFileError::WriteFailed` - Failed to write temp file
    /// * `TempFileError::OpenFailed` - Failed to launch default application
    ///
    /// # Platform Behavior
    ///
    /// - **Windows**: Uses `cmd /c start`
    /// - **macOS**: Uses `open`
    /// - **Linux**: Uses `xdg-open`
    pub fn open_in_application(
        &self,
        session: &VaultSession,
        file_uuid: Uuid,
    ) -> Result<PathBuf, TempFileError> {
        // Create temp file (or reuse if already exists)
        let temp_path = if self.has_temp_file(&file_uuid) {
            self.get_temp_file(&file_uuid).unwrap().path
        } else {
            self.create_temp_file(session, file_uuid)?
        };

        // Open with system default application
        open_with_system(&temp_path)?;

        Ok(temp_path)
    }

    /// Securely deletes a temporary file.
    ///
    /// Overwrites the file content with random data before deletion to prevent
    /// recovery of plaintext data.
    ///
    /// # Arguments
    ///
    /// * `file_uuid` - UUID of the file to delete
    ///
    /// # Errors
    ///
    /// * `TempFileError::ReadFailed` - Failed to read file for size
    /// * `TempFileError::WriteFailed` - Failed to overwrite file
    /// * `TempFileError::DeleteFailed` - Failed to delete file
    pub fn secure_delete(&self, file_uuid: &Uuid) -> Result<(), TempFileError> {
        let info = {
            let mut files = self.files.lock().unwrap();
            files.remove(file_uuid)
        };

        if let Some(info) = info {
            if info.path.exists() {
                secure_delete_file(&info.path)?;
            }
        }

        Ok(())
    }

    /// Securely deletes all tracked temporary files.
    ///
    /// Should be called when locking the vault to ensure no plaintext remains.
    pub fn cleanup_all(&self) {
        let files: Vec<TempFileInfo> = {
            let mut files = self.files.lock().unwrap();
            files.drain().map(|(_, info)| info).collect()
        };

        for info in files {
            if info.path.exists() {
                let _ = secure_delete_file(&info.path);
            }
        }

        // Try to remove the temp directory if empty
        let _ = fs::remove_dir(&self.temp_dir);
    }

    /// Returns list of all tracked temp files.
    #[must_use]
    pub fn list_files(&self) -> Vec<TempFileInfo> {
        self.files.lock().unwrap().values().cloned().collect()
    }
}

impl Drop for TempFileManager {
    fn drop(&mut self) {
        // Cleanup all temp files on drop
        self.cleanup_all();
    }
}

// ============================================================================
// Secure Deletion
// ============================================================================

/// Securely deletes a file by overwriting with random data before deletion.
///
/// Performs multiple overwrite passes with random data to prevent recovery
/// of the original file content.
///
/// # Arguments
///
/// * `path` - Path to the file to securely delete
///
/// # Errors
///
/// * `TempFileError::ReadFailed` - Failed to get file metadata
/// * `TempFileError::WriteFailed` - Failed to overwrite file
/// * `TempFileError::DeleteFailed` - Failed to delete file
/// * `TempFileError::RandomFailed` - Failed to generate random data
pub fn secure_delete_file<P: AsRef<Path>>(path: P) -> Result<(), TempFileError> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(());
    }

    // Get file size
    let metadata = fs::metadata(path).map_err(TempFileError::ReadFailed)?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        // Empty file, just delete
        fs::remove_file(path).map_err(TempFileError::DeleteFailed)?;
        return Ok(());
    }

    // Perform multiple overwrite passes
    for _ in 0..OVERWRITE_PASSES {
        overwrite_file_with_random(path, file_size)?;
    }

    // Truncate file to zero length
    {
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(TempFileError::WriteFailed)?;
        file.sync_all().map_err(TempFileError::WriteFailed)?;
    }

    // Finally delete the file
    fs::remove_file(path).map_err(TempFileError::DeleteFailed)?;

    Ok(())
}

/// Overwrites a file with random data.
fn overwrite_file_with_random<P: AsRef<Path>>(path: P, size: usize) -> Result<(), TempFileError> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(TempFileError::WriteFailed)?;

    let mut buffer = vec![0u8; OVERWRITE_BLOCK_SIZE];
    let mut remaining = size;

    while remaining > 0 {
        let to_write = std::cmp::min(remaining, OVERWRITE_BLOCK_SIZE);

        // Fill buffer with random data
        getrandom::getrandom(&mut buffer[..to_write]).map_err(|_| TempFileError::RandomFailed)?;

        file.write_all(&buffer[..to_write]).map_err(TempFileError::WriteFailed)?;
        remaining -= to_write;
    }

    file.sync_all().map_err(TempFileError::WriteFailed)?;

    Ok(())
}

// ============================================================================
// System Open
// ============================================================================

/// Opens a file with the system's default application.
///
/// # Arguments
///
/// * `path` - Path to the file to open
///
/// # Errors
///
/// Returns `TempFileError::OpenFailed` if the command fails.
///
/// # Platform Behavior
///
/// - **Windows**: Uses `cmd /c start "" "path"`
/// - **macOS**: Uses `open path`
/// - **Linux**: Uses `xdg-open path`
pub fn open_with_system<P: AsRef<Path>>(path: P) -> Result<(), TempFileError> {
    let path = path.as_ref();

    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/c", "start", "", path.to_str().unwrap_or("")])
            .spawn()
            .map_err(TempFileError::OpenFailed)?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(path)
            .spawn()
            .map_err(TempFileError::OpenFailed)?;
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(TempFileError::OpenFailed)?;
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        return Err(TempFileError::OpenFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unsupported platform for file opening",
        )));
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

    #[test]
    fn test_temp_file_manager_new() {
        let manager = TempFileManager::new();
        assert!(manager.is_ok());

        let manager = manager.unwrap();
        assert!(manager.temp_dir().exists());
        assert_eq!(manager.file_count(), 0);
    }

    #[test]
    fn test_temp_file_manager_with_custom_dir() {
        let dir = tempdir().unwrap();
        let custom_dir = dir.path().join("custom_temp");

        let manager = TempFileManager::with_temp_dir(&custom_dir).unwrap();
        assert!(custom_dir.exists());
        assert_eq!(manager.temp_dir(), custom_dir);
    }

    #[test]
    fn test_secure_delete_file_basic() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_file.txt");

        // Create test file
        let content = b"This is sensitive content that should be securely deleted";
        fs::write(&file_path, content).unwrap();
        assert!(file_path.exists());

        // Secure delete
        secure_delete_file(&file_path).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_secure_delete_file_empty() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("empty_file.txt");

        // Create empty file
        fs::write(&file_path, b"").unwrap();
        assert!(file_path.exists());

        // Secure delete
        secure_delete_file(&file_path).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_secure_delete_file_nonexistent() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("nonexistent.txt");

        // Should not error on non-existent file
        let result = secure_delete_file(&file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_delete_large_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("large_file.bin");

        // Create file larger than OVERWRITE_BLOCK_SIZE
        let size = OVERWRITE_BLOCK_SIZE * 3 + 500;
        let content = vec![0xABu8; size];
        fs::write(&file_path, &content).unwrap();
        assert!(file_path.exists());

        // Secure delete
        secure_delete_file(&file_path).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_temp_file_manager_cleanup_all() {
        let dir = tempdir().unwrap();
        let manager = TempFileManager::with_temp_dir(dir.path().join("tesseract_test")).unwrap();

        // Create some files manually (simulating tracked files)
        let file1 = manager.temp_dir().join("file1.txt");
        let file2 = manager.temp_dir().join("file2.txt");
        fs::write(&file1, b"content 1").unwrap();
        fs::write(&file2, b"content 2").unwrap();

        // Add to tracked files
        {
            let mut files = manager.files.lock().unwrap();
            files.insert(Uuid::new_v4(), TempFileInfo {
                path: file1.clone(),
                file_uuid: Uuid::new_v4(),
                original_name: "file1.txt".to_string(),
                size: 9,
                created_at: std::time::Instant::now(),
            });
            files.insert(Uuid::new_v4(), TempFileInfo {
                path: file2.clone(),
                file_uuid: Uuid::new_v4(),
                original_name: "file2.txt".to_string(),
                size: 9,
                created_at: std::time::Instant::now(),
            });
        }

        assert_eq!(manager.file_count(), 2);

        // Cleanup all
        manager.cleanup_all();

        assert_eq!(manager.file_count(), 0);
        assert!(!file1.exists());
        assert!(!file2.exists());
    }

    #[test]
    fn test_temp_file_manager_drop_cleanup() {
        let dir = tempdir().unwrap();
        let test_file;

        {
            let manager = TempFileManager::with_temp_dir(dir.path().join("tesseract_drop")).unwrap();
            test_file = manager.temp_dir().join("drop_test.txt");
            fs::write(&test_file, b"content").unwrap();

            let mut files = manager.files.lock().unwrap();
            files.insert(Uuid::new_v4(), TempFileInfo {
                path: test_file.clone(),
                file_uuid: Uuid::new_v4(),
                original_name: "drop_test.txt".to_string(),
                size: 7,
                created_at: std::time::Instant::now(),
            });
            // Manager dropped here
        }

        // File should be cleaned up after drop
        assert!(!test_file.exists());
    }

    #[test]
    fn test_temp_file_info() {
        let info = TempFileInfo {
            path: PathBuf::from("/tmp/test.txt"),
            file_uuid: Uuid::new_v4(),
            original_name: "document.pdf".to_string(),
            size: 1024,
            created_at: std::time::Instant::now(),
        };

        assert_eq!(info.original_name, "document.pdf");
        assert_eq!(info.size, 1024);
    }

    #[test]
    fn test_temp_file_status_equality() {
        assert_eq!(TempFileStatus::Active, TempFileStatus::Active);
        assert_eq!(TempFileStatus::Deleting, TempFileStatus::Deleting);
        assert_eq!(TempFileStatus::Deleted, TempFileStatus::Deleted);
        assert_ne!(TempFileStatus::Active, TempFileStatus::Deleted);
    }

    #[test]
    fn test_temp_file_error_display() {
        let err = TempFileError::RandomFailed;
        assert_eq!(format!("{}", err), "Failed to generate random data");

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = TempFileError::CreateDirFailed(io_err);
        assert!(format!("{}", err).contains("Failed to create temp directory"));
    }

    #[test]
    fn test_has_temp_file() {
        let dir = tempdir().unwrap();
        let manager = TempFileManager::with_temp_dir(dir.path().join("has_test")).unwrap();

        let uuid = Uuid::new_v4();
        assert!(!manager.has_temp_file(&uuid));

        // Create file and track it
        let file_path = manager.temp_dir().join("tracked.txt");
        fs::write(&file_path, b"content").unwrap();

        {
            let mut files = manager.files.lock().unwrap();
            files.insert(uuid, TempFileInfo {
                path: file_path,
                file_uuid: uuid,
                original_name: "tracked.txt".to_string(),
                size: 7,
                created_at: std::time::Instant::now(),
            });
        }

        assert!(manager.has_temp_file(&uuid));
    }

    #[test]
    fn test_get_temp_file() {
        let dir = tempdir().unwrap();
        let manager = TempFileManager::with_temp_dir(dir.path().join("get_test")).unwrap();

        let uuid = Uuid::new_v4();
        assert!(manager.get_temp_file(&uuid).is_none());

        // Add tracked file
        let file_path = manager.temp_dir().join("get_tracked.txt");
        {
            let mut files = manager.files.lock().unwrap();
            files.insert(uuid, TempFileInfo {
                path: file_path.clone(),
                file_uuid: uuid,
                original_name: "get_tracked.txt".to_string(),
                size: 100,
                created_at: std::time::Instant::now(),
            });
        }

        let info = manager.get_temp_file(&uuid);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.original_name, "get_tracked.txt");
        assert_eq!(info.size, 100);
    }

    #[test]
    fn test_secure_delete_specific() {
        let dir = tempdir().unwrap();
        let manager = TempFileManager::with_temp_dir(dir.path().join("delete_test")).unwrap();

        let uuid = Uuid::new_v4();
        let file_path = manager.temp_dir().join("to_delete.txt");
        fs::write(&file_path, b"sensitive data").unwrap();

        {
            let mut files = manager.files.lock().unwrap();
            files.insert(uuid, TempFileInfo {
                path: file_path.clone(),
                file_uuid: uuid,
                original_name: "to_delete.txt".to_string(),
                size: 14,
                created_at: std::time::Instant::now(),
            });
        }

        assert!(file_path.exists());
        assert!(manager.has_temp_file(&uuid));

        manager.secure_delete(&uuid).unwrap();

        assert!(!file_path.exists());
        assert!(!manager.has_temp_file(&uuid));
    }

    #[test]
    fn test_list_files() {
        let dir = tempdir().unwrap();
        let manager = TempFileManager::with_temp_dir(dir.path().join("list_test")).unwrap();

        assert!(manager.list_files().is_empty());

        // Add some files
        for i in 0..3 {
            let uuid = Uuid::new_v4();
            let mut files = manager.files.lock().unwrap();
            files.insert(uuid, TempFileInfo {
                path: manager.temp_dir().join(format!("file{}.txt", i)),
                file_uuid: uuid,
                original_name: format!("file{}.txt", i),
                size: 100 * (i + 1) as u64,
                created_at: std::time::Instant::now(),
            });
        }

        let files = manager.list_files();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_overwrite_passes() {
        // Verify constants are reasonable
        assert_eq!(OVERWRITE_PASSES, 3);
        assert_eq!(OVERWRITE_BLOCK_SIZE, 4096);
    }

    // Note: Cannot test open_in_application without a real vault session
    // and file UUID. That would require integration tests.

    // Note: Cannot test create_temp_file without a vault session.
    // That would require integration tests with a real vault.
}
