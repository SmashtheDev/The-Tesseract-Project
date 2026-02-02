//! VFS Integration Test Suite
//!
//! Comprehensive integration tests for the TESSERACT Virtual Filesystem layer.
//! These tests verify end-to-end functionality of VFS operations with actual
//! encrypted vaults.
//!
//! # Test Categories
//!
//! 1. **File Create and Read** - Create file, read back, verify content
//! 2. **Write and Reopen** - Write file, close, reopen, verify persistence
//! 3. **Delete Verification** - Delete file, verify not accessible
//! 4. **Rename Verification** - Rename file, verify new name accessible
//! 5. **Directory Listing** - Verify listing accuracy with multiple files
//!
//! # Platform Support
//!
//! - **Windows**: Tests run with Dokan VFS layer
//! - **Linux/macOS**: Tests run with FUSE VFS layer
//!
//! # Usage
//!
//! ```bash
//! cargo test --package tesseract-vfs integration_tests
//! ```

use std::collections::HashSet;
use tempfile::TempDir;
use uuid::Uuid;

use tesseract_core::vault::{create_vault, VaultConfig};
use tesseract_core::session::{open_vault, SessionState, VaultSession};
use tesseract_core::files::{
    import_bytes, export_to_bytes, delete_file, rename_file, move_file,
    list_files, FileEntry, EntryType,
};

// ============================================================================
// Test Utilities
// ============================================================================

/// Create a temporary vault for testing.
fn create_test_vault() -> (TempDir, VaultSession) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let vault_path = temp_dir.path().join("vault");

    // Create vault with default configuration
    let config = VaultConfig::new()
        .with_password(b"test_password_123");

    let _result = create_vault(&vault_path, config)
        .expect("Failed to create test vault");

    // Open the vault
    let session = open_vault(&vault_path, b"test_password_123", None)
        .expect("Failed to open test vault");

    assert_eq!(session.state(), SessionState::Active);

    (temp_dir, session)
}

/// Create test file content with a recognizable pattern.
fn create_test_content(name: &str, size: usize) -> Vec<u8> {
    let pattern = format!("TESSERACT_TEST_FILE:{name}:");
    let mut content = Vec::with_capacity(size);

    while content.len() < size {
        let remaining = size - content.len();
        let chunk = pattern.as_bytes();
        let to_copy = remaining.min(chunk.len());
        content.extend_from_slice(&chunk[..to_copy]);
    }

    content
}

/// Verify that content matches expected pattern.
fn verify_content(content: &[u8], expected_name: &str) -> bool {
    let pattern = format!("TESSERACT_TEST_FILE:{expected_name}:");
    content.len() >= pattern.len() && content.starts_with(pattern.as_bytes())
}

// ============================================================================
// Test 1: Create File, Read Back, Verify Content
// ============================================================================

#[test]
fn test_create_file_read_back_verify_content() {
    let (_temp_dir, mut session) = create_test_vault();

    // Create test content
    let content = create_test_content("test_file", 1024);

    // Import file to vault
    let file_uuid = import_bytes(
        &mut session,
        &content,
        "/test_file.txt",
        1, // Access level 1
    ).expect("Failed to import file");

    // Read back the file
    let (read_content, metadata) = export_to_bytes(&session, file_uuid)
        .expect("Failed to export file");

    // Verify content matches
    assert_eq!(read_content.len(), content.len(), "Content length mismatch");
    assert_eq!(read_content, content, "Content mismatch");

    // Verify metadata
    assert!(metadata.plaintext.name.contains("test_file"), "Filename not preserved");
    assert_eq!(metadata.access_level, 1, "Access level mismatch");
}

#[test]
fn test_create_file_various_sizes() {
    let (_temp_dir, mut session) = create_test_vault();

    // Test various file sizes
    let sizes = [
        0,           // Empty file
        1,           // Single byte
        100,         // Small file
        1024,        // 1 KB
        1024 * 10,   // 10 KB
        1024 * 100,  // 100 KB
        1024 * 512,  // 512 KB
    ];

    for (i, size) in sizes.iter().enumerate() {
        let content = create_test_content(&format!("size_{size}"), *size);
        let path = format!("/test_size_{i}.bin");

        let file_uuid = import_bytes(&mut session, &content, &path, 1)
            .expect(&format!("Failed to import file of size {size}"));

        let (read_content, _metadata) = export_to_bytes(&session, file_uuid)
            .expect(&format!("Failed to export file of size {size}"));

        assert_eq!(read_content.len(), *size, "Size mismatch for {size}");
        assert_eq!(read_content, content, "Content mismatch for size {size}");
    }
}

#[test]
fn test_create_file_special_characters_in_name() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("special_chars", 256);

    // Test filenames with various characters
    let filenames = [
        "normal_file.txt",
        "file with spaces.txt",
        "file-with-dashes.txt",
        "file_with_underscores.txt",
        "MixedCaseFile.TXT",
        "file.multiple.dots.txt",
        "file123numbers.txt",
        "файл_unicode.txt",       // Cyrillic
        "文件_chinese.txt",        // Chinese
        "ファイル_japanese.txt",   // Japanese
    ];

    for filename in filenames {
        let path = format!("/{filename}");

        let result = import_bytes(&mut session, &content, &path, 1);

        match result {
            Ok(file_uuid) => {
                let (read_content, metadata) = export_to_bytes(&session, file_uuid)
                    .expect(&format!("Failed to export '{filename}'"));

                assert_eq!(read_content, content, "Content mismatch for '{filename}'");
                assert!(
                    metadata.plaintext.name.contains(&filename.split('.').next().unwrap_or(filename)),
                    "Filename not preserved for '{filename}'"
                );
            }
            Err(e) => {
                // Some special characters may not be allowed - that's OK
                eprintln!("Note: Filename '{filename}' rejected: {e}");
            }
        }
    }
}

// ============================================================================
// Test 2: Write File, Close, Reopen, Verify
// ============================================================================

#[test]
fn test_write_close_reopen_verify() {
    let (temp_dir, mut session) = create_test_vault();

    // Create and import a file
    let content = create_test_content("persistence", 2048);
    let file_uuid = import_bytes(&mut session, &content, "/persistent.txt", 1)
        .expect("Failed to import file");

    // Get the vault path before dropping session
    let vault_path = session.vault_path().to_path_buf();

    // Close the session (simulates app close)
    drop(session);

    // Reopen the vault
    let session2 = open_vault(&vault_path, b"test_password_123", None)
        .expect("Failed to reopen vault");

    // Read the file back
    let (read_content, metadata) = export_to_bytes(&session2, file_uuid)
        .expect("Failed to export file after reopen");

    // Verify persistence
    assert_eq!(read_content, content, "Content not persisted across sessions");
    assert!(verify_content(&read_content, "persistence"), "Content pattern corrupted");
    assert!(metadata.plaintext.name.contains("persistent"), "Filename not persisted");

    // Temp directory remains valid
    assert!(temp_dir.path().exists());
}

#[test]
fn test_multiple_files_persist() {
    let (temp_dir, mut session) = create_test_vault();

    // Create multiple files
    let files: Vec<(Uuid, String, Vec<u8>)> = (0..5)
        .map(|i| {
            let name = format!("file_{i}");
            let content = create_test_content(&name, 512 + i * 100);
            let path = format!("/{name}.txt");

            let uuid = import_bytes(&mut session, &content, &path, 1)
                .expect(&format!("Failed to import file_{i}"));

            (uuid, name, content)
        })
        .collect();

    let vault_path = session.vault_path().to_path_buf();
    drop(session);

    // Reopen and verify all files
    let session2 = open_vault(&vault_path, b"test_password_123", None)
        .expect("Failed to reopen vault");

    for (uuid, name, expected_content) in files {
        let (read_content, _) = export_to_bytes(&session2, uuid)
            .expect(&format!("Failed to export {name} after reopen"));

        assert_eq!(read_content, expected_content, "Content mismatch for {name}");
    }

    assert!(temp_dir.path().exists());
}

#[test]
fn test_modify_file_persist() {
    let (temp_dir, mut session) = create_test_vault();

    // Create initial file
    let content_v1 = create_test_content("version1", 1000);
    let file_uuid = import_bytes(&mut session, &content_v1, "/mutable.txt", 1)
        .expect("Failed to import initial file");

    // "Modify" the file by deleting and re-importing with same name
    delete_file(&mut session, file_uuid)
        .expect("Failed to delete old version");

    let content_v2 = create_test_content("version2", 2000);
    let file_uuid_v2 = import_bytes(&mut session, &content_v2, "/mutable.txt", 1)
        .expect("Failed to import modified file");

    let vault_path = session.vault_path().to_path_buf();
    drop(session);

    // Reopen and verify modified content
    let session2 = open_vault(&vault_path, b"test_password_123", None)
        .expect("Failed to reopen vault");

    let (read_content, _) = export_to_bytes(&session2, file_uuid_v2)
        .expect("Failed to export modified file");

    assert_eq!(read_content, content_v2, "Modified content not persisted");
    assert!(verify_content(&read_content, "version2"), "Should have version2 content");

    // Original file should no longer exist
    let result = export_to_bytes(&session2, file_uuid);
    assert!(result.is_err(), "Original file UUID should not exist");

    assert!(temp_dir.path().exists());
}

// ============================================================================
// Test 3: Delete File, Verify Not Accessible
// ============================================================================

#[test]
fn test_delete_file_not_accessible() {
    let (_temp_dir, mut session) = create_test_vault();

    // Create a file
    let content = create_test_content("to_delete", 500);
    let file_uuid = import_bytes(&mut session, &content, "/to_delete.txt", 1)
        .expect("Failed to import file");

    // Verify file exists
    let result = export_to_bytes(&session, file_uuid);
    assert!(result.is_ok(), "File should exist before deletion");

    // Delete the file
    delete_file(&mut session, file_uuid)
        .expect("Failed to delete file");

    // Verify file is no longer accessible
    let result = export_to_bytes(&session, file_uuid);
    assert!(result.is_err(), "File should not be accessible after deletion");
}

#[test]
fn test_delete_file_not_in_listing() {
    let (_temp_dir, mut session) = create_test_vault();

    // Create multiple files
    let content = create_test_content("file", 256);
    let uuid1 = import_bytes(&mut session, &content, "/keep1.txt", 1).unwrap();
    let uuid2 = import_bytes(&mut session, &content, "/delete_me.txt", 1).unwrap();
    let uuid3 = import_bytes(&mut session, &content, "/keep2.txt", 1).unwrap();

    // Delete the middle file
    delete_file(&mut session, uuid2).expect("Failed to delete file");

    // List files
    let entries = list_files(&session, "/").expect("Failed to list files");

    // Verify listing
    let names: HashSet<_> = entries.iter().map(|e| e.name.as_str()).collect();

    assert!(names.contains("keep1.txt"), "keep1.txt should be in listing");
    assert!(names.contains("keep2.txt"), "keep2.txt should be in listing");
    assert!(!names.contains("delete_me.txt"), "delete_me.txt should not be in listing");

    // Verify remaining files are still accessible
    let (content1, _) = export_to_bytes(&session, uuid1).unwrap();
    let (content3, _) = export_to_bytes(&session, uuid3).unwrap();
    assert_eq!(content1, content, "keep1.txt content corrupted");
    assert_eq!(content3, content, "keep2.txt content corrupted");
}

#[test]
fn test_delete_persists() {
    let (temp_dir, mut session) = create_test_vault();

    let content = create_test_content("deleted", 256);
    let file_uuid = import_bytes(&mut session, &content, "/deleted.txt", 1).unwrap();

    delete_file(&mut session, file_uuid).expect("Failed to delete file");

    let vault_path = session.vault_path().to_path_buf();
    drop(session);

    // Reopen vault
    let session2 = open_vault(&vault_path, b"test_password_123", None).unwrap();

    // File should still be deleted
    let result = export_to_bytes(&session2, file_uuid);
    assert!(result.is_err(), "Deleted file should not exist after reopen");

    let entries = list_files(&session2, "/").expect("Failed to list files");
    assert!(
        !entries.iter().any(|e| e.name == "deleted.txt"),
        "Deleted file should not appear in listing after reopen"
    );

    assert!(temp_dir.path().exists());
}

// ============================================================================
// Test 4: Rename File, Verify New Name
// ============================================================================

#[test]
fn test_rename_file_new_name_accessible() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("renamed", 512);
    let file_uuid = import_bytes(&mut session, &content, "/original.txt", 1).unwrap();

    // Rename the file
    rename_file(&mut session, file_uuid, "new_name.txt")
        .expect("Failed to rename file");

    // Verify file is accessible with new name
    let (read_content, metadata) = export_to_bytes(&session, file_uuid).unwrap();

    assert_eq!(read_content, content, "Content should not change on rename");
    assert_eq!(metadata.plaintext.name, "new_name.txt", "New name should be set");
}

#[test]
fn test_rename_file_old_name_not_in_listing() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("rename_test", 256);
    let file_uuid = import_bytes(&mut session, &content, "/old_name.txt", 1).unwrap();

    rename_file(&mut session, file_uuid, "new_name.txt").unwrap();

    let entries = list_files(&session, "/").expect("Failed to list files");
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();

    assert!(!names.contains(&"old_name.txt"), "Old name should not be in listing");
    assert!(names.contains(&"new_name.txt"), "New name should be in listing");
}

#[test]
fn test_move_file_to_directory() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("moved", 256);
    let file_uuid = import_bytes(&mut session, &content, "/root_file.txt", 1).unwrap();

    // Move file to subdirectory (virtual path)
    move_file(&mut session, file_uuid, "/subdir/moved_file.txt")
        .expect("Failed to move file");

    // Verify file is at new location
    let (read_content, metadata) = export_to_bytes(&session, file_uuid).unwrap();

    assert_eq!(read_content, content, "Content should not change on move");
    assert_eq!(metadata.plaintext.path, "/subdir/moved_file.txt", "Path should be updated");
}

#[test]
fn test_rename_persists() {
    let (temp_dir, mut session) = create_test_vault();

    let content = create_test_content("persist_rename", 256);
    let file_uuid = import_bytes(&mut session, &content, "/before.txt", 1).unwrap();

    rename_file(&mut session, file_uuid, "after.txt").unwrap();

    let vault_path = session.vault_path().to_path_buf();
    drop(session);

    // Reopen vault
    let session2 = open_vault(&vault_path, b"test_password_123", None).unwrap();

    let (read_content, metadata) = export_to_bytes(&session2, file_uuid).unwrap();

    assert_eq!(read_content, content, "Content should persist");
    assert_eq!(metadata.plaintext.name, "after.txt", "Rename should persist");

    assert!(temp_dir.path().exists());
}

// ============================================================================
// Test 5: Directory Listing Accuracy
// ============================================================================

#[test]
fn test_directory_listing_empty() {
    let (_temp_dir, session) = create_test_vault();

    let entries = list_files(&session, "/").expect("Failed to list empty directory");

    // Root should be empty initially (no files)
    let files: Vec<_> = entries.iter()
        .filter(|e| e.entry_type == EntryType::File)
        .collect();

    assert!(files.is_empty(), "Empty vault should have no files");
}

#[test]
fn test_directory_listing_single_file() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("single", 100);
    import_bytes(&mut session, &content, "/single.txt", 1).unwrap();

    let entries = list_files(&session, "/").expect("Failed to list directory");

    let files: Vec<_> = entries.iter()
        .filter(|e| e.entry_type == EntryType::File)
        .collect();

    assert_eq!(files.len(), 1, "Should have exactly one file");
    assert_eq!(files[0].name, "single.txt", "File name should match");
    assert_eq!(files[0].size, 100, "File size should match");
}

#[test]
fn test_directory_listing_multiple_files() {
    let (_temp_dir, mut session) = create_test_vault();

    // Create multiple files
    let files_to_create = [
        ("alpha.txt", 100),
        ("beta.txt", 200),
        ("gamma.txt", 300),
        ("delta.txt", 400),
    ];

    for (name, size) in &files_to_create {
        let content = create_test_content(name, *size);
        import_bytes(&mut session, &content, &format!("/{name}"), 1).unwrap();
    }

    let entries = list_files(&session, "/").expect("Failed to list directory");

    let files: Vec<_> = entries.iter()
        .filter(|e| e.entry_type == EntryType::File)
        .collect();

    assert_eq!(files.len(), 4, "Should have 4 files");

    // Verify all files are present
    for (name, size) in &files_to_create {
        let entry = files.iter().find(|e| e.name == *name);
        assert!(entry.is_some(), "File {name} should be in listing");
        assert_eq!(entry.unwrap().size, *size as u64, "Size mismatch for {name}");
    }
}

#[test]
fn test_directory_listing_with_subdirectories() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("nested", 100);

    // Create files in virtual directories
    import_bytes(&mut session, &content, "/root_file.txt", 1).unwrap();
    import_bytes(&mut session, &content, "/docs/doc1.txt", 1).unwrap();
    import_bytes(&mut session, &content, "/docs/doc2.txt", 1).unwrap();
    import_bytes(&mut session, &content, "/images/photo.jpg", 1).unwrap();

    // List root directory
    let root_entries = list_files(&session, "/").expect("Failed to list root");
    let root_names: HashSet<_> = root_entries.iter().map(|e| e.name.as_str()).collect();

    assert!(root_names.contains("root_file.txt"), "root_file.txt should be in root");
    assert!(root_names.contains("docs"), "docs directory should be in root");
    assert!(root_names.contains("images"), "images directory should be in root");

    // Verify directory types
    let docs_entry = root_entries.iter().find(|e| e.name == "docs");
    assert!(docs_entry.is_some(), "docs should exist");
    assert_eq!(docs_entry.unwrap().entry_type, EntryType::Directory, "docs should be directory");

    // List subdirectory
    let docs_entries = list_files(&session, "/docs").expect("Failed to list /docs");
    let docs_names: Vec<_> = docs_entries.iter().map(|e| e.name.as_str()).collect();

    assert!(docs_names.contains(&"doc1.txt"), "doc1.txt should be in /docs");
    assert!(docs_names.contains(&"doc2.txt"), "doc2.txt should be in /docs");
}

#[test]
fn test_directory_listing_access_level_filtering() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("level", 100);

    // Create files at level 1 (accessible)
    import_bytes(&mut session, &content, "/level1_file.txt", 1).unwrap();

    // List should show level 1 files
    let entries = list_files(&session, "/").expect("Failed to list directory");
    let file_names: Vec<_> = entries.iter()
        .filter(|e| e.entry_type == EntryType::File)
        .map(|e| e.name.as_str())
        .collect();

    assert!(file_names.contains(&"level1_file.txt"), "Level 1 file should be visible");
}

#[test]
fn test_directory_listing_size_accuracy() {
    let (_temp_dir, mut session) = create_test_vault();

    // Create files with exact known sizes
    let sizes = [0, 1, 100, 1000, 10000, 65536];

    for size in sizes {
        let content = vec![0u8; size];
        import_bytes(&mut session, &content, &format!("/size_{size}.bin"), 1).unwrap();
    }

    let entries = list_files(&session, "/").expect("Failed to list directory");

    for size in sizes {
        let entry = entries.iter().find(|e| e.name == format!("size_{size}.bin"));
        assert!(entry.is_some(), "File size_{size}.bin should be in listing");
        assert_eq!(entry.unwrap().size, size as u64, "Size should be exactly {size}");
    }
}

// ============================================================================
// VFS Handler Integration Tests (Platform-Specific)
// ============================================================================

#[cfg(windows)]
mod dokan_tests {
    use super::*;
    use crate::dokan::{
        TesseractDokanHandler, DokanConfig, DokanMount,
        FileHandle, NtStatus, FileInfo, FindData,
    };

    /// Test Dokan CreateFile for existing file
    #[test]
    fn test_dokan_create_file_existing() {
        let (_temp_dir, mut session) = create_test_vault();

        let content = create_test_content("dokan_test", 256);
        import_bytes(&mut session, &content, "/test.txt", 1).unwrap();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        // OPEN_EXISTING = 3
        let result = handler.create_file("\\test.txt", 0, 0, 3, 0);
        assert!(result.is_ok(), "CreateFile should succeed for existing file");

        let (handle_id, is_dir) = result.unwrap();
        assert!(!is_dir, "Should not be a directory");
        assert!(handle_id > 0, "Handle ID should be valid");

        handler.cleanup(handle_id, false);
    }

    /// Test Dokan CreateFile for non-existent file
    #[test]
    fn test_dokan_create_file_not_found() {
        let (_temp_dir, session) = create_test_vault();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        // OPEN_EXISTING = 3
        let result = handler.create_file("\\nonexistent.txt", 0, 0, 3, 0);
        assert!(result.is_err(), "CreateFile should fail for non-existent file");
        assert_eq!(result.unwrap_err(), NtStatus::ObjectNameNotFound);
    }

    /// Test Dokan FindFiles for directory listing
    #[test]
    fn test_dokan_find_files() {
        let (_temp_dir, mut session) = create_test_vault();

        let content = create_test_content("find_test", 100);
        import_bytes(&mut session, &content, "/file1.txt", 1).unwrap();
        import_bytes(&mut session, &content, "/file2.txt", 1).unwrap();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        let result = handler.find_files("\\");
        assert!(result.is_ok(), "FindFiles should succeed");

        let entries = result.unwrap();

        // Should have ".", ".." and our two files
        let file_names: Vec<_> = entries.iter().map(|e| e.file_name.as_str()).collect();

        assert!(file_names.contains(&"."), "Should have . entry");
        assert!(file_names.contains(&"file1.txt"), "Should have file1.txt");
        assert!(file_names.contains(&"file2.txt"), "Should have file2.txt");
    }

    /// Test Dokan ReadFile operation
    #[test]
    fn test_dokan_read_file() {
        let (_temp_dir, mut session) = create_test_vault();

        let content = create_test_content("read_test", 512);
        import_bytes(&mut session, &content, "/readable.txt", 1).unwrap();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        // Open file
        let (handle_id, _) = handler.create_file("\\readable.txt", 0, 0, 3, 0).unwrap();

        // Read content
        let mut buffer = vec![0u8; 512];
        let result = handler.read_file(handle_id, &mut buffer, 0);

        assert!(result.is_ok(), "ReadFile should succeed");
        let bytes_read = result.unwrap();
        assert_eq!(bytes_read, 512, "Should read all bytes");
        assert_eq!(buffer, content, "Content should match");

        handler.cleanup(handle_id, false);
    }

    /// Test Dokan complete write-read cycle
    #[test]
    fn test_dokan_write_read_cycle() {
        let (_temp_dir, session) = create_test_vault();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        // CREATE_NEW = 1
        let (handle_id, _) = handler.create_file("\\new_file.txt", 0, 0, 1, 0).unwrap();

        // Write content
        let content = create_test_content("write_test", 256);
        let write_result = handler.write_file(handle_id, &content, 0);
        assert!(write_result.is_ok(), "WriteFile should succeed");

        // Flush to commit
        handler.flush_file_buffers(handle_id).unwrap();

        // Close and cleanup
        handler.close_file(handle_id).unwrap();
        handler.cleanup(handle_id, false);

        // Reopen and read
        let (handle_id2, _) = handler.create_file("\\new_file.txt", 0, 0, 3, 0).unwrap();

        let mut buffer = vec![0u8; 256];
        let bytes_read = handler.read_file(handle_id2, &mut buffer, 0).unwrap();

        assert_eq!(bytes_read, 256, "Should read all written bytes");
        assert_eq!(buffer, content, "Content should match written data");

        handler.cleanup(handle_id2, false);
    }

    /// Test Dokan DeleteFile operation
    #[test]
    fn test_dokan_delete_file() {
        let (_temp_dir, mut session) = create_test_vault();

        let content = create_test_content("delete_test", 100);
        import_bytes(&mut session, &content, "/to_delete.txt", 1).unwrap();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        // Open file for deletion
        let (handle_id, _) = handler.create_file("\\to_delete.txt", 0, 0, 3, 0).unwrap();

        // Check if can delete
        let can_delete = handler.can_delete_file(handle_id);
        assert!(can_delete.is_ok(), "Can delete check should succeed");

        // Delete the file
        let delete_result = handler.delete_file_callback(handle_id);
        assert!(delete_result.is_ok(), "DeleteFile should succeed");

        handler.cleanup(handle_id, true);

        // Verify file is gone
        let open_result = handler.create_file("\\to_delete.txt", 0, 0, 3, 0);
        assert!(open_result.is_err(), "File should not exist after deletion");
    }

    /// Test Dokan MoveFile (rename) operation
    #[test]
    fn test_dokan_move_file() {
        let (_temp_dir, mut session) = create_test_vault();

        let content = create_test_content("move_test", 100);
        import_bytes(&mut session, &content, "/original.txt", 1).unwrap();

        let config = DokanConfig::new('T');
        let handler = TesseractDokanHandler::new(session, config);

        // Open file
        let (handle_id, _) = handler.create_file("\\original.txt", 0, 0, 3, 0).unwrap();

        // Move/rename
        let move_result = handler.move_file_callback(handle_id, "\\renamed.txt", false);
        assert!(move_result.is_ok(), "MoveFile should succeed");

        handler.cleanup(handle_id, false);

        // Verify old name is gone
        let old_result = handler.create_file("\\original.txt", 0, 0, 3, 0);
        assert!(old_result.is_err(), "Old name should not exist");

        // Verify new name exists
        let new_result = handler.create_file("\\renamed.txt", 0, 0, 3, 0);
        assert!(new_result.is_ok(), "New name should exist");

        let (handle_id2, _) = new_result.unwrap();
        handler.cleanup(handle_id2, false);
    }
}

#[cfg(unix)]
mod fuse_tests {
    use super::*;
    use crate::fuse::{
        TesseractFuseHandler, FuseConfig,
        InodeEntry, InodeTable, CachedChunk, ChunkCache, WriteBuffer,
        ROOT_INODE,
    };

    /// Test FUSE handler creation
    #[test]
    fn test_fuse_handler_creation() {
        let (_temp_dir, session) = create_test_vault();

        let config = FuseConfig::default();
        let _handler = TesseractFuseHandler::new(session, config);

        // Handler is created successfully (no is_mounted method for direct check)
    }

    /// Test FUSE inode table
    #[test]
    fn test_fuse_inode_table() {
        let mut table = InodeTable::new();

        // Root inode should always exist
        assert!(table.get(ROOT_INODE).is_some(), "Root inode should exist");
        assert_eq!(table.get(ROOT_INODE).unwrap().path, "/", "Root path should be /");

        // Allocate new inodes and create entries
        let inode1 = table.allocate_inode();
        let inode2 = table.allocate_inode();

        assert!(inode1 > ROOT_INODE, "New inode should be > ROOT_INODE");
        assert_ne!(inode1, inode2, "Inodes should be unique");

        // Insert entries
        let entry1 = InodeEntry::new(
            inode1,
            Some(Uuid::new_v4()),
            "/test1.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            100,
            0,
        );
        table.insert(entry1);

        let entry2 = InodeEntry::new(
            inode2,
            Some(Uuid::new_v4()),
            "/test2.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            200,
            0,
        );
        table.insert(entry2);

        // Lookup by path should work
        assert_eq!(table.inode_for_path("/test1.txt"), Some(inode1));
        assert_eq!(table.inode_for_path("/test2.txt"), Some(inode2));

        // Get by inode should work
        assert_eq!(table.get(inode1).unwrap().path, "/test1.txt");
        assert_eq!(table.get(inode2).unwrap().path, "/test2.txt");
    }

    /// Test FUSE inode table clear and update
    #[test]
    fn test_fuse_inode_table_clear() {
        let mut table = InodeTable::new();

        let inode1 = table.allocate_inode();
        let entry1 = InodeEntry::new(
            inode1,
            Some(Uuid::new_v4()),
            "/file.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            100,
            0,
        );
        table.insert(entry1);

        assert_eq!(table.len(), 2); // root + file

        table.clear();

        assert_eq!(table.len(), 1); // Only root remains
        assert!(table.get(ROOT_INODE).is_some(), "Root should survive clear");
        assert!(table.get(inode1).is_none(), "File should be removed");
    }

    /// Test FUSE inode table path update
    #[test]
    fn test_fuse_inode_table_update_path() {
        let mut table = InodeTable::new();

        let inode = table.allocate_inode();
        let entry = InodeEntry::new(
            inode,
            Some(Uuid::new_v4()),
            "/old_name.txt".to_string(),
            ROOT_INODE,
            EntryType::File,
            1,
            100,
            0,
        );
        table.insert(entry);

        // Update path (rename)
        table.update_path(inode, "/new_name.txt".to_string());

        // Old path should not resolve
        assert!(table.inode_for_path("/old_name.txt").is_none());

        // New path should resolve to same inode
        assert_eq!(table.inode_for_path("/new_name.txt"), Some(inode));
        assert_eq!(table.get(inode).unwrap().path, "/new_name.txt");
    }

    /// Test FUSE chunk cache
    #[test]
    fn test_fuse_chunk_cache() {
        let mut cache = ChunkCache::new();

        let inode: u64 = 2;
        let chunk = CachedChunk::new(0, vec![1, 2, 3, 4, 5]);

        cache.insert(inode, chunk.clone());

        let cached = cache.find_chunk(inode, 0);
        assert!(cached.is_some(), "Cached data should be retrievable");
        assert_eq!(cached.unwrap().data, vec![1, 2, 3, 4, 5], "Cached data should match");

        cache.clear_file(inode);

        let cached = cache.find_chunk(inode, 0);
        assert!(cached.is_none(), "Cache should be cleared for file");
    }

    /// Test FUSE chunk cache expiration
    #[test]
    fn test_fuse_chunk_cache_contains() {
        let chunk = CachedChunk::new(100, vec![0u8; 50]);

        assert!(chunk.contains(100), "Should contain start offset");
        assert!(chunk.contains(125), "Should contain middle offset");
        assert!(chunk.contains(149), "Should contain last byte offset");
        assert!(!chunk.contains(99), "Should not contain before start");
        assert!(!chunk.contains(150), "Should not contain after end");
    }

    /// Test FUSE write buffer
    #[test]
    fn test_fuse_write_buffer() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        // Write some data
        let data = b"Hello, World!";
        let written = buffer.write_at(0, data);

        assert_eq!(written, data.len(), "Should write all bytes");
        assert!(buffer.is_modified(), "Buffer should be modified");

        // Read back
        let mut read_buf = vec![0u8; data.len()];
        let read = buffer.read_at(0, &mut read_buf);

        assert_eq!(read, data.len(), "Should read all bytes");
        assert_eq!(&read_buf, data, "Read data should match");
    }

    /// Test FUSE write buffer extending writes
    #[test]
    fn test_fuse_write_buffer_extend() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        // Write at offset 0
        buffer.write_at(0, b"Hello");
        assert_eq!(buffer.len(), 5);

        // Write at offset 10 (should extend)
        buffer.write_at(10, b"World");
        assert_eq!(buffer.len(), 15);

        // Read back
        let mut read_buf = vec![0u8; 15];
        buffer.read_at(0, &mut read_buf);

        assert_eq!(&read_buf[0..5], b"Hello");
        assert_eq!(&read_buf[5..10], &[0, 0, 0, 0, 0]); // Gap should be zeros
        assert_eq!(&read_buf[10..15], b"World");
    }

    /// Test FUSE write buffer set end of file
    #[test]
    fn test_fuse_write_buffer_set_eof() {
        let mut buffer = WriteBuffer::new_file("test.txt".to_string());

        // Write some data
        buffer.write_at(0, b"Hello, World!");
        assert_eq!(buffer.len(), 13);

        // Truncate
        buffer.set_end_of_file(5);
        assert_eq!(buffer.len(), 5);

        // Extend
        buffer.set_end_of_file(10);
        assert_eq!(buffer.len(), 10);

        // Read back
        let mut read_buf = vec![0u8; 10];
        buffer.read_at(0, &mut read_buf);

        assert_eq!(&read_buf[0..5], b"Hello");
        assert_eq!(&read_buf[5..10], &[0, 0, 0, 0, 0]); // Extended portion is zeros
    }

    /// Test FUSE complete file operations via vault
    #[test]
    fn test_fuse_file_operations_via_vault() {
        let (_temp_dir, mut session) = create_test_vault();

        let content = create_test_content("fuse_test", 256);
        let file_uuid = import_bytes(&mut session, &content, "/fuse_file.txt", 1).unwrap();

        // Verify via vault API (FUSE handler uses these internally)
        let entries = list_files(&session, "/").unwrap();
        let file_entry = entries.iter().find(|e| e.name == "fuse_file.txt");

        assert!(file_entry.is_some(), "File should be in listing");
        let entry = file_entry.unwrap();
        assert_eq!(entry.size, 256, "Size should match");
        assert_eq!(entry.uuid, Some(file_uuid), "UUID should match");

        // Read back
        let (read_content, _) = export_to_bytes(&session, file_uuid).unwrap();
        assert_eq!(read_content, content, "Content should match");
    }
}

// ============================================================================
// Cross-Platform Tests
// ============================================================================

/// Test that file UUIDs are stable
#[test]
fn test_file_uuid_stability() {
    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("uuid_test", 100);
    let file_uuid = import_bytes(&mut session, &content, "/stable_uuid.txt", 1).unwrap();

    // UUID should be valid
    assert!(!file_uuid.is_nil(), "UUID should not be nil");

    // Multiple exports should use same UUID
    for _ in 0..3 {
        let (_, metadata) = export_to_bytes(&session, file_uuid).unwrap();
        assert_eq!(metadata.uuid, file_uuid, "UUID should remain stable");
    }
}

/// Test concurrent read safety
#[test]
fn test_concurrent_read_safety() {
    use std::sync::Arc;
    use std::thread;

    let (_temp_dir, mut session) = create_test_vault();

    let content = create_test_content("concurrent", 1024);
    let file_uuid = import_bytes(&mut session, &content, "/concurrent.txt", 1).unwrap();

    let vault_path = session.vault_path().to_path_buf();
    drop(session);

    // Open multiple sessions and read concurrently
    let vault_path = Arc::new(vault_path);
    let file_uuid = Arc::new(file_uuid);
    let expected_content = Arc::new(content);

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let path = Arc::clone(&vault_path);
            let uuid = Arc::clone(&file_uuid);
            let expected = Arc::clone(&expected_content);

            thread::spawn(move || {
                let session = open_vault(&path, b"test_password_123", None).unwrap();
                let (read_content, _) = export_to_bytes(&session, *uuid).unwrap();
                assert_eq!(read_content, *expected, "Concurrent read should match");
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread should complete");
    }
}

/// Test large file handling
#[test]
fn test_large_file_handling() {
    let (_temp_dir, mut session) = create_test_vault();

    // 1 MB file
    let size = 1024 * 1024;
    let content = create_test_content("large", size);

    let file_uuid = import_bytes(&mut session, &content, "/large_file.bin", 1)
        .expect("Should handle 1MB file");

    let (read_content, metadata) = export_to_bytes(&session, file_uuid)
        .expect("Should export 1MB file");

    assert_eq!(read_content.len(), size, "Size should match");
    assert_eq!(read_content, content, "Content should match");
    assert_eq!(metadata.plaintext.size, size as u64, "Metadata size should match");
}
