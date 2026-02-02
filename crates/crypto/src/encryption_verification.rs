//! Metadata Encryption Verification (US-065).
//!
//! This module provides comprehensive verification that no plaintext leakage
//! occurs in encrypted vault storage. It tests that:
//!
//! - Filenames are properly encrypted
//! - File paths are properly encrypted
//! - Directory names are properly encrypted
//! - Sensitive strings do not appear anywhere in the vault
//!
//! # Test Methodology
//!
//! 1. Create a vault with known, distinctive filenames
//! 2. Import files with sensitive/distinctive names and paths
//! 3. Hex dump the entire vault directory (header, keystores, blobs, metadata)
//! 4. Search for any plaintext filename or path component strings
//! 5. Zero matches = verification passed
//!
//! # References
//!
//! - TESSERACT Specification: All metadata must be encrypted
//! - OWASP: Verify no sensitive data in storage leaks
//!
//! # Example
//!
//! ```ignore
//! use tesseract_crypto::encryption_verification::{run_metadata_verification, VerificationResult};
//!
//! let result = run_metadata_verification(&vault_path)?;
//! assert!(result.all_passed(), "Plaintext leakage detected!");
//! ```

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

// ============================================================================
// Verification Types
// ============================================================================

/// Result of running the metadata encryption verification.
#[derive(Debug, Clone, Default)]
pub struct VerificationResult {
    /// Total bytes scanned in the vault.
    pub total_bytes_scanned: usize,
    /// Number of files scanned.
    pub files_scanned: usize,
    /// Patterns that were searched for.
    pub patterns_searched: Vec<String>,
    /// Patterns that were found (should be empty for passing).
    pub patterns_found: Vec<PatternMatch>,
    /// List of files that were scanned.
    pub scanned_files: Vec<String>,
}

impl VerificationResult {
    /// Returns true if no plaintext patterns were found.
    pub fn all_passed(&self) -> bool {
        self.patterns_found.is_empty()
    }

    /// Returns the number of patterns that were found.
    pub fn failed_count(&self) -> usize {
        self.patterns_found.len()
    }

    /// Formats a human-readable report of the verification results.
    pub fn format_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Metadata Encryption Verification Report ===\n");
        report.push_str(&format!("Files scanned: {}\n", self.files_scanned));
        report.push_str(&format!("Total bytes: {} ({:.2} KB)\n",
            self.total_bytes_scanned,
            self.total_bytes_scanned as f64 / 1024.0
        ));
        report.push_str(&format!("Patterns searched: {}\n", self.patterns_searched.len()));

        if self.all_passed() {
            report.push_str("\n✓ PASSED: No plaintext patterns found!\n");
        } else {
            report.push_str(&format!("\n✗ FAILED: {} pattern(s) found in plaintext!\n",
                self.patterns_found.len()
            ));
            for match_info in &self.patterns_found {
                report.push_str(&format!("  - '{}' found in {} at offset {}\n",
                    match_info.pattern,
                    match_info.file_path,
                    match_info.offset
                ));
            }
        }

        report
    }
}

/// Information about a pattern match in the vault.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// The pattern that was found.
    pub pattern: String,
    /// The file path where it was found.
    pub file_path: String,
    /// Byte offset where the pattern was found.
    pub offset: usize,
    /// Context bytes around the match (for debugging).
    pub context: Vec<u8>,
}

// ============================================================================
// Verification Configuration
// ============================================================================

/// Configuration for the verification process.
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Patterns to search for (sensitive strings).
    pub patterns: Vec<String>,
    /// Whether to include context bytes in match results.
    pub include_context: bool,
    /// Number of context bytes before/after match.
    pub context_bytes: usize,
    /// Whether to scan hidden files (starting with .).
    pub scan_hidden_files: bool,
    /// Maximum file size to scan (prevents memory issues).
    pub max_file_size: usize,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            include_context: true,
            context_bytes: 16,
            scan_hidden_files: true,
            max_file_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

impl VerificationConfig {
    /// Creates a new configuration with the specified patterns.
    pub fn with_patterns(patterns: Vec<String>) -> Self {
        Self {
            patterns,
            ..Default::default()
        }
    }

    /// Adds a pattern to search for.
    pub fn add_pattern(&mut self, pattern: impl Into<String>) -> &mut Self {
        self.patterns.push(pattern.into());
        self
    }

    /// Sets whether to include context bytes.
    pub fn with_context(mut self, include: bool, bytes: usize) -> Self {
        self.include_context = include;
        self.context_bytes = bytes;
        self
    }
}

// ============================================================================
// Standard Test Patterns
// ============================================================================

/// Returns a set of standard patterns used for testing.
///
/// These are distinctive strings that should never appear in encrypted data.
pub fn standard_test_patterns() -> Vec<String> {
    vec![
        // File names
        "TOP_SECRET_CONFIDENTIAL.doc".to_string(),
        "NUCLEAR_LAUNCH_CODES.txt".to_string(),
        "bank_account_password.pdf".to_string(),
        "social_security_number.doc".to_string(),
        "private_ssh_key.pem".to_string(),
        "secret_recipe.txt".to_string(),
        "classified_intel.docx".to_string(),
        // Path components
        "CLASSIFIED_DOCUMENTS".to_string(),
        "NUCLEAR_SECRETS".to_string(),
        "TOP_SECRET".to_string(),
        "CONFIDENTIAL".to_string(),
        // Unique markers for testing
        "TESSERACT_MARKER_12345".to_string(),
        "UNIQUE_TEST_STRING_67890".to_string(),
        "ZZZZ_VERIFICATION_ZZZZ".to_string(),
    ]
}

/// Returns sensitive term patterns that should not appear.
///
/// These are common sensitive terms that might appear in file names or paths.
pub fn sensitive_term_patterns() -> Vec<String> {
    vec![
        "password".to_string(),
        "secret".to_string(),
        "private".to_string(),
        "confidential".to_string(),
        "classified".to_string(),
        "nuclear".to_string(),
        "launch_codes".to_string(),
        "bank_account".to_string(),
        "social_security".to_string(),
        "ssh_key".to_string(),
        "recipe".to_string(),
        "intel".to_string(),
    ]
}

// ============================================================================
// Core Verification Functions
// ============================================================================

/// Scans a byte slice for plaintext patterns.
///
/// Uses a sliding window approach to find byte-level matches.
///
/// # Arguments
///
/// * `data` - The bytes to scan
/// * `patterns` - Patterns to search for
/// * `file_path` - Path of the file being scanned (for reporting)
/// * `config` - Verification configuration
///
/// # Returns
///
/// Vector of pattern matches found in the data.
pub fn scan_for_patterns(
    data: &[u8],
    patterns: &[String],
    file_path: &str,
    config: &VerificationConfig,
) -> Vec<PatternMatch> {
    let mut matches = Vec::new();

    for pattern in patterns {
        let pattern_bytes = pattern.as_bytes();
        if pattern_bytes.is_empty() {
            continue;
        }

        // Scan using sliding window
        for (offset, window) in data.windows(pattern_bytes.len()).enumerate() {
            if window == pattern_bytes {
                let context = if config.include_context {
                    let start = offset.saturating_sub(config.context_bytes);
                    let end = (offset + pattern_bytes.len() + config.context_bytes).min(data.len());
                    data[start..end].to_vec()
                } else {
                    Vec::new()
                };

                matches.push(PatternMatch {
                    pattern: pattern.clone(),
                    file_path: file_path.to_string(),
                    offset,
                    context,
                });
            }
        }
    }

    matches
}

/// Scans a single file for plaintext patterns.
///
/// # Arguments
///
/// * `file_path` - Path to the file to scan
/// * `patterns` - Patterns to search for
/// * `config` - Verification configuration
///
/// # Returns
///
/// Tuple of (bytes_read, pattern_matches).
pub fn scan_file(
    file_path: &Path,
    patterns: &[String],
    config: &VerificationConfig,
) -> Result<(usize, Vec<PatternMatch>), std::io::Error> {
    let metadata = fs::metadata(file_path)?;

    // Skip files that are too large
    if metadata.len() as usize > config.max_file_size {
        return Ok((0, Vec::new()));
    }

    // Read the file
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut buffer)?;

    let path_str = file_path.to_string_lossy().to_string();
    let matches = scan_for_patterns(&buffer, patterns, &path_str, config);

    Ok((buffer.len(), matches))
}

/// Recursively scans a directory for plaintext patterns.
///
/// Scans all files in the directory tree, including hidden files if configured.
///
/// # Arguments
///
/// * `dir_path` - Path to the directory to scan
/// * `patterns` - Patterns to search for
/// * `config` - Verification configuration
/// * `result` - Result struct to accumulate findings
///
/// # Returns
///
/// Result indicating success or I/O error.
pub fn scan_directory(
    dir_path: &Path,
    patterns: &[String],
    config: &VerificationConfig,
    result: &mut VerificationResult,
) -> Result<(), std::io::Error> {
    if !dir_path.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Skip hidden files if configured
        if !config.scan_hidden_files && name_str.starts_with('.') {
            continue;
        }

        if path.is_dir() {
            // Recursively scan subdirectory
            scan_directory(&path, patterns, config, result)?;
        } else if path.is_file() {
            // Scan the file
            match scan_file(&path, patterns, config) {
                Ok((bytes, matches)) => {
                    result.total_bytes_scanned += bytes;
                    result.files_scanned += 1;
                    result.scanned_files.push(path.to_string_lossy().to_string());
                    result.patterns_found.extend(matches);
                }
                Err(e) => {
                    // Log but continue on read errors
                    eprintln!("Warning: Could not read {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(())
}

/// Runs the full metadata encryption verification on a vault directory.
///
/// This is the main entry point for verification. It scans the entire vault
/// directory structure for any plaintext patterns.
///
/// # Arguments
///
/// * `vault_path` - Path to the vault root directory
/// * `config` - Verification configuration (patterns to search for)
///
/// # Returns
///
/// VerificationResult containing all findings.
///
/// # Example
///
/// ```ignore
/// use tesseract_crypto::encryption_verification::{run_verification, VerificationConfig};
///
/// let config = VerificationConfig::with_patterns(vec![
///     "secret_document.txt".to_string(),
///     "classified".to_string(),
/// ]);
///
/// let result = run_verification(&vault_path, &config)?;
/// assert!(result.all_passed(), "Plaintext leakage detected!");
/// ```
pub fn run_verification(
    vault_path: &Path,
    config: &VerificationConfig,
) -> Result<VerificationResult, std::io::Error> {
    let mut result = VerificationResult {
        patterns_searched: config.patterns.clone(),
        ..Default::default()
    };

    scan_directory(vault_path, &config.patterns, config, &mut result)?;

    Ok(result)
}

/// Runs verification with standard test patterns.
///
/// Convenience function that uses the standard test patterns defined
/// in this module.
pub fn run_standard_verification(vault_path: &Path) -> Result<VerificationResult, std::io::Error> {
    let mut patterns = standard_test_patterns();
    patterns.extend(sensitive_term_patterns());

    let config = VerificationConfig::with_patterns(patterns);
    run_verification(vault_path, &config)
}

/// Creates a hex dump of a byte slice.
///
/// Useful for debugging and manual inspection.
pub fn hex_dump(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Creates a hex dump with ASCII representation.
///
/// Format: offset: hex bytes | ascii chars
pub fn hex_dump_with_ascii(data: &[u8], bytes_per_line: usize) -> String {
    let mut result = String::new();

    for (i, chunk) in data.chunks(bytes_per_line).enumerate() {
        let offset = i * bytes_per_line;

        // Offset
        result.push_str(&format!("{:08x}: ", offset));

        // Hex bytes
        for byte in chunk {
            result.push_str(&format!("{:02x} ", byte));
        }

        // Padding for incomplete lines
        for _ in chunk.len()..bytes_per_line {
            result.push_str("   ");
        }

        result.push_str("| ");

        // ASCII representation
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                result.push(byte as char);
            } else {
                result.push('.');
            }
        }

        result.push('\n');
    }

    result
}

/// Reads all bytes from a directory tree.
///
/// Useful for comprehensive scanning of an entire vault.
pub fn read_all_vault_bytes(vault_path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let mut all_bytes = Vec::new();
    collect_bytes_recursive(vault_path, &mut all_bytes)?;
    Ok(all_bytes)
}

fn collect_bytes_recursive(path: &Path, buffer: &mut Vec<u8>) -> Result<(), std::io::Error> {
    if path.is_file() {
        let mut file = File::open(path)?;
        file.read_to_end(buffer)?;
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            collect_bytes_recursive(&entry.path(), buffer)?;
        }
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::io::Write;

    // ========================================================================
    // Pattern Scanning Tests
    // ========================================================================

    #[test]
    fn test_scan_for_patterns_finds_exact_match() {
        let data = b"This is a test with SECRET_PASSWORD in it";
        let patterns = vec!["SECRET_PASSWORD".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern, "SECRET_PASSWORD");
        assert_eq!(matches[0].offset, 20);
    }

    #[test]
    fn test_scan_for_patterns_no_match() {
        let data = b"This is encrypted gibberish: \x12\x34\x56\x78";
        let patterns = vec!["SECRET".to_string(), "PASSWORD".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_for_patterns_multiple_matches() {
        let data = b"SECRET at start and SECRET at end";
        let patterns = vec!["SECRET".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_scan_for_patterns_multiple_patterns() {
        let data = b"Both SECRET and PASSWORD appear here";
        let patterns = vec!["SECRET".to_string(), "PASSWORD".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_scan_for_patterns_includes_context() {
        let data = b"beforeSECRET_TEXTafter";
        let patterns = vec!["SECRET_TEXT".to_string()];
        let mut config = VerificationConfig::default();
        config.context_bytes = 4;

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert_eq!(matches.len(), 1);
        assert!(!matches[0].context.is_empty());
    }

    #[test]
    fn test_scan_for_patterns_empty_input() {
        let data = b"";
        let patterns = vec!["SECRET".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_for_patterns_empty_patterns() {
        let data = b"Some data here";
        let patterns: Vec<String> = vec![];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        assert!(matches.is_empty());
    }

    // ========================================================================
    // File Scanning Tests
    // ========================================================================

    #[test]
    fn test_scan_file_with_pattern() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.bin");

        {
            let mut file = File::create(&file_path).unwrap();
            file.write_all(b"Random data SENSITIVE_INFO more data").unwrap();
        }

        let patterns = vec!["SENSITIVE_INFO".to_string()];
        let config = VerificationConfig::default();

        let (bytes, matches) = scan_file(&file_path, &patterns, &config).unwrap();

        assert!(bytes > 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern, "SENSITIVE_INFO");
    }

    #[test]
    fn test_scan_file_no_pattern() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("encrypted.bin");

        {
            let mut file = File::create(&file_path).unwrap();
            // Simulate encrypted data (random bytes)
            file.write_all(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]).unwrap();
        }

        let patterns = vec!["SECRET".to_string()];
        let config = VerificationConfig::default();

        let (bytes, matches) = scan_file(&file_path, &patterns, &config).unwrap();

        assert!(bytes > 0);
        assert!(matches.is_empty());
    }

    // ========================================================================
    // Directory Scanning Tests
    // ========================================================================

    #[test]
    fn test_scan_directory_recursive() {
        let temp = TempDir::new().unwrap();

        // Create nested structure
        let sub_dir = temp.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();

        // File in root
        {
            let mut file = File::create(temp.path().join("root.bin")).unwrap();
            file.write_all(b"No secrets here").unwrap();
        }

        // File in subdir with pattern
        {
            let mut file = File::create(sub_dir.join("nested.bin")).unwrap();
            file.write_all(b"Contains TOP_SECRET data").unwrap();
        }

        let patterns = vec!["TOP_SECRET".to_string()];
        let config = VerificationConfig::with_patterns(patterns);
        let mut result = VerificationResult::default();
        result.patterns_searched = config.patterns.clone();

        scan_directory(temp.path(), &config.patterns, &config, &mut result).unwrap();

        assert_eq!(result.files_scanned, 2);
        assert_eq!(result.patterns_found.len(), 1);
        assert_eq!(result.patterns_found[0].pattern, "TOP_SECRET");
    }

    #[test]
    fn test_scan_directory_hidden_files() {
        let temp = TempDir::new().unwrap();

        // Create a hidden directory with files
        let hidden_dir = temp.path().join(".hidden");
        fs::create_dir(&hidden_dir).unwrap();

        {
            let mut file = File::create(hidden_dir.join("secret.bin")).unwrap();
            file.write_all(b"HIDDEN_SECRET_DATA").unwrap();
        }

        // Scan with hidden files enabled (default)
        let patterns = vec!["HIDDEN_SECRET".to_string()];
        let config = VerificationConfig::with_patterns(patterns);
        let mut result = VerificationResult::default();
        result.patterns_searched = config.patterns.clone();

        scan_directory(temp.path(), &config.patterns, &config, &mut result).unwrap();

        assert_eq!(result.patterns_found.len(), 1);
    }

    #[test]
    fn test_scan_directory_skip_hidden_files() {
        let temp = TempDir::new().unwrap();

        // Create a hidden file
        {
            let mut file = File::create(temp.path().join(".hidden_file")).unwrap();
            file.write_all(b"HIDDEN_SECRET_DATA").unwrap();
        }

        // Scan with hidden files disabled
        let patterns = vec!["HIDDEN_SECRET".to_string()];
        let mut config = VerificationConfig::with_patterns(patterns);
        config.scan_hidden_files = false;

        let mut result = VerificationResult::default();
        result.patterns_searched = config.patterns.clone();

        scan_directory(temp.path(), &config.patterns, &config, &mut result).unwrap();

        // Hidden file should be skipped
        assert!(result.patterns_found.is_empty());
    }

    // ========================================================================
    // Verification Result Tests
    // ========================================================================

    #[test]
    fn test_verification_result_all_passed() {
        let result = VerificationResult {
            patterns_found: vec![],
            ..Default::default()
        };

        assert!(result.all_passed());
        assert_eq!(result.failed_count(), 0);
    }

    #[test]
    fn test_verification_result_failed() {
        let result = VerificationResult {
            patterns_found: vec![PatternMatch {
                pattern: "SECRET".to_string(),
                file_path: "test.bin".to_string(),
                offset: 10,
                context: vec![],
            }],
            ..Default::default()
        };

        assert!(!result.all_passed());
        assert_eq!(result.failed_count(), 1);
    }

    #[test]
    fn test_verification_result_format_report_passed() {
        let result = VerificationResult {
            total_bytes_scanned: 1024,
            files_scanned: 5,
            patterns_searched: vec!["SECRET".to_string()],
            patterns_found: vec![],
            scanned_files: vec!["file1.bin".to_string()],
        };

        let report = result.format_report();

        assert!(report.contains("PASSED"));
        assert!(report.contains("Files scanned: 5"));
    }

    #[test]
    fn test_verification_result_format_report_failed() {
        let result = VerificationResult {
            total_bytes_scanned: 1024,
            files_scanned: 5,
            patterns_searched: vec!["SECRET".to_string()],
            patterns_found: vec![PatternMatch {
                pattern: "SECRET".to_string(),
                file_path: "vault.bin".to_string(),
                offset: 100,
                context: vec![],
            }],
            scanned_files: vec!["vault.bin".to_string()],
        };

        let report = result.format_report();

        assert!(report.contains("FAILED"));
        assert!(report.contains("SECRET"));
        assert!(report.contains("vault.bin"));
    }

    // ========================================================================
    // Hex Dump Tests
    // ========================================================================

    #[test]
    fn test_hex_dump() {
        let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
        let hex = hex_dump(&data);
        assert_eq!(hex, "48656c6c6f");
    }

    #[test]
    fn test_hex_dump_empty() {
        let data: [u8; 0] = [];
        let hex = hex_dump(&data);
        assert_eq!(hex, "");
    }

    #[test]
    fn test_hex_dump_with_ascii() {
        let data = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x01]; // "Hello" + nulls
        let dump = hex_dump_with_ascii(&data, 8);

        assert!(dump.contains("00000000:"));
        assert!(dump.contains("Hello"));
    }

    // ========================================================================
    // Standard Patterns Tests
    // ========================================================================

    #[test]
    fn test_standard_test_patterns_not_empty() {
        let patterns = standard_test_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.len() >= 10);
    }

    #[test]
    fn test_sensitive_term_patterns_not_empty() {
        let patterns = sensitive_term_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.len() >= 8);
    }

    #[test]
    fn test_standard_patterns_are_distinctive() {
        let patterns = standard_test_patterns();

        // Each pattern should be reasonably long (at least 6 characters)
        for pattern in &patterns {
            assert!(
                pattern.len() >= 6,
                "Pattern '{}' is too short for reliable detection",
                pattern
            );
        }
    }

    // ========================================================================
    // Full Verification Tests
    // ========================================================================

    #[test]
    fn test_run_verification_clean_vault() {
        let temp = TempDir::new().unwrap();

        // Create simulated encrypted vault files (random data)
        fs::create_dir(temp.path().join(".metadata")).unwrap();
        fs::create_dir(temp.path().join(".blobs")).unwrap();
        fs::create_dir(temp.path().join(".keystores")).unwrap();

        // Write random bytes to simulate encrypted data
        for name in &["vault.header", ".metadata/file1.meta", ".blobs/file1.blob"] {
            let path = temp.path().join(name);
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).unwrap();
                }
            }
            let mut file = File::create(&path).unwrap();
            // Write random-looking bytes
            let random_data: Vec<u8> = (0..256).map(|i| (i * 7 + 13) as u8).collect();
            file.write_all(&random_data).unwrap();
        }

        let config = VerificationConfig::with_patterns(standard_test_patterns());
        let result = run_verification(temp.path(), &config).unwrap();

        assert!(result.all_passed(), "Clean vault should pass verification");
        assert!(result.files_scanned >= 3);
    }

    #[test]
    fn test_run_verification_leaky_vault() {
        let temp = TempDir::new().unwrap();

        // Create a "leaky" vault with plaintext in metadata
        fs::create_dir(temp.path().join(".metadata")).unwrap();

        {
            let mut file = File::create(temp.path().join(".metadata/file1.meta")).unwrap();
            // Simulate a bug where filename is stored in plaintext
            // This string matches 3 patterns: "TOP_SECRET_CONFIDENTIAL.doc", "TOP_SECRET", "CONFIDENTIAL"
            file.write_all(b"\x12\x34TOP_SECRET_CONFIDENTIAL.doc\x56\x78").unwrap();
        }

        let config = VerificationConfig::with_patterns(standard_test_patterns());
        let result = run_verification(temp.path(), &config).unwrap();

        assert!(!result.all_passed(), "Leaky vault should fail verification");
        // The string "TOP_SECRET_CONFIDENTIAL.doc" matches 3 patterns:
        // - "TOP_SECRET_CONFIDENTIAL.doc" (full match)
        // - "TOP_SECRET" (substring)
        // - "CONFIDENTIAL" (substring)
        assert_eq!(result.failed_count(), 3);
        // Verify all expected patterns were found
        let found_patterns: Vec<&str> = result.patterns_found.iter().map(|p| p.pattern.as_str()).collect();
        assert!(found_patterns.contains(&"TOP_SECRET_CONFIDENTIAL.doc"));
        assert!(found_patterns.contains(&"TOP_SECRET"));
        assert!(found_patterns.contains(&"CONFIDENTIAL"));
    }

    #[test]
    fn test_run_standard_verification() {
        let temp = TempDir::new().unwrap();

        // Create clean encrypted-looking files
        fs::create_dir(temp.path().join(".metadata")).unwrap();

        {
            let mut file = File::create(temp.path().join(".metadata/test.meta")).unwrap();
            // Random bytes that won't match any pattern
            let data: Vec<u8> = (0..512).map(|i| ((i * 17 + 31) % 256) as u8).collect();
            file.write_all(&data).unwrap();
        }

        let result = run_standard_verification(temp.path()).unwrap();

        assert!(result.all_passed());
        assert!(!result.patterns_searched.is_empty());
    }

    // ========================================================================
    // Read All Vault Bytes Tests
    // ========================================================================

    #[test]
    fn test_read_all_vault_bytes() {
        let temp = TempDir::new().unwrap();

        // Create multiple files with known content
        {
            let mut file = File::create(temp.path().join("file1.bin")).unwrap();
            file.write_all(b"AAAA").unwrap();
        }
        {
            let mut file = File::create(temp.path().join("file2.bin")).unwrap();
            file.write_all(b"BBBB").unwrap();
        }

        let all_bytes = read_all_vault_bytes(temp.path()).unwrap();

        // Should contain both files' contents
        assert!(all_bytes.len() >= 8);

        // Both patterns should be findable in the combined bytes
        let patterns = vec!["AAAA".to_string(), "BBBB".to_string()];
        let config = VerificationConfig::default();
        let matches = scan_for_patterns(&all_bytes, &patterns, "vault", &config);

        assert_eq!(matches.len(), 2);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_binary_pattern_at_boundaries() {
        let data = b"SECRET";
        let patterns = vec!["SECRET".to_string()];
        let config = VerificationConfig::default();

        // Pattern at start
        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0);
    }

    #[test]
    fn test_pattern_spanning_end() {
        let data = b"SEC";
        let patterns = vec!["SECRET".to_string()];
        let config = VerificationConfig::default();

        // Partial pattern at end should not match
        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_unicode_pattern() {
        let data = "Contains 日本語 text".as_bytes();
        let patterns = vec!["日本語".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_very_long_pattern() {
        let long_pattern = "A".repeat(1000);
        let data = format!("start{}end", long_pattern);
        let patterns = vec![long_pattern.clone()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data.as_bytes(), &patterns, "test.bin", &config);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_overlapping_patterns() {
        let data = b"SECRETSECRET";
        let patterns = vec!["SECRET".to_string()];
        let config = VerificationConfig::default();

        let matches = scan_for_patterns(data, &patterns, "test.bin", &config);

        // Should find both occurrences
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[1].offset, 6);
    }
}
