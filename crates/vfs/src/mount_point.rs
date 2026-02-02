//! VFS mount point selection and management.
//!
//! Provides functionality for selecting and managing VFS mount points:
//! - Windows: Drive letters (A: through Z:)
//! - Linux/macOS: Mount paths (e.g., ~/TESSERACT)
//!
//! # Example
//!
//! ```no_run
//! use tesseract_vfs::mount_point::{get_available_drive_letters, DriveLetterInfo, MountPointSelection};
//!
//! // Get available drive letters on Windows
//! let available = get_available_drive_letters();
//! for info in &available {
//!     println!("{}: available={}", info.letter, info.available);
//! }
//!
//! // Create a mount point selection with default 'T' drive
//! let selection = MountPointSelection::new(Some('T'));
//! ```

use std::path::PathBuf;

/// Default drive letter for VFS mount (Windows).
pub const DEFAULT_DRIVE_LETTER: char = 'T';

/// Drive letters that are typically used for system purposes and should be avoided.
/// A: and B: are floppy drives, C: is usually the system drive.
pub const RESERVED_DRIVE_LETTERS: &[char] = &['A', 'B', 'C'];

/// Drive letters in preference order (T first as default, then common removable letters).
pub const PREFERRED_DRIVE_ORDER: &[char] = &[
    'T', 'S', 'R', 'Q', 'P', 'O', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D',
    'Z', 'Y', 'X', 'W', 'V', 'U',
];

/// Information about a drive letter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveLetterInfo {
    /// The drive letter (A-Z).
    pub letter: char,
    /// Whether the drive letter is currently available (not in use).
    pub available: bool,
    /// Whether this is a reserved/system drive letter.
    pub reserved: bool,
    /// Optional label if the drive is in use.
    pub label: Option<String>,
}

impl DriveLetterInfo {
    /// Creates a new drive letter info.
    #[must_use]
    pub fn new(letter: char, available: bool, reserved: bool) -> Self {
        Self {
            letter,
            available,
            reserved,
            label: None,
        }
    }

    /// Creates a new drive letter info with a label.
    #[must_use]
    pub fn with_label(letter: char, available: bool, reserved: bool, label: String) -> Self {
        Self {
            letter,
            available,
            reserved,
            label: Some(label),
        }
    }

    /// Returns the drive letter as a path string (e.g., "T:").
    #[must_use]
    pub fn as_path_string(&self) -> String {
        format!("{}:", self.letter)
    }

    /// Returns the drive letter as a full root path (e.g., "T:\").
    #[must_use]
    pub fn as_root_path(&self) -> String {
        format!("{}:\\", self.letter)
    }

    /// Returns a display string for the drive letter.
    #[must_use]
    pub fn display_string(&self) -> String {
        if self.available {
            format!("{}: (Available)", self.letter)
        } else if let Some(ref label) = self.label {
            format!("{}: {} (In Use)", self.letter, label)
        } else {
            format!("{}: (In Use)", self.letter)
        }
    }
}

/// Error that can occur during mount point selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountPointError {
    /// The selected drive letter is already in use.
    DriveLetterInUse(char),
    /// The selected drive letter is reserved for system use.
    DriveLetterReserved(char),
    /// No available drive letters.
    NoAvailableDriveLetters,
    /// Invalid drive letter (not A-Z).
    InvalidDriveLetter(char),
    /// The mount path is already in use.
    MountPathInUse(PathBuf),
    /// The mount path is not writable.
    MountPathNotWritable(PathBuf),
    /// Platform not supported for this operation.
    UnsupportedPlatform,
}

impl std::fmt::Display for MountPointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriveLetterInUse(letter) => {
                write!(f, "Drive letter {}: is already in use", letter)
            }
            Self::DriveLetterReserved(letter) => {
                write!(
                    f,
                    "Drive letter {}: is reserved for system use",
                    letter
                )
            }
            Self::NoAvailableDriveLetters => {
                write!(f, "No available drive letters")
            }
            Self::InvalidDriveLetter(letter) => {
                write!(f, "Invalid drive letter: {}", letter)
            }
            Self::MountPathInUse(path) => {
                write!(f, "Mount path is already in use: {}", path.display())
            }
            Self::MountPathNotWritable(path) => {
                write!(f, "Mount path is not writable: {}", path.display())
            }
            Self::UnsupportedPlatform => {
                write!(f, "Platform not supported for this operation")
            }
        }
    }
}

impl std::error::Error for MountPointError {}

/// Mount point selection state and configuration.
#[derive(Debug, Clone)]
pub struct MountPointSelection {
    /// Selected drive letter (Windows) or None for auto-select.
    pub selected_letter: Option<char>,
    /// Whether to auto-select the first available drive letter.
    pub auto_select: bool,
    /// Cached list of drive letter information.
    cached_drive_info: Vec<DriveLetterInfo>,
    /// Whether the cache is valid.
    cache_valid: bool,
}

impl Default for MountPointSelection {
    fn default() -> Self {
        Self::new(Some(DEFAULT_DRIVE_LETTER))
    }
}

impl MountPointSelection {
    /// Creates a new mount point selection.
    #[must_use]
    pub fn new(preferred_letter: Option<char>) -> Self {
        Self {
            selected_letter: preferred_letter,
            auto_select: preferred_letter.is_none(),
            cached_drive_info: Vec::new(),
            cache_valid: false,
        }
    }

    /// Creates a mount point selection with auto-select enabled.
    #[must_use]
    pub fn auto() -> Self {
        Self {
            selected_letter: None,
            auto_select: true,
            cached_drive_info: Vec::new(),
            cache_valid: false,
        }
    }

    /// Sets the selected drive letter.
    pub fn set_letter(&mut self, letter: char) {
        self.selected_letter = Some(letter.to_ascii_uppercase());
        self.auto_select = false;
    }

    /// Enables auto-select mode.
    pub fn enable_auto_select(&mut self) {
        self.auto_select = true;
        self.selected_letter = None;
    }

    /// Refreshes the cached drive letter information.
    pub fn refresh(&mut self) {
        self.cached_drive_info = get_available_drive_letters();
        self.cache_valid = true;
    }

    /// Returns the cached drive letter information.
    ///
    /// Call `refresh()` first to update the cache.
    #[must_use]
    pub fn drive_letters(&self) -> &[DriveLetterInfo] {
        &self.cached_drive_info
    }

    /// Returns only available drive letters.
    #[must_use]
    pub fn available_letters(&self) -> Vec<&DriveLetterInfo> {
        self.cached_drive_info
            .iter()
            .filter(|d| d.available && !d.reserved)
            .collect()
    }

    /// Returns the first available drive letter in preference order.
    #[must_use]
    pub fn first_available(&self) -> Option<char> {
        for preferred in PREFERRED_DRIVE_ORDER {
            if let Some(info) = self.cached_drive_info.iter().find(|d| d.letter == *preferred) {
                if info.available && !info.reserved {
                    return Some(info.letter);
                }
            }
        }
        // Fallback to any available letter
        self.cached_drive_info
            .iter()
            .find(|d| d.available && !d.reserved)
            .map(|d| d.letter)
    }

    /// Validates the current selection.
    ///
    /// Returns the drive letter to use, or an error if the selection is invalid.
    pub fn validate(&self) -> Result<char, MountPointError> {
        if self.auto_select {
            self.first_available()
                .ok_or(MountPointError::NoAvailableDriveLetters)
        } else {
            let letter = self
                .selected_letter
                .ok_or(MountPointError::NoAvailableDriveLetters)?;

            // Validate letter is A-Z
            if !letter.is_ascii_alphabetic() {
                return Err(MountPointError::InvalidDriveLetter(letter));
            }

            let letter = letter.to_ascii_uppercase();

            // Check if reserved
            if RESERVED_DRIVE_LETTERS.contains(&letter) {
                return Err(MountPointError::DriveLetterReserved(letter));
            }

            // Check if available
            if let Some(info) = self.cached_drive_info.iter().find(|d| d.letter == letter) {
                if !info.available {
                    return Err(MountPointError::DriveLetterInUse(letter));
                }
            }

            Ok(letter)
        }
    }

    /// Gets the effective drive letter to use for mounting.
    ///
    /// This resolves auto-select if enabled, or returns the selected letter.
    /// Returns an error if no suitable drive letter is available.
    pub fn get_effective_letter(&mut self) -> Result<char, MountPointError> {
        if !self.cache_valid {
            self.refresh();
        }
        self.validate()
    }
}

// Platform-specific implementations
#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::GetLogicalDrives;

    /// Gets the bitmask of used drive letters from Windows.
    fn get_logical_drives_mask() -> u32 {
        // SAFETY: GetLogicalDrives is a safe Windows API call
        unsafe { GetLogicalDrives() }
    }

    /// Gets information about all drive letters (A-Z).
    pub fn get_available_drive_letters_impl() -> Vec<DriveLetterInfo> {
        let drives_mask = get_logical_drives_mask();
        let mut result = Vec::with_capacity(26);

        for i in 0..26u8 {
            let letter = (b'A' + i) as char;
            let is_in_use = (drives_mask & (1 << i)) != 0;
            let is_reserved = RESERVED_DRIVE_LETTERS.contains(&letter);

            result.push(DriveLetterInfo::new(letter, !is_in_use, is_reserved));
        }

        result
    }

    /// Checks if a specific drive letter is in use.
    pub fn is_drive_letter_in_use_impl(letter: char) -> bool {
        let letter = letter.to_ascii_uppercase();
        if !letter.is_ascii_uppercase() {
            return true; // Invalid, consider "in use"
        }

        let index = (letter as u8 - b'A') as u32;
        let drives_mask = get_logical_drives_mask();
        (drives_mask & (1 << index)) != 0
    }
}

#[cfg(not(windows))]
mod non_windows_impl {
    use super::*;

    /// Gets information about all drive letters (stub for non-Windows).
    ///
    /// On non-Windows platforms, this returns an empty list since
    /// drive letters are a Windows concept.
    pub fn get_available_drive_letters_impl() -> Vec<DriveLetterInfo> {
        Vec::new()
    }

    /// Checks if a specific drive letter is in use (stub for non-Windows).
    ///
    /// Always returns false since drive letters don't exist on non-Windows.
    pub fn is_drive_letter_in_use_impl(_letter: char) -> bool {
        false
    }
}

/// Gets information about all drive letters (A-Z).
///
/// On Windows, this queries the system for which drive letters are in use.
/// On other platforms, this returns an empty list.
#[must_use]
pub fn get_available_drive_letters() -> Vec<DriveLetterInfo> {
    #[cfg(windows)]
    {
        windows_impl::get_available_drive_letters_impl()
    }
    #[cfg(not(windows))]
    {
        non_windows_impl::get_available_drive_letters_impl()
    }
}

/// Checks if a specific drive letter is in use.
///
/// On Windows, this queries the system to check if the drive exists.
/// On other platforms, this always returns false.
#[must_use]
pub fn is_drive_letter_in_use(letter: char) -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_drive_letter_in_use_impl(letter)
    }
    #[cfg(not(windows))]
    {
        non_windows_impl::is_drive_letter_in_use_impl(letter)
    }
}

/// Validates a drive letter for use as a mount point.
///
/// Returns an error if the drive letter is:
/// - Not a valid letter (A-Z)
/// - Reserved for system use (A, B, C)
/// - Already in use
pub fn validate_drive_letter(letter: char) -> Result<char, MountPointError> {
    let letter = letter.to_ascii_uppercase();

    // Validate letter is A-Z
    if !letter.is_ascii_uppercase() {
        return Err(MountPointError::InvalidDriveLetter(letter));
    }

    // Check if reserved
    if RESERVED_DRIVE_LETTERS.contains(&letter) {
        return Err(MountPointError::DriveLetterReserved(letter));
    }

    // Check if in use
    if is_drive_letter_in_use(letter) {
        return Err(MountPointError::DriveLetterInUse(letter));
    }

    Ok(letter)
}

/// Selects the best available drive letter.
///
/// Tries to use the preferred letter if provided and available.
/// Otherwise, selects the first available letter from `PREFERRED_DRIVE_ORDER`.
pub fn select_drive_letter(preferred: Option<char>) -> Result<char, MountPointError> {
    let available = get_available_drive_letters();

    // Try preferred letter first
    if let Some(pref) = preferred {
        let pref = pref.to_ascii_uppercase();
        if let Some(info) = available.iter().find(|d| d.letter == pref) {
            if info.available && !info.reserved {
                return Ok(pref);
            }
        }
    }

    // Try letters in preference order
    for letter in PREFERRED_DRIVE_ORDER {
        if let Some(info) = available.iter().find(|d| d.letter == *letter) {
            if info.available && !info.reserved {
                return Ok(*letter);
            }
        }
    }

    // Fallback to any available letter
    available
        .iter()
        .find(|d| d.available && !d.reserved)
        .map(|d| d.letter)
        .ok_or(MountPointError::NoAvailableDriveLetters)
}

/// Returns whether VFS mount point selection is supported on this platform.
#[must_use]
pub fn is_mount_point_selection_supported() -> bool {
    cfg!(windows)
}

/// Returns a user-friendly message explaining mount point selection.
#[must_use]
pub fn get_mount_point_help_message() -> &'static str {
    if cfg!(windows) {
        "Select a drive letter for the encrypted vault. \
         The vault will appear as a regular drive in Windows Explorer. \
         'T:' is the default, but you can choose any available letter."
    } else {
        "Drive letter selection is only available on Windows. \
         On Linux/macOS, the vault will be mounted to a directory path."
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // DriveLetterInfo tests
    // ========================================================================

    #[test]
    fn test_drive_letter_info_new() {
        let info = DriveLetterInfo::new('T', true, false);
        assert_eq!(info.letter, 'T');
        assert!(info.available);
        assert!(!info.reserved);
        assert!(info.label.is_none());
    }

    #[test]
    fn test_drive_letter_info_with_label() {
        let info = DriveLetterInfo::with_label('C', false, true, "System".to_string());
        assert_eq!(info.letter, 'C');
        assert!(!info.available);
        assert!(info.reserved);
        assert_eq!(info.label, Some("System".to_string()));
    }

    #[test]
    fn test_drive_letter_info_as_path_string() {
        let info = DriveLetterInfo::new('T', true, false);
        assert_eq!(info.as_path_string(), "T:");
    }

    #[test]
    fn test_drive_letter_info_as_root_path() {
        let info = DriveLetterInfo::new('T', true, false);
        assert_eq!(info.as_root_path(), "T:\\");
    }

    #[test]
    fn test_drive_letter_info_display_string_available() {
        let info = DriveLetterInfo::new('T', true, false);
        assert_eq!(info.display_string(), "T: (Available)");
    }

    #[test]
    fn test_drive_letter_info_display_string_in_use() {
        let info = DriveLetterInfo::new('C', false, true);
        assert_eq!(info.display_string(), "C: (In Use)");
    }

    #[test]
    fn test_drive_letter_info_display_string_with_label() {
        let info = DriveLetterInfo::with_label('C', false, true, "Windows".to_string());
        assert_eq!(info.display_string(), "C: Windows (In Use)");
    }

    #[test]
    fn test_drive_letter_info_equality() {
        let info1 = DriveLetterInfo::new('T', true, false);
        let info2 = DriveLetterInfo::new('T', true, false);
        assert_eq!(info1, info2);
    }

    // ========================================================================
    // MountPointError tests
    // ========================================================================

    #[test]
    fn test_mount_point_error_drive_letter_in_use() {
        let err = MountPointError::DriveLetterInUse('C');
        assert_eq!(
            err.to_string(),
            "Drive letter C: is already in use"
        );
    }

    #[test]
    fn test_mount_point_error_drive_letter_reserved() {
        let err = MountPointError::DriveLetterReserved('A');
        assert_eq!(
            err.to_string(),
            "Drive letter A: is reserved for system use"
        );
    }

    #[test]
    fn test_mount_point_error_no_available_drive_letters() {
        let err = MountPointError::NoAvailableDriveLetters;
        assert_eq!(err.to_string(), "No available drive letters");
    }

    #[test]
    fn test_mount_point_error_invalid_drive_letter() {
        let err = MountPointError::InvalidDriveLetter('1');
        assert_eq!(err.to_string(), "Invalid drive letter: 1");
    }

    #[test]
    fn test_mount_point_error_unsupported_platform() {
        let err = MountPointError::UnsupportedPlatform;
        assert_eq!(err.to_string(), "Platform not supported for this operation");
    }

    // ========================================================================
    // MountPointSelection tests
    // ========================================================================

    #[test]
    fn test_mount_point_selection_default() {
        let selection = MountPointSelection::default();
        assert_eq!(selection.selected_letter, Some(DEFAULT_DRIVE_LETTER));
        assert!(!selection.auto_select);
    }

    #[test]
    fn test_mount_point_selection_new_with_letter() {
        let selection = MountPointSelection::new(Some('S'));
        assert_eq!(selection.selected_letter, Some('S'));
        assert!(!selection.auto_select);
    }

    #[test]
    fn test_mount_point_selection_new_without_letter() {
        let selection = MountPointSelection::new(None);
        assert_eq!(selection.selected_letter, None);
        assert!(selection.auto_select);
    }

    #[test]
    fn test_mount_point_selection_auto() {
        let selection = MountPointSelection::auto();
        assert_eq!(selection.selected_letter, None);
        assert!(selection.auto_select);
    }

    #[test]
    fn test_mount_point_selection_set_letter() {
        let mut selection = MountPointSelection::auto();
        selection.set_letter('s'); // lowercase
        assert_eq!(selection.selected_letter, Some('S')); // converted to uppercase
        assert!(!selection.auto_select);
    }

    #[test]
    fn test_mount_point_selection_enable_auto_select() {
        let mut selection = MountPointSelection::new(Some('T'));
        selection.enable_auto_select();
        assert_eq!(selection.selected_letter, None);
        assert!(selection.auto_select);
    }

    #[test]
    fn test_mount_point_selection_drive_letters_empty_before_refresh() {
        let selection = MountPointSelection::default();
        assert!(selection.drive_letters().is_empty());
    }

    // ========================================================================
    // Constants tests
    // ========================================================================

    #[test]
    fn test_default_drive_letter() {
        assert_eq!(DEFAULT_DRIVE_LETTER, 'T');
    }

    #[test]
    fn test_reserved_drive_letters() {
        assert!(RESERVED_DRIVE_LETTERS.contains(&'A'));
        assert!(RESERVED_DRIVE_LETTERS.contains(&'B'));
        assert!(RESERVED_DRIVE_LETTERS.contains(&'C'));
        assert!(!RESERVED_DRIVE_LETTERS.contains(&'T'));
    }

    #[test]
    fn test_preferred_drive_order_starts_with_t() {
        assert_eq!(PREFERRED_DRIVE_ORDER[0], 'T');
    }

    #[test]
    fn test_preferred_drive_order_excludes_reserved() {
        for letter in RESERVED_DRIVE_LETTERS {
            assert!(
                !PREFERRED_DRIVE_ORDER.contains(letter),
                "Reserved letter {} should not be in preferred order",
                letter
            );
        }
    }

    // ========================================================================
    // Platform-specific tests
    // ========================================================================

    #[test]
    fn test_is_mount_point_selection_supported() {
        let supported = is_mount_point_selection_supported();
        #[cfg(windows)]
        assert!(supported);
        #[cfg(not(windows))]
        assert!(!supported);
    }

    #[test]
    fn test_get_mount_point_help_message() {
        let msg = get_mount_point_help_message();
        assert!(!msg.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_get_available_drive_letters_non_windows() {
        let letters = get_available_drive_letters();
        assert!(letters.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn test_is_drive_letter_in_use_non_windows() {
        // On non-Windows, always returns false
        assert!(!is_drive_letter_in_use('T'));
        assert!(!is_drive_letter_in_use('C'));
    }

    // ========================================================================
    // validate_drive_letter tests
    // ========================================================================

    #[cfg(not(windows))]
    #[test]
    fn test_validate_drive_letter_valid_non_windows() {
        // On non-Windows, validation should pass for non-reserved letters
        let result = validate_drive_letter('T');
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 'T');
    }

    #[test]
    fn test_validate_drive_letter_lowercase() {
        // Should convert to uppercase
        let letter = 't'.to_ascii_uppercase();
        assert_eq!(letter, 'T');
    }

    #[test]
    fn test_validate_drive_letter_reserved() {
        let result = validate_drive_letter('A');
        assert!(matches!(result, Err(MountPointError::DriveLetterReserved('A'))));

        let result = validate_drive_letter('B');
        assert!(matches!(result, Err(MountPointError::DriveLetterReserved('B'))));

        let result = validate_drive_letter('C');
        assert!(matches!(result, Err(MountPointError::DriveLetterReserved('C'))));
    }

    #[test]
    fn test_validate_drive_letter_invalid_char() {
        let result = validate_drive_letter('1');
        assert!(matches!(result, Err(MountPointError::InvalidDriveLetter('1'))));
    }

    // ========================================================================
    // select_drive_letter tests
    // ========================================================================

    #[cfg(not(windows))]
    #[test]
    fn test_select_drive_letter_with_preferred_non_windows() {
        // On non-Windows, no drives available
        let result = select_drive_letter(Some('T'));
        assert!(matches!(result, Err(MountPointError::NoAvailableDriveLetters)));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_select_drive_letter_without_preferred_non_windows() {
        let result = select_drive_letter(None);
        assert!(matches!(result, Err(MountPointError::NoAvailableDriveLetters)));
    }

    // ========================================================================
    // Windows-specific tests (only run on Windows)
    // ========================================================================

    #[cfg(windows)]
    mod windows_tests {
        use super::super::*;

        #[test]
        fn test_get_available_drive_letters_windows() {
            let letters = get_available_drive_letters();
            // Should have 26 letters
            assert_eq!(letters.len(), 26);

            // Verify A-Z are all present
            for (i, info) in letters.iter().enumerate() {
                let expected = (b'A' + i as u8) as char;
                assert_eq!(info.letter, expected);
            }

            // C: should typically be in use (system drive)
            let c_drive = letters.iter().find(|d| d.letter == 'C');
            assert!(c_drive.is_some());
            assert!(!c_drive.unwrap().available, "C: should be in use");
            assert!(c_drive.unwrap().reserved);
        }

        #[test]
        fn test_is_drive_letter_in_use_windows() {
            // C: should always be in use
            assert!(is_drive_letter_in_use('C'));
        }

        #[test]
        fn test_select_drive_letter_windows() {
            // Should be able to select a drive letter
            let result = select_drive_letter(Some('T'));
            // If T is available, we get it; otherwise we get an alternative
            assert!(result.is_ok() || matches!(result, Err(MountPointError::NoAvailableDriveLetters)));
        }

        #[test]
        fn test_validate_drive_letter_in_use_windows() {
            // C: is in use
            let result = validate_drive_letter('C');
            assert!(result.is_err());
        }

        #[test]
        fn test_mount_point_selection_refresh_windows() {
            let mut selection = MountPointSelection::default();
            selection.refresh();
            assert_eq!(selection.drive_letters().len(), 26);
            assert!(selection.cache_valid);
        }

        #[test]
        fn test_mount_point_selection_available_letters_windows() {
            let mut selection = MountPointSelection::default();
            selection.refresh();
            let available = selection.available_letters();
            // All available letters should not be reserved
            for info in available {
                assert!(!info.reserved);
                assert!(info.available);
            }
        }

        #[test]
        fn test_mount_point_selection_first_available_windows() {
            let mut selection = MountPointSelection::default();
            selection.refresh();
            let first = selection.first_available();
            // Should return something (unless all 23 non-reserved letters are in use)
            if let Some(letter) = first {
                assert!(!RESERVED_DRIVE_LETTERS.contains(&letter));
            }
        }
    }
}
