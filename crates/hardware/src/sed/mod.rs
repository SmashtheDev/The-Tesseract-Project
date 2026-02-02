//! Self-Encrypting Drive (SED) support.
//!
//! This module provides support for TCG Opal 2.0 Self-Encrypting Drives.
//! When a drive supports hardware encryption, TESSERACT can use it for
//! an additional layer of protection.

pub mod opal;

pub use opal::{OpalDrive, OpalStatus};

use crate::error::Result;
use std::path::Path;

/// Check if a drive supports TCG Opal.
///
/// # Implementation Note
///
/// Full implementation in platform-specific stories (US-010, US-016, US-021).
pub fn is_opal_supported(device_path: &Path) -> Result<bool> {
    opal::query_opal_support(device_path)
}

/// Get the Opal status for a drive.
pub fn get_opal_status(device_path: &Path) -> Result<OpalStatus> {
    opal::get_opal_status(device_path)
}

/// Unlock a self-encrypting drive.
///
/// Attempts to unlock a TCG Opal drive using the provided password.
pub fn unlock_drive(device_path: &Path, password: &[u8]) -> Result<()> {
    let status = get_opal_status(device_path)?;
    let mut drive = OpalDrive::new(device_path.to_path_buf(), status);
    drive.unlock(password)
}

/// Initialize encryption on a drive.
///
/// Sets up TCG Opal encryption on a drive with the provided password.
pub fn initialize_drive(device_path: &Path, password: &[u8]) -> Result<()> {
    let status = get_opal_status(device_path)?;
    let mut drive = OpalDrive::new(device_path.to_path_buf(), status);
    drive.initialize(password)
}

/// Lock a self-encrypting drive.
///
/// Locks a TCG Opal drive, requiring password to unlock again.
pub fn lock_drive(device_path: &Path) -> Result<()> {
    let status = get_opal_status(device_path)?;
    let mut drive = OpalDrive::new(device_path.to_path_buf(), status);
    drive.lock()
}
