//! TESSERACT Command-Line Interface
//!
//! Provides CLI access to vault operations and USB preparation.
//!
//! # Usage
//!
//! ## USB Preparation
//!
//! ```bash
//! # Prepare a USB drive for TESSERACT
//! tesseract-prepare prepare /mnt/usb
//!
//! # Check if TESSERACT is installed
//! tesseract-prepare check /mnt/usb
//!
//! # Get installation info
//! tesseract-prepare info /mnt/usb
//! ```
//!
//! ## Options
//!
//! - `--skip-validation` - Skip removable drive check (testing only)
//! - `--force` - Overwrite existing installation
//! - `--init-vault` - Create vault directory structure
//! - `--executables <path>` - Source directory for platform executables
//! - `--version <version>` - Version string to embed

#![warn(missing_docs)]
#![warn(clippy::all)]

/// CLI commands.
pub mod commands;

// Re-export for convenience
pub use commands::{Cli, Commands, execute, init_logging};
