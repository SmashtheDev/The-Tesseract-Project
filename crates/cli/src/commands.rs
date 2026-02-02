//! CLI commands for TESSERACT.
//!
//! Provides subcommand implementations for the `tesseract-prepare` CLI tool.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};

use tesseract_packaging::{
    prepare_drive, get_install_info, is_installed,
    PrepareConfig, PrepareError,
};

/// TESSERACT USB Preparation Tool
///
/// Prepares removable drives for TESSERACT deployment by creating
/// the necessary directory structure and copying platform executables.
#[derive(Parser, Debug)]
#[command(name = "tesseract-prepare")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Prepare a USB drive for TESSERACT.
    Prepare(PrepareArgs),

    /// Check if TESSERACT is installed on a drive.
    Check(CheckArgs),

    /// Show installation info for a drive.
    Info(InfoArgs),
}

/// Arguments for the prepare command.
#[derive(Parser, Debug)]
pub struct PrepareArgs {
    /// Target device or mount point (e.g., /Volumes/USB, /mnt/usb, E:\).
    #[arg(required = true)]
    pub device: PathBuf,

    /// Skip removable drive validation (for testing on non-removable drives).
    #[arg(long)]
    pub skip_validation: bool,

    /// Force overwrite if TESSERACT is already installed.
    #[arg(short, long)]
    pub force: bool,

    /// Initialize an empty vault after preparation.
    #[arg(long)]
    pub init_vault: bool,

    /// Source directory containing platform executables.
    /// If not provided, creates placeholder files.
    #[arg(long)]
    pub executables: Option<PathBuf>,

    /// Version string to write to VERSION.txt.
    #[arg(long, default_value = env!("CARGO_PKG_VERSION"))]
    pub version: String,
}

/// Arguments for the check command.
#[derive(Parser, Debug)]
pub struct CheckArgs {
    /// Target device or mount point to check.
    #[arg(required = true)]
    pub device: PathBuf,
}

/// Arguments for the info command.
#[derive(Parser, Debug)]
pub struct InfoArgs {
    /// Target device or mount point to get info for.
    #[arg(required = true)]
    pub device: PathBuf,
}

/// Executes the CLI based on parsed arguments.
///
/// # Errors
///
/// Returns an error if the subcommand fails.
pub fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Prepare(args) => execute_prepare(args),
        Commands::Check(args) => execute_check(args),
        Commands::Info(args) => execute_info(args),
    }
}

/// Executes the prepare command.
fn execute_prepare(args: PrepareArgs) -> Result<()> {
    info!("Preparing USB drive: {:?}", args.device);

    let mut config = PrepareConfig::new(&args.device)
        .skip_validation(args.skip_validation)
        .force(args.force)
        .init_vault(args.init_vault)
        .version(&args.version);

    if let Some(executables) = args.executables {
        config = config.executables_source(executables);
    }

    match prepare_drive(&config) {
        Ok(result) => {
            println!("✓ USB drive preparation complete!");
            println!();
            println!("Created:");
            println!("  TESSERACT directory: {}", result.tesseract_dir.display());
            println!("  Vault directory:     {}", result.vault_dir.display());
            println!("  README:              {}", result.readme_path.display());
            println!();

            if result.vault_initialized {
                println!("  Vault initialized:   Yes");
            } else {
                println!("  Vault initialized:   No (will be set up on first run)");
            }

            if !result.warnings.is_empty() {
                println!();
                println!("Warnings:");
                for warning in &result.warnings {
                    warn!("{}", warning);
                    println!("  ⚠ {warning}");
                }
            }

            println!();
            println!("Next steps:");
            println!("  1. Safely eject the USB drive");
            println!("  2. Insert into target machine");
            println!("  3. Run TESSERACT from the TESSERACT directory");
            println!("  4. See {} for detailed instructions", result.readme_path.display());

            Ok(())
        }
        Err(PrepareError::AlreadyInstalled(path)) => {
            eprintln!("Error: TESSERACT is already installed at {}", path.display());
            eprintln!();
            eprintln!("Use --force to overwrite the existing installation.");
            std::process::exit(1);
        }
        Err(PrepareError::NotRemovable { path, drive_type }) => {
            eprintln!("Error: Target is not a removable drive");
            eprintln!();
            eprintln!("  Path: {}", path.display());
            eprintln!("  Detected type: {drive_type}");
            eprintln!();
            eprintln!("TESSERACT must be installed on a removable drive (USB/SD card).");
            eprintln!("Use --skip-validation to override (for testing only).");
            std::process::exit(1);
        }
        Err(PrepareError::PathNotFound(path)) => {
            eprintln!("Error: Target path does not exist: {}", path.display());
            eprintln!();
            eprintln!("Make sure the USB drive is mounted and accessible.");
            std::process::exit(1);
        }
        Err(e) => {
            Err(e).context("Failed to prepare USB drive")
        }
    }
}

/// Executes the check command.
fn execute_check(args: CheckArgs) -> Result<()> {
    if is_installed(&args.device) {
        println!("✓ TESSERACT is installed on {}", args.device.display());
        Ok(())
    } else {
        println!("✗ TESSERACT is NOT installed on {}", args.device.display());
        std::process::exit(1);
    }
}

/// Executes the info command.
fn execute_info(args: InfoArgs) -> Result<()> {
    match get_install_info(&args.device) {
        Some(info) => {
            println!("TESSERACT Installation Info");
            println!("===========================");
            println!();
            println!("TESSERACT directory: {}", info.tesseract_dir.display());

            if let Some(vault_dir) = &info.vault_dir {
                println!("Vault directory:     {}", vault_dir.display());
            } else {
                println!("Vault directory:     Not found");
            }

            if let Some(version) = &info.version {
                println!("Version:             {version}");
            } else {
                println!("Version:             Unknown");
            }

            println!();
            println!("Platform Executables:");
            println!("  Windows (.exe):    {}", if info.has_windows { "✓" } else { "✗" });
            println!("  Linux (AppImage):  {}", if info.has_linux { "✓" } else { "✗" });
            println!("  macOS (.app):      {}", if info.has_macos { "✓" } else { "✗" });

            Ok(())
        }
        None => {
            eprintln!("Error: TESSERACT is not installed on {}", args.device.display());
            eprintln!();
            eprintln!("Use 'tesseract-prepare prepare <device>' to install.");
            std::process::exit(1);
        }
    }
}

/// Initializes logging based on verbosity.
pub fn init_logging(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_prepare() {
        let cli = Cli::parse_from([
            "tesseract-prepare",
            "prepare",
            "/mnt/usb",
            "--force",
            "--skip-validation",
        ]);

        match cli.command {
            Commands::Prepare(args) => {
                assert_eq!(args.device, PathBuf::from("/mnt/usb"));
                assert!(args.force);
                assert!(args.skip_validation);
                assert!(!args.init_vault);
            }
            _ => panic!("Expected Prepare command"),
        }
    }

    #[test]
    fn test_cli_parse_prepare_with_init_vault() {
        let cli = Cli::parse_from([
            "tesseract-prepare",
            "prepare",
            "/Volumes/USB",
            "--init-vault",
            "--version",
            "2.0.0",
        ]);

        match cli.command {
            Commands::Prepare(args) => {
                assert_eq!(args.device, PathBuf::from("/Volumes/USB"));
                assert!(args.init_vault);
                assert_eq!(args.version, "2.0.0");
            }
            _ => panic!("Expected Prepare command"),
        }
    }

    #[test]
    fn test_cli_parse_prepare_with_executables() {
        let cli = Cli::parse_from([
            "tesseract-prepare",
            "prepare",
            "E:\\",
            "--executables",
            "/path/to/exes",
        ]);

        match cli.command {
            Commands::Prepare(args) => {
                assert_eq!(args.device, PathBuf::from("E:\\"));
                assert_eq!(args.executables, Some(PathBuf::from("/path/to/exes")));
            }
            _ => panic!("Expected Prepare command"),
        }
    }

    #[test]
    fn test_cli_parse_check() {
        let cli = Cli::parse_from([
            "tesseract-prepare",
            "check",
            "/dev/sdb1",
        ]);

        match cli.command {
            Commands::Check(args) => {
                assert_eq!(args.device, PathBuf::from("/dev/sdb1"));
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_cli_parse_info() {
        let cli = Cli::parse_from([
            "tesseract-prepare",
            "info",
            "/Volumes/MyUSB",
        ]);

        match cli.command {
            Commands::Info(args) => {
                assert_eq!(args.device, PathBuf::from("/Volumes/MyUSB"));
            }
            _ => panic!("Expected Info command"),
        }
    }

    #[test]
    fn test_cli_verbose_flag() {
        let cli = Cli::parse_from([
            "tesseract-prepare",
            "-v",
            "check",
            "/mnt/usb",
        ]);

        assert!(cli.verbose);
    }
}
