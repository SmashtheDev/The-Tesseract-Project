# TESSERACT

[![CI](https://github.com/OWNER/tesseract/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/tesseract/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Production-grade removable storage encryption with AES-256-GCM, multi-level access control, and seamless file system integration.

## Overview

TESSERACT is a portable encryption application designed for enterprise and government classified data protection. It provides:

- **AES-256-GCM** authenticated encryption with hardware acceleration
- **Argon2id** key derivation for password-based encryption
- **Four-tier key hierarchy** for defense in depth
- **Multi-level access control** with hierarchical visibility
- **Virtual filesystem integration** (Dokan/FUSE) for transparent encryption
- **Cross-platform GUI** for Windows, Linux, and macOS

## Security Features

- Zero plaintext metadata exposure
- Nonce collision prevention
- Secure memory handling with automatic key wiping
- Exponential backoff and lockout protection
- Recovery key support

## Project Structure

```
tesseract/
├── crates/
│   ├── core/       # Vault management, file operations
│   ├── crypto/     # Cryptographic primitives
│   ├── vfs/        # Virtual filesystem (FUSE/Dokan)
│   ├── gui/        # Cross-platform GUI (egui)
│   ├── cli/        # Command-line interface
│   └── packaging/  # USB prep, multi-platform bundling
├── docs/           # Documentation
└── tests/          # Integration tests
```

## Building

### Prerequisites

- Rust 1.75 or later
- Linux: `libfuse3-dev` and `pkg-config`
- Windows: Dokan or WinFsp driver (optional, for VFS)
- macOS: macFUSE (optional, for VFS)

### Build Commands

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Build release
cargo build --workspace --release

# Run clippy lints
cargo clippy --workspace -- -D warnings
```

## Usage

TESSERACT is designed to run from a removable USB drive. The application will refuse to run if launched from a fixed disk.

### Quick Start

1. Insert USB drive
2. Run TESSERACT executable from the USB
3. Create a new vault or open an existing one
4. Enter your password
5. Access your encrypted files through the built-in browser or mounted drive

## License

MIT License - see [LICENSE](LICENSE) for details.

## Downloads

Pre-built packages are available from [GitHub Actions](https://github.com/OWNER/tesseract/actions) artifacts:

| Platform | Format | Notes |
|----------|--------|-------|
| Windows x64 | `.exe` | Windows 10/11 x64 |
| Linux x64 | AppImage | Ubuntu 22.04+, Fedora 38+ |
| macOS | `.app` bundle | macOS 12 (Monterey)+ |

To download:
1. Go to the [Actions](https://github.com/OWNER/tesseract/actions) tab
2. Click on the latest successful workflow run
3. Download the artifact for your platform from the "Artifacts" section

## Status

This project is under active development. See [CHANGELOG.md](CHANGELOG.md) for version history.
