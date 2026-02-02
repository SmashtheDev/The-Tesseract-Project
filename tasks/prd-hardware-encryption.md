# PRD: Tesseract Hardware Encryption

## Introduction

Add hardware-level encryption to Tesseract, creating a triple-layer security model that protects USB drives at the hardware level (Layer 1), vault level (Layer 2), and file access level (Layer 3). This feature enables true "plug and authenticate" security where encrypted drives require a password before any data is accessible, while preserving Tesseract's existing multi-level access control system.

The implementation uses a custom Tesseract Hardware Container (THC) format for software-based full-disk encryption on all platforms, with optional TCG Opal 2.0 support for Self-Encrypting Drives. A single master password unlocks the drive and vault layers, while separate passwords control access to each security level (1-4).

## Goals

- Encrypt entire USB drives with AES-256-XTS at the hardware/container level
- Support all USB drives (SED and non-SED) across Linux, Windows, and macOS
- Maintain single master password for drive + vault unlock
- Preserve existing 4-tier access level system with independent passwords
- Provide seamless GUI integration with drive detection and setup wizards
- Auto-detect TCG Opal 2.0 capable drives and utilize hardware encryption
- Create portable, cross-platform THC container format for non-SED drives

## User Stories

### Phase 1: Core Infrastructure

#### US-001: Create tesseract-hardware crate structure
**Description:** As a developer, I need the foundational crate structure for hardware encryption so that platform-specific implementations can be built on top.

**Acceptance Criteria:**
- [ ] Create `crates/hardware/` directory with Cargo.toml
- [ ] Add crate to workspace in root Cargo.toml
- [ ] Create module structure: lib.rs, error.rs, detect.rs, container.rs, crypto.rs
- [ ] Create platform module stubs: platform/mod.rs, linux.rs, windows.rs, macos.rs
- [ ] Create SED module stubs: sed/mod.rs, opal.rs
- [ ] Define public API traits and types in lib.rs
- [ ] Crate compiles with `cargo build`

#### US-002: Implement AES-256-XTS encryption for containers
**Description:** As a developer, I need AES-256-XTS encryption support so that drive containers can be encrypted with sector-level encryption.

**Acceptance Criteria:**
- [ ] Add aes and xts-mode dependencies to tesseract-crypto crate
- [ ] Implement `Xts256` struct with encrypt_sector/decrypt_sector methods
- [ ] Sector size configurable (default 512 bytes)
- [ ] Support sector number as tweak value
- [ ] Unit tests pass for encrypt/decrypt round-trip
- [ ] Unit tests pass for known test vectors
- [ ] Typecheck passes

#### US-003: Define THC container header format
**Description:** As a developer, I need a standardized header format for Tesseract Hardware Containers so that encrypted drives can be identified and unlocked.

**Acceptance Criteria:**
- [ ] Define `ThcHeader` struct with all fields (magic, version, cipher, KDF params, salt, encrypted master key, MAC)
- [ ] Implement `ThcHeader::new()` to create header with given password
- [ ] Implement `ThcHeader::to_bytes()` serialization (4096 bytes total)
- [ ] Implement `ThcHeader::from_bytes()` deserialization with validation
- [ ] Implement `ThcHeader::unlock()` to derive and verify master key
- [ ] Magic bytes: "TESS-HWC\0" (8 bytes)
- [ ] Header MAC verification prevents tampering
- [ ] Unit tests for serialization round-trip
- [ ] Typecheck passes

#### US-004: Implement dual-key derivation from master password
**Description:** As a developer, I need to derive separate hardware and vault keys from a single master password so that one password unlocks both layers securely.

**Acceptance Criteria:**
- [ ] Implement `derive_dual_keys(password, hw_salt, vault_salt, params)` function
- [ ] Use Argon2id for initial key derivation
- [ ] Use HKDF-SHA256 to derive hardware key with context "TESSERACT-HARDWARE-KEY"
- [ ] Use HKDF-SHA256 to derive vault key with context "TESSERACT-SOFTWARE-KEY"
- [ ] Keys are cryptographically independent (compromising one doesn't reveal other)
- [ ] Add HKDF implementation to tesseract-crypto if not present
- [ ] Unit tests verify key independence
- [ ] Typecheck passes

#### US-005: Implement drive detection API
**Description:** As a developer, I need to detect connected USB drives and their capabilities so that the application can offer appropriate encryption options.

**Acceptance Criteria:**
- [ ] Define `DriveInfo` struct (path, size, vendor, model, serial, drive_type)
- [ ] Define `DriveType` enum (SedOpal, TesseractContainer, Unencrypted, Unknown)
- [ ] Implement `detect_drives()` -> `Vec<DriveInfo>` for current platform
- [ ] Detect if drive has THC header (check magic bytes)
- [ ] Return empty vec on unsupported platforms (graceful degradation)
- [ ] Unit tests with mock filesystem
- [ ] Typecheck passes

### Phase 2: Linux Implementation

#### US-006: Implement Linux drive enumeration
**Description:** As a Linux user, I need the application to detect my USB drives so that I can encrypt them.

**Acceptance Criteria:**
- [ ] Enumerate block devices from /sys/block/
- [ ] Filter to removable devices (check /sys/block/*/removable)
- [ ] Read device info from sysfs (vendor, model, size)
- [ ] Get mount points from /proc/mounts
- [ ] Detect partition layout (single partition vs multiple)
- [ ] Integration test with actual /sys filesystem
- [ ] Typecheck passes

#### US-007: Implement Linux THC container creation
**Description:** As a Linux user, I need to create an encrypted container on my USB drive so that the entire drive is protected.

**Acceptance Criteria:**
- [ ] Implement `create_container(device_path, password, params)` for Linux
- [ ] Write THC header to first 4096 bytes of device/partition
- [ ] Initialize encrypted data region with zeros
- [ ] Require confirmation before overwriting existing data
- [ ] Handle permission errors gracefully (suggest sudo)
- [ ] Progress callback for long operations
- [ ] Integration test (requires root or loop device)
- [ ] Typecheck passes

#### US-008: Implement Linux container unlock/mount
**Description:** As a Linux user, I need to unlock and mount my encrypted container so that I can access the encrypted filesystem.

**Acceptance Criteria:**
- [ ] Implement `unlock_container(device_path, password)` for Linux
- [ ] Read and validate THC header
- [ ] Derive decryption key from password
- [ ] Create loop device for container data region
- [ ] Set up dm-crypt mapping with derived key
- [ ] Mount filesystem to user-accessible location
- [ ] Return mount point path on success
- [ ] Handle incorrect password gracefully
- [ ] Typecheck passes

#### US-009: Implement Linux container lock/unmount
**Description:** As a Linux user, I need to lock my encrypted container so that data is protected when I'm done.

**Acceptance Criteria:**
- [ ] Implement `lock_container(mount_point)` for Linux
- [ ] Unmount filesystem cleanly
- [ ] Remove dm-crypt mapping
- [ ] Detach loop device
- [ ] Zeroize keys from memory
- [ ] Handle busy filesystem (files open) gracefully
- [ ] Typecheck passes

#### US-010: Implement Linux TCG Opal detection
**Description:** As a Linux user with an SED drive, I need the application to detect Opal capability so that hardware encryption can be used.

**Acceptance Criteria:**
- [ ] Query drive for TCG Opal support using sedutil-cli or ATA commands
- [ ] Detect Opal 2.0 feature set
- [ ] Check if drive is already initialized/locked
- [ ] Return OpalStatus enum (NotSupported, Uninitialized, Locked, Unlocked)
- [ ] Handle missing sedutil gracefully
- [ ] Typecheck passes

#### US-011: Implement Linux TCG Opal unlock
**Description:** As a Linux user with an Opal SED, I need to unlock my drive using hardware encryption so that it's accessible.

**Acceptance Criteria:**
- [ ] Implement `unlock_opal(device_path, password)` for Linux
- [ ] Use sedutil-cli to send unlock command
- [ ] Handle incorrect password (drive remains locked)
- [ ] Handle drive not initialized (return appropriate error)
- [ ] Verify drive is unlocked after command
- [ ] Typecheck passes

### Phase 3: Windows Implementation

#### US-012: Implement Windows drive enumeration
**Description:** As a Windows user, I need the application to detect my USB drives so that I can encrypt them.

**Acceptance Criteria:**
- [ ] Use Windows API to enumerate removable drives
- [ ] Get drive info (vendor, model, size, drive letter)
- [ ] Detect if drive is mounted/accessible
- [ ] Filter to USB/removable devices only
- [ ] Typecheck passes

#### US-013: Implement Windows THC container creation
**Description:** As a Windows user, I need to create an encrypted container on my USB drive.

**Acceptance Criteria:**
- [ ] Implement `create_container(device_path, password, params)` for Windows
- [ ] Write THC header using raw disk access
- [ ] Request admin privileges if needed
- [ ] Handle drive letter vs physical drive path
- [ ] Progress callback for long operations
- [ ] Typecheck passes

#### US-014: Implement Windows container unlock/mount
**Description:** As a Windows user, I need to unlock and mount my encrypted container as a drive letter.

**Acceptance Criteria:**
- [ ] Implement `unlock_container(device_path, password)` for Windows
- [ ] Read and validate THC header
- [ ] Mount decrypted container as virtual drive
- [ ] Assign available drive letter
- [ ] Return drive letter on success
- [ ] Handle incorrect password gracefully
- [ ] Typecheck passes

#### US-015: Implement Windows container lock/unmount
**Description:** As a Windows user, I need to lock my encrypted container when done.

**Acceptance Criteria:**
- [ ] Implement `lock_container(drive_letter)` for Windows
- [ ] Dismount virtual drive cleanly
- [ ] Release drive letter
- [ ] Zeroize keys from memory
- [ ] Handle files in use gracefully
- [ ] Typecheck passes

#### US-016: Implement Windows TCG Opal support
**Description:** As a Windows user with an SED drive, I need Opal detection and unlock support.

**Acceptance Criteria:**
- [ ] Detect TCG Opal capability on Windows
- [ ] Implement `unlock_opal(device_path, password)` for Windows
- [ ] Use sedutil.exe or Windows TCG API
- [ ] Handle missing dependencies gracefully
- [ ] Typecheck passes

### Phase 4: macOS Implementation

#### US-017: Implement macOS drive enumeration
**Description:** As a macOS user, I need the application to detect my USB drives.

**Acceptance Criteria:**
- [ ] Use DiskArbitration framework to enumerate drives
- [ ] Get drive info (vendor, model, size, mount point)
- [ ] Filter to external/removable devices
- [ ] Detect partition scheme
- [ ] Typecheck passes

#### US-018: Implement macOS THC container creation
**Description:** As a macOS user, I need to create an encrypted container on my USB drive.

**Acceptance Criteria:**
- [ ] Implement `create_container(device_path, password, params)` for macOS
- [ ] Write THC header using raw disk access
- [ ] Request authorization if needed
- [ ] Handle disk identifiers (/dev/diskN)
- [ ] Progress callback for long operations
- [ ] Typecheck passes

#### US-019: Implement macOS container unlock/mount
**Description:** As a macOS user, I need to unlock and mount my encrypted container.

**Acceptance Criteria:**
- [ ] Implement `unlock_container(device_path, password)` for macOS
- [ ] Read and validate THC header
- [ ] Mount decrypted container using hdiutil or FUSE
- [ ] Return mount point path
- [ ] Handle incorrect password gracefully
- [ ] Typecheck passes

#### US-020: Implement macOS container lock/unmount
**Description:** As a macOS user, I need to lock my encrypted container when done.

**Acceptance Criteria:**
- [ ] Implement `lock_container(mount_point)` for macOS
- [ ] Unmount cleanly using diskutil
- [ ] Zeroize keys from memory
- [ ] Handle files in use gracefully
- [ ] Typecheck passes

#### US-021: Implement macOS TCG Opal support
**Description:** As a macOS user with an SED drive, I need Opal detection and unlock support.

**Acceptance Criteria:**
- [ ] Detect TCG Opal capability on macOS
- [ ] Implement `unlock_opal(device_path, password)` for macOS
- [ ] Use sedutil or IOKit
- [ ] Handle SIP restrictions gracefully
- [ ] Typecheck passes

### Phase 5: GUI Integration

#### US-022: Add drive detection screen
**Description:** As a user, I want to see connected USB drives so that I can choose which one to encrypt.

**Acceptance Criteria:**
- [ ] New "Drives" screen accessible from main menu
- [ ] Lists all detected USB drives with info (name, size, status)
- [ ] Shows encryption status icon (locked, unlocked, unencrypted)
- [ ] "Refresh" button to rescan drives
- [ ] "Initialize" button for unencrypted drives
- [ ] "Unlock" button for locked drives
- [ ] Typecheck passes

#### US-023: Add hardware unlock dialog
**Description:** As a user, I want a password prompt when I select a locked drive so that I can unlock it.

**Acceptance Criteria:**
- [ ] Modal dialog appears for locked drives
- [ ] Password field with show/hide toggle
- [ ] "Unlock Drive & Vault" button
- [ ] Progress indicator during unlock (Argon2 takes time)
- [ ] Error message for incorrect password
- [ ] Success transitions to vault file browser
- [ ] Typecheck passes

#### US-024: Add drive initialization wizard
**Description:** As a user, I want a step-by-step wizard to set up encryption on a new drive.

**Acceptance Criteria:**
- [ ] Step 1: Drive selection with size and info display
- [ ] Step 2: Master password entry with strength meter
- [ ] Step 3: Access level configuration (names and passwords for levels 1-4)
- [ ] Step 4: Encryption strength selection (Standard/High/Maximum)
- [ ] Step 5: Confirmation with warning about data loss
- [ ] Step 6: Progress display during initialization
- [ ] Step 7: Success screen with recovery key display
- [ ] Back/Next navigation between steps
- [ ] Cancel aborts without changes
- [ ] Typecheck passes

#### US-025: Add drive status to main window
**Description:** As a user, I want to see the current drive status in the main window so I know if my drive is protected.

**Acceptance Criteria:**
- [ ] Status bar shows current drive (if any)
- [ ] Shows lock/unlock status with icon
- [ ] Shows drive name and size
- [ ] "Lock Drive" button when unlocked
- [ ] "Eject" button for safe removal
- [ ] Typecheck passes

#### US-026: Integrate hardware unlock with vault open flow
**Description:** As a user, I want opening a vault on an encrypted drive to automatically unlock the drive first.

**Acceptance Criteria:**
- [ ] Detect if selected vault is on encrypted drive
- [ ] If drive locked, show hardware unlock first
- [ ] Use same password for drive and vault unlock (dual key derivation)
- [ ] Single password entry unlocks both layers seamlessly
- [ ] Then proceed to access level selection
- [ ] Typecheck passes

#### US-027: Add auto-lock on drive removal
**Description:** As a user, I want the vault to auto-lock if I remove the drive so that my data stays protected.

**Acceptance Criteria:**
- [ ] Monitor for drive disconnect events
- [ ] On disconnect: immediately lock vault session
- [ ] Clear all keys from memory
- [ ] Show notification "Drive removed - vault locked"
- [ ] Return to welcome/drive selection screen
- [ ] Typecheck passes

#### US-028: Add drive password change functionality
**Description:** As a user, I want to change my drive master password so that I can update security credentials.

**Acceptance Criteria:**
- [ ] "Change Master Password" option in settings (when drive unlocked)
- [ ] Requires current password verification
- [ ] New password with confirmation field
- [ ] Password strength requirements enforced
- [ ] Re-encrypts drive header with new key
- [ ] Success confirmation message
- [ ] Typecheck passes

### Phase 6: Integration & Polish

#### US-029: Implement unified error handling
**Description:** As a developer, I need consistent error handling across all hardware operations so that users get clear feedback.

**Acceptance Criteria:**
- [ ] Define `HardwareError` enum with all error cases
- [ ] Map platform-specific errors to common types
- [ ] Include actionable error messages (e.g., "Run as administrator")
- [ ] Errors propagate cleanly to GUI
- [ ] Typecheck passes

#### US-030: Add comprehensive logging
**Description:** As a developer, I need detailed logging for hardware operations to debug issues.

**Acceptance Criteria:**
- [ ] Log all drive detection events
- [ ] Log unlock/lock operations (without passwords)
- [ ] Log errors with context
- [ ] Use tracing crate consistently
- [ ] Configurable log levels
- [ ] Typecheck passes

#### US-031: Implement secure key cleanup
**Description:** As a security feature, keys must be zeroized when no longer needed so that memory doesn't retain sensitive data.

**Acceptance Criteria:**
- [ ] All key material uses `Zeroizing<>` wrapper
- [ ] Keys cleared on lock operation
- [ ] Keys cleared on application exit
- [ ] Keys cleared on drive removal
- [ ] Verify with memory inspection in tests
- [ ] Typecheck passes

#### US-032: Add hardware encryption documentation
**Description:** As a user, I need documentation explaining the hardware encryption feature so that I understand how to use it.

**Acceptance Criteria:**
- [ ] Update user manual with hardware encryption section
- [ ] Document setup wizard steps
- [ ] Document daily unlock workflow
- [ ] Document password recovery process
- [ ] Document supported drive types
- [ ] Include security model explanation
- [ ] Typecheck passes (docs build)

#### US-033: Cross-platform build and test verification
**Description:** As a developer, I need CI/CD verification that hardware encryption builds on all platforms.

**Acceptance Criteria:**
- [ ] Crate compiles on Linux (x86_64, aarch64)
- [ ] Crate compiles on Windows (x86_64)
- [ ] Crate compiles on macOS (x86_64, aarch64)
- [ ] Unit tests pass on all platforms
- [ ] Feature flags work correctly for platform-specific code
- [ ] Typecheck passes on all platforms

## Functional Requirements

- FR-1: The system must detect all connected USB drives on Linux, Windows, and macOS
- FR-2: The system must identify TCG Opal 2.0 capable drives and offer hardware encryption
- FR-3: The system must create THC encrypted containers on non-SED drives
- FR-4: THC containers must use AES-256-XTS encryption with Argon2id key derivation
- FR-5: A single master password must unlock both hardware and vault encryption layers
- FR-6: The existing 4-tier access level system must remain fully functional
- FR-7: Each access level must maintain independent encryption keys and passwords
- FR-8: The system must auto-lock when encrypted drives are removed
- FR-9: All key material must be zeroized when no longer needed
- FR-10: The GUI must provide drive detection, initialization wizard, and unlock dialogs
- FR-11: Error messages must be actionable and user-friendly
- FR-12: The system must handle permission requirements gracefully (admin/sudo prompts)

## Non-Goals

- BitLocker/FileVault/LUKS integration (using custom THC format only)
- Network drive encryption
- Cloud backup of encrypted drives
- Hardware security module (HSM) integration
- Smart card / FIDO2 authentication
- Automatic drive initialization without user confirmation
- Support for TCG Opal 1.0 (only 2.0)
- ATA Security password feature (only Opal)
- Encrypted partition resizing
- Multi-user drive access (single master password only)

## Technical Considerations

- **Permissions**: Linux requires root or appropriate capabilities for raw disk access; Windows requires admin; macOS requires authorization
- **Dependencies**: sedutil-cli needed for Opal support (optional, graceful degradation if missing)
- **Filesystem**: THC containers will contain exFAT filesystem for cross-platform compatibility
- **Performance**: XTS encryption is parallelizable; consider SIMD optimization
- **Block size**: THC uses 512-byte sectors to match common drive sector sizes
- **Recovery**: Master password loss means data loss (no backdoor by design)
- **Testing**: Platform-specific code requires actual hardware or VMs for full testing

## Success Metrics

- Drive initialization completes in under 5 minutes for 256GB drive
- Unlock operation completes in under 3 seconds (excluding Argon2 derivation)
- Zero data loss from normal lock/unlock operations
- Application handles unexpected drive removal without crashing
- Users can set up encrypted drive without reading documentation (wizard is self-explanatory)

## Open Questions

1. Should we support encrypting only a partition vs entire drive?
2. What filesystem should THC containers use internally (exFAT for compatibility, or ext4/NTFS for features)?
3. Should auto-lock have a configurable delay for brief disconnections?
4. How to handle drives that are already encrypted with BitLocker/FileVault?
