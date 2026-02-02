# Tesseract Hardware Encryption Specification

## Overview

This specification defines the implementation of hardware-level encryption for Tesseract, providing **triple-layer security** (hardware + vault + access levels) with a unified password experience across all platforms while preserving Tesseract's multi-level access control system.

## Requirements

| Requirement | Description |
|-------------|-------------|
| **R1** | Support all USB drives (SED-capable and standard drives) |
| **R2** | Cross-platform support (Linux, Windows, macOS) |
| **R3** | Triple encryption: Hardware (drive) + Vault (container) + Access Levels (files) |
| **R4** | Master password unlocks hardware and vault layers |
| **R5** | Preserve existing multi-level access system (Level 1-4 with separate passwords) |
| **R6** | Each access level maintains independent encryption keys |

## Architecture - Triple-Layer Security Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TESSERACT TRIPLE-LAYER SECURITY                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ LAYER 1: HARDWARE ENCRYPTION (Drive Level)                             │ │
│  │ ══════════════════════════════════════════                             │ │
│  │ • Encrypts entire drive                                                │ │
│  │ • AES-256-XTS (SED or Container)                                       │ │
│  │ • Unlocked with: MASTER PASSWORD                                       │ │
│  │ • Protection: Physical theft, drive removal                            │ │
│  │                                                                         │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │ │
│  │  │ LAYER 2: VAULT ENCRYPTION (Container Level)                      │  │ │
│  │  │ ════════════════════════════════════════════                     │  │ │
│  │  │ • Encrypts vault metadata and structure                          │  │ │
│  │  │ • AES-256-GCM                                                    │  │ │
│  │  │ • Unlocked with: MASTER PASSWORD (same as Layer 1)               │  │ │
│  │  │ • Protection: Unauthorized vault access                          │  │ │
│  │  │                                                                   │  │ │
│  │  │  ┌────────────────────────────────────────────────────────────┐  │  │ │
│  │  │  │ LAYER 3: ACCESS LEVEL ENCRYPTION (File Level)              │  │  │ │
│  │  │  │ ══════════════════════════════════════════════             │  │  │ │
│  │  │  │                                                             │  │  │ │
│  │  │  │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │  │  │ │
│  │  │  │ │  LEVEL 1    │ │  LEVEL 2    │ │  LEVEL 3    │ ...        │  │  │ │
│  │  │  │ │  (Public)   │ │(Restricted) │ │(Classified) │            │  │  │ │
│  │  │  │ │             │ │             │ │             │            │  │  │ │
│  │  │  │ │ Password: A │ │ Password: B │ │ Password: C │            │  │  │ │
│  │  │  │ │ Key: K1     │ │ Key: K2     │ │ Key: K3     │            │  │  │ │
│  │  │  │ │             │ │             │ │             │            │  │  │ │
│  │  │  │ │ [Files]     │ │ [Files]     │ │ [Files]     │            │  │  │ │
│  │  │  │ └─────────────┘ └─────────────┘ └─────────────┘            │  │  │ │
│  │  │  │                                                             │  │  │ │
│  │  │  │ • Each level has INDEPENDENT encryption key                 │  │  │ │
│  │  │  │ • Each level has SEPARATE password                          │  │  │ │
│  │  │  │ • AES-256-GCM per file                                      │  │  │ │
│  │  │  │ • Protection: Compartmentalized access                      │  │  │ │
│  │  │  └────────────────────────────────────────────────────────────┘  │  │ │
│  │  └──────────────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Password & Key Hierarchy

```
                    ┌─────────────────────┐
                    │   MASTER PASSWORD   │
                    │  (User enters once) │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │    Argon2id KDF     │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
     ┌────────────────┐ ┌────────────┐ ┌────────────────┐
     │ HARDWARE KEY   │ │ VAULT KEY  │ │ LEVEL KEYS     │
     │ (HKDF derive)  │ │ (HKDF)     │ │ (Separate)     │
     └───────┬────────┘ └─────┬──────┘ └───────┬────────┘
             │                │                │
             ▼                ▼                ▼
     ┌────────────────┐ ┌────────────┐ ┌────────────────────────────┐
     │ Unlock Drive   │ │Unlock Vault│ │ Level 1 Key ◄─ Password 1  │
     │ (Layer 1)      │ │ (Layer 2)  │ │ Level 2 Key ◄─ Password 2  │
     └────────────────┘ └────────────┘ │ Level 3 Key ◄─ Password 3  │
                                       │ Level 4 Key ◄─ Password 4  │
                                       └────────────────────────────┘
```

## Access Level System (Preserved from Original Tesseract)

| Level | Default Name | Description | Password |
|-------|--------------|-------------|----------|
| **1** | Public | Non-sensitive files | Level-specific |
| **2** | Restricted | Internal documents | Level-specific |
| **3** | Classified | Sensitive data | Level-specific |
| **4** | Top Secret | Highest sensitivity | Level-specific |

### Access Level Features (Unchanged)

- **Independent Keys**: Each level derives its own encryption key
- **Separate Passwords**: Each level can have a different password
- **Hierarchical Access**: Higher levels can optionally access lower levels
- **Plausible Deniability**: Revealing one level doesn't expose others
- **Per-File Encryption**: Each file encrypted with level-specific key

### Integration with Hardware Layer

```rust
/// Complete unlock flow for triple-layer security
pub async fn unlock_vault_complete(
    drive_path: &Path,
    master_password: &[u8],
    level_passwords: &HashMap<u32, Vec<u8>>,  // Level ID -> Password
) -> Result<UnlockedVault, TesseractError> {
    // Step 1: Derive keys from master password
    let (hw_key, vault_key) = derive_master_keys(master_password)?;

    // Step 2: Unlock hardware layer (Layer 1)
    let drive = EncryptedDrive::detect(drive_path)?;
    let mount_point = drive.unlock(&hw_key)?;

    // Step 3: Unlock vault (Layer 2)
    let vault_path = mount_point.join("vault.tess");
    let mut session = VaultSession::open(&vault_path, &vault_key)?;

    // Step 4: Unlock access levels as needed (Layer 3)
    for (level_id, level_password) in level_passwords {
        session.unlock_level(*level_id, level_password)?;
    }

    Ok(UnlockedVault {
        drive,
        session,
        unlocked_levels: level_passwords.keys().copied().collect(),
    })
}
```

## User Experience Flow

### First-Time Setup

```
1. Insert USB Drive
        │
        ▼
2. Launch Tesseract → "New Encrypted Drive Detected"
        │
        ▼
3. Setup Wizard
   ┌─────────────────────────────────────────────┐
   │ Step 1: Set MASTER PASSWORD                 │
   │         (Unlocks drive + vault)             │
   │                                             │
   │ Step 2: Configure ACCESS LEVELS             │
   │         □ Level 1: [Name] [Password]        │
   │         □ Level 2: [Name] [Password]        │
   │         □ Level 3: [Name] [Password]        │
   │         □ Level 4: [Name] [Password]        │
   │                                             │
   │ Step 3: Choose encryption strength          │
   │         ○ Standard (faster)                 │
   │         ● High (recommended)                │
   │         ○ Maximum (slower)                  │
   │                                             │
   │ Step 4: Initialize & Create Vault           │
   └─────────────────────────────────────────────┘
        │
        ▼
4. Drive Ready - Encrypted with triple-layer security
```

### Daily Use - Quick Unlock

```
1. Insert USB Drive
        │
        ▼
2. Tesseract Auto-Detects Locked Drive
   ┌─────────────────────────────────────────────┐
   │                                             │
   │  🔒 Encrypted Drive Detected                │
   │                                             │
   │  Enter Master Password:                     │
   │  [••••••••••••••]                          │
   │                                             │
   │  [Unlock Drive & Vault]                     │
   │                                             │
   └─────────────────────────────────────────────┘
        │
        ▼
3. Drive & Vault Unlocked (Layers 1 & 2)
   ┌─────────────────────────────────────────────┐
   │                                             │
   │  ✓ Drive Unlocked                           │
   │  ✓ Vault Opened                             │
   │                                             │
   │  Select Access Level:                       │
   │  ┌─────────────────────────────────────┐   │
   │  │ ○ Level 1: Public                   │   │
   │  │ ○ Level 2: Restricted               │   │
   │  │ ○ Level 3: Classified               │   │
   │  │ ○ Level 4: Top Secret               │   │
   │  └─────────────────────────────────────┘   │
   │                                             │
   │  Level Password: [••••••••]                 │
   │                                             │
   │  [Access Files]                             │
   │                                             │
   └─────────────────────────────────────────────┘
        │
        ▼
4. Full Access to Selected Level (Layer 3)
```

### Multi-Level Access (Advanced)

Users can unlock multiple levels simultaneously:

```
┌─────────────────────────────────────────────────────────┐
│ TESSERACT - Multi-Level Access                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Unlocked Levels:                                        │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ ✓ Level 1: Public         [Lock]                    │ │
│ │ ✓ Level 2: Restricted     [Lock]                    │ │
│ │ 🔒 Level 3: Classified    [Unlock...]               │ │
│ │ 🔒 Level 4: Top Secret    [Unlock...]               │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ File Browser:                                           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 📁 Documents/                                        │ │
│ │ ├── 📄 report.pdf          [Level 1]                │ │
│ │ ├── 📄 contract.docx       [Level 2]                │ │
│ │ ├── 🔒 classified.xlsx     [Level 3 - Locked]       │ │
│ │ └── 📁 Projects/                                    │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Hardware Encryption Strategies

### Strategy 1: SED Drives (TCG Opal 2.0)

For Self-Encrypting Drives that support TCG Opal standard.

**Supported Drives:**
- Samsung T7 / T7 Shield / T7 Touch
- Samsung X5
- Crucial X8, X6
- SanDisk Extreme Pro
- Most enterprise SSDs

**Implementation:**
```rust
pub trait SedController {
    /// Detect if drive supports TCG Opal
    fn is_opal_capable(&self) -> Result<bool, HardwareError>;

    /// Initialize drive encryption (first-time setup)
    fn initialize_opal(&self, password: &[u8]) -> Result<(), HardwareError>;

    /// Unlock drive with password
    fn unlock_opal(&self, password: &[u8]) -> Result<(), HardwareError>;

    /// Lock drive (requires re-authentication)
    fn lock_opal(&self) -> Result<(), HardwareError>;

    /// Change drive password
    fn change_password(&self, old: &[u8], new: &[u8]) -> Result<(), HardwareError>;
}
```

**Platform-Specific Implementations:**
| Platform | Method |
|----------|--------|
| Linux | `sedutil-cli` or direct ATA commands via `hdparm`/`sg_raw` |
| Windows | `sedutil.exe` or Windows TCG Opal API |
| macOS | `sedutil` or IOKit framework |

### Strategy 2: Software Full-Disk Encryption (Non-SED Drives)

For standard USB drives without hardware encryption.

**Implementation:**
Create an encrypted container that spans the entire drive partition.

| Platform | Technology | Library/Tool |
|----------|------------|--------------|
| Linux | LUKS2/dm-crypt | `libcryptsetup` |
| Windows | Custom AES-XTS container | Native Rust implementation |
| macOS | Custom AES-XTS container | Native Rust implementation |

**Container Format (Tesseract Hardware Container - THC):**
```
┌────────────────────────────────────────────────────────────┐
│ THC Header (4 KB)                                          │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Magic: "TESS-HWC\0" (8 bytes)                          │ │
│ │ Version: u32 (4 bytes)                                 │ │
│ │ Cipher: u32 (AES-256-XTS = 1)                         │ │
│ │ KDF: u32 (Argon2id = 1)                               │ │
│ │ Salt: [u8; 32]                                        │ │
│ │ Argon2 params: memory, iterations, parallelism        │ │
│ │ Encrypted Master Key: [u8; 64] (AES-256-GCM wrapped)  │ │
│ │ Header MAC: [u8; 32]                                  │ │
│ │ Reserved: padding to 4KB                              │ │
│ └────────────────────────────────────────────────────────┘ │
├────────────────────────────────────────────────────────────┤
│ Encrypted Data Region (AES-256-XTS)                        │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Filesystem (exFAT/ext4/APFS)                          │ │
│ │ └── Tesseract Vault Files                             │ │
│ └────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

## Unified Password Flow

### Single Password, Dual Derivation

To use one password for both hardware and software layers while maintaining security:

```rust
/// Derives separate keys for hardware and software encryption
/// from a single user password
pub fn derive_dual_keys(
    password: &[u8],
    hardware_salt: &[u8; 32],
    software_salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<(HardwareKey, SoftwareKey), CryptoError> {
    // Derive intermediate key from password
    let intermediate = argon2id_derive(password, hardware_salt, params)?;

    // Derive hardware key using HKDF
    let hardware_key = hkdf_expand(&intermediate, b"TESSERACT-HARDWARE-KEY", 32)?;

    // Derive software key using HKDF with different context
    let software_key = hkdf_expand(&intermediate, b"TESSERACT-SOFTWARE-KEY", 32)?;

    Ok((HardwareKey(hardware_key), SoftwareKey(software_key)))
}
```

### Unlock Sequence

```
User enters password
         │
         ▼
┌─────────────────────┐
│ Derive dual keys    │
│ (Argon2id + HKDF)   │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
┌───────┐   ┌───────┐
│ HW    │   │ SW    │
│ Key   │   │ Key   │
└───┬───┘   └───┬───┘
    │           │
    ▼           │
┌───────────┐   │
│ Unlock    │   │
│ Hardware  │   │
│ Layer     │   │
└─────┬─────┘   │
      │         │
      ▼         ▼
┌─────────────────────┐
│ Mount Drive         │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Unlock Tesseract    │
│ Vault (SW Key)      │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Access Granted      │
│ (Double Encrypted)  │
└─────────────────────┘
```

## New Crate: `tesseract-hardware`

### Module Structure

```
crates/hardware/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API
│   ├── error.rs            # Error types
│   ├── detect.rs           # Drive detection & capability probing
│   ├── container.rs        # THC container format
│   ├── crypto.rs           # AES-XTS implementation
│   ├── sed/
│   │   ├── mod.rs          # SED abstraction
│   │   ├── opal.rs         # TCG Opal implementation
│   │   └── ata.rs          # ATA security commands
│   └── platform/
│       ├── mod.rs          # Platform abstraction
│       ├── linux.rs        # Linux-specific (LUKS, udev)
│       ├── windows.rs      # Windows-specific (volume management)
│       └── macos.rs        # macOS-specific (diskutil, IOKit)
```

### Public API

```rust
//! Tesseract Hardware Encryption Layer

/// Represents an encrypted drive (hardware or container)
pub struct EncryptedDrive {
    path: PathBuf,
    drive_type: DriveType,
    status: DriveStatus,
}

#[derive(Debug, Clone)]
pub enum DriveType {
    /// Self-Encrypting Drive with TCG Opal
    SedOpal { vendor: String, model: String },
    /// Self-Encrypting Drive with ATA Security
    SedAta { vendor: String, model: String },
    /// Software-encrypted container (THC format)
    TesseractContainer,
    /// Unencrypted drive (can be initialized)
    Unencrypted,
}

#[derive(Debug, Clone)]
pub enum DriveStatus {
    Locked,
    Unlocked,
    Uninitialized,
    Error(String),
}

impl EncryptedDrive {
    /// Detect drive type and capabilities
    pub fn detect(path: impl AsRef<Path>) -> Result<Self, HardwareError>;

    /// Initialize encryption on the drive
    pub fn initialize(&mut self, password: &[u8], params: &EncryptionParams) -> Result<(), HardwareError>;

    /// Unlock the drive
    pub fn unlock(&mut self, password: &[u8]) -> Result<PathBuf, HardwareError>;

    /// Lock the drive
    pub fn lock(&mut self) -> Result<(), HardwareError>;

    /// Check if drive is unlocked
    pub fn is_unlocked(&self) -> bool;

    /// Get mount point (if unlocked)
    pub fn mount_point(&self) -> Option<&Path>;

    /// Change encryption password
    pub fn change_password(&mut self, old: &[u8], new: &[u8]) -> Result<(), HardwareError>;
}

/// High-level API for Tesseract integration
pub struct HardwareManager {
    drives: Vec<EncryptedDrive>,
}

impl HardwareManager {
    /// Scan for connected USB drives
    pub fn scan_drives() -> Result<Self, HardwareError>;

    /// Get list of detected drives
    pub fn drives(&self) -> &[EncryptedDrive];

    /// Find drive by path
    pub fn find_drive(&self, path: impl AsRef<Path>) -> Option<&EncryptedDrive>;

    /// Watch for drive connect/disconnect events
    pub fn watch_events(&self) -> impl Stream<Item = DriveEvent>;
}
```

## GUI Integration

### New Screens

1. **Drive Detection Screen**
   - Shows connected USB drives
   - Indicates encryption status (SED, Container, None)
   - "Initialize Encryption" button for unencrypted drives

2. **Hardware Unlock Screen**
   - Appears when locked drive is detected
   - Single password field
   - "Unlock Drive & Vault" button
   - Progress indicator for Argon2 derivation

3. **Drive Setup Wizard**
   - Step 1: Select drive
   - Step 2: Choose encryption method (Auto/SED/Container)
   - Step 3: Set password (with strength meter)
   - Step 4: Confirm and initialize
   - Step 5: Create Tesseract vault on encrypted drive

### Workflow Changes

```
Current Flow:
  Plug in drive → Run Tesseract → Open vault → Enter password

New Flow:
  Plug in drive → Run Tesseract → Detect hardware encryption
       │
       ├─► Drive locked → Enter password → Unlock HW + SW → Access files
       │
       └─► Drive unlocked → Open vault → Already unlocked (session key cached)
```

## Platform-Specific Implementation Details

### Linux

**SED Drives:**
```bash
# Using sedutil-cli
sedutil-cli --initialSetup <password> /dev/sdX
sedutil-cli --setLockingRange 0 RW <password> /dev/sdX
sedutil-cli --enableLockingRange 0 <password> /dev/sdX
```

**Software Container:**
- Use `libcryptsetup` for LUKS2 container management
- Or implement custom THC container with `dm-crypt` via `devicemapper` crate

**Drive Events:**
- Use `udev` for hotplug detection
- Monitor `/dev/disk/by-id/` for USB drives

### Windows

**SED Drives:**
- Use `sedutil.exe` or Windows Storage API
- Requires admin privileges

**Software Container:**
- Mount as virtual disk using `Virtual Disk Service` API
- Or use `ImDisk` / `WinFsp` for userspace mounting

**Drive Events:**
- Use `WMI` for device change notifications
- Or `RegisterDeviceNotification` API

### macOS

**SED Drives:**
- Use `sedutil` compiled for macOS
- May require SIP adjustments

**Software Container:**
- Use `hdiutil` for disk image mounting
- Or FUSE for custom container

**Drive Events:**
- Use `DiskArbitration` framework
- Or `IOKit` for device notifications

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Stolen drive (powered off) | Hardware encryption + software vault |
| Evil maid attack | Boot integrity (out of scope) |
| Cold boot attack | Key stored in hardware (SED) or secure memory |
| Password brute force | Argon2id with high parameters |
| Drive firmware attack | Defense in depth with software layer |

### Key Management

1. **Hardware key** is used only for drive unlock, never stored
2. **Software key** is derived fresh each session, held in secure memory
3. **Session keys** are zeroized on lock/timeout
4. **Password** is never stored, only processed in secure memory

## Implementation Phases

### Phase 1: Foundation (Core Infrastructure)
- [ ] Create `tesseract-hardware` crate
- [ ] Implement drive detection (cross-platform)
- [ ] Implement THC container format
- [ ] Add AES-256-XTS to crypto crate

### Phase 2: Linux Implementation
- [ ] SED/Opal support via sedutil
- [ ] LUKS container support
- [ ] udev hotplug integration
- [ ] GUI drive detection screen

### Phase 3: Windows Implementation
- [ ] SED support via sedutil.exe
- [ ] Virtual disk mounting
- [ ] WMI device events
- [ ] Windows installer updates

### Phase 4: macOS Implementation
- [ ] SED support
- [ ] Disk image container
- [ ] DiskArbitration events
- [ ] macOS app bundle updates

### Phase 5: Integration & Polish
- [ ] Unified password flow
- [ ] Auto-lock on drive removal
- [ ] Password change across both layers
- [ ] Comprehensive testing

## Dependencies

### New Crate Dependencies

```toml
[dependencies]
# Cross-platform
aes = "0.8"
xts-mode = "0.5"           # AES-XTS implementation
block-modes = "0.9"

# Linux
libcryptsetup-rs = "0.9"   # LUKS support
udev = "0.8"               # Device events

# Windows
windows = "0.52"           # Windows API bindings

# macOS
core-foundation = "0.9"    # macOS framework bindings
```

## Testing Strategy

1. **Unit Tests**: Container format, crypto operations
2. **Integration Tests**: Drive detection, mount/unmount
3. **Platform Tests**: CI/CD with platform-specific runners
4. **Hardware Tests**: Manual testing with various SED drives
5. **Security Audit**: Third-party review of crypto implementation

## References

- [TCG Opal 2.0 Specification](https://trustedcomputinggroup.org/resource/storage-work-group-storage-security-subsystem-class-opal/)
- [sedutil Documentation](https://github.com/Drive-Trust-Alliance/sedutil)
- [LUKS2 Specification](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS2-Format)
- [AES-XTS Mode (IEEE 1619)](https://standards.ieee.org/standard/1619-2018.html)
