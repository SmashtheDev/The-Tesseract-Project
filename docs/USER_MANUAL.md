# TESSERACT User Manual

> Version 1.0 | Last Updated: January 2026

TESSERACT is a production-grade removable storage encryption application designed for enterprise and government classified data protection. This manual covers all features of the application.

---

## Table of Contents

1. [Installation](#installation)
2. [Vault Management](#vault-management)
3. [File Operations](#file-operations)
4. [Access Levels](#access-levels)
5. [Hardware Encryption](#hardware-encryption)
6. [Recovery](#recovery)
7. [Troubleshooting](#troubleshooting)
8. [Technical Reference](#technical-reference)

---

## Installation

### System Requirements

| Platform | Minimum Version | Notes |
|----------|-----------------|-------|
| Windows | Windows 10 (64-bit) | Windows 11 recommended |
| Linux | Ubuntu 22.04 LTS or equivalent | glibc 2.35+, libfuse3 |
| macOS | macOS 12 Monterey | Apple Silicon and Intel supported |

### Hardware Requirements

- **RAM:** 512 MB minimum (1 GB recommended for large files)
- **Storage:** USB flash drive or removable media
- **CPU:** x86-64 processor with AES-NI support recommended

### Obtaining TESSERACT

#### From GitHub Releases

1. Go to the [TESSERACT Releases](https://github.com/OWNER/tesseract/releases) page
2. Download the appropriate package for your platform:
   - **Windows:** `tesseract-windows-x64.exe`
   - **Linux:** `TESSERACT-x86_64.AppImage`
   - **macOS:** `TESSERACT-macos.app.zip`

#### From CI Artifacts

1. Navigate to [GitHub Actions](https://github.com/OWNER/tesseract/actions)
2. Click on the latest successful CI run
3. Download the artifact for your platform

### Installing on USB Drive

TESSERACT is designed to run exclusively from removable media for security:

1. **Format your USB drive** (optional but recommended):
   - Windows: exFAT or NTFS
   - Linux/macOS: exFAT for cross-platform compatibility

2. **Copy the executable:**
   - Create a folder called `TESSERACT` at the root of your USB drive
   - Copy the platform-specific executable(s) into this folder

3. **Directory structure:**
   ```
   USB_DRIVE/
   ├── TESSERACT/
   │   ├── tesseract.exe      (Windows)
   │   ├── TESSERACT.AppImage (Linux)
   │   └── TESSERACT.app/     (macOS)
   └── vault/                  (created on first run)
   ```

### Installing VFS Drivers (Optional)

For virtual filesystem integration (access encrypted files as a drive letter):

#### Windows

Install one of the following:
- [Dokan](https://github.com/dokan-dev/dokany/releases) - Version 2.0 or later
- [WinFsp](https://winfsp.dev/rel/) - Version 2.0 or later

#### Linux

```bash
# Ubuntu/Debian
sudo apt install fuse3

# Fedora/RHEL
sudo dnf install fuse3

# Arch Linux
sudo pacman -S fuse3
```

#### macOS

Install [macFUSE](https://osxfuse.github.io/) version 4.0 or later.

---

## Vault Management

### Understanding Vaults

A vault is an encrypted container that stores your files securely. Each vault consists of:

- **Header file:** Contains encrypted master key and authentication data
- **Keystores:** Per-access-level encryption key bundles
- **Blobs:** Encrypted file contents
- **Metadata:** Encrypted file names, paths, and timestamps

All data is encrypted with AES-256-GCM, and no plaintext information is stored on disk.

### Creating a New Vault

1. Launch TESSERACT from your USB drive
2. Click **Create New Vault**
3. Select a location for your vault (defaults to `/vault` on the USB drive)

#### Setting Your Master Password

Your master password protects the entire vault. Choose wisely:

| Strength | Requirements | Password Meter |
|----------|--------------|----------------|
| Very Weak | Under 6 characters | Red |
| Weak | 6-7 characters | Orange |
| Fair | 8-11 characters with mix | Yellow |
| Strong | 12-15 characters with variety | Light Green |
| Very Strong | 16+ characters with uppercase, lowercase, numbers, symbols | Green |

**Password Requirements:**
- Minimum 8 characters recommended
- Mix of uppercase and lowercase letters
- Include numbers and special characters
- Avoid dictionary words and personal information

#### Configuring Access Levels

During vault creation, you can configure access levels:

- **Default:** Three levels (Level 1, Level 2, Level 3)
- **Custom:** Between 1 and 10 levels
- Each level requires a separate password

See [Access Levels](#access-levels) for detailed information.

#### Saving Your Recovery Key

**CRITICAL:** After entering your password, you will be shown a 24-word recovery key:

```
word1 word2 word3 word4 word5 word6
word7 word8 word9 word10 word11 word12
word13 word14 word15 word16 word17 word18
word19 word20 word21 word22 word23 word24
```

This recovery key:
- Is the ONLY way to regain access if you forget your password
- Is shown ONLY ONCE during vault creation
- Should be written on paper and stored securely (not digitally)
- Should be kept separate from your USB drive

**Options for saving:**
- **Copy:** Copies to clipboard (auto-clears after 60 seconds)
- **Print:** Opens a printable formatted version

You must check "I have saved my recovery key" before proceeding.

### Opening an Existing Vault

1. Launch TESSERACT
2. Click **Open Existing Vault**
3. Navigate to your vault directory
4. Enter your password
5. Wait for key derivation (Argon2id, may take 1-2 seconds)

#### Recent Vaults

TESSERACT remembers recently opened vaults for convenience:
- Recent vaults are displayed on the main screen
- Click a recent vault to open it directly
- Recent vault list is stored on the USB drive (portable with your vaults)

### Locking Your Vault

Locking your vault ensures all encryption keys are wiped from memory:

#### Manual Lock
- Click the **Lock** button in the toolbar
- Or close the application

#### Auto-Lock
By default, TESSERACT automatically locks after 15 minutes of inactivity:
- Navigate to **Settings > Auto-Lock Timeout** to configure
- Options: 5, 10, 15, 30, 60 minutes, or Never
- Activity is detected from mouse/keyboard input

When locked:
- All keys (Master Key, KEKs, DEKs) are securely zeroed
- Temporary preview files are securely deleted
- VFS mounts are unmounted
- You must re-authenticate to access files

### Deleting a Vault

To permanently delete a vault and all its contents:

1. Navigate to the vault folder on your USB drive
2. Delete the entire vault directory

**Warning:** This action is irreversible. All encrypted files will be permanently lost.

---

## File Operations

### The File Browser

The built-in file browser displays your encrypted files with:

| Column | Description |
|--------|-------------|
| Icon | File type indicator (file or folder) |
| Name | Decrypted filename |
| Size | File size in human-readable format |
| Modified | Last modification timestamp |
| Level | Access level (L1, L2, L3, etc.) |

**Navigation:**
- Click folders to navigate into them
- Use breadcrumb navigation at the top to move up
- Click any breadcrumb segment to jump to that location

### Importing Files

#### Drag and Drop

1. Open your system file manager alongside TESSERACT
2. Select files or folders to encrypt
3. Drag them into the TESSERACT window
4. A drop overlay appears with "Drop files to import"
5. Release to import

After dropping:
1. An import dialog appears
2. Select the destination access level
3. Click **Import**
4. Progress bar shows encryption progress

#### Import Button

1. Click **Import** in the toolbar
2. A file browser opens
3. Select files or folders
4. Click Open/Select
5. Choose access level and confirm

### Exporting Files

To decrypt files and save them outside the vault:

#### Single File Export

1. Select a file in the file browser
2. Right-click > **Export**, or press `Ctrl+E`
3. Choose destination folder
4. File is decrypted to that location

#### Multiple File Export

1. Select multiple files (Shift+click or Ctrl+click)
2. Right-click > **Export**
3. Choose destination folder
4. All selected files are exported

**Note:** Exported files are no longer encrypted. They are plain files on your computer.

### Previewing Files

Double-click a file to preview it temporarily:

1. File is decrypted to a secure temporary directory
2. Opens with your system's default application
3. When you lock the vault, the temporary file is securely deleted

**Supported for preview:** Any file type your system can open (documents, images, PDFs, etc.)

**Secure deletion:** Temporary files are overwritten 3 times with random data before deletion.

### Renaming Files

1. Select a file
2. Right-click > **Rename**, or press `F2`
3. Enter the new name
4. Press Enter or click **Rename**

File paths within the vault are encrypted; renaming updates the encrypted metadata.

### Moving Files

1. Select a file
2. Right-click > **Move**
3. Navigate to or enter the new path
4. Click **Move**

Alternatively, use drag-and-drop within the file browser to move files between folders.

### Deleting Files

1. Select file(s)
2. Right-click > **Delete**, or press `Delete`
3. Confirm the deletion

**Deletion is permanent:** Deleted files cannot be recovered from within TESSERACT.

When a file is deleted:
- Encrypted blob is removed from `.blobs/`
- Encrypted metadata is removed from `.metadata/`
- DEK is removed from the keystore

### Creating Folders

1. Right-click in empty space or on a folder
2. Select **New Folder**
3. Enter folder name
4. Press Enter or click **Create**

Folders are virtual—they exist as encrypted path metadata.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Delete` | Delete selected file(s) |
| `F2` | Rename selected file |
| `Ctrl+E` | Export selected file(s) |
| `Ctrl+A` | Select all files in current view |
| `Enter` | Open/preview selected file |
| `Escape` | Cancel dialog / Deselect all |
| `Backspace` | Navigate to parent folder |

---

## Access Levels

### Understanding Access Levels

TESSERACT supports multi-level access control, allowing you to compartmentalize files by security classification:

```
┌─────────────────────────────────────────┐
│              Level 3                     │
│  (Sees Level 1 + Level 2 + Level 3)     │
│  ┌─────────────────────────────────┐    │
│  │          Level 2                 │    │
│  │  (Sees Level 1 + Level 2)       │    │
│  │  ┌─────────────────────────┐    │    │
│  │  │        Level 1           │    │    │
│  │  │  (Sees Level 1 only)    │    │    │
│  │  └─────────────────────────┘    │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

**Hierarchical Access Mode (Default):**
- Logging in with Level 3 password unlocks Levels 1, 2, and 3
- Logging in with Level 2 password unlocks Levels 1 and 2
- Logging in with Level 1 password unlocks Level 1 only

**Use Cases:**
- **Level 1:** General files, shared with all users
- **Level 2:** Confidential files, restricted access
- **Level 3:** Top Secret files, highest clearance only

### Viewing Current Access Level

The status bar at the bottom of the file browser shows:
- Current access level (e.g., "Access: Level 2")
- Number of accessible files

Files from inaccessible levels are completely invisible—not just hidden, but cryptographically inaccessible.

### Assigning Files to Access Levels

Files are assigned to an access level during import. To change an existing file's level:

1. Select the file
2. Right-click > **Change Access Level**
3. Select the new level
4. Enter the password for the target level
5. Click **Change**

**Technical note:** Changing access level re-wraps the file's DEK (Data Encryption Key) with the target level's KEK (Key Encryption Key).

### Managing Access Levels

Navigate to **Settings > Access Levels** to manage levels:

#### Creating a New Level

1. Click **Add Level**
2. Enter level name (e.g., "Classified")
3. Set password for this level
4. Click **Create**

Maximum 10 levels supported per vault.

#### Changing Level Password

1. Find the level in the settings list
2. Click **Change Password**
3. Enter current password
4. Enter new password twice
5. Click **Change**

The level's KEK is re-encrypted with the new password-derived key.

#### Deleting a Level

1. Ensure no files are assigned to this level
2. Click **Delete** next to the level
3. Confirm deletion

**Note:** You cannot delete a level that contains files. Move or delete files first.

#### Level Properties

Each level displays:
- Level name
- File count (number of files at this level)
- Created date
- Enabled/disabled status

---

## Hardware Encryption

TESSERACT supports hardware-level encryption for USB drives, providing triple-layer security: Hardware encryption (AES-256-XTS), Vault encryption (AES-256-GCM), and Access Levels. This section explains how to use this advanced feature.

### Overview

Hardware encryption protects your data at the drive level, meaning:
- The entire drive is encrypted, not just individual files
- Data is encrypted before being written to the physical storage
- Protection persists even if the drive is removed from the computer
- Compatible with TCG Opal 2.0 Self-Encrypting Drives (SEDs) or TESSERACT Hardware Container (THC) format

### Security Model

TESSERACT's hardware encryption uses a triple-layer approach:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Layer 1: Hardware                           │
│         AES-256-XTS full-drive encryption                       │
│         (Protects physical drive against theft)                 │
├─────────────────────────────────────────────────────────────────┤
│                      Layer 2: Vault                             │
│         AES-256-GCM authenticated encryption                    │
│         (Protects vault structure and file metadata)            │
├─────────────────────────────────────────────────────────────────┤
│                   Layer 3: Access Levels                        │
│         Per-file encryption with level-specific keys            │
│         (Provides plausible deniability)                        │
└─────────────────────────────────────────────────────────────────┘
```

A single master password derives all three encryption keys using Argon2id key derivation, making one password sufficient to unlock all layers.

### Supported Drive Types

| Type | Description | Support |
|------|-------------|---------|
| **TCG Opal 2.0 SED** | Self-Encrypting Drive with hardware AES engine | Full support (Linux) |
| **THC Container** | TESSERACT's software-based container format | Full support (all platforms) |
| **Standard USB** | Can be converted to THC format | Requires initialization |

### Setting Up Hardware Encryption

#### First-Time Setup Wizard

1. **Connect your USB drive** and launch TESSERACT
2. **Navigate to Hardware Encryption**: Menu → Settings → Hardware Encryption
3. **Select your drive** from the detected drives list
4. **Choose encryption strength**:
   - **Standard**: Fast key derivation (64MB memory, 3 iterations)
   - **High**: Balanced security (128MB memory, 4 iterations) - Recommended
   - **Maximum**: Maximum security (256MB memory, 6 iterations)
5. **Configure access levels**: Set up 1-4 access levels with individual passwords
6. **Enter master password**: This will be your primary unlock password
7. **Confirm data erasure**: WARNING - All existing data on the drive will be lost!
8. **Save your recovery key**: Write down the 24-word recovery phrase securely
9. **Wait for initialization**: This may take several minutes depending on drive size

#### Setup Wizard Steps

| Step | Action | Notes |
|------|--------|-------|
| 1. Drive Selection | Select target USB drive | Shows vendor, model, size, current status |
| 2. Encryption Settings | Choose strength level | Higher = more secure but slower unlock |
| 3. Access Levels | Configure 1-4 levels | Each gets a separate password |
| 4. Master Password | Enter primary password | Minimum 8 characters recommended |
| 5. Confirmation | Review and confirm | Final check before data erasure |
| 6. Initialization | Wait for completion | Progress bar shows status |
| 7. Recovery Key | Save your 24-word key | Store securely offline |

### Daily Unlock Workflow

#### Unlocking Your Encrypted Drive

1. **Connect the encrypted USB drive**
2. **TESSERACT will detect it automatically** (green shield icon)
3. **Enter your master password** when prompted
4. **Select access level** (if multiple levels configured)
5. **Click Unlock** to access your files

#### Quick Unlock (Unified Password Mode)

If you enabled "Unified Password" during setup:
- Enter your master password once
- All layers unlock automatically
- No need to enter separate vault/level passwords

#### Locking Your Drive

When finished working:
1. Click **Lock Drive** in the toolbar, or
2. Go to Menu → Hardware → Lock Drive, or
3. Simply disconnect the USB drive (auto-locks)

### Password Recovery Process

If you forget your master password:

1. **Connect the encrypted drive** to a computer with TESSERACT
2. **Click "Forgot Password"** on the unlock screen
3. **Enter your 24-word recovery key**:
   - Words separated by spaces
   - Case-insensitive
   - Or use base64 format if you have it
4. **Verify the recovery key**
5. **Set a new master password**
6. **Your drive is unlocked** with the new password

**Important:**
- The recovery key can reset the master password only
- Individual access level passwords require their own reset
- Keep your recovery key stored securely offline

### Troubleshooting

#### Drive Not Detected

| Symptom | Possible Cause | Solution |
|---------|---------------|----------|
| No drives shown | USB not connected | Check USB connection |
| Drive shown as "Unknown" | Not initialized | Initialize as THC container |
| Wrong drive type | Opal not supported | Use THC format instead |

#### Unlock Failures

| Error | Cause | Solution |
|-------|-------|----------|
| "Invalid password" | Wrong password | Check caps lock, try again |
| "Container corrupted" | Damaged header | Use recovery key |
| "Device busy" | Drive in use | Unmount other mounts first |

#### Performance Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Slow unlock | High encryption strength | Expected behavior, wait |
| Slow file access | USB 2.0 connection | Use USB 3.0 port if available |
| Timeouts | Large drive initialization | Ensure stable power |

### Security Best Practices

1. **Use a strong master password**: Minimum 12 characters with mixed case, numbers, symbols
2. **Store recovery key offline**: Never on a networked computer
3. **Lock drive when unattended**: Don't leave unlocked drives accessible
4. **Keep software updated**: Install TESSERACT updates for security fixes
5. **Verify drive integrity**: Periodically check for hardware errors

---

## Recovery

### Using Your Recovery Key

If you forget your password, you can use your 24-word recovery key to regain access:

1. On the password entry screen, click **Forgot Password**
2. Enter your 24-word recovery key:
   - Words separated by spaces
   - Case-insensitive
   - Or paste the base64 version if you have it
3. Click **Verify**
4. If valid, you'll be prompted to create a new password
5. Enter and confirm your new password
6. Click **Reset Password**

**Important notes:**
- Your recovery key remains valid after password reset
- You do not need to save a new recovery key
- Your files remain intact and encrypted

### What the Recovery Key Protects

The recovery key can decrypt the vault's master key, which allows:
- Resetting the master password
- Resetting individual level passwords
- Full vault access

### If You Lose Your Recovery Key

**There is no way to recover a vault without either:**
1. The correct password, or
2. The recovery key

If you have lost both, your data cannot be recovered. This is by design—it ensures no backdoor exists.

### Best Practices for Recovery Keys

1. **Write it on paper** - Don't store digitally
2. **Store in multiple locations** - Home safe, bank deposit box
3. **Keep separate from USB drive** - If drive is stolen, recovery key is safe
4. **Don't photograph it** - Photos may sync to cloud
5. **Consider splitting** - Write words 1-12 and 13-24 on separate papers

---

## Troubleshooting

### Application Issues

#### "Fixed disk detected" error

**Cause:** TESSERACT is running from an internal drive (HDD/SSD).

**Solution:**
1. Copy TESSERACT to a USB flash drive
2. Run it from the USB drive
3. This is a security requirement, not a bug

#### "No VFS driver found"

**Cause:** Dokan/WinFsp (Windows), FUSE (Linux), or macFUSE (macOS) is not installed.

**Solution:**
- Install the appropriate driver (see [Installing VFS Drivers](#installing-vfs-drivers-optional))
- Or use the built-in file browser (VFS is optional)

#### Application crashes on startup

**Possible causes:**
1. Corrupted executable - re-download
2. Missing system libraries (Linux) - install libfuse3
3. Antivirus blocking - add exception
4. Insufficient memory - close other applications

### Authentication Issues

#### "Invalid password"

**Causes:**
1. Incorrect password entered
2. Caps Lock is on
3. Wrong keyboard layout

**Solutions:**
1. Try typing password in a text editor first to verify
2. Check Caps Lock and Num Lock
3. Ensure correct keyboard layout

#### "Vault is locked out"

**Cause:** Too many failed password attempts (default: 10).

**Solution:**
- Wait for lockout period to expire (default: 15 minutes)
- A countdown timer shows remaining time
- Or use your recovery key to reset password

#### "Authentication rate limited"

**Cause:** Failed password attempts trigger exponential backoff.

**Solution:**
- Wait the displayed time before trying again
- Delays increase: 1s, 2s, 4s, 8s... up to 60s

### File Operation Issues

#### "Cannot decrypt file"

**Possible causes:**
1. Vault corruption
2. File at higher access level

**Solutions:**
1. Check you're logged in at correct level
2. File may be corrupted - check vault integrity

#### "Export failed: Permission denied"

**Cause:** Destination folder is not writable.

**Solutions:**
1. Choose a different destination
2. Check folder permissions
3. Ensure disk is not full

#### Files disappear after adding

**Cause:** Files were imported at a different access level.

**Solution:**
1. Log in with a higher-level password
2. Check all access levels for the file

### VFS Issues

#### Drive letter not appearing (Windows)

**Possible causes:**
1. Dokan/WinFsp not running
2. Drive letter already in use
3. Insufficient permissions

**Solutions:**
1. Restart Dokan service
2. Choose a different drive letter in Settings
3. Run TESSERACT as Administrator

#### "Permission denied" when mounting (Linux/macOS)

**Cause:** FUSE permissions not configured.

**Solutions:**

Linux:
```bash
# Add yourself to fuse group
sudo usermod -a -G fuse $USER
# Log out and back in

# Or set FUSE permissions
sudo chmod 4755 /usr/bin/fusermount3
```

macOS:
- Open System Preferences > Security & Privacy
- Allow macFUSE kernel extension

#### Files show as empty in mounted drive

**Cause:** Vault session expired or locked.

**Solution:**
1. Return to TESSERACT application
2. Re-enter password if prompted
3. VFS should refresh automatically

### Vault Issues

#### "Vault header corrupted"

**Cause:** The vault header file was damaged.

**Solutions:**
1. If you have a backup, restore it
2. Use recovery key to create new vault and re-import files
3. If no backup or recovery key: data is lost

#### Vault takes long time to open

**Cause:** Argon2id key derivation is intentionally slow (security feature).

**Solution:**
- Normal behavior: 1-3 seconds depending on hardware
- If >10 seconds: check system resources

### Platform-Specific Issues

#### Windows: "DLL not found"

**Solution:** Install [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)

#### Linux: "libfuse.so.3: cannot open shared object"

**Solution:**
```bash
sudo apt install libfuse3-3  # Debian/Ubuntu
sudo dnf install fuse3-libs  # Fedora
```

#### macOS: "App is damaged"

**Cause:** Gatekeeper blocking unsigned app.

**Solution:**
```bash
# Remove quarantine attribute
xattr -cr /path/to/TESSERACT.app
```

Or open System Preferences > Security & Privacy and click "Open Anyway."

---

## Technical Reference

### Cryptographic Algorithms

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| File Encryption | AES-256-GCM | 256 bits |
| Key Derivation | Argon2id | 256 bits output |
| Integrity | HMAC-SHA256 | 256 bits |
| Random Generation | OS CSPRNG | N/A |

### Argon2id Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Memory | 64 MB | RAM used during derivation |
| Iterations | 3 | Time cost factor |
| Parallelism | 4 | Thread count |
| Output | 32 bytes | Derived key length |

### Key Hierarchy

```
Password
    │
    ▼
[Argon2id KDF]
    │
    ▼
Master Key (MK)
    │
    ├── Access Level Key (ALK) ─── derived per password
    │       │
    │       ▼
    │   Key Encryption Key (KEK) ─── per access level
    │       │
    │       ▼
    │   Data Encryption Key (DEK) ─── per file
    │
    └── Recovery Key ─── backup access to MK
```

### Vault Directory Structure

```
vault/
├── vault.header          # Encrypted header (512 bytes)
├── .keystores/
│   ├── L1.keys.enc      # Level 1 keystore
│   ├── L2.keys.enc      # Level 2 keystore
│   └── L3.keys.enc      # Level 3 keystore
├── .blobs/
│   ├── {uuid1}.blob     # Encrypted file content
│   └── {uuid2}.blob
├── .metadata/
│   ├── {uuid1}.meta     # Encrypted file metadata
│   └── {uuid2}.meta
└── .levels/
    └── levels.enc       # Access level configuration
```

### File Format Details

#### Blob Format
```
[Nonce: 12 bytes][Ciphertext: variable][Auth Tag: 16 bytes]
```

#### Metadata Format
```
[Nonce: 12 bytes][Encrypted bincode: variable][Auth Tag: 16 bytes]
```

#### Streaming Chunk Format
```
[TESS: 4 bytes][Version: 1 byte][Base Nonce: 12 bytes][Chunk Size: 4 bytes]
[Chunk 1: [Nonce][Ciphertext][Tag]]
[Chunk 2: [Nonce][Ciphertext][Tag]]
...
```

### Performance Characteristics

| Operation | Typical Time |
|-----------|--------------|
| Vault unlock (Argon2id) | 1-2 seconds |
| File encrypt (1 MB) | ~10 ms |
| File decrypt (1 MB) | ~10 ms |
| First byte latency | <100 ms |

With AES-NI hardware acceleration, throughput typically achieves 85%+ of native (unencrypted) disk speed.

---

## Appendix: Glossary

| Term | Definition |
|------|------------|
| **AAD** | Additional Authenticated Data - extra data authenticated but not encrypted |
| **AES-GCM** | AES in Galois/Counter Mode - authenticated encryption |
| **Argon2id** | Memory-hard password hashing algorithm |
| **Blob** | Encrypted file content storage unit |
| **DEK** | Data Encryption Key - unique key per file |
| **FUSE** | Filesystem in Userspace - Linux/macOS VFS technology |
| **GCM** | Galois/Counter Mode - provides authentication and encryption |
| **HMAC** | Hash-based Message Authentication Code |
| **KEK** | Key Encryption Key - wraps DEKs per access level |
| **MK** | Master Key - top of key hierarchy, derived from password |
| **Nonce** | Number used once - unique value for each encryption |
| **VFS** | Virtual File System - makes vault appear as drive |

---

## Appendix: Support

### Getting Help

- **Documentation:** Check the [Quick Start Guide](QUICKSTART.md) and this manual
- **Issues:** Report bugs at [GitHub Issues](https://github.com/OWNER/tesseract/issues)
- **Security:** Report vulnerabilities via private disclosure

### Version History

See [CHANGELOG.md](../CHANGELOG.md) for version history and release notes.

---

*TESSERACT - Secure your data on any platform*
