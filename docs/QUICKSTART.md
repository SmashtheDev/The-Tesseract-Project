# TESSERACT Quick Start Guide

Get started with TESSERACT in under 5 minutes. This guide covers launching the application, creating your first vault, adding files, and locking up when done.

---

## Prerequisites

- A USB flash drive or other removable storage device
- The TESSERACT application copied to your removable drive

> **Note:** TESSERACT requires a removable drive for security. It will not run from your internal hard drive.

---

## Step 1: First Run

1. Insert your USB drive containing TESSERACT
2. Navigate to the TESSERACT folder on the drive
3. Launch the application:
   - **Windows:** Double-click `tesseract.exe`
   - **Linux:** Run `./TESSERACT.AppImage` (or double-click)
   - **macOS:** Open `TESSERACT.app`

![First Run Screen](screenshots/01-first-run.png)
*The vault selection screen appears on first launch*

---

## Step 2: Create a New Vault

If this is your first time using TESSERACT, you'll need to create a vault:

1. Click **Create New Vault**
2. Choose a location on your USB drive (or use the default `/vault` folder)
3. Set your **master password**:
   - Use a strong password (12+ characters recommended)
   - The password strength meter shows your password quality
   - **Remember this password** - it cannot be recovered without your recovery key!

![Password Setup](screenshots/02-create-vault.png)
*Setting up your master password with strength indicator*

4. Configure access levels (or accept the defaults: Level 1, 2, 3)
5. **IMPORTANT:** Save your 24-word recovery key
   - Write it down on paper
   - Store it separately from your USB drive
   - Click **Copy** to copy to clipboard (auto-clears after 60 seconds)
   - Check the "I have saved my recovery key" box

![Recovery Key](screenshots/03-recovery-key.png)
*Your 24-word recovery key - save this securely!*

6. Click **Create Vault**

---

## Step 3: Add Files to Your Vault

Once your vault is unlocked, you can add files:

### Method A: Drag and Drop
1. Open your system file manager (Explorer, Finder, etc.)
2. Drag files from your computer into the TESSERACT window
3. Select the access level for the files
4. Click **Import**

![Drag and Drop](screenshots/04-drag-drop.png)
*Drag files directly into TESSERACT to encrypt them*

### Method B: Import Button
1. Click the **Import** button in the toolbar
2. Browse to select files
3. Choose the access level
4. Click **Import**

### Viewing Your Files
- Files appear in the file browser with their name, size, date, and access level
- Navigate folders using the breadcrumb navigation at the top
- Double-click a file to open it temporarily (auto-deleted when you lock the vault)
- Right-click for more options: Export, Rename, Delete, Change Access Level

![File Browser](screenshots/05-file-browser.png)
*The file browser shows all accessible files*

---

## Step 4: Lock Your Vault

When you're done working with your files, lock the vault to protect them:

### Manual Lock
- Click the **Lock** button in the toolbar, or
- Close the TESSERACT application

### Auto-Lock
- By default, TESSERACT auto-locks after 15 minutes of inactivity
- Configure this in **Settings > Auto-Lock Timeout**

![Lock Button](screenshots/06-lock-vault.png)
*Click Lock to secure your vault*

When locked:
- All encryption keys are securely wiped from memory
- Temporary files are securely deleted (overwritten then removed)
- You'll need to enter your password again to access files

---

## Quick Reference

| Action | How |
|--------|-----|
| Create vault | Launch app > Create New Vault > Set password |
| Open vault | Launch app > Open Existing Vault > Enter password |
| Add files | Drag & drop or Import button |
| Export files | Select file > Right-click > Export |
| Delete files | Select file > Right-click > Delete (or press Delete key) |
| Rename files | Select file > Right-click > Rename (or press F2) |
| Lock vault | Click Lock button or close app |
| Mount as drive | Settings > Enable VFS > Choose drive letter |

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Delete` | Delete selected file(s) |
| `F2` | Rename selected file |
| `Ctrl+E` | Export selected file(s) |
| `Ctrl+A` | Select all files |
| `Enter` | Open selected file |
| `Escape` | Cancel / Deselect |

---

## Troubleshooting

### "Fixed disk detected" error
TESSERACT requires a removable drive. Copy the application to a USB drive and run it from there.

### Forgot your password?
Use your 24-word recovery key:
1. Click **Forgot Password** on the login screen
2. Enter your recovery key (24 words or base64 string)
3. Set a new password

### VFS mount not working
- **Windows:** Install [Dokan](https://github.com/dokan-dev/dokany) or [WinFsp](https://winfsp.dev/)
- **Linux:** Install `fuse3` (`apt install fuse3` or `dnf install fuse3`)
- **macOS:** Install [macFUSE](https://osxfuse.github.io/)

---

## Next Steps

- Read the full [User Manual](USER_MANUAL.md) for all features
- Review the [Security Whitepaper](SECURITY_WHITEPAPER.md) for technical details
- Check the [Vault Format Specification](VAULT_FORMAT.md) for developers

---

*TESSERACT - Secure your data on any platform*
