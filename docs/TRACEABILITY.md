# TESSERACT Requirements Traceability Matrix

This document maps each requirement from the TESSERACT Requirements Specification to its implementing module and associated tests.

**Version:** 1.0
**Last Updated:** January 2026

---

## Legend

| Column | Description |
|--------|-------------|
| **Requirement ID** | Unique identifier from the requirements specification |
| **Module** | Rust crate and source file implementing the requirement |
| **Test** | Test module or function verifying the implementation |
| **Status** | Implementation status: Complete, Partial, Planned |

---

## 1. Security Requirements (SEC-*)

### 1.1 Encryption

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| SEC-001 | AES-256-GCM encryption | `crypto::aes` | `aes::tests::test_nist_*` | Complete |
| SEC-002 | Unique nonces | `crypto::nonce` | `nonce::tests::test_100k_no_collision`, `stress_tests::test_one_million_nonces` | Complete |
| SEC-003 | Argon2id KDF | `crypto::kdf` | `kdf::tests::test_rfc9106_*` | Complete |
| SEC-004 | CSPRNG | `crypto::random` | `random::tests::test_generate_*` | Complete |
| SEC-005 | Encrypted metadata | `core::metadata` | `metadata::tests::test_no_plaintext_*`, `encryption_verification::*` | Complete |
| SEC-006 | Per-file DEKs | `core::keystore` | `keystore::tests::test_add_file_dek_*` | Complete |
| SEC-007 | Configurable Argon2id | `crypto::kdf` | `kdf::tests::test_custom_params` | Complete |

### 1.2 Key Management (KEY-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| KEY-001 | Four-tier key hierarchy | `core::header`, `core::keystore`, `core::session` | `session::tests::test_full_hierarchy` | Complete |
| KEY-002 | No plaintext keys on disk | `crypto::secure_memory`, `core::header` | `header::tests::test_encrypted_master_key` | Complete |
| KEY-003 | Secure memory wiping | `crypto::secure_memory` | `secure_memory::tests::test_zeroize_*` | Complete |
| KEY-004 | Recovery key generation | `crypto::recovery` | `recovery::tests::test_generate_*`, `recovery::tests::test_bip39_*` | Complete |
| KEY-005 | Hardware token binding | - | - | Planned |
| KEY-006 | Key rotation | - | - | Planned |

### 1.3 Authentication (AUTH-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| AUTH-001 | Password authentication | `core::session` | `session::tests::test_open_vault_*` | Complete |
| AUTH-002 | Exponential backoff | `core::header` | `header::tests::test_backoff_*` | Complete |
| AUTH-003 | Temporary lockout | `core::header` | `header::tests::test_lockout_*` | Complete |
| AUTH-004 | Audit logging | - | - | Planned |
| AUTH-005 | Keystore destruction | - | - | Planned |
| AUTH-006 | Session timeout | `gui::app` | `app::tests::test_auto_lock_*` | Complete |
| AUTH-007 | Recovery key auth | `core::session`, `crypto::recovery` | `session::tests::test_recovery_*` | Complete |

### 1.4 Integrity Protection (INT-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| INT-001 | HMAC-SHA256 metadata | `crypto::hmac`, `core::metadata` | `hmac::tests::test_rfc4231_*`, `metadata::tests::test_tamper_*` | Complete |
| INT-002 | GCM authentication | `crypto::aes` | `aes::tests::test_tampered_*` | Complete |
| INT-003 | Header integrity | `core::header` | `header::tests::test_verify_integrity_*` | Complete |
| INT-004 | Executable integrity | - | - | Planned |

---

## 2. Functional Requirements

### 2.1 Multi-Level Access Control (MLA-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| MLA-001 | 3+ access levels | `core::access` | `access::tests::test_create_level_*` | Complete |
| MLA-002 | Password-level mapping | `core::session` | `session::tests::test_unlock_level_*` | Complete |
| MLA-003 | Hierarchical access | `core::session` | `session::tests::test_hierarchical_*` | Complete |
| MLA-004 | Compartmented mode | `core::access` | `access::tests::test_compartmented_*` | Complete |
| MLA-005 | File-level assignment | `core::files`, `core::session` | `session::tests::test_assign_file_level_*` | Complete |
| MLA-006 | Bulk assignment | - | - | Planned |
| MLA-007 | Level CRUD | `core::access` | `access::tests::test_create_delete_level_*` | Complete |
| MLA-008 | Visual level mapping | `gui::app` | `screens::tests::test_file_browser_*` | Complete |

### 2.2 Virtual Filesystem (VFS-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| VFS-001 | Windows drive mount | `vfs::dokan`, `vfs::mount_point` | `dokan::tests::test_mount_*`, `mount_point::tests::*` | Complete |
| VFS-002 | Linux/macOS mount | `vfs::fuse` | `fuse::tests::test_mount_*` | Complete |
| VFS-003 | Read decryption | `vfs::dokan`, `vfs::fuse` | `dokan::tests::test_read_*`, `integration_tests::test_read_*` | Complete |
| VFS-004 | Write encryption | `vfs::dokan`, `vfs::fuse` | `dokan::tests::test_write_*`, `integration_tests::test_write_*` | Complete |
| VFS-005 | Level filtering | `core::files`, `vfs::dokan` | `files::tests::test_list_files_*`, `integration_tests::test_directory_*` | Complete |
| VFS-006 | File operations | `vfs::ops`, `vfs::dokan`, `vfs::fuse` | `integration_tests::test_create_*`, `integration_tests::test_delete_*`, `integration_tests::test_rename_*` | Complete |
| VFS-007 | File locking | - | - | Planned |
| VFS-008 | Dokan driver | `vfs::dokan`, `vfs::detection` | `dokan::tests::*`, `detection::tests::test_dokan_*` | Complete |
| VFS-009 | Linux FUSE | `vfs::fuse` | `fuse::tests::*` | Complete |
| VFS-010 | macOS macFUSE | `vfs::fuse` | `fuse::tests::test_macos_*` | Complete |

### 2.3 Portable GUI Mode (GUI-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| GUI-001 | File browser | `gui::app`, `gui::screens` | `screens::tests::test_file_browser_*` | Complete |
| GUI-002 | Drag-drop import | `gui::app` | `app::tests::test_drag_drop_import_*` | Complete |
| GUI-003 | Drag-drop export | `gui::app` | `app::tests::test_export_*` | Complete |
| GUI-004 | In-place viewing | `core::tempfile` | `tempfile::tests::test_open_with_*` | Complete |
| GUI-005 | Secure temp files | `core::tempfile` | `tempfile::tests::test_secure_delete_*` | Complete |
| GUI-006 | Portable execution | `packaging::detection` | `detection::tests::test_is_removable_*` | Complete |
| GUI-007 | WebDAV fallback | - | - | Planned |

### 2.4 User Management (USR-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| USR-001 | Create users | - | - | Planned |
| USR-002 | Modify passwords | `core::session` | `session::tests::test_change_level_password_*` | Complete |
| USR-003 | Delete users | - | - | Planned |
| USR-004 | Password strength | `gui::screens` | `screens::tests::test_password_strength_*` | Complete |
| USR-005 | Single-user mode | `core::vault`, `core::session` | `vault::tests::*`, `session::tests::*` | Complete |

### 2.5 Vault Management (VLT-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| VLT-001 | Create vault | `core::vault` | `vault::tests::test_create_vault_*` | Complete |
| VLT-002 | Open vault | `core::session` | `session::tests::test_open_vault_*` | Complete |
| VLT-003 | Close/lock vault | `core::session`, `vfs::ops` | `session::tests::test_lock_*`, `ops::tests::test_unmount_*` | Complete |
| VLT-004 | Format versioning | `core::header` | `header::tests::test_version_*` | Complete |
| VLT-005 | Vault backup | - | - | Planned |
| VLT-006 | Integrity check | - | - | Planned |
| VLT-007 | Vault compaction | - | - | Planned |

---

## 3. Platform Requirements (PLT-*, EXE-*)

### 3.1 Operating System Support

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| PLT-001 | Windows 10 | All modules | CI: `windows-latest` | Complete |
| PLT-002 | Windows 11 | All modules | CI: `windows-latest` | Complete |
| PLT-003 | Ubuntu 22.04 | All modules | CI: `ubuntu-22.04` | Complete |
| PLT-004 | Ubuntu 24.04 | All modules | CI: `ubuntu-latest` | Complete |
| PLT-005 | Fedora 38+ | All modules | Manual testing | Partial |
| PLT-006 | macOS 12+ | All modules | CI: `macos-latest` | Complete |
| PLT-007 | macOS 14+ | All modules | CI: `macos-latest` | Complete |

### 3.2 Execution Constraints

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| EXE-001 | Removable media only | `packaging::detection` | `detection::tests::test_is_removable_*`, `detection::tests::test_validate_*` | Complete |
| EXE-002 | Windows portable exe | `packaging::bundle` | `bundle::tests::test_windows_*` | Complete |
| EXE-003 | Linux AppImage | `packaging::appimage` | `appimage::tests::*` | Complete |
| EXE-004 | macOS app bundle | `packaging::macos` | `macos::tests::*` | Complete |
| EXE-005 | No admin rights | `gui::app`, `vfs::detection` | `detection::tests::test_non_admin_*` | Complete |

---

## 4. Performance Requirements (PRF-*, LAT-*, RES-*, SCL-*)

### 4.1 Throughput

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| PRF-001 | Read throughput | `crypto::benchmarks` | `benchmarks::test_sequential_read_*` | Complete |
| PRF-002 | Write throughput | `crypto::benchmarks` | `benchmarks::test_sequential_write_*` | Complete |
| PRF-003 | Random 4K read | - | - | Planned |
| PRF-004 | Random 4K write | - | - | Planned |
| PRF-005 | AES-NI detection | `crypto::acceleration` | `acceleration::tests::test_has_aes_ni_*` | Complete |

### 4.2 Latency

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| LAT-001 | App startup | `gui::app` | Manual benchmark | Partial |
| LAT-002 | Vault unlock (empty) | `crypto::benchmarks` | `benchmarks::test_vault_unlock_*` | Complete |
| LAT-003 | Vault unlock (10K files) | - | - | Planned |
| LAT-004 | File open latency | `vfs::dokan` | `dokan::tests::test_read_first_byte_*` | Complete |
| LAT-005 | Directory listing | `core::files` | `files::tests::test_list_performance_*` | Partial |
| LAT-006 | Mount time | `vfs::dokan`, `vfs::fuse` | `dokan::tests::test_mount_time_*` | Complete |
| LAT-007 | Unmount time | `vfs::ops` | `ops::tests::test_unmount_time_*` | Complete |

### 4.3 Resource Usage

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| RES-001 | Memory idle | - | Manual benchmark | Partial |
| RES-002 | Memory active | - | Manual benchmark | Partial |
| RES-003 | CPU idle | - | Manual benchmark | Partial |
| RES-004 | Streaming encryption | `crypto::streaming` | `streaming::tests::test_large_file_*` | Complete |
| RES-005 | Disk footprint | `packaging::bundle` | `bundle::tests::test_size_limit_*` | Complete |

### 4.4 Scalability

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| SCL-001 | 100K files | - | - | Planned |
| SCL-002 | 100 GB files | `crypto::streaming` | `streaming::tests::test_large_file_*` | Partial |
| SCL-003 | 2 TB vault | - | - | Planned |
| SCL-004 | Deep nesting | `core::files` | `files::tests::test_deep_path_*` | Partial |
| SCL-005 | Long filenames | `core::metadata` | `metadata::tests::test_long_filename_*` | Complete |
| SCL-006 | Unicode filenames | `core::metadata`, `core::files` | `metadata::tests::test_unicode_*`, `files::tests::test_unicode_*` | Complete |

---

## 5. Usability Requirements (UIX-*, DOC-*)

### 5.1 User Interface

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| UIX-001 | First-run experience | `gui::app`, `gui::screens` | `screens::tests::test_wizard_*` | Complete |
| UIX-002 | Error messages | `core::error`, `vfs::error`, `crypto::error` | `error::tests::*` | Complete |
| UIX-003 | Progress indicators | `gui::app` | `app::tests::test_progress_*` | Complete |
| UIX-004 | Keyboard shortcuts | `gui::app` | `app::tests::test_keyboard_*` | Complete |
| UIX-005 | Dark mode | `gui::theme` | - | Planned |
| UIX-006 | High DPI | `gui::app` | Manual testing | Partial |
| UIX-007 | Accessibility | - | - | Planned |

### 5.2 Documentation

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| DOC-001 | Quick start guide | `docs/QUICKSTART.md` | File exists | Complete |
| DOC-002 | User manual | `docs/USER_MANUAL.md` | File exists | Complete |
| DOC-003 | Security whitepaper | `docs/SECURITY_WHITEPAPER.md` | File exists | Complete |
| DOC-004 | In-app help | - | - | Planned |
| DOC-005 | FAQ | - | - | Planned |

---

## 6. Reliability Requirements (REL-*, ERR-*)

### 6.1 Data Integrity

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| REL-001 | Crash recovery | `core::vault` | `vault::tests::test_atomic_*` | Complete |
| REL-002 | Atomic operations | `core::vault`, `vfs::dokan` | `vault::tests::test_atomic_*`, `dokan::tests::test_atomic_*` | Complete |
| REL-003 | USB removal | `vfs::error` | `error::tests::test_media_removed_*` | Complete |
| REL-004 | Power loss | - | - | Planned |

### 6.2 Error Handling

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| ERR-001 | Disk full | `vfs::error` | `error::tests::test_disk_full_*` | Complete |
| ERR-002 | Read errors | `vfs::error` | `error::tests::test_io_error_*` | Complete |
| ERR-003 | Permission errors | `vfs::error`, `vfs::dokan` | `error::tests::test_access_denied_*` | Complete |
| ERR-004 | Driver crash recovery | - | - | Planned |

---

## 7. Testing Requirements (TST-*, SEC-TST-*)

### 7.1 Test Coverage

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| TST-001 | Unit test coverage | All modules | CI: coverage job | Complete |
| TST-002 | Integration tests | `vfs::integration_tests` | `integration_tests::*` | Complete |
| TST-003 | Cross-platform CI | `.github/workflows/ci.yml` | CI pipeline | Complete |
| TST-004 | Fuzz testing | - | - | Planned |
| TST-005 | Performance regression | `crypto::benchmarks` | CI: benchmark job | Complete |

### 7.2 Security Testing

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| SEC-TST-001 | Crypto test vectors | `crypto::test_vectors` | `test_vectors::*` | Complete |
| SEC-TST-002 | Memory analysis | `crypto::secure_memory` | `secure_memory::tests::test_verify_wiped_*` | Complete |
| SEC-TST-003 | Static analysis | CI: clippy | CI: clippy job | Complete |
| SEC-TST-004 | Penetration testing | - | - | Planned |
| SEC-TST-005 | Side-channel resistance | `crypto::hmac` | `hmac::tests::test_constant_time_*` | Complete |

---

## 8. Compliance Requirements (CMP-*)

| Req ID | Requirement | Module | Test | Status |
|--------|-------------|--------|------|--------|
| CMP-001 | NIST standards | `crypto::aes`, `crypto::hmac` | `test_vectors::test_nist_*`, `hmac::tests::test_rfc4231_*` | Complete |
| CMP-002 | RFC 9106 (Argon2) | `crypto::kdf` | `test_vectors::test_argon2_*`, `kdf::tests::test_rfc9106_*` | Complete |
| CMP-003 | Dependency vetting | `Cargo.toml` | CI: audit job | Complete |
| CMP-004 | Windows code signing | `packaging::bundle` | Placeholder | Planned |
| CMP-005 | macOS notarization | `packaging::macos` | Placeholder | Planned |

---

## Summary Statistics

| Category | Total | Complete | Partial | Planned |
|----------|-------|----------|---------|---------|
| Security (SEC-*) | 7 | 7 | 0 | 0 |
| Key Management (KEY-*) | 6 | 4 | 0 | 2 |
| Authentication (AUTH-*) | 7 | 5 | 0 | 2 |
| Integrity (INT-*) | 4 | 3 | 0 | 1 |
| Multi-Level Access (MLA-*) | 8 | 7 | 0 | 1 |
| VFS (VFS-*) | 10 | 9 | 0 | 1 |
| GUI (GUI-*) | 7 | 6 | 0 | 1 |
| User Management (USR-*) | 5 | 3 | 0 | 2 |
| Vault Management (VLT-*) | 7 | 4 | 0 | 3 |
| Platform (PLT-*) | 7 | 6 | 1 | 0 |
| Execution (EXE-*) | 5 | 5 | 0 | 0 |
| Performance (PRF-*) | 5 | 3 | 0 | 2 |
| Latency (LAT-*) | 7 | 4 | 2 | 1 |
| Resources (RES-*) | 5 | 2 | 3 | 0 |
| Scalability (SCL-*) | 6 | 2 | 2 | 2 |
| Usability (UIX-*) | 7 | 4 | 1 | 2 |
| Documentation (DOC-*) | 5 | 3 | 0 | 2 |
| Reliability (REL-*) | 4 | 3 | 0 | 1 |
| Error Handling (ERR-*) | 4 | 3 | 0 | 1 |
| Testing (TST-*) | 5 | 4 | 0 | 1 |
| Security Testing (SEC-TST-*) | 5 | 4 | 0 | 1 |
| Compliance (CMP-*) | 5 | 3 | 0 | 2 |
| **TOTAL** | **131** | **94** | **9** | **28** |

**Coverage: 72% Complete, 7% Partial, 21% Planned**

---

## Appendix A: Module Reference

| Crate | Module | Primary Requirements |
|-------|--------|---------------------|
| `crypto` | `aes` | SEC-001, INT-002 |
| `crypto` | `acceleration` | PRF-005 |
| `crypto` | `kdf` | SEC-003, SEC-007 |
| `crypto` | `random` | SEC-004 |
| `crypto` | `nonce` | SEC-002 |
| `crypto` | `secure_memory` | KEY-002, KEY-003 |
| `crypto` | `hmac` | INT-001, SEC-TST-005 |
| `crypto` | `recovery` | KEY-004, AUTH-007 |
| `crypto` | `streaming` | RES-004, SCL-002 |
| `crypto` | `test_vectors` | SEC-TST-001, CMP-001, CMP-002 |
| `crypto` | `stress_tests` | SEC-002 |
| `crypto` | `encryption_verification` | SEC-005 |
| `crypto` | `benchmarks` | PRF-001, PRF-002, LAT-002, TST-005 |
| `core` | `header` | KEY-001, INT-003, VLT-004, AUTH-002, AUTH-003 |
| `core` | `keystore` | KEY-001, SEC-006 |
| `core` | `session` | KEY-001, AUTH-001, AUTH-006, AUTH-007, MLA-002, MLA-003, VLT-002, VLT-003 |
| `core` | `vault` | VLT-001, REL-001, REL-002 |
| `core` | `access` | MLA-001, MLA-004, MLA-007 |
| `core` | `files` | MLA-005, VFS-005, SCL-004, SCL-005, SCL-006 |
| `core` | `metadata` | SEC-005, SCL-005, SCL-006 |
| `core` | `blob` | SEC-006 |
| `core` | `tempfile` | GUI-004, GUI-005 |
| `vfs` | `detection` | VFS-008, EXE-001 |
| `vfs` | `mount_point` | VFS-001 |
| `vfs` | `dokan` | VFS-001, VFS-003, VFS-004, VFS-006, VFS-008 |
| `vfs` | `fuse` | VFS-002, VFS-003, VFS-004, VFS-006, VFS-009, VFS-010 |
| `vfs` | `ops` | VLT-003, LAT-007 |
| `vfs` | `error` | ERR-001, ERR-002, ERR-003, REL-003 |
| `vfs` | `integration_tests` | TST-002, VFS-003, VFS-004, VFS-005, VFS-006 |
| `gui` | `app` | AUTH-006, GUI-001, GUI-002, GUI-003, UIX-001, UIX-003, UIX-004 |
| `gui` | `screens` | GUI-001, MLA-008, UIX-001, USR-004 |
| `gui` | `config` | GUI-006 |
| `packaging` | `detection` | EXE-001, GUI-006 |
| `packaging` | `appimage` | EXE-003 |
| `packaging` | `macos` | EXE-004, CMP-005 |
| `packaging` | `bundle` | EXE-002, RES-005 |
| `packaging` | `usb` | GUI-006 |
| `cli` | `commands` | VLT-001 |

---

## Appendix B: Test Module Reference

| Test Module | Requirements Verified |
|-------------|----------------------|
| `crypto::aes::tests` | SEC-001, INT-002 |
| `crypto::kdf::tests` | SEC-003, SEC-007, CMP-002 |
| `crypto::random::tests` | SEC-004 |
| `crypto::nonce::tests` | SEC-002 |
| `crypto::secure_memory::tests` | KEY-002, KEY-003, SEC-TST-002 |
| `crypto::hmac::tests` | INT-001, CMP-001, SEC-TST-005 |
| `crypto::recovery::tests` | KEY-004, AUTH-007 |
| `crypto::streaming::tests` | RES-004, SCL-002 |
| `crypto::test_vectors` | SEC-TST-001, CMP-001, CMP-002 |
| `crypto::stress_tests` | SEC-002 |
| `crypto::encryption_verification` | SEC-005 |
| `crypto::benchmarks` | PRF-001, PRF-002, LAT-002, TST-005 |
| `core::header::tests` | KEY-001, INT-003, VLT-004, AUTH-002, AUTH-003 |
| `core::keystore::tests` | KEY-001, SEC-006 |
| `core::session::tests` | AUTH-001, AUTH-007, MLA-002, MLA-003, MLA-005, VLT-002 |
| `core::vault::tests` | VLT-001, REL-001, REL-002 |
| `core::access::tests` | MLA-001, MLA-004, MLA-007 |
| `core::files::tests` | MLA-005, VFS-005, SCL-004, SCL-006 |
| `core::metadata::tests` | SEC-005, SCL-005, SCL-006 |
| `core::tempfile::tests` | GUI-004, GUI-005 |
| `vfs::detection::tests` | VFS-008, EXE-001 |
| `vfs::mount_point::tests` | VFS-001 |
| `vfs::dokan::tests` | VFS-001, VFS-003, VFS-004, VFS-006, VFS-008, LAT-004, LAT-006 |
| `vfs::fuse::tests` | VFS-002, VFS-009, VFS-010 |
| `vfs::ops::tests` | VLT-003, LAT-007 |
| `vfs::error::tests` | ERR-001, ERR-002, ERR-003, REL-003 |
| `vfs::integration_tests` | TST-002, VFS-003, VFS-004, VFS-005, VFS-006 |
| `gui::app::tests` | AUTH-006, GUI-002, GUI-003, UIX-003, UIX-004 |
| `gui::screens::tests` | GUI-001, MLA-008, UIX-001, USR-004 |
| `packaging::detection::tests` | EXE-001 |
| `packaging::appimage::tests` | EXE-003 |
| `packaging::macos::tests` | EXE-004 |
| `packaging::bundle::tests` | EXE-002, RES-005 |

---

*End of Traceability Matrix*
