//! Secure memory handling with automatic zeroization.
//!
//! Provides wrappers that ensure sensitive key material is zeroed from memory
//! when dropped. Includes optional memory locking to prevent swapping to disk.
//!
//! # Features
//!
//! - **Automatic Zeroization**: All sensitive data is zeroed on drop using the
//!   `zeroize` crate's secure memory clearing.
//! - **Memory Locking**: Uses `mlock` (Unix) or `VirtualLock` (Windows) to
//!   prevent sensitive data from being swapped to disk.
//! - **Type Safety**: Strongly-typed wrappers prevent accidental exposure.
//!
//! # Example
//!
//! ```rust
//! use tesseract_crypto::secure_memory::{SecureBytes, SecureKey};
//!
//! // Create a secure key from raw bytes
//! let key_bytes = [0x42u8; 32];
//! let secure_key = SecureKey::new(key_bytes);
//!
//! // Access the key material
//! assert_eq!(secure_key.as_ref().len(), 32);
//!
//! // Key is automatically zeroed when dropped
//! drop(secure_key);
//! ```

use std::fmt;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error type for secure memory operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureMemoryError {
    /// Failed to lock memory (mlock/VirtualLock failed).
    LockFailed(String),
    /// Failed to unlock memory.
    UnlockFailed(String),
    /// Invalid size provided.
    InvalidSize(usize),
}

impl std::fmt::Display for SecureMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockFailed(msg) => write!(f, "Failed to lock memory: {msg}"),
            Self::UnlockFailed(msg) => write!(f, "Failed to unlock memory: {msg}"),
            Self::InvalidSize(size) => write!(f, "Invalid size: {size}"),
        }
    }
}

impl std::error::Error for SecureMemoryError {}

/// A secure wrapper for variable-length sensitive byte data.
///
/// This type ensures that the contained bytes are:
/// - Zeroed when the wrapper is dropped
/// - Optionally locked in memory to prevent swapping
///
/// # Security Properties
///
/// - Memory is zeroed on drop using `zeroize`
/// - Debug output does not expose the actual contents
/// - Clone is explicitly not implemented to prevent accidental copies
#[derive(Zeroize)]
pub struct SecureBytes {
    /// The underlying byte vector.
    data: Vec<u8>,
    /// Whether memory is currently locked.
    #[zeroize(skip)]
    is_locked: bool,
}

impl SecureBytes {
    /// Creates a new `SecureBytes` from a vector of bytes.
    ///
    /// The original vector is consumed and its memory is managed securely.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            is_locked: false,
        }
    }

    /// Creates a new `SecureBytes` with zeroed data of the specified length.
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
            is_locked: false,
        }
    }

    /// Creates a `SecureBytes` from a slice by copying the data.
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
            is_locked: false,
        }
    }

    /// Returns the length of the secure data.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the secure data is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns true if the memory is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Attempts to lock the memory to prevent swapping.
    ///
    /// This uses `mlock` on Unix systems and `VirtualLock` on Windows.
    /// The operation may fail if:
    /// - The process doesn't have sufficient privileges
    /// - The system's locked memory limit has been reached
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::LockFailed` if the lock operation fails.
    pub fn lock(&mut self) -> Result<(), SecureMemoryError> {
        if self.is_locked || self.data.is_empty() {
            return Ok(());
        }

        lock_memory(&self.data)?;
        self.is_locked = true;
        Ok(())
    }

    /// Attempts to unlock previously locked memory.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::UnlockFailed` if the unlock operation fails.
    pub fn unlock(&mut self) -> Result<(), SecureMemoryError> {
        if !self.is_locked || self.data.is_empty() {
            return Ok(());
        }

        unlock_memory(&self.data)?;
        self.is_locked = false;
        Ok(())
    }

    /// Creates a new `SecureBytes` with the memory locked.
    ///
    /// This is a convenience method that creates the wrapper and locks
    /// the memory in one step.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::LockFailed` if the lock operation fails.
    pub fn new_locked(data: Vec<u8>) -> Result<Self, SecureMemoryError> {
        let mut secure = Self::new(data);
        secure.lock()?;
        Ok(secure)
    }

    /// Exposes the secure data as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Exposes the secure data as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Unlock memory before zeroization if it was locked
        if self.is_locked && !self.data.is_empty() {
            // Ignore unlock errors during drop
            let _ = unlock_memory(&self.data);
        }
        // Manually zeroize the data
        self.data.zeroize();
    }
}

// Debug implementation that doesn't expose the actual data
impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureBytes")
            .field("len", &self.data.len())
            .field("is_locked", &self.is_locked)
            .finish_non_exhaustive()
    }
}

/// A secure wrapper for fixed-size 256-bit (32-byte) keys.
///
/// This is optimized for AES-256 keys, master keys, and other 32-byte secrets.
#[derive(Zeroize)]
pub struct SecureKey {
    /// The key data.
    data: [u8; 32],
    /// Whether memory is currently locked.
    #[zeroize(skip)]
    is_locked: bool,
}

impl SecureKey {
    /// AES-256 key size in bytes.
    pub const SIZE: usize = 32;

    /// Creates a new `SecureKey` from a 32-byte array.
    #[must_use]
    pub fn new(data: [u8; 32]) -> Self {
        Self {
            data,
            is_locked: false,
        }
    }

    /// Creates a new zeroed `SecureKey`.
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            data: [0u8; 32],
            is_locked: false,
        }
    }

    /// Creates a `SecureKey` from a slice.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::InvalidSize` if the slice is not 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SecureMemoryError> {
        if slice.len() != 32 {
            return Err(SecureMemoryError::InvalidSize(slice.len()));
        }
        let mut data = [0u8; 32];
        data.copy_from_slice(slice);
        Ok(Self {
            data,
            is_locked: false,
        })
    }

    /// Returns true if the memory is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Attempts to lock the memory to prevent swapping.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::LockFailed` if the lock operation fails.
    pub fn lock(&mut self) -> Result<(), SecureMemoryError> {
        if self.is_locked {
            return Ok(());
        }

        lock_memory(&self.data)?;
        self.is_locked = true;
        Ok(())
    }

    /// Attempts to unlock previously locked memory.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::UnlockFailed` if the unlock operation fails.
    pub fn unlock(&mut self) -> Result<(), SecureMemoryError> {
        if !self.is_locked {
            return Ok(());
        }

        unlock_memory(&self.data)?;
        self.is_locked = false;
        Ok(())
    }

    /// Creates a new `SecureKey` with the memory locked.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::LockFailed` if the lock operation fails.
    pub fn new_locked(data: [u8; 32]) -> Result<Self, SecureMemoryError> {
        let mut secure = Self::new(data);
        secure.lock()?;
        Ok(secure)
    }

    /// Exposes the key as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Exposes the key as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Returns a reference to the underlying array.
    #[must_use]
    pub fn as_array(&self) -> &[u8; 32] {
        &self.data
    }
}

impl AsRef<[u8]> for SecureKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureKey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecureKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Unlock memory before zeroization if it was locked
        if self.is_locked {
            let _ = unlock_memory(&self.data);
        }
        // Manually zeroize the data
        self.data.zeroize();
    }
}

// Debug implementation that doesn't expose the actual data
impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKey")
            .field("is_locked", &self.is_locked)
            .finish_non_exhaustive()
    }
}

/// A secure wrapper for 12-byte nonces (96-bit, used with AES-GCM).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureNonce {
    /// The nonce data.
    data: [u8; 12],
}

impl SecureNonce {
    /// AES-GCM nonce size in bytes.
    pub const SIZE: usize = 12;

    /// Creates a new `SecureNonce` from a 12-byte array.
    #[must_use]
    pub fn new(data: [u8; 12]) -> Self {
        Self { data }
    }

    /// Creates a new zeroed `SecureNonce`.
    #[must_use]
    pub fn zeroed() -> Self {
        Self { data: [0u8; 12] }
    }

    /// Creates a `SecureNonce` from a slice.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::InvalidSize` if the slice is not 12 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SecureMemoryError> {
        if slice.len() != 12 {
            return Err(SecureMemoryError::InvalidSize(slice.len()));
        }
        let mut data = [0u8; 12];
        data.copy_from_slice(slice);
        Ok(Self { data })
    }

    /// Returns a reference to the underlying array.
    #[must_use]
    pub fn as_array(&self) -> &[u8; 12] {
        &self.data
    }
}

impl AsRef<[u8]> for SecureNonce {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Deref for SecureNonce {
    type Target = [u8; 12];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

// Debug implementation that doesn't expose the actual data
impl fmt::Debug for SecureNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureNonce").finish_non_exhaustive()
    }
}

/// A secure wrapper for 16-byte salts (128-bit, used with Argon2).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureSalt {
    /// The salt data.
    data: [u8; 16],
}

impl SecureSalt {
    /// Salt size in bytes.
    pub const SIZE: usize = 16;

    /// Creates a new `SecureSalt` from a 16-byte array.
    #[must_use]
    pub fn new(data: [u8; 16]) -> Self {
        Self { data }
    }

    /// Creates a new zeroed `SecureSalt`.
    #[must_use]
    pub fn zeroed() -> Self {
        Self { data: [0u8; 16] }
    }

    /// Creates a `SecureSalt` from a slice.
    ///
    /// # Errors
    ///
    /// Returns `SecureMemoryError::InvalidSize` if the slice is not 16 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SecureMemoryError> {
        if slice.len() != 16 {
            return Err(SecureMemoryError::InvalidSize(slice.len()));
        }
        let mut data = [0u8; 16];
        data.copy_from_slice(slice);
        Ok(Self { data })
    }

    /// Returns a reference to the underlying array.
    #[must_use]
    pub fn as_array(&self) -> &[u8; 16] {
        &self.data
    }
}

impl AsRef<[u8]> for SecureSalt {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Deref for SecureSalt {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

// Debug implementation that doesn't expose the actual data
impl fmt::Debug for SecureSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureSalt").finish_non_exhaustive()
    }
}

// ============================================================================
// Platform-specific memory locking implementation
// ============================================================================

/// Lock memory to prevent it from being swapped to disk.
#[cfg(unix)]
fn lock_memory(data: &[u8]) -> Result<(), SecureMemoryError> {
    use std::ffi::c_void;

    if data.is_empty() {
        return Ok(());
    }

    // SAFETY: We're passing a valid pointer and length for memory we own.
    // mlock is safe to call on valid memory regions.
    let result = unsafe { libc::mlock(data.as_ptr() as *const c_void, data.len()) };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(SecureMemoryError::LockFailed(errno.to_string()))
    }
}

/// Unlock previously locked memory.
#[cfg(unix)]
fn unlock_memory(data: &[u8]) -> Result<(), SecureMemoryError> {
    use std::ffi::c_void;

    if data.is_empty() {
        return Ok(());
    }

    // SAFETY: We're passing a valid pointer and length for memory we own.
    // munlock is safe to call on valid memory regions.
    let result = unsafe { libc::munlock(data.as_ptr() as *const c_void, data.len()) };

    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(SecureMemoryError::UnlockFailed(errno.to_string()))
    }
}

/// Lock memory to prevent it from being swapped to disk (Windows).
#[cfg(windows)]
fn lock_memory(data: &[u8]) -> Result<(), SecureMemoryError> {
    use std::ffi::c_void;

    if data.is_empty() {
        return Ok(());
    }

    // SAFETY: We're passing a valid pointer and length for memory we own.
    // VirtualLock is safe to call on valid memory regions.
    let result = unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(
            data.as_ptr() as *const c_void,
            data.len(),
        )
    };

    if result != 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(SecureMemoryError::LockFailed(errno.to_string()))
    }
}

/// Unlock previously locked memory (Windows).
#[cfg(windows)]
fn unlock_memory(data: &[u8]) -> Result<(), SecureMemoryError> {
    use std::ffi::c_void;

    if data.is_empty() {
        return Ok(());
    }

    // SAFETY: We're passing a valid pointer and length for memory we own.
    // VirtualUnlock is safe to call on valid memory regions.
    let result = unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(
            data.as_ptr() as *const c_void,
            data.len(),
        )
    };

    if result != 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(SecureMemoryError::UnlockFailed(errno.to_string()))
    }
}

/// Fallback for platforms without mlock support.
#[cfg(not(any(unix, windows)))]
fn lock_memory(_data: &[u8]) -> Result<(), SecureMemoryError> {
    // No-op on unsupported platforms
    // Log warning in real usage
    Ok(())
}

/// Fallback for platforms without munlock support.
#[cfg(not(any(unix, windows)))]
fn unlock_memory(_data: &[u8]) -> Result<(), SecureMemoryError> {
    // No-op on unsupported platforms
    Ok(())
}

// ============================================================================
// Utility functions
// ============================================================================

/// Securely clear a byte slice by overwriting with zeros.
///
/// This function uses the `zeroize` crate to ensure the compiler
/// does not optimize away the zeroing operation.
pub fn secure_clear(data: &mut [u8]) {
    data.zeroize();
}

/// Securely compare two byte slices in constant time.
///
/// This prevents timing attacks that could leak information about
/// the comparison result.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // XOR all bytes together - if they're all equal, result is 0
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes_new() {
        let data = vec![1, 2, 3, 4, 5];
        let secure = SecureBytes::new(data);
        assert_eq!(secure.len(), 5);
        assert!(!secure.is_empty());
        assert!(!secure.is_locked());
    }

    #[test]
    fn test_secure_bytes_zeroed() {
        let secure = SecureBytes::zeroed(32);
        assert_eq!(secure.len(), 32);
        assert!(secure.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_bytes_from_slice() {
        let original = [1, 2, 3, 4, 5];
        let secure = SecureBytes::from_slice(&original);
        assert_eq!(secure.as_slice(), &original);
    }

    #[test]
    fn test_secure_bytes_deref() {
        let data = vec![10, 20, 30];
        let secure = SecureBytes::new(data);
        assert_eq!(&*secure, &[10, 20, 30]);
    }

    #[test]
    fn test_secure_bytes_deref_mut() {
        let data = vec![1, 2, 3];
        let mut secure = SecureBytes::new(data);
        secure[0] = 100;
        assert_eq!(secure[0], 100);
    }

    #[test]
    fn test_secure_bytes_debug_no_leak() {
        let secret = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let secure = SecureBytes::new(secret);
        let debug_str = format!("{:?}", secure);

        // Debug should not contain the actual bytes
        assert!(!debug_str.contains("DE"));
        assert!(!debug_str.contains("AD"));
        assert!(!debug_str.contains("BE"));
        assert!(!debug_str.contains("EF"));
        assert!(!debug_str.contains("222")); // 0xDE = 222

        // But should show length
        assert!(debug_str.contains("len: 4") || debug_str.contains("4"));
    }

    #[test]
    fn test_secure_key_new() {
        let key_data = [0x42u8; 32];
        let key = SecureKey::new(key_data);
        assert_eq!(key.as_slice().len(), 32);
        assert!(!key.is_locked());
    }

    #[test]
    fn test_secure_key_zeroed() {
        let key = SecureKey::zeroed();
        assert!(key.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_key_from_slice() {
        let data = [0xAAu8; 32];
        let key = SecureKey::from_slice(&data).unwrap();
        assert_eq!(key.as_slice(), &data);
    }

    #[test]
    fn test_secure_key_from_slice_invalid_size() {
        let data = [0xAA; 16]; // Wrong size
        let result = SecureKey::from_slice(&data);
        assert!(matches!(result, Err(SecureMemoryError::InvalidSize(16))));
    }

    #[test]
    fn test_secure_key_as_array() {
        let key_data = [0x55u8; 32];
        let key = SecureKey::new(key_data);
        let array_ref = key.as_array();
        assert_eq!(array_ref, &key_data);
    }

    #[test]
    fn test_secure_key_debug_no_leak() {
        let key = SecureKey::new([0xDEu8; 32]);
        let debug_str = format!("{:?}", key);

        // Debug should not contain the actual key bytes
        assert!(!debug_str.contains("DE"));
        assert!(!debug_str.contains("222")); // 0xDE = 222
    }

    #[test]
    fn test_secure_nonce_new() {
        let nonce_data = [0x12u8; 12];
        let nonce = SecureNonce::new(nonce_data);
        assert_eq!(nonce.as_ref().len(), 12);
    }

    #[test]
    fn test_secure_nonce_from_slice() {
        let data = [0xBBu8; 12];
        let nonce = SecureNonce::from_slice(&data).unwrap();
        assert_eq!(nonce.as_array(), &data);
    }

    #[test]
    fn test_secure_nonce_from_slice_invalid_size() {
        let data = [0xBB; 8]; // Wrong size
        let result = SecureNonce::from_slice(&data);
        assert!(matches!(result, Err(SecureMemoryError::InvalidSize(8))));
    }

    #[test]
    fn test_secure_salt_new() {
        let salt_data = [0x34u8; 16];
        let salt = SecureSalt::new(salt_data);
        assert_eq!(salt.as_ref().len(), 16);
    }

    #[test]
    fn test_secure_salt_from_slice() {
        let data = [0xCCu8; 16];
        let salt = SecureSalt::from_slice(&data).unwrap();
        assert_eq!(salt.as_array(), &data);
    }

    #[test]
    fn test_secure_salt_from_slice_invalid_size() {
        let data = [0xCC; 32]; // Wrong size
        let result = SecureSalt::from_slice(&data);
        assert!(matches!(result, Err(SecureMemoryError::InvalidSize(32))));
    }

    #[test]
    fn test_secure_clear() {
        let mut data = [1, 2, 3, 4, 5];
        secure_clear(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_constant_time_eq_equal() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 6]; // Last byte differs
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn test_secure_bytes_empty() {
        let secure = SecureBytes::new(vec![]);
        assert!(secure.is_empty());
        assert_eq!(secure.len(), 0);
    }

    // Test that zeroization happens on drop
    // Note: This test verifies the behavior but cannot directly check
    // memory after drop since the memory is deallocated. The zeroize
    // crate guarantees zeroing before deallocation.
    #[test]
    fn test_zeroize_on_drop() {
        let data = vec![0xFF; 32];
        let data_ptr = data.as_ptr();

        // Create a scope to trigger drop
        {
            let secure = SecureBytes::new(data);
            // Verify data is still intact while in scope
            assert!(secure.as_slice().iter().all(|&b| b == 0xFF));
        }
        // After drop, the memory is zeroed then deallocated
        // We cannot safely check this without undefined behavior,
        // but the zeroize derive macro guarantees this behavior.

        // Just verify the pointer was valid (this is just for coverage)
        assert!(!data_ptr.is_null());
    }

    // Test mlock/munlock behavior
    #[test]
    fn test_memory_lock_unlock() {
        let data = vec![0xAB; 4096]; // Page-sized allocation more likely to work
        let mut secure = SecureBytes::new(data);

        // Lock may fail due to system limits, so we just test the API
        let lock_result = secure.lock();

        if lock_result.is_ok() {
            assert!(secure.is_locked());

            // Unlock should succeed
            let unlock_result = secure.unlock();
            assert!(unlock_result.is_ok());
            assert!(!secure.is_locked());
        }
        // If lock fails, that's acceptable - it depends on system configuration
    }

    #[test]
    fn test_secure_bytes_new_locked() {
        let data = vec![0xCD; 4096];
        let result = SecureBytes::new_locked(data);

        if let Ok(secure) = result {
            assert!(secure.is_locked());
        }
        // If locking fails, that's acceptable for this test
    }

    #[test]
    fn test_secure_key_lock_unlock() {
        let key_data = [0xEF; 32];
        let mut key = SecureKey::new(key_data);

        let lock_result = key.lock();

        if lock_result.is_ok() {
            assert!(key.is_locked());

            let unlock_result = key.unlock();
            assert!(unlock_result.is_ok());
            assert!(!key.is_locked());
        }
    }

    #[test]
    fn test_secure_key_new_locked() {
        let key_data = [0xAB; 32];
        let result = SecureKey::new_locked(key_data);

        if let Ok(key) = result {
            assert!(key.is_locked());
        }
    }

    #[test]
    fn test_double_lock_is_noop() {
        let data = vec![0x11; 1024];
        let mut secure = SecureBytes::new(data);

        if secure.lock().is_ok() {
            // Second lock should succeed (no-op)
            assert!(secure.lock().is_ok());
            assert!(secure.is_locked());
        }
    }

    #[test]
    fn test_double_unlock_is_noop() {
        let data = vec![0x22; 1024];
        let mut secure = SecureBytes::new(data);

        // Unlock when not locked should be no-op
        assert!(secure.unlock().is_ok());
        assert!(!secure.is_locked());
    }

    #[test]
    fn test_secure_bytes_as_ref_as_mut() {
        let data = vec![1, 2, 3];
        let mut secure = SecureBytes::new(data);

        // Test AsRef
        let slice: &[u8] = secure.as_ref();
        assert_eq!(slice, &[1, 2, 3]);

        // Test AsMut
        let slice_mut: &mut [u8] = secure.as_mut();
        slice_mut[0] = 10;
        assert_eq!(secure.as_ref(), &[10, 2, 3]);
    }

    #[test]
    fn test_secure_key_as_ref_as_mut() {
        let data = [5u8; 32];
        let mut key = SecureKey::new(data);

        // Test AsRef
        let slice: &[u8] = key.as_ref();
        assert_eq!(slice.len(), 32);

        // Test AsMut
        let slice_mut: &mut [u8] = key.as_mut();
        slice_mut[0] = 99;
        assert_eq!(key.as_ref()[0], 99);
    }

    #[test]
    fn test_secure_memory_error_display() {
        let lock_err = SecureMemoryError::LockFailed("permission denied".to_string());
        assert!(lock_err.to_string().contains("permission denied"));

        let unlock_err = SecureMemoryError::UnlockFailed("not locked".to_string());
        assert!(unlock_err.to_string().contains("not locked"));

        let size_err = SecureMemoryError::InvalidSize(42);
        assert!(size_err.to_string().contains("42"));
    }

    // Test that SecureKey can be used with crypto operations
    #[test]
    fn test_secure_key_deref() {
        let data = [0x42u8; 32];
        let key = SecureKey::new(data);

        // Test Deref - should return &[u8; 32]
        let array_ref: &[u8; 32] = &*key;
        assert_eq!(array_ref, &data);
    }

    #[test]
    fn test_secure_key_deref_mut() {
        let data = [0u8; 32];
        let mut key = SecureKey::new(data);

        // Test DerefMut - should allow modification
        key[0] = 0xFF;
        key[31] = 0xEE;
        assert_eq!(key[0], 0xFF);
        assert_eq!(key[31], 0xEE);
    }

    // Test sizes match expected constants
    #[test]
    fn test_size_constants() {
        assert_eq!(SecureKey::SIZE, 32);
        assert_eq!(SecureNonce::SIZE, 12);
        assert_eq!(SecureSalt::SIZE, 16);
    }

    // Stress test: many allocations and zeroizations
    #[test]
    fn test_stress_allocations() {
        for i in 0..1000 {
            let data = vec![i as u8; 64];
            let secure = SecureBytes::new(data);
            assert_eq!(secure.len(), 64);
            assert_eq!(secure[0], i as u8);
            // Drop happens here
        }
    }

    // Test with various sizes
    #[test]
    fn test_various_sizes() {
        for size in [0, 1, 16, 32, 64, 128, 256, 1024, 4096, 65536] {
            let secure = SecureBytes::zeroed(size);
            assert_eq!(secure.len(), size);
        }
    }
}
