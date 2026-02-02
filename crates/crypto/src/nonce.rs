//! Nonce Uniqueness Enforcement
//!
//! This module provides a registry to track used nonces and prevent nonce reuse
//! within encryption operations. Nonce reuse in AES-GCM is catastrophic as it
//! can lead to complete key recovery.
//!
//! # Security Model
//!
//! - The registry tracks nonces used during a single session
//! - On vault lock, the registry is cleared (nonces are per-session)
//! - For 96-bit random nonces, the birthday bound is ~2^48 uses for 50% collision probability
//! - This registry provides defense-in-depth by detecting accidental reuse
//!
//! # Thread Safety
//!
//! The `NonceRegistry` uses a `RwLock` for thread-safe access, allowing multiple
//! readers to check if a nonce exists while ensuring exclusive access for registration.
//!
//! # Example
//!
//! ```
//! use tesseract_crypto::nonce::NonceRegistry;
//! use tesseract_crypto::random::generate_nonce;
//!
//! let registry = NonceRegistry::new();
//!
//! // Generate and register a nonce
//! let nonce = generate_nonce().expect("Failed to generate nonce");
//! registry.register_nonce(&nonce).expect("Nonce should register successfully");
//!
//! // Attempting to register the same nonce again will fail
//! assert!(registry.register_nonce(&nonce).is_err());
//!
//! // Clear on vault lock
//! registry.clear();
//! ```

use crate::CryptoError;
use std::collections::HashSet;
use std::sync::RwLock;

/// The standard nonce size in bytes (96-bit for AES-GCM).
pub const NONCE_SIZE: usize = 12;

/// A registry for tracking used nonces to prevent nonce reuse.
///
/// The registry maintains an in-memory set of all nonces used during the current
/// session. Before any encryption operation, the nonce should be registered using
/// [`register_nonce`](Self::register_nonce) which will detect and reject duplicates.
///
/// # Thread Safety
///
/// This type uses internal synchronization (`RwLock`) and can be safely shared
/// across threads. The API uses interior mutability to allow registration from
/// shared references.
///
/// # Memory Considerations
///
/// Each nonce consumes 12 bytes in the registry. For typical usage patterns,
/// memory consumption is negligible. For high-throughput scenarios:
/// - 1 million nonces ≈ 12 MB
/// - 100 million nonces ≈ 1.2 GB
///
/// The registry is automatically cleared on vault lock via [`clear`](Self::clear).
#[derive(Debug, Default)]
pub struct NonceRegistry {
    /// Set of registered nonces (using fixed-size array as key).
    nonces: RwLock<HashSet<[u8; NONCE_SIZE]>>,
}

impl NonceRegistry {
    /// Creates a new, empty nonce registry.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// let registry = NonceRegistry::new();
    /// assert_eq!(registry.len(), 0);
    /// ```
    #[inline]
    pub fn new() -> Self {
        Self {
            nonces: RwLock::new(HashSet::new()),
        }
    }

    /// Creates a new nonce registry with pre-allocated capacity.
    ///
    /// Use this when you expect a large number of nonces to be registered
    /// during the session to avoid reallocation.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The initial capacity for the internal hash set.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// // Pre-allocate for 10,000 expected operations
    /// let registry = NonceRegistry::with_capacity(10_000);
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            nonces: RwLock::new(HashSet::with_capacity(capacity)),
        }
    }

    /// Registers a nonce and checks for collisions.
    ///
    /// This method should be called before any encryption operation using the
    /// given nonce. If the nonce has already been used, an error is returned
    /// and the encryption must be aborted.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The 12-byte nonce to register.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - The nonce was successfully registered (first use).
    /// * `Err(CryptoError::NonceCollision)` - The nonce has already been used.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (another thread panicked while
    /// holding the lock). In practice, this indicates a bug in the application.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    /// use tesseract_crypto::CryptoError;
    ///
    /// let registry = NonceRegistry::new();
    /// let nonce = [0u8; 12];
    ///
    /// // First registration succeeds
    /// assert!(registry.register_nonce(&nonce).is_ok());
    ///
    /// // Second registration fails with collision error
    /// match registry.register_nonce(&nonce) {
    ///     Err(CryptoError::NonceCollision) => { /* expected */ }
    ///     _ => panic!("Expected NonceCollision error"),
    /// }
    /// ```
    pub fn register_nonce(&self, nonce: &[u8; NONCE_SIZE]) -> Result<(), CryptoError> {
        let mut nonces = self.nonces.write().expect("Nonce registry lock poisoned");
        if nonces.insert(*nonce) {
            Ok(())
        } else {
            Err(CryptoError::NonceCollision)
        }
    }

    /// Checks if a nonce has already been registered without registering it.
    ///
    /// This is useful for diagnostic purposes or when you need to check before
    /// performing a potentially expensive operation.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The 12-byte nonce to check.
    ///
    /// # Returns
    ///
    /// `true` if the nonce has been registered, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// let registry = NonceRegistry::new();
    /// let nonce = [1u8; 12];
    ///
    /// assert!(!registry.contains(&nonce));
    /// registry.register_nonce(&nonce).unwrap();
    /// assert!(registry.contains(&nonce));
    /// ```
    #[inline]
    pub fn contains(&self, nonce: &[u8; NONCE_SIZE]) -> bool {
        let nonces = self.nonces.read().expect("Nonce registry lock poisoned");
        nonces.contains(nonce)
    }

    /// Returns the number of registered nonces.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// let registry = NonceRegistry::new();
    /// assert_eq!(registry.len(), 0);
    ///
    /// let nonce1 = [0u8; 12];
    /// let nonce2 = [1u8; 12];
    ///
    /// registry.register_nonce(&nonce1).unwrap();
    /// assert_eq!(registry.len(), 1);
    ///
    /// registry.register_nonce(&nonce2).unwrap();
    /// assert_eq!(registry.len(), 2);
    /// ```
    #[inline]
    pub fn len(&self) -> usize {
        let nonces = self.nonces.read().expect("Nonce registry lock poisoned");
        nonces.len()
    }

    /// Returns `true` if the registry contains no nonces.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// let registry = NonceRegistry::new();
    /// assert!(registry.is_empty());
    ///
    /// registry.register_nonce(&[0u8; 12]).unwrap();
    /// assert!(!registry.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all registered nonces.
    ///
    /// This method should be called when the vault is locked to release memory
    /// and reset the session state. Nonces are per-session, so after clearing,
    /// previously used nonces can be safely reused in a new session (though the
    /// probability of collision with random generation is negligible).
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// let registry = NonceRegistry::new();
    /// registry.register_nonce(&[0u8; 12]).unwrap();
    /// registry.register_nonce(&[1u8; 12]).unwrap();
    /// assert_eq!(registry.len(), 2);
    ///
    /// registry.clear();
    /// assert!(registry.is_empty());
    ///
    /// // Can re-register after clear
    /// registry.register_nonce(&[0u8; 12]).unwrap();
    /// ```
    pub fn clear(&self) {
        let mut nonces = self.nonces.write().expect("Nonce registry lock poisoned");
        nonces.clear();
    }

    /// Shrinks the internal storage to fit the current number of nonces.
    ///
    /// This can be useful after clearing a large registry to reclaim memory.
    ///
    /// # Example
    ///
    /// ```
    /// use tesseract_crypto::nonce::NonceRegistry;
    ///
    /// let registry = NonceRegistry::with_capacity(100_000);
    /// // After clearing, shrink to reclaim memory
    /// registry.clear();
    /// registry.shrink_to_fit();
    /// ```
    pub fn shrink_to_fit(&self) {
        let mut nonces = self.nonces.write().expect("Nonce registry lock poisoned");
        nonces.shrink_to_fit();
    }
}

/// Generates a nonce and registers it in one atomic operation.
///
/// This is a convenience function that combines nonce generation with
/// registration. It ensures that the generated nonce is unique within
/// the session before returning.
///
/// # Arguments
///
/// * `registry` - The nonce registry to register with.
///
/// # Returns
///
/// * `Ok([u8; 12])` - A unique, registered nonce.
/// * `Err(CryptoError)` - Nonce generation or registration failed.
///
/// # Security Note
///
/// With 96-bit random nonces, the probability of collision is negligible
/// (~2^-48 after 2^24 uses). This function provides defense-in-depth by
/// detecting the extremely unlikely case of a collision.
///
/// # Example
///
/// ```
/// use tesseract_crypto::nonce::{NonceRegistry, generate_and_register_nonce};
///
/// let registry = NonceRegistry::new();
/// let nonce = generate_and_register_nonce(&registry).expect("Failed to generate nonce");
/// assert_eq!(nonce.len(), 12);
/// assert!(registry.contains(&nonce));
/// ```
pub fn generate_and_register_nonce(registry: &NonceRegistry) -> Result<[u8; NONCE_SIZE], CryptoError> {
    let nonce = crate::random::generate_nonce()?;
    registry.register_nonce(&nonce)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::generate_nonce;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_new_registry_is_empty() {
        let registry = NonceRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_with_capacity() {
        let registry = NonceRegistry::with_capacity(1000);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_register_nonce_success() {
        let registry = NonceRegistry::new();
        let nonce = [0u8; NONCE_SIZE];

        assert!(registry.register_nonce(&nonce).is_ok());
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(&nonce));
    }

    #[test]
    fn test_register_nonce_collision() {
        let registry = NonceRegistry::new();
        let nonce = [1u8; NONCE_SIZE];

        // First registration should succeed
        assert!(registry.register_nonce(&nonce).is_ok());

        // Second registration should fail with collision
        match registry.register_nonce(&nonce) {
            Err(CryptoError::NonceCollision) => { /* expected */ }
            Ok(()) => panic!("Expected collision error"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // Length should still be 1
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_register_multiple_unique_nonces() {
        let registry = NonceRegistry::new();

        for i in 0u8..100 {
            let mut nonce = [0u8; NONCE_SIZE];
            nonce[0] = i;
            assert!(registry.register_nonce(&nonce).is_ok(), "Nonce {} should register", i);
        }

        assert_eq!(registry.len(), 100);
    }

    #[test]
    fn test_contains() {
        let registry = NonceRegistry::new();
        let nonce = [42u8; NONCE_SIZE];

        assert!(!registry.contains(&nonce));
        registry.register_nonce(&nonce).unwrap();
        assert!(registry.contains(&nonce));
    }

    #[test]
    fn test_clear() {
        let registry = NonceRegistry::new();

        // Register some nonces
        for i in 0u8..10 {
            let mut nonce = [0u8; NONCE_SIZE];
            nonce[0] = i;
            registry.register_nonce(&nonce).unwrap();
        }
        assert_eq!(registry.len(), 10);

        // Clear the registry
        registry.clear();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_clear_allows_reuse() {
        let registry = NonceRegistry::new();
        let nonce = [123u8; NONCE_SIZE];

        // Register and verify collision
        registry.register_nonce(&nonce).unwrap();
        assert!(registry.register_nonce(&nonce).is_err());

        // Clear and verify nonce can be registered again
        registry.clear();
        assert!(registry.register_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_shrink_to_fit() {
        let registry = NonceRegistry::with_capacity(10000);

        // Add a few nonces
        for i in 0u8..10 {
            let mut nonce = [0u8; NONCE_SIZE];
            nonce[0] = i;
            registry.register_nonce(&nonce).unwrap();
        }

        // Shrink should not fail
        registry.shrink_to_fit();
        assert_eq!(registry.len(), 10);
    }

    #[test]
    fn test_generate_and_register_nonce() {
        let registry = NonceRegistry::new();

        let nonce = generate_and_register_nonce(&registry).expect("Should generate and register");
        assert_eq!(nonce.len(), NONCE_SIZE);
        assert!(registry.contains(&nonce));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_generate_and_register_multiple() {
        let registry = NonceRegistry::new();

        for _ in 0..100 {
            let nonce = generate_and_register_nonce(&registry).expect("Should generate");
            assert!(registry.contains(&nonce));
        }

        assert_eq!(registry.len(), 100);
    }

    /// Test: Zero collisions across 100,000 random nonce generations
    /// This is the primary acceptance criterion for US-006.
    #[test]
    fn test_zero_collisions_100k_nonces() {
        let registry = NonceRegistry::with_capacity(100_000);

        for i in 0..100_000 {
            let nonce = generate_nonce().expect("Failed to generate nonce");
            match registry.register_nonce(&nonce) {
                Ok(()) => { /* expected */ }
                Err(CryptoError::NonceCollision) => {
                    panic!("Collision detected at iteration {}", i);
                }
                Err(e) => panic!("Unexpected error at iteration {}: {:?}", i, e),
            }
        }

        assert_eq!(registry.len(), 100_000);
    }

    #[test]
    fn test_thread_safety_concurrent_registration() {
        let registry = Arc::new(NonceRegistry::new());
        let num_threads = 4;
        let nonces_per_thread = 1000;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    let mut registered = Vec::new();
                    for _ in 0..nonces_per_thread {
                        let nonce = generate_nonce().expect("Failed to generate nonce");
                        if registry.register_nonce(&nonce).is_ok() {
                            registered.push(nonce);
                        }
                    }
                    registered
                })
            })
            .collect();

        let mut total_registered = 0;
        for handle in handles {
            let nonces = handle.join().expect("Thread panicked");
            total_registered += nonces.len();
        }

        // All nonces should have been registered (no collisions expected)
        assert_eq!(registry.len(), total_registered);
        assert_eq!(total_registered, num_threads * nonces_per_thread);
    }

    #[test]
    fn test_thread_safety_concurrent_reads() {
        let registry = Arc::new(NonceRegistry::new());

        // Pre-populate with some nonces
        let known_nonce = [99u8; NONCE_SIZE];
        registry.register_nonce(&known_nonce).unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        assert!(registry.contains(&known_nonce));
                        let _ = registry.len();
                        let _ = registry.is_empty();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_edge_case_all_zeros_nonce() {
        let registry = NonceRegistry::new();
        let zero_nonce = [0u8; NONCE_SIZE];

        assert!(registry.register_nonce(&zero_nonce).is_ok());
        assert!(registry.register_nonce(&zero_nonce).is_err());
    }

    #[test]
    fn test_edge_case_all_ones_nonce() {
        let registry = NonceRegistry::new();
        let ones_nonce = [0xFF; NONCE_SIZE];

        assert!(registry.register_nonce(&ones_nonce).is_ok());
        assert!(registry.register_nonce(&ones_nonce).is_err());
    }

    #[test]
    fn test_different_nonces_not_confused() {
        let registry = NonceRegistry::new();

        // Create two nonces that differ by only one byte
        let mut nonce1 = [0u8; NONCE_SIZE];
        let mut nonce2 = [0u8; NONCE_SIZE];
        nonce1[0] = 1;
        nonce2[0] = 2;

        assert!(registry.register_nonce(&nonce1).is_ok());
        assert!(registry.register_nonce(&nonce2).is_ok());

        // Verify both are registered
        assert!(registry.contains(&nonce1));
        assert!(registry.contains(&nonce2));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_default_implementation() {
        let registry: NonceRegistry = Default::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_debug_implementation() {
        let registry = NonceRegistry::new();
        let debug_str = format!("{:?}", registry);
        assert!(debug_str.contains("NonceRegistry"));
    }

    /// Test that the nonce size constant is correct for AES-GCM.
    #[test]
    fn test_nonce_size_constant() {
        assert_eq!(NONCE_SIZE, 12, "AES-GCM nonce should be 12 bytes (96 bits)");
    }

    /// Stress test with many registrations and clears.
    #[test]
    fn test_stress_register_clear_cycles() {
        let registry = NonceRegistry::new();

        for cycle in 0..10 {
            for i in 0..1000 {
                let mut nonce = [0u8; NONCE_SIZE];
                nonce[0] = (cycle * 10 + i / 256) as u8;
                nonce[1] = (i % 256) as u8;
                registry.register_nonce(&nonce).unwrap();
            }

            assert_eq!(registry.len(), 1000);
            registry.clear();
            assert!(registry.is_empty());
        }
    }
}
